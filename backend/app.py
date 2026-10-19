from __future__ import annotations

import csv
import io
import json
import re
import sqlite3
from datetime import datetime, timezone
from difflib import SequenceMatcher
import os
from pathlib import Path
from urllib.parse import urlsplit

import joblib
from flask import Flask, Response, jsonify, request, send_from_directory

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"
MODEL_PATH = ROOT / "models" / "phishlens_strict_hostname_comp_augmented.joblib"
DB_PATH = Path(os.environ.get("DATABASE_PATH", str(ROOT / "results" / "phishlens_history.db")))
MAX_URL_LENGTH = 4096
MAX_BULK_URLS = 100

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
_model_bundle = None


def load_model():
    """Load the saved vectorizer/classifier bundle without retraining."""
    global _model_bundle
    if _model_bundle is None:
        if not MODEL_PATH.is_file():
            raise FileNotFoundError(f"Production model missing: {MODEL_PATH}")
        bundle = joblib.load(MODEL_PATH)
        if not isinstance(bundle, dict):
            raise ValueError("Expected a dictionary model bundle.")
        vectorizer = bundle.get("vectorizer")
        model = bundle.get("model", bundle.get("classifier"))
        if vectorizer is None or model is None:
            raise ValueError("Model bundle must contain vectorizer and model.")
        if not hasattr(model, "classes_") or 0 not in list(model.classes_):
            raise ValueError("Classifier does not expose the expected phishing class 0.")
        _model_bundle = (vectorizer, model)
    return _model_bundle


def connect_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            url TEXT NOT NULL,
            hostname TEXT NOT NULL,
            prediction TEXT NOT NULL,
            is_phishing INTEGER NOT NULL,
            score REAL,
            scanned_at TEXT NOT NULL
        )
    """)
    conn.commit()
    return conn


def validate_url(raw):
    if not isinstance(raw, str):
        raise ValueError("Enter a URL as text.")
    url = raw.strip()
    if not url:
        raise ValueError("Enter a URL to scan.")
    if len(url) > MAX_URL_LENGTH:
        raise ValueError(f"URL is too long (maximum {MAX_URL_LENGTH} characters).")
    if any(ch.isspace() for ch in url):
        raise ValueError("The URL cannot contain spaces or line breaks.")
    if not re.match(r"^https?://", url, re.IGNORECASE):
        raise ValueError("Include http:// or https:// at the start of the URL.")
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        _ = parsed.port  # Trigger invalid-port validation.
    except ValueError as exc:
        raise ValueError("This URL appears to be malformed.") from exc
    if not hostname or "." not in hostname and hostname.lower() != "localhost":
        raise ValueError("A valid hostname is required.")
    return url, parsed, hostname.lower().rstrip(".")


def visible_indicators(url, parsed, hostname):
    labels = hostname.split(".")
    try:
        import ipaddress
        ipaddress.ip_address(hostname)
        ip_host = True
    except ValueError:
        ip_host = False
    lowered = url.lower()
    shorteners = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "cutt.ly", "rebrand.ly"}
    suspicious = {"login", "verify", "verification", "secure", "account", "password", "signin", "banking", "update", "confirm", "wallet", "recover"}
    return [
        {"key": "https", "label": "Uses HTTPS", "value": parsed.scheme.lower() == "https",
         "detail": "HTTPS encrypts the connection but does not prove a site is trustworthy."},
        {"key": "ip_host", "label": "IP address used as host", "value": ip_host,
         "detail": "IP-address hosts can be unusual for public sign-in pages."},
        {"key": "long", "label": "Long URL", "value": len(url) > 100,
         "detail": "Length alone is a weak signal; many legitimate URLs are long."},
        {"key": "subdomains", "label": "Multiple subdomains", "value": max(0, len(labels) - 2),
         "detail": "Subdomains are common. Check the actual registered domain."},
        {"key": "query", "label": "Has query parameters", "value": bool(parsed.query),
         "detail": "Query parameters are common on legitimate websites too."},
        {"key": "fragment", "label": "Has URL fragment", "value": bool(parsed.fragment),
         "detail": "A fragment is not inherently malicious."},
        {"key": "shortener", "label": "Known URL shortener", "value": hostname in shorteners or any(hostname.endswith("." + d) for d in shorteners),
         "detail": "Shortened links can obscure their final destination."},
        {"key": "keyword", "label": "Selected suspicious keyword", "value": any(word in lowered for word in suspicious),
         "detail": "Keyword matches are weak signals and also appear on legitimate pages."},
    ]


def analyze_url(raw):
    url, parsed, hostname = validate_url(raw)
    vectorizer, model = load_model()
    vector = vectorizer.transform([url])
    predicted_class = int(model.predict(vector)[0])
    # The project's documented label convention is 0 = phishing, 1 = legitimate.
    is_phishing = predicted_class == 0
    score = None
    if hasattr(model, "predict_proba"):
        probabilities = model.predict_proba(vector)[0]
        classes = list(model.classes_)
        score = float(probabilities[classes.index(0)]) * 100.0
    scanned_at = datetime.now(timezone.utc).isoformat()
    return {
        "url": url,
        "hostname": hostname,
        "scheme": parsed.scheme.lower(),
        "path": parsed.path or "/",
        "prediction": "Potential phishing" if is_phishing else "Likely legitimate",
        "is_phishing": is_phishing,
        "score": round(score, 2) if score is not None else None,
        "score_label": "Model phishing score",
        "indicators": visible_indicators(url, parsed, hostname),
        "scanned_at": scanned_at,
        "disclaimer": (
            "This is a machine-learning screening result, not a guarantee or a calibrated "
            "real-world probability. Verify the domain independently before entering sensitive information."
        ),
    }


def save_history(result):
    conn = connect_db()
    try:
        conn.execute(
            """INSERT INTO scan_history
               (url, hostname, prediction, is_phishing, score, scanned_at)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (result["url"], result["hostname"], result["prediction"],
             int(result["is_phishing"]), result["score"], result["scanned_at"]),
        )
        conn.commit()
    finally:
        conn.close()


@app.get("/")
def index():
    return send_from_directory(FRONTEND, "index.html")


@app.get("/<path:filename>")
def frontend_files(filename):
    return send_from_directory(FRONTEND, filename)


@app.get("/api/health")
def health():
    try:
        vectorizer, model = load_model()
        model_loaded = vectorizer is not None and model is not None
        message = "Production model loaded"
    except Exception as exc:
        model_loaded = False
        message = str(exc)
    return jsonify({"ok": True, "model_exists": MODEL_PATH.is_file(),
                    "model_loaded": model_loaded, "message": message})


@app.post("/api/scan")
def scan():
    body = request.get_json(silent=True) or {}
    try:
        result = analyze_url(body.get("url", ""))
        if body.get("save_history") is True:
            save_history(result)
        return jsonify({"ok": True, "result": result})
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except FileNotFoundError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 503
    except Exception:
        app.logger.exception("Scan failed")
        return jsonify({"ok": False, "error": "Scan failed. Check the backend terminal for details."}), 500


@app.post("/api/bulk")
def bulk():
    body = request.get_json(silent=True) or {}
    raw_urls = body.get("urls", [])
    if isinstance(raw_urls, str):
        raw_urls = raw_urls.splitlines()
    if not isinstance(raw_urls, list):
        return jsonify({"ok": False, "error": "Provide a list of URLs."}), 400
    urls = [str(item).strip() for item in raw_urls if str(item).strip()]
    if not urls:
        return jsonify({"ok": False, "error": "Paste at least one URL."}), 400
    if len(urls) > MAX_BULK_URLS:
        return jsonify({"ok": False, "error": f"Maximum {MAX_BULK_URLS} URLs per bulk scan."}), 400
    results, errors = [], []
    for item in urls:
        try:
            result = analyze_url(item)
            results.append(result)
            if body.get("save_history") is True:
                save_history(result)
        except (ValueError, FileNotFoundError) as exc:
            errors.append({"url": item, "error": str(exc)})
        except Exception:
            app.logger.exception("Bulk scan item failed")
            errors.append({"url": item, "error": "Scan failed due to a server error."})
    return jsonify({"ok": True, "results": results, "errors": errors})


@app.get("/api/history")
def history():
    conn = connect_db()
    try:
        rows = conn.execute("SELECT * FROM scan_history ORDER BY id DESC LIMIT 500").fetchall()
        return jsonify({"ok": True, "items": [dict(row) for row in rows]})
    finally:
        conn.close()


@app.delete("/api/history")
def clear_history():
    conn = connect_db()
    try:
        conn.execute("DELETE FROM scan_history")
        conn.commit()
        return jsonify({"ok": True})
    finally:
        conn.close()


@app.get("/api/history.csv")
def history_csv():
    conn = connect_db()
    try:
        rows = conn.execute(
            "SELECT url, hostname, prediction, score, scanned_at FROM scan_history ORDER BY id DESC"
        ).fetchall()
    finally:
        conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["URL", "Hostname", "Prediction", "Model phishing score (%)", "Scanned at (UTC)"])
    writer.writerows([tuple(row) for row in rows])
    return Response(output.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=phishlens-history.csv"})


@app.post("/api/compare")
def compare():
    body = request.get_json(silent=True) or {}
    def hostname_of(value):
        value = str(value or "").strip()
        if not value:
            raise ValueError("Enter both URLs or hostnames.")
        if "://" not in value:
            value = "https://" + value
        try:
            parsed = urlsplit(value)
        except ValueError as exc:
            raise ValueError("Could not parse one of the hostnames.") from exc
        if not parsed.hostname:
            raise ValueError("Could not read a hostname from one of the inputs.")
        return parsed.hostname.lower().rstrip(".")
    try:
        first, second = hostname_of(body.get("first")), hostname_of(body.get("second"))
        similarity = round(SequenceMatcher(None, first, second).ratio() * 100, 2)
        return jsonify({"ok": True, "first": first, "second": second, "similarity": similarity,
                        "note": "Text similarity is only a heuristic. It does not verify ownership, reputation, or safety."})
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"ok": False, "error": "Request too large. Reduce the submitted data."}), 413


if __name__ == "__main__":
    conn = connect_db()
    conn.close()
    print(f"PhishLens rebuild: {ROOT}")
    print(f"Model: {MODEL_PATH}")
    app.run(host="127.0.0.1", port=5000, debug=False)
