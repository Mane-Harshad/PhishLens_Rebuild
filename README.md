# PhishLens — HTML/CSS/JavaScript + Flask replacement

This is a replacement for the Streamlit interface. It reuses the existing trained model and `src/url_features.py` from your PhishLens project.

## Expected placement

Copy these folders/files into your existing project root so it looks like this:

```text
PhishLens/
├── backend/app.py
├── frontend/index.html
├── frontend/css/style.css
├── frontend/js/app.js
├── frontend/js/scanner.js
├── frontend/js/history.js
├── models/phishlens_strict_hostname_comp_augmented.joblib  # existing
├── src/url_features.py                                     # existing
├── results/                                                # existing
└── requirements-flask.txt
```

Do not delete your existing `models`, `src`, or `data` folders. Do not overwrite the trained model.

## Install and run on Windows PowerShell

From your existing project folder:

```powershell
cd "$HOME\Desktop\PhishLens"
.\.venv\Scripts\python.exe -m pip install -r requirements-flask.txt
.\.venv\Scripts\python.exe backend\app.py
```

Open this in your browser:

`http://127.0.0.1:5000`

Keep the terminal window open while using the site. Press `Ctrl+C` in that terminal to stop the server.

## Included

- Custom responsive HTML/CSS/JavaScript interface
- Flask JSON API connected to the existing production model
- Single URL analysis and indicator breakdown
- Bulk URL scan (up to 100 per batch) with CSV export
- Optional local SQLite scan history, search and export
- Text-based hostname similarity comparison
- Backend health endpoint

## Important

- The score is the model's output for the phishing class, not a calibrated real-world probability.
- The model may misclassify legitimate URLs. A clean verdict is not a safety guarantee.
- History is stored locally in `results/phishlens_history.db`; saved URLs may contain private tokens or query values. Saving is opt-in.
- The app performs local model inference; it does not fetch or crawl the URL being scanned.
- Do not expose the Flask development server directly to the public internet.
