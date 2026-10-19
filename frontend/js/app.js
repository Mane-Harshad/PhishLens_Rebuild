const $ = (s) => document.querySelector(s);
const $$ = (s) => [...document.querySelectorAll(s)];
const state = { latest: null, bulkResults: [], history: [] };
function esc(v) { return String(v ?? "").replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c])); }
function errorAt(sel, msg) { const e=$(sel); e.textContent=msg; e.classList.remove("hidden"); }
function clearError(sel) { const e=$(sel); e.textContent=""; e.classList.add("hidden"); }
let toastTimer;
function toast(msg) { const e=$("#toast"); e.textContent=msg; e.classList.add("show"); clearTimeout(toastTimer); toastTimer=setTimeout(()=>e.classList.remove("show"),2400); }
async function api(url, options={}) {
  const res=await fetch(url,{...options,headers:{"Content-Type":"application/json",...(options.headers||{})}});
  let data; try { data=await res.json(); } catch { throw new Error("The server returned an unreadable response."); }
  if(!res.ok || data.ok===false) throw new Error(data.error || `Request failed (${res.status}).`);
  return data;
}
function busy(btn,on,label) {
  if(on){btn.dataset.old=btn.innerHTML;btn.disabled=true;btn.textContent=label;}
  else{btn.disabled=false;if(btn.dataset.old)btn.innerHTML=btn.dataset.old;}
}
function dateFmt(v){if(!v)return "—";const d=new Date(v);return Number.isNaN(d.getTime())?v:d.toLocaleString([], {dateStyle:"medium",timeStyle:"short"});}
function pill(phishing,text){return `<span class="pill ${phishing?"":"safe"}">${esc(text || (phishing?"Potential phishing":"Likely legitimate"))}</span>`;}
function renderResult(r){
  state.latest=r;$("#result-panel").classList.remove("hidden");
  $("#verdict-icon").textContent=r.is_phishing?"!":"✓";$("#verdict-icon").classList.toggle("safe",!r.is_phishing);
  $("#verdict-title").textContent=r.prediction;$("#verdict-host").textContent=r.hostname;$("#result-time").textContent=dateFmt(r.scanned_at);
  $("#score-value").textContent=r.score==null?"N/A":Number(r.score).toFixed(2);$("#score-fill").style.width=`${Math.max(0,Math.min(100,Number(r.score)||0))}%`;
  $("#score-fill").style.background=r.is_phishing?"var(--amber)":"var(--mint)";$("#verdict-note").textContent=r.disclaimer;
  const items=r.indicators||[];$("#indicator-count").textContent=`${items.length} indicators`;
  $("#indicator-grid").innerHTML=items.map(i=>`<article class="indicator"><span class="indicator-mark ${i.value?"flag":""}">${i.value?"!":"✓"}</span><div><strong>${esc(i.label)} <small style="color:${i.value?"var(--amber)":"var(--mint)"};font:9px var(--mono)">${i.value?"PRESENT":"NOT DETECTED"}</small></strong><p>${esc(i.detail)}</p></div></article>`).join("");
  $("#result-panel").scrollIntoView({behavior:"smooth",block:"start"});
}
async function health(){
  try{const d=await api("/api/health");const ok=d.model_loaded;$("#health-dot").style.background=ok?"var(--mint)":"var(--red)";$("#health-text").textContent=ok?"Production model loaded":d.message;$("#model-live").textContent=ok?"AVAILABLE":"ERROR";$("#model-name").textContent=ok?"Production model ready":"Model not ready";}
  catch{$("#health-text").textContent="Backend unavailable";$("#model-live").textContent="OFFLINE";$("#model-name").textContent="Backend not connected";}
}
function activate(name){
  $$(".view").forEach(v=>v.classList.toggle("active",v.id===`view-${name}`));$$(".nav-item").forEach(b=>b.classList.toggle("active",b.dataset.view===name));
  const b=$(`.nav-item[data-view="${name}"]`);$("#crumb").textContent=b?b.textContent.trim().replace(/\s+\d+$/,""):name;
  if(name==="history")loadHistory();window.scrollTo({top:0,behavior:"smooth"});
}
$$(".nav-item").forEach(b=>b.addEventListener("click",()=>activate(b.dataset.view)));
$("#url-input").addEventListener("input",()=>$("#input-count").textContent=`${$("#url-input").value.length} / 4096`);
$("#url-input").addEventListener("keydown",e=>{if(e.key==="Enter")$("#scan-button").click();});
$("#scan-button").addEventListener("click",async()=>{
  clearError("#scan-error");$("#result-panel").classList.add("hidden");const b=$("#scan-button");busy(b,true,"Analyzing URL…");
  try{const d=await api("/api/scan",{method:"POST",body:JSON.stringify({url:$("#url-input").value,save_history:$("#save-scan").checked})});renderResult(d.result);if($("#save-scan").checked)toast("Scan saved to local history.");}
  catch(e){errorAt("#scan-error",e.message);}finally{busy(b,false);}
});
$("#clear-result").addEventListener("click",()=>{state.latest=null;$("#result-panel").classList.add("hidden");});
$("#copy-report").addEventListener("click",async()=>{
  if(!state.latest)return;const r=state.latest;const txt=["PhishLens URL Analysis",`URL: ${r.url}`,`Hostname: ${r.hostname}`,`Verdict: ${r.prediction}`,`Model phishing score: ${r.score==null?"Unavailable":`${Number(r.score).toFixed(2)}%`}`,`Scanned: ${r.scanned_at}`,r.disclaimer].join("\n");
  try{await navigator.clipboard.writeText(txt);toast("Report copied.");}catch{errorAt("#scan-error","Clipboard access was blocked by the browser.");}
});
function downloadText(content,name,type){const blob=new Blob([content],{type});const a=document.createElement("a");a.href=URL.createObjectURL(blob);a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(a.href),1000);}
$("#bulk-button").addEventListener("click",async()=>{
  clearError("#bulk-error");const urls=$("#bulk-input").value.split(/\r?\n/).map(x=>x.trim()).filter(Boolean);
  if(!urls.length)return errorAt("#bulk-error","Paste at least one URL, one per line.");if(urls.length>100)return errorAt("#bulk-error","Maximum 100 URLs per batch.");
  const b=$("#bulk-button");busy(b,true,`Analyzing ${urls.length} URLs…`);
  try{const d=await api("/api/bulk",{method:"POST",body:JSON.stringify({urls,save_history:$("#bulk-save").checked})});state.bulkResults=d.results||[];$("#bulk-results-panel").classList.remove("hidden");
    const ph=state.bulkResults.filter(x=>x.is_phishing).length;$("#bulk-summary").innerHTML=`<span class="summary-chip"><strong>${state.bulkResults.length}</strong> scanned</span><span class="summary-chip"><strong>${ph}</strong> flagged by model</span><span class="summary-chip"><strong>${d.errors.length}</strong> failed</span>`;
    $("#bulk-results").innerHTML=state.bulkResults.map(r=>`<tr><td><div class="table-url">${esc(r.url)}</div><div class="table-host">${esc(r.hostname)}</div></td><td>${pill(r.is_phishing,r.prediction)}</td><td class="score-cell">${r.score==null?"N/A":Number(r.score).toFixed(2)+"%"}</td></tr>`).join("");
    $("#bulk-failures").textContent=d.errors.length?"Some URLs could not be scanned: "+d.errors.map(e=>`${e.url}: ${e.error}`).join(" | "):"";if($("#bulk-save").checked&&state.bulkResults.length)toast("Successful scans saved.");$("#bulk-results-panel").scrollIntoView({behavior:"smooth"});
  }catch(e){errorAt("#bulk-error",e.message);}finally{busy(b,false);}
});
$("#bulk-export").addEventListener("click",()=>{const rows=[["URL","Hostname","Verdict","Model phishing score (%)","Scanned at"],...state.bulkResults.map(r=>[r.url,r.hostname,r.prediction,r.score??"",r.scanned_at])];downloadText(rows.map(row=>row.map(v=>`"${String(v).replace(/"/g,'""')}"`).join(",")).join("\r\n"),"phishlens-bulk-results.csv","text/csv");});
$("#compare-button").addEventListener("click",async()=>{
  clearError("#compare-error");$("#compare-result").classList.add("hidden");const b=$("#compare-button");busy(b,true,"Comparing…");
  try{const d=await api("/api/compare",{method:"POST",body:JSON.stringify({first:$("#compare-a").value,second:$("#compare-b").value})});$("#compare-result").innerHTML=`<div class="compare-result-head"><div><div class="eyebrow">HOSTNAME COMPARISON</div><strong>${esc(d.first)} ↔ ${esc(d.second)}</strong></div><div class="similarity-value">${d.similarity}%</div></div><div class="similarity-track"><span style="width:${d.similarity}%"></span></div><p class="fine-print">${esc(d.note)}</p>`;$("#compare-result").classList.remove("hidden");}
  catch(e){errorAt("#compare-error",e.message);}finally{busy(b,false);}
});
async function loadHistory(){
  const tbody=$("#history-results");tbody.innerHTML="<tr><td colspan='4'>Loading…</td></tr>";
  try{const d=await api("/api/history");state.history=d.items||[];renderHistory();}
  catch(e){$("#history-count").textContent="History unavailable";tbody.innerHTML=`<tr><td colspan="4">${esc(e.message)}</td></tr>`;}
}
function renderHistory(){
  const q=$("#history-search").value.trim().toLowerCase();const rows=state.history.filter(r=>`${r.url} ${r.hostname} ${r.prediction}`.toLowerCase().includes(q));
  $("#history-count").textContent=`${rows.length} shown · ${state.history.length} stored`;
  $("#history-results").innerHTML=rows.map(r=>`<tr><td><div class="table-url">${esc(r.url)}</div><div class="table-host">${esc(r.hostname)}</div></td><td>${pill(Boolean(r.is_phishing),r.prediction)}</td><td class="score-cell">${r.score==null?"N/A":Number(r.score).toFixed(2)+"%"}</td><td>${esc(dateFmt(r.scanned_at))}</td></tr>`).join("");
  $("#history-empty").classList.toggle("hidden",rows.length!==0);$("#history-table-wrap").classList.toggle("hidden",rows.length===0);
}
$("#history-search").addEventListener("input",renderHistory);
$("#clear-history").addEventListener("click",async()=>{if(!confirm("Delete all saved scan history? This cannot be undone."))return;try{await api("/api/history",{method:"DELETE"});state.history=[];renderHistory();toast("History cleared.");}catch(e){toast(e.message);}});
health();
