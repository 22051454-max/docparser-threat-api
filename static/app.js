const $ = (id) => document.getElementById(id);
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const badge = (v, s) => `<span class="v ${esc(v)}">${esc(v)}${s !== undefined ? " · " + s : ""}</span>`;

async function call(path, opts) {
  opts.headers = Object.assign({ "X-API-Key": $("key").value }, opts.headers || {});
  const r = await fetch(path, opts);
  const data = await r.json();
  $("out").textContent = JSON.stringify(data, null, 2);
  return data;
}

$("parseBtn").onclick = async () => {
  const f = $("docfile").files[0]; if (!f) return alert("Choose a file");
  const fd = new FormData(); fd.append("file", f);
  const d = await call("/api/v1/documents", { method: "POST", body: fd });
  if (d.error) { $("summary").textContent = d.error; return; }
  let h = `<p>Threat scan: ${badge(d.threat_scan.verdict, d.threat_scan.score)} · status <b>${esc(d.status)}</b></p>`;
  if (d.document) {
    const doc = d.document;
    h += `<p>Type: <b>${esc(doc.document_type)}</b> (confidence ${doc.confidence}) · engine ${esc(doc.extraction_engine)}</p>`;
    h += "<table>" + Object.entries(doc.fields).map(([k, v]) => `<tr><th>${esc(k)}</th><td>${esc(v)}</td></tr>`).join("") + "</table>";
    if (doc.line_items.length) h += "<h4>Line items</h4><table><tr><th>Item</th><th>Qty</th><th>Rate</th><th>Amount</th></tr>" +
      doc.line_items.map(i => `<tr><td>${esc(i.description)}</td><td>${i.quantity}</td><td>${i.unit_price}</td><td>${i.amount}</td></tr>`).join("") + "</table>";
    if (doc.validation_issues.length) h += `<p>⚠️ ${doc.validation_issues.map(esc).join("<br>")}</p>`;
    h += `<p>Text threat check: ${badge(doc.text_threats.verdict, doc.text_threats.score)}</p>`;
  }
  $("summary").innerHTML = h;
};

$("urlBtn").onclick = async () => {
  const urls = $("urls").value.split("\n").map(s => s.trim()).filter(Boolean);
  const d = await call("/api/v1/threats/url", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ urls }) });
  if (Array.isArray(d)) $("summary").innerHTML = "<table>" + d.map(u => `<tr><td>${esc(u.url)}</td><td>${badge(u.verdict, u.score)}</td><td>${u.indicators.map(i => esc(i.indicator)).join(", ")}</td></tr>`).join("") + "</table>";
};

$("textBtn").onclick = async () => {
  const d = await call("/api/v1/threats/text", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text: $("text").value }) });
  if (d.iocs) $("summary").innerHTML = `<p>${badge(d.verdict, d.score)}</p><table>` +
    Object.entries(d.iocs).filter(([, v]) => v.length).map(([k, v]) => `<tr><th>${esc(k)}</th><td>${v.map(esc).join("<br>")}</td></tr>`).join("") + "</table>";
};
