import hmac
import json
import os
import sqlite3
import time
import uuid
from functools import wraps

from flask import Flask, g, jsonify, request, send_from_directory

from .extract import extract_text, normalize
from .parser import parse_document
from .threats import scan_file, scan_text, scan_url

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
PARSEABLE = (".pdf", ".docx", ".docm", ".txt", ".csv", ".json", ".md", ".eml")


def create_app(test_config=None):
    app = Flask(__name__, static_folder=STATIC, static_url_path="/static")
    keys = [k.strip() for k in os.environ.get("API_KEYS", "").split(",") if k.strip()]
    app.config.update(
        API_KEYS=keys or ["demo-key-123"],
        DB_PATH=os.environ.get("DB_PATH", os.path.join(app.instance_path, "jobs.db")),
        MAX_CONTENT_LENGTH=int(os.environ.get("MAX_UPLOAD_MB", "10")) * 1024 * 1024,
        USE_VIRUSTOTAL=True,
    )
    if test_config:
        app.config.update(test_config)
    os.makedirs(os.path.dirname(app.config["DB_PATH"]) or ".", exist_ok=True)
    with sqlite3.connect(app.config["DB_PATH"]) as con:
        con.execute("""CREATE TABLE IF NOT EXISTS jobs(id TEXT PRIMARY KEY, created REAL, filename TEXT,
                       status TEXT, verdict TEXT, result TEXT)""")

    def db():
        if "db" not in g:
            g.db = sqlite3.connect(app.config["DB_PATH"])
            g.db.row_factory = sqlite3.Row
        return g.db

    @app.teardown_appcontext
    def close(_):
        if (c := g.pop("db", None)):
            c.close()

    def require_key(view):
        @wraps(view)
        def wrapped(*a, **kw):
            supplied = request.headers.get("X-API-Key", "")
            if not any(hmac.compare_digest(supplied, k) for k in app.config["API_KEYS"]):
                return jsonify(error="Invalid or missing X-API-Key"), 401
            return view(*a, **kw)
        return wrapped

    @app.after_request
    def headers(resp):
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'")
        return resp

    @app.get("/")
    def ui():
        return send_from_directory(STATIC, "index.html")

    @app.get("/docs")
    def docs():
        return send_from_directory(STATIC, "docs.html")

    @app.get("/api/v1/health")
    def health():
        return jsonify(status="ok", llm=bool(os.environ.get("OPENAI_API_KEY")), virustotal=bool(os.environ.get("VT_API_KEY")),
                       demo_key=app.config["API_KEYS"] == ["demo-key-123"])

    def _file():
        f = request.files.get("file")
        if not f or not f.filename:
            return None, None, (jsonify(error="Upload a file in the 'file' form field"), 400)
        return f.filename, f.read(), None

    @app.post("/api/v1/documents")
    @require_key
    def create_document():
        filename, data, err = _file()
        if err:
            return err
        job_id, t0 = uuid.uuid4().hex[:12], time.perf_counter()
        threat = scan_file(filename, data, app.config["USE_VIRUSTOTAL"])
        result = {"id": job_id, "filename": filename, "threat_scan": threat}
        if threat["verdict"] == "malicious":
            status = "quarantined"
            result["message"] = "File was not parsed because the threat scan classified it as malicious."
        elif not filename.lower().endswith(PARSEABLE):
            status = "unsupported"
            result["message"] = f"Parsing supports {', '.join(PARSEABLE)}"
        else:
            try:
                text = normalize(extract_text(filename, data))
                result["document"] = parse_document(text)
                result["document"]["text_threats"] = scan_text(text)
                status = "parsed"
            except Exception as exc:
                status, result["message"] = "failed", f"Could not extract text: {type(exc).__name__}"
        result["status"], result["processing_ms"] = status, int((time.perf_counter() - t0) * 1000)
        db().execute("INSERT INTO jobs VALUES(?,?,?,?,?,?)",
                     (job_id, time.time(), filename, status, threat["verdict"], json.dumps(result)))
        db().commit()
        return jsonify(result), 201 if status == "parsed" else 200

    @app.get("/api/v1/documents")
    @require_key
    def list_documents():
        rows = db().execute("SELECT id, created, filename, status, verdict FROM jobs ORDER BY created DESC LIMIT 100").fetchall()
        return jsonify([dict(r) for r in rows])

    @app.get("/api/v1/documents/<job_id>")
    @require_key
    def get_document(job_id):
        row = db().execute("SELECT result FROM jobs WHERE id=?", (job_id,)).fetchone()
        return (jsonify(json.loads(row["result"])), 200) if row else (jsonify(error="Not found"), 404)

    @app.post("/api/v1/threats/file")
    @require_key
    def threat_file():
        filename, data, err = _file()
        return err or jsonify(scan_file(filename, data, app.config["USE_VIRUSTOTAL"]))

    @app.post("/api/v1/threats/url")
    @require_key
    def threat_url():
        urls = (request.get_json(silent=True) or {}).get("urls") or [(request.get_json(silent=True) or {}).get("url")]
        urls = [u for u in urls if isinstance(u, str) and u][:50]
        if not urls:
            return jsonify(error="Provide 'url' or 'urls'"), 400
        return jsonify([scan_url(u) for u in urls])

    @app.post("/api/v1/threats/text")
    @require_key
    def threat_text():
        text = (request.get_json(silent=True) or {}).get("text", "")
        if not isinstance(text, str) or not text.strip():
            return jsonify(error="Provide 'text'"), 400
        return jsonify(scan_text(text[:200_000]))

    @app.errorhandler(413)
    def too_big(_):
        return jsonify(error="File too large"), 413

    return app
