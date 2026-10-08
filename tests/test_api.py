import io
import zipfile

import pytest

from docapi import create_app
from docapi.threats import scan_file, scan_url

H = {"X-API-Key": "demo-key-123"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    monkeypatch.delenv("VT_API_KEY", raising=False)
    monkeypatch.delenv("API_KEYS", raising=False)
    return create_app({"TESTING": True, "DB_PATH": str(tmp_path / "j.db")}).test_client()


def upload(client, path_or_bytes, name):
    data = open(path_or_bytes, "rb").read() if isinstance(path_or_bytes, str) else path_or_bytes
    return client.post("/api/v1/documents", headers=H, data={"file": (io.BytesIO(data), name)},
                       content_type="multipart/form-data")


def test_requires_api_key(client):
    assert client.get("/api/v1/documents").status_code == 401


def test_parse_pdf_invoice(client):
    r = upload(client, "samples/invoice_acme.pdf", "invoice.pdf")
    body = r.get_json()
    assert r.status_code == 201
    doc = body["document"]
    assert doc["document_type"] == "invoice"
    assert doc["fields"]["invoice_number"] == "INV-2026-0042"
    assert doc["fields"]["total"].endswith("45430.00")
    assert len(doc["line_items"]) == 3
    assert body["threat_scan"]["verdict"] == "clean"
    assert client.get(f"/api/v1/documents/{body['id']}", headers=H).get_json()["id"] == body["id"]


def test_eicar_quarantined(client):
    eicar = (b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$" + b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*")
    body = upload(client, eicar, "notes.txt").get_json()
    assert body["status"] == "quarantined" and body["threat_scan"]["verdict"] == "malicious"


def test_pdf_autorun_flagged():
    r = scan_file("x.pdf", open("samples/suspicious_autorun.pdf", "rb").read(), False)
    names = {i["indicator"] for i in r["indicators"]}
    assert {"pdf-javascript", "pdf-openaction"} <= names and r["verdict"] != "clean"


def test_macro_docm_and_double_extension():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("word/document.xml", "<w:document/>")
        z.writestr("word/vbaProject.bin", b"\x00" * 10)
    r = scan_file("invoice.pdf.docm", buf.getvalue(), False)
    assert "office-macros" in {i["indicator"] for i in r["indicators"]}
    assert scan_file("invoice.pdf.exe", b"MZ\x90\x00", False)["verdict"] == "malicious"


def test_url_heuristics(client):
    r = client.post("/api/v1/threats/url", headers=H, json={"urls": ["http://paypal.account-verify.top/login", "https://github.com"]})
    a, b = r.get_json()
    assert a["verdict"] in ("suspicious", "malicious") and b["verdict"] == "clean"
    assert scan_url("http://user@185.220.101.44/x.exe")["verdict"] == "malicious"


def test_text_iocs(client):
    r = client.post("/api/v1/threats/text", headers=H, json={"text": open("samples/phishing_email.txt").read()}).get_json()
    assert "185.220.101.44" in r["iocs"]["ipv4"]
    assert r["iocs"]["md5"] and r["verdict"] == "malicious"


def test_pan_masked():
    from docapi.parser import parse_document
    d = parse_document("PAN: ABCDE1234F invoice no: X-1 total: Rs. 10")
    assert d["entities"]["pans"] == ["******234F"]
