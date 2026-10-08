"""Static threat detection for uploaded files, URLs and text, with optional VirusTotal lookup."""
import hashlib
import io
import ipaddress
import math
import os
import re
import zipfile
from urllib.parse import urlparse

import requests

# SHA-256 of the industry-standard EICAR antivirus test file, plus room for your own blocklist.
KNOWN_BAD_SHA256 = {
    "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": "EICAR-Test-File",
}
EICAR_MARKER = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE"

EXEC_MAGIC = {b"MZ": "Windows PE executable", b"\x7fELF": "ELF executable", b"#!": "Script with shebang",
              b"\xca\xfe\xba\xbe": "Mach-O / Java class"}
DANGEROUS_EXT = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".hta", ".msi", ".jar", ".lnk", ".iso"}
EXPECTED_MAGIC = {".pdf": b"%PDF", ".docx": b"PK", ".docm": b"PK", ".xlsx": b"PK", ".xlsm": b"PK", ".zip": b"PK",
                  ".png": b"\x89PNG", ".jpg": b"\xff\xd8", ".jpeg": b"\xff\xd8"}
PDF_MARKERS = {b"/JavaScript": 30, b"/JS": 20, b"/OpenAction": 15, b"/AA": 10, b"/Launch": 40,
               b"/EmbeddedFile": 20, b"/RichMedia": 15, b"/XFA": 10, b"/SubmitForm": 10}
SUSPICIOUS_TLDS = {"zip", "mov", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "click", "country", "work", "rest", "cam"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rb.gy"}
BRANDS = ["paypal", "microsoft", "office365", "sbi", "hdfc", "icici", "amazon", "apple", "google", "netflix", "gov"]
PHISH_PHRASES = ["verify your account", "account suspended", "urgent action required", "confirm your password",
                 "unusual sign-in", "click here to", "update your kyc", "your account will be", "reset your password immediately",
                 "won a prize", "gift card", "wire transfer", "kindly", "login to avoid"]

IOC_PATTERNS = {
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    "urls": r"https?://[^\s<>\"')]+",
    "domains": r"\b(?:[a-z0-9-]+\.)+(?:com|net|org|in|io|xyz|top|ru|cn|info|biz|tk|ml|zip|click|gov|edu|co)\b",
    "md5": r"\b[a-f0-9]{32}\b", "sha1": r"\b[a-f0-9]{40}\b", "sha256": r"\b[a-f0-9]{64}\b",
    "emails": r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
    "cves": r"\bCVE-\d{4}-\d{4,7}\b",
}


def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return round(-sum(c / n * math.log2(c / n) for c in counts if c), 3)


def hashes(data):
    return {"md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(),
            "sha256": hashlib.sha256(data).hexdigest()}


def _ind(name, weight, detail):
    return {"indicator": name, "weight": weight, "detail": detail}


def scan_url(url):
    inds = []
    try:
        p = urlparse(url if "://" in url else "http://" + url)
    except ValueError:
        return {"url": url, "score": 50, "verdict": "suspicious", "indicators": [_ind("unparseable-url", 50, url)]}
    host = (p.hostname or "").lower()
    try:
        ipaddress.ip_address(host)
        inds.append(_ind("ip-host", 25, "URL uses a raw IP address instead of a domain"))
    except ValueError:
        pass
    if p.scheme == "http":
        inds.append(_ind("no-tls", 10, "Plain HTTP"))
    if "xn--" in host:
        inds.append(_ind("punycode", 30, "Internationalised (possibly look-alike) domain"))
    if "@" in p.netloc:
        inds.append(_ind("userinfo-trick", 35, "'@' in authority hides the real host"))
    if host.count(".") >= 4:
        inds.append(_ind("deep-subdomains", 15, f"{host.count('.')} levels of subdomains"))
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    if tld in SUSPICIOUS_TLDS:
        inds.append(_ind("suspicious-tld", 20, f".{tld} is frequently abused"))
    if host in SHORTENERS:
        inds.append(_ind("shortener", 15, "URL shortener hides the destination"))
    for b in BRANDS:
        if b in host and not re.search(rf"(^|\.){b}\.(com|in|co\.in|gov\.in|net|org)$", host):
            inds.append(_ind("brand-impersonation", 30, f"'{b}' appears in a non-official domain"))
            break
    if re.search(r"login|verify|secure|account|update|kyc|password|signin", url, re.I):
        inds.append(_ind("credential-keywords", 10, "Credential-themed words in URL"))
    if len(url) > 150:
        inds.append(_ind("long-url", 5, f"{len(url)} characters"))
    if re.search(r"\.(exe|scr|js|hta|apk|bat|ps1|iso)(\?|$)", p.path, re.I):
        inds.append(_ind("executable-download", 40, "Links directly to an executable"))
    return _verdict({"url": url, "host": host}, inds)


def scan_text(text):
    iocs = {k: sorted(set(re.findall(p, text, re.I)))[:50] for k, p in IOC_PATTERNS.items()}
    iocs["sha1"] = [h for h in iocs["sha1"] if h not in "".join(iocs["sha256"])]
    low = text.lower()
    phrases = [ph for ph in PHISH_PHRASES if ph in low]
    inds = []
    if phrases:
        inds.append(_ind("phishing-language", min(15 * len(phrases), 60), ", ".join(phrases)))
    url_results = [scan_url(u) for u in iocs["urls"][:20]]
    bad_urls = [u for u in url_results if u["verdict"] != "clean"]
    if bad_urls:
        inds.append(_ind("suspicious-links", max(u["score"] for u in bad_urls), f"{len(bad_urls)} risky link(s)"))
    res = _verdict({"iocs": iocs, "urls": url_results}, inds)
    return res


def _scan_pdf(data, inds):
    for marker, w in PDF_MARKERS.items():
        n = len(re.findall(re.escape(marker) + rb"(?![A-Za-z])", data))
        if n:
            inds.append(_ind("pdf" + marker.decode().lower().replace("/", "-"), w, f"{marker.decode()} appears {n}x"))


def _scan_zip(data, ext, inds):
    try:
        z = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        inds.append(_ind("corrupt-archive", 15, "Claims to be a ZIP/Office file but cannot be opened"))
        return
    names = z.namelist()
    total = sum(i.file_size for i in z.infolist())
    if data and total / max(len(data), 1) > 100:
        inds.append(_ind("zip-bomb", 50, f"Compression ratio {total // max(len(data), 1)}:1"))
    if any(n.lower().endswith("vbaproject.bin") for n in names):
        inds.append(_ind("office-macros", 40, "Document contains VBA macros"))
    for n in names:
        if n.endswith(".rels"):
            rel = z.read(n)[:200_000]
            if b'TargetMode="External"' in rel and (b"attachedTemplate" in rel or b"oleObject" in rel):
                inds.append(_ind("remote-template", 45, f"External template/OLE reference in {n} (template injection)"))
                break
    for n in names:
        if os.path.splitext(n.lower())[1] in DANGEROUS_EXT:
            inds.append(_ind("archive-executable", 40, f"Archive contains {n}"))
            break


def scan_file(filename, data, use_virustotal=True):
    filename = os.path.basename(filename or "upload.bin")
    low = filename.lower()
    ext = os.path.splitext(low)[1]
    h = hashes(data)
    inds = []
    if h["sha256"] in KNOWN_BAD_SHA256:
        inds.append(_ind("known-bad-hash", 100, KNOWN_BAD_SHA256[h["sha256"]]))
    elif EICAR_MARKER in data[:1024]:
        inds.append(_ind("eicar-signature", 100, "EICAR test signature"))
    for magic, desc in EXEC_MAGIC.items():
        if data.startswith(magic):
            inds.append(_ind("executable-content", 50, desc))
            break
    if ext in DANGEROUS_EXT:
        inds.append(_ind("dangerous-extension", 30, ext))
    parts = low.split(".")
    if len(parts) >= 3 and "." + parts[-1] in DANGEROUS_EXT:
        inds.append(_ind("double-extension", 35, filename))
    if ext in EXPECTED_MAGIC and not data.startswith(EXPECTED_MAGIC[ext]):
        inds.append(_ind("magic-mismatch", 30, f"Content does not match {ext}"))
    if data.startswith(b"%PDF"):
        _scan_pdf(data, inds)
    if data.startswith(b"PK"):
        _scan_zip(data, ext, inds)
    ent = entropy(data[:1_000_000])
    if ent > 7.5 and ext not in (".png", ".jpg", ".jpeg", ".zip", ".docx", ".xlsx", ".pdf", ".gz"):
        inds.append(_ind("high-entropy", 15, f"Entropy {ent} suggests packed/encrypted content"))
    result = _verdict({"filename": filename, "size": len(data), "hashes": h, "entropy": ent}, inds)
    if use_virustotal:
        vt = virustotal_lookup(h["sha256"])
        if vt:
            result["virustotal"] = vt
            if vt.get("malicious", 0) >= 3:
                result["indicators"].append(_ind("virustotal", 80, f"{vt['malicious']} engines flag this file"))
                result.update(_score(result["indicators"]))
    return result


def virustotal_lookup(sha256):
    key = os.environ.get("VT_API_KEY")
    if not key:
        return None
    try:
        r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}", headers={"x-apikey": key}, timeout=15)
        if r.status_code == 404:
            return {"found": False}
        r.raise_for_status()
        stats = r.json()["data"]["attributes"]["last_analysis_stats"]
        return {"found": True, **stats}
    except Exception as exc:
        return {"error": type(exc).__name__}


def _score(inds):
    # noisy-OR over indicator weights (0-100) -> overall 0-100
    p = 1.0
    for i in inds:
        p *= 1 - min(i["weight"], 100) / 100
    score = round((1 - p) * 100)
    verdict = "malicious" if score >= 70 else "suspicious" if score >= 30 else "clean"
    return {"score": score, "verdict": verdict}


def _verdict(base, inds):
    base["indicators"] = sorted(inds, key=lambda i: -i["weight"])
    base.update(_score(inds))
    return base
