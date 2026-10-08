"""Text extraction for PDF, DOCX, TXT/CSV/JSON."""
import io
import re
import zipfile
from xml.etree import ElementTree

from pypdf import PdfReader

MAX_CHARS = 200_000


def extract_text(filename: str, data: bytes) -> str:
    name = filename.lower()
    if name.endswith(".pdf") or data.startswith(b"%PDF"):
        reader = PdfReader(io.BytesIO(data))
        return "\n".join((p.extract_text() or "") for p in reader.pages[:50])[:MAX_CHARS]
    if name.endswith((".docx", ".docm")):
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            xml = z.read("word/document.xml")
        ns = "{http://schemas.openxmlformats.org/wordprocessingml/2006/main}"
        root = ElementTree.fromstring(xml)
        paras = ["".join(t.text or "" for t in p.iter(ns + "t")) for p in root.iter(ns + "p")]
        return "\n".join(paras)[:MAX_CHARS]
    return data.decode("utf-8", errors="replace")[:MAX_CHARS]


def normalize(text: str) -> str:
    text = re.sub(r"[ \t]+", " ", text)
    return re.sub(r"\n\s*\n+", "\n", text).strip()
