"""Generate sample PDFs: a clean invoice and a suspicious PDF with auto-run JavaScript (harmless alert)."""
import os

HERE = os.path.dirname(os.path.abspath(__file__))


def build_pdf(lines, extra_catalog=b"", extra_objs=()):
    content = b"BT /F1 11 Tf 50 780 Td 14 TL " + b" ".join(b"(" + l.replace("(", "[").replace(")", "]").encode() + b") '" for l in lines) + b" ET"
    objs = [b"<< /Type /Catalog /Pages 2 0 R " + extra_catalog + b">>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
            b"<< /Length %d >>\nstream\n" % len(content) + content + b"\nendstream",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", *extra_objs]
    out, offsets = bytearray(b"%PDF-1.4\n"), []
    for i, o in enumerate(objs, 1):
        offsets.append(len(out))
        out += b"%d 0 obj\n" % i + o + b"\nendobj\n"
    xref = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1) + b"".join(b"%010d 00000 n \n" % o for o in offsets)
    out += b"trailer << /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref)
    return bytes(out)


if __name__ == "__main__":
    lines = open(os.path.join(HERE, "invoice_acme.txt")).read().splitlines()
    open(os.path.join(HERE, "invoice_acme.pdf"), "wb").write(build_pdf(lines))
    js = b"<< /Type /Action /S /JavaScript /JS (app.alert\\('Demo: this PDF runs JavaScript on open'\\);) >>"
    open(os.path.join(HERE, "suspicious_autorun.pdf"), "wb").write(
        build_pdf(["Please enable content to view this document."], b"/OpenAction 6 0 R ", [js]))
    print("samples written")
