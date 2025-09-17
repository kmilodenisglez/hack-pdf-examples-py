#!/usr/bin/env python3
"""
simulate_pdf_signature_attack_pikepdf.py

Simulates PDF signing and two attack variants:
 - incremental_rewrite_attack: original version (rewrites PDF; does NOT preserve signature)
 - incremental_pikepdf_attack: adds a page as an incremental update
    (preserves embedded signature in the original PDF; shows how reader detects
    appended/incremental update)

Requirements:
  pip install endesive cryptography pypdf reportlab fpdf2 pikepdf
  (qpdf/ghostscript optional)
"""

import logging
import os
import re
import hashlib
import warnings
from datetime import datetime, timezone
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s"
)
log = logging.getLogger(__name__)

# Create outputs directory
OUTPUTS_DIR = "outputs"
if not os.path.exists(OUTPUTS_DIR):
    os.makedirs(OUTPUTS_DIR)
    log.info("✅ Created outputs directory: %s", OUTPUTS_DIR)


# -----------------------
# STEP 1: Create original PDF
# -----------------------
def create_original_pdf(path=None):
    from fpdf import FPDF

    if path is None:
        path = os.path.join(OUTPUTS_DIR, "original.pdf")

    if os.path.exists(path):
        log.info("Original PDF already exists: %s", path)
        return path

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", size=16, style="B")
    pdf.cell(0, 10, "Official Academic Certificate", new_x="LMARGIN", new_y="NEXT", align='C')
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 10, "Name: John Doe", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, "Course: Introduction to Blockchain", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, "Grade: 14/20", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d')}", new_x="LMARGIN", new_y="NEXT")
    pdf.output(path)
    log.info("✅ Original PDF created: %s", path)
    return path


# -----------------------
# STEP 2: Sign PDF
# -----------------------
def sign_pdf(pdf_in=None, cert_pem_path="certs/cert.pem", key_pem_path="certs/key.pem", out=None):
    import endesive.pdf.cms as cms
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    if pdf_in is None:
        pdf_in = os.path.join(OUTPUTS_DIR, "original.pdf")
    if out is None:
        out = os.path.join(OUTPUTS_DIR, "signed.pdf")

    with open(cert_pem_path, "rb") as f:
        cert_pem = f.read()
    with open(key_pem_path, "rb") as f:
        key_pem = f.read()

    cert_obj = load_pem_x509_certificate(cert_pem, default_backend())
    priv_key_obj = load_pem_private_key(key_pem, password=None, backend=default_backend())

    with open(pdf_in, "rb") as f:
        data = f.read()

    date = datetime.now(timezone.utc).strftime("D:%Y%m%d%H%M%S+00'00'")
    dct = {
        "sigpage": 0,
        "sigfield": "Signature1",
        "auto_sigfield": True,
        "signature": "Digital Signature - Secure University",
        "contact": "security@university.edu",
        "location": "Lima, Peru",
        "signingdate": date,
        "reason": "Officially issued certificate",
    }

    try:
        signed = cms.sign(datau=data, udct=dct, key=priv_key_obj, cert=cert_obj, othercerts=[cert_obj], algomd="sha256")
    except TypeError:
        log.info("Retrying sign(...) using 'dct' instead of 'udct'")
        signed = cms.sign(datau=data, dct=dct, key=priv_key_obj, cert=cert_obj, othercerts=[cert_obj], algomd="sha256")

    out_bytes = signed if signed.startswith(b"%PDF") else data + signed

    with open(out, "wb") as f:
        f.write(out_bytes)

    log.info("✅ Signed PDF saved: %s", out)
    return out


# -----------------------
# STEP 3a: Incremental rewrite attack (does NOT preserve signature)
# -----------------------
def incremental_rewrite_attack(signed_pdf=None, out=None):
    from pypdf import PdfReader, PdfWriter
    from reportlab.pdfgen import canvas
    from reportlab.lib.colors import red
    from io import BytesIO

    if signed_pdf is None:
        signed_pdf = os.path.join(OUTPUTS_DIR, "signed.pdf")
    if out is None:
        out = os.path.join(OUTPUTS_DIR, "attacked_rewrite.pdf")

    reader = PdfReader(signed_pdf)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)

    packet = BytesIO()
    can = canvas.Canvas(packet, pagesize=(595, 842))
    can.setFont("Helvetica-Bold", 24)
    can.setFillColor(red)
    can.drawString(50, 700, "GRADE: 20/20 - HONOR PASS")
    can.save()
    packet.seek(0)

    from pypdf import PdfReader as PR
    temp_reader = PR(packet)
    writer.add_page(temp_reader.pages[0])

    with open(out, "wb") as fp:
        writer.write(fp)
    log.warning("🔴 Incremental rewrite attack applied (does NOT preserve signature): %s", out)
    return out


# -----------------------
# STEP 3b: Real incremental attack using PikePDF
# -----------------------
def incremental_pikepdf_attack(signed_pdf=None, out=None):
    import pikepdf
    from reportlab.pdfgen import canvas
    from io import BytesIO
    import tempfile

    if signed_pdf is None:
        signed_pdf = os.path.join(OUTPUTS_DIR, "signed.pdf")
    if out is None:
        out = os.path.join(OUTPUTS_DIR, "attacked_incremental_pikepdf.pdf")

    packet = BytesIO()
    can = canvas.Canvas(packet, pagesize=(595, 842))
    can.setFont("Helvetica-Bold", 24)
    can.drawString(50, 700, "GRADE: 20/20 - HONOR PASS")
    can.save()
    packet.seek(0)

    tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    try:
        tmp.write(packet.read())
        tmp.flush()
        tmp.close()

        with pikepdf.open(signed_pdf, allow_overwriting_input=True) as pdf:
            with pikepdf.open(tmp.name) as mal_pdf:
                pdf.pages.extend(mal_pdf.pages)
            pdf.save(out, linearize=False)
        log.warning("🔴 Real incremental attack applied (PikePDF). Output: %s", out)
        return out
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass


# -----------------------
# STEP 4: Basic verification (new, robust)
# -----------------------
def basic_verification(pdf_path, original_signed=None):
    import hashlib
    import re
    from endesive.pdf.verify import verify

    if not os.path.exists(pdf_path):
        raise FileNotFoundError(pdf_path)

    with open(pdf_path, "rb") as f:
        data = f.read()

    # Signature verification
    try:
        result = verify(data)
        if result:
            print(f"✅ {pdf_path}: signatures detected")
            for idx, r in enumerate(result):
                print(f"  - Signer #{idx+1}: {r.get('signer_name', 'Unknown')}")
                print(f"    Signing Time: {r.get('signing_time', 'N/A')}")
                print(f"    Signature Hash: {r.get('md', 'N/A')}")
        else:
            print(f"⚠️ {pdf_path}: no signatures detected")
    except AssertionError:
        print(f"⚠️ {pdf_path}: contains incremental updates; verification incomplete.")
    except Exception as e:
        print(f"❌ {pdf_path}: verification error: {e}")

    pdf_hash = hashlib.sha256(data).hexdigest()
    print(f"   SHA-256 Hash: {pdf_hash}")

    startxref_count = len(re.findall(b'startxref', data))
    eof_count = len(re.findall(b'%%EOF', data))
    print(f"   startxref: {startxref_count}, %%EOF: {eof_count}")

    if startxref_count > 1 or eof_count > 1:
        print("⚠️ PDF has multiple sections/incremental updates (possible manipulation)")
    else:
        print("✅ PDF seems to have no additional incremental updates")

    # Compare with original signed PDF if provided
    if original_signed and os.path.exists(original_signed):
        orig_hash = hashlib.sha256(open(original_signed, "rb").read()).hexdigest()
        if pdf_hash != orig_hash:
            print("❌ PDF content differs from original signed file: signature may be invalid")
        else:
            print("✅ PDF content matches original signed file: signature likely intact")


# -----------------------
# STEP 5: Detect incremental update / modifications
# -----------------------
def detect_incremental_update_advanced(signed=None, attacked=None):
    import hashlib
    import re

    if signed is None:
        signed = os.path.join(OUTPUTS_DIR, "signed.pdf")
    if attacked is None:
        attacked = os.path.join(OUTPUTS_DIR, "attacked_incremental_pikepdf.pdf")

    def count_start_eof(path):
        with open(path, "rb") as f:
            data = f.read()
        return len(re.findall(b'startxref', data)), len(re.findall(b'%%EOF', data))

    def compute_hash(path):
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while chunk := f.read(8192):
                h.update(chunk)
        return h.hexdigest()

    s_signed, e_signed = count_start_eof(signed)
    s_attacked, e_attacked = count_start_eof(attacked)
    log.info("startxref (signed)=%d, %%EOF (signed)=%d", s_signed, e_signed)
    log.info("startxref (attacked)=%d, %%EOF (attacked)=%d", s_attacked, e_attacked)

    if s_attacked > s_signed or e_attacked > e_signed:
        log.warning("⚠️ Incremental update detected (more startxref/%%EOF in attacked PDF)")
    else:
        log.info("✅ No additional incremental updates detected via markers.")

    hash_signed = compute_hash(signed)
    hash_attacked = compute_hash(attacked)
    log.info("Hash (signed):   %s", hash_signed)
    log.info("Hash (attacked): %s", hash_attacked)

    if hash_signed != hash_attacked:
        log.error("⛔ PDF content differs: likely modified after signing (signature may be invalid)")
        print("❌ ALERT: PDF has been modified after signing!")
    else:
        print("✅ PDF appears unmodified and signature likely intact.")


# -----------------------
# STEP 6: Flattening
# -----------------------
def apply_flattening_pypdf(input_pdf=None, out=None):
    from pypdf import PdfReader, PdfWriter

    if input_pdf is None:
        input_pdf = os.path.join(OUTPUTS_DIR, "attacked_incremental_pikepdf.pdf")
    if out is None:
        out = os.path.join(OUTPUTS_DIR, "flattened.pdf")

    reader = PdfReader(input_pdf)
    writer = PdfWriter()
    for p in reader.pages:
        writer.add_page(p)
    with open(out, "wb") as f:
        writer.write(f)
    log.info("🟢 PDF flattened with pypdf: %s", out)
    return out


# -----------------------
# MAIN FLOW
# -----------------------
def main():
    original = create_original_pdf()
    signed = sign_pdf(original)
    attacked_rewrite = incremental_rewrite_attack(signed)
    attacked_pike = incremental_pikepdf_attack(signed)

    print("\n=== CASE 1: Basic Verification ===")
    basic_verification(attacked_rewrite, original_signed=signed)
    basic_verification(attacked_pike, original_signed=signed)

    print("\n=== CASE 2: Advanced Attack Detection ===")
    detect_incremental_update_advanced(signed, attacked_pike)

    print("\n=== STEP 3: Flattening ===")
    apply_flattening_pypdf(attacked_pike)


if __name__ == "__main__":
    main()