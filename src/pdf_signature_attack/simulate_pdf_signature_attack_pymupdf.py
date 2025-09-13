#!/usr/bin/env python3
"""
simulate_pdf_signature_attack_pymupdf.py

Simulates PDF signing and two attack variants:
 - incremental_rewrite_attack: rewrites PDF (does NOT preserve signature)
 - incremental_pymupdf_attack: adds a page as incremental update (preserves signature)

Requirements:
  pip install endesive cryptography pypdf reportlab fpdf2 pymupdf
  (Ghostscript optional for flattening)
"""

import logging
import os
import re
import subprocess
import hashlib
from datetime import datetime, timezone
import warnings
from cryptography.utils import CryptographyDeprecationWarning

warnings.filterwarnings("ignore", category=CryptographyDeprecationWarning)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)


# -----------------------
# STEP 1: Create original PDF
# -----------------------
def create_original_pdf(path="original.pdf"):
    from fpdf import FPDF

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
def sign_pdf(pdf_in="original.pdf", cert_pem_path="cert.pem", key_pem_path="key.pem", out="signed.pdf"):
    import endesive.pdf.cms as cms
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

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
def incremental_rewrite_attack(signed_pdf="signed.pdf", out="attacked_rewrite.pdf"):
    from pypdf import PdfReader, PdfWriter
    from reportlab.pdfgen import canvas
    from reportlab.lib.colors import red
    from io import BytesIO

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

    with open(out, "wb") as f:
        writer.write(f)
    log.warning("🔴 Incremental rewrite attack applied (does NOT preserve signature): %s", out)
    return out


# -----------------------
# STEP 3b: Real incremental attack using PyMuPDF
# -----------------------
def incremental_pymupdf_attack(signed_pdf="signed.pdf", out="attacked_incremental_pymupdf.pdf"):
    """
    Simulates an incremental attack using PyMuPDF:
      - Inserts a malicious page at the end
      - Preserves the original signed pages
      - Cannot use incremental=True due to signed PDF
      - Saves new PDF separately in 'out'
    """
    import fitz
    from reportlab.pdfgen import canvas
    from io import BytesIO
    import tempfile
    import shutil
    import os

    if not os.path.exists(signed_pdf):
        raise FileNotFoundError(f"Signed PDF not found: {signed_pdf}")

    # Create malicious page in memory
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

        # Open signed PDF and malicious PDF
        doc = fitz.open(signed_pdf)
        mal = fitz.open(tmp.name)

        # Create new PDF: copy all original pages + malicious page
        new_pdf = fitz.open()
        new_pdf.insert_pdf(doc)
        new_pdf.insert_pdf(mal)

        # Save new PDF separately
        new_pdf.save(out)
        new_pdf.close()
        doc.close()
        mal.close()

        log.warning("🔴 Simulated incremental attack applied (PyMuPDF). Output: %s", out)
        return out
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass


# -----------------------
# STEP 4: Basic verification
# -----------------------
def basic_verification(pdf_path, original_signed=None):
    import hashlib
    import re
    from endesive.pdf.verify import verify

    with open(pdf_path, "rb") as f:
        data = f.read()

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

    if original_signed and os.path.exists(original_signed):
        orig_hash = hashlib.sha256(open(original_signed, "rb").read()).hexdigest()
        if pdf_hash != orig_hash:
            print("❌ PDF content differs from original signed file: signature may be invalid")
        else:
            print("✅ PDF content matches original signed file: signature likely intact")


# -----------------------
# STEP 5: Advanced incremental update detection
# -----------------------
def detect_incremental_update_advanced(signed="signed.pdf", attacked="attacked_incremental.pdf"):
    import hashlib
    import re

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
    hash_signed = compute_hash(signed)
    hash_attacked = compute_hash(attacked)

    if s_attacked > s_signed or e_attacked > e_signed:
        print("⚠️ Incremental update detected (more startxref/%%EOF in attacked PDF)")
    if hash_signed != hash_attacked:
        print("❌ PDF content differs: likely modified after signing (signature may be invalid)")
    if (s_attacked <= s_signed and e_attacked <= e_signed) and (hash_signed == hash_attacked):
        print("✅ PDF appears unmodified and signature likely intact.")


# -----------------------
# STEP 6: Flattening
# -----------------------
def apply_flattening_pypdf(input_pdf="attacked_incremental_pymupdf.pdf", out="flattened.pdf"):
    from pypdf import PdfReader, PdfWriter
    reader = PdfReader(input_pdf)
    writer = PdfWriter()
    for p in reader.pages:
        writer.add_page(p)
    with open(out, "wb") as f:
        writer.write(f)
    log.info("🟢 PDF rewritten with pypdf: %s", out)
    return out


# -----------------------
# MAIN FLOW
# -----------------------
def main():
    log.info("🚀 Simulation: Incremental Update PDF Attack")
    create_original_pdf()
    signed = sign_pdf()
    attacked_rewrite = incremental_rewrite_attack(signed)
    attacked_pymupdf = incremental_pymupdf_attack(signed)

    print("\n=== CASE 1: Basic Verification ===")
    basic_verification(attacked_rewrite, original_signed=signed)
    basic_verification(attacked_pymupdf, original_signed=signed)

    print("\n=== CASE 2: Advanced Incremental Detection ===")
    detect_incremental_update_advanced(signed, attacked_pymupdf)

    print("\n=== STEP 3: Flattening ===")
    apply_flattening_pypdf(attacked_pymupdf)


if __name__ == "__main__":
    main()
