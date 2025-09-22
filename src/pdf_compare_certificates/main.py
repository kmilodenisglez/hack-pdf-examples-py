#!/usr/bin/env python3
"""
Workshop 1 - Digital Certificate Vulnerabilities

This script is an educational tool for demonstrating vulnerabilities in digital certificates,
with an emphasis on incremental updates. It combines the original functions for generating
and verifying documents with new functionalities for certificate inspection and PDF analysis.

Dependencies:
    pip install endesive fpdf2 pikepdf cryptography pypdf reportlab

Required certificates (place in working dir or provide paths via
CERT_* environment variables):
    - cert_fea.pem / key_fea.pem   -> FEA (simulated advanced signature)
    - cert_fec.pem / key_fec.pem   -> FEC/QES (simulated qualified signature)
"""

import os
import sys
import hashlib
import logging
import argparse
import importlib.util
import json
from datetime import datetime, timezone
from pprint import pprint
import tempfile

# Optional imports used inside functions (we check preflight)
import pikepdf
from fpdf import FPDF

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger(__name__)

# Default certificate filenames (can be overridden by env vars)
CERT_FEA = os.environ.get("CERT_FEA", "certs/cert_fea.pem")
KEY_FEA = os.environ.get("KEY_FEA", "certs/key_fea.pem")
CERT_FEC = os.environ.get("CERT_FEC", "certs/cert_fec.pem")
KEY_FEC = os.environ.get("KEY_FEC", "certs/key_fec.pem")


# -----------------------
# Preflight / Helpers
# -----------------------
def check_python_packages(packages):
    """Returns missing packages from the given list."""
    missing = []
    for pkg in packages:
        if importlib.util.find_spec(pkg) is None:
            missing.append(pkg)
    return missing

def preflight_check(require_attack=False, require_crypto=False):
    """
    Checks for certificates and dependencies.
    If require_attack=True, also validates packages for attack simulation.
    If require_crypto=True, validates packages for crypto functions.
    """
    missing = []
    # Check cert files
    for p in [CERT_FEA, KEY_FEA, CERT_FEC, KEY_FEC]:
        if not os.path.exists(p):
            missing.append(f"missing file: {p}")

    # Check Python packages
    pkgs = ["endesive", "fpdf", "pikepdf", "cryptography"]
    if require_attack:
        pkgs += ["pypdf", "reportlab"]
    if require_crypto:
        pkgs += ["cryptography"]
    missing_pkgs = check_python_packages(pkgs)
    if missing_pkgs:
        missing.extend([f"missing package: {m}" for m in missing_pkgs])

    return missing

# -----------------------
# Utilities
# -----------------------
def ensure_outdir(outdir):
    if not outdir:
        outdir = "."
    os.makedirs(outdir, exist_ok=True)
    return outdir

def path_in(outdir, filename):
    return os.path.join(outdir, filename)

def now_ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

# -----------------------
# Test Certificate Generation
# -----------------------
def generate_test_certs(common_name, outdir="certs"):
    """
    Generates a new private key and a self-signed test certificate
    using the cryptography library.
    """
    try:
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives import serialization
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        log.error("The certificate generation function requires the 'cryptography' library.")
        sys.exit(1)

    outdir = ensure_outdir(outdir)
    key_path = os.path.join(outdir, "key.pem")
    cert_path = os.path.join(outdir, "cert.pem")

    log.info("Generating a new private key...")
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    log.info("Generating a new self-signed certificate...")
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"EC"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"Guayas"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"Guayaquil"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Software Security Workshop"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow().replace(year=datetime.utcnow().year + 1)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(u"localhost")]),
        critical=False,
    ).sign(key, hashes.SHA256(), default_backend())

    log.info("Saving key and certificate...")
    with open(key_path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))
    with open(cert_path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    log.info("✅ Certificates generated at %s and %s", key_path, cert_path)

# -----------------------
# PDF generation / signing
# -----------------------
def create_sample_pdf(name="John Doe", course="Course", grade="14/20", path="temp.pdf"):
    """
    Generate a sample PDF certificate.
    """
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", size=16, style="B")
    pdf.cell(0, 10, "OFFICIAL ACADEMIC CERTIFICATE", new_x="LMARGIN", new_y="NEXT", align='C')
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 10, f"Name: {name}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"Course: {course}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"Grade: {grade}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d')}", new_x="LMARGIN", new_y="NEXT")
    pdf.output(path)
    log.info("📄 PDF generated: %s", path)
    return path

def sign_pdf(pdf_in, cert_pem, key_pem, output, is_qualified=False):
    """
    Sign a PDF using Endesive and save a compatible signed PDF.
    """
    from endesive.pdf import cms
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    log.debug("Signing %s with cert=%s key=%s", pdf_in, cert_pem, key_pem)

    with open(pdf_in, "rb") as f:
        data = f.read()
    with open(cert_pem, "rb") as f:
        cert_bytes = f.read()
    with open(key_pem, "rb") as f:
        key_bytes = f.read()

    cert = load_pem_x509_certificate(cert_bytes, default_backend())
    key = load_pem_private_key(key_bytes, password=None, backend=default_backend())

    date = datetime.now(timezone.utc).strftime("D:%Y%m%d%H%M%S+00'00'")
    dct = {
        'sigpage': 0,
        'sigfield': 'Signature1',
        'auto_sigfield': True,
        'signature': 'QUALIFIED SIGNATURE' if is_qualified else 'Advanced Signature',
        'contact': 'security@university.edu',
        'location': 'Lima, Peru',
        'signingdate': date,
        'reason': 'Official certificate',
    }

    signed_bytes = cms.sign(datau=data, udct=dct, key=key, cert=cert, othercerts=[cert], algomd='sha256')

    with open(output, "wb") as f:
        f.write(data + signed_bytes)

    log.info("🔒 PDF signed and saved: %s", output)
    return output

# -----------------------
# Certificate Validation
# -----------------------
def validate_certificate_info(cert_path):
    """
    Extracts and displays key information from a certificate.
    """
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        log.error("This function requires the 'cryptography' library.")
        sys.exit(1)

    if not os.path.exists(cert_path):
        log.error("Certificate not found: %s", cert_path)
        return

    with open(cert_path, "rb") as f:
        cert_bytes = f.read()

    try:
        cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
        info = {
            "Subject": cert.subject.rfc4514_string(),
            "Issuer": cert.issuer.rfc4514_string(),
            "Serial Number": cert.serial_number,
            "Validity": {
                "Not Before": cert.not_valid_before.strftime("%Y-%m-%d %H:%M:%S"),
                "Not After": cert.not_valid_after.strftime("%Y-%m-%d %H:%M:%S"),
            },
            "Signature Algorithm": cert.signature_hash_algorithm.name,
            "Public Key Size": cert.public_key().key_size,
            "Fingerprint (SHA256)": cert.fingerprint(hashes.SHA256()).hex(),
        }
        log.info("📊 Certificate information for %s:", cert_path)
        pprint(info)

        # Expiration check
        now = datetime.utcnow()
        if now > cert.not_valid_after:
            log.warning("⚠️ The certificate has expired.")
        elif now < cert.not_valid_before:
            log.warning("⚠️ The certificate is not yet valid.")
        else:
            log.info("✅ The certificate is currently valid.")

    except Exception as e:
        log.error("Error processing the certificate: %s", e)


# -----------------------
# Verification and Reports
# -----------------------
def compute_hash(pdf_path):
    h = hashlib.sha256()
    with open(pdf_path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def extract_text(pdf_path):
    text_content = []
    try:
        with pikepdf.open(pdf_path) as pdf:
            for page in pdf.pages:
                text_content.append(page.extract_text())
    except Exception as e:
        log.debug("pikepdf failed to open %s: %s", pdf_path, e)
        return []
    return text_content

def verify_certificate(original_path, modified_path, label=""):
    """
    Verifies a file and returns a result dict for reporting.
    """
    from endesive.pdf.verify import verify

    result = {
        "label": label,
        "original": original_path,
        "modified": modified_path,
        "timestamp": now_ts(),
        "orig_hash": None,
        "mod_hash": None,
        "hash_match": None,
        "signatures": [],
        "incremental": False,
        "text_snippets": [],
        "error": None,
    }
    if not os.path.exists(modified_path):
        result["error"] = "modified file not found"
        return result
    try:
        if os.path.exists(original_path):
            result["orig_hash"] = compute_hash(original_path)
        result["mod_hash"] = compute_hash(modified_path)
        result["hash_match"] = (result["orig_hash"] == result["mod_hash"])
        try:
            with open(modified_path, 'rb') as f:
                data = f.read()
            sigs = verify(data)
            if sigs:
                for r in sigs:
                    result["signatures"].append({
                        "signer": r.get("signer_name", "Unknown"),
                        "ok": bool(r.get("ok")),
                        "signing_time": r.get("signing_time")
                    })
            else:
                result["signatures"] = []
        except AssertionError:
            result["error"] = "verification incomplete (incremental updates present)"
        except Exception as e:
            result["error"] = f"signature verification error: {e}"
        with open(modified_path, 'rb') as f:
            content = f.read()
        startxref = content.count(b'startxref')
        eof = content.count(b'%%EOF')
        result["incremental"] = (startxref > 1 or eof > 1)
        texts = extract_text(modified_path)
        snippets = [t[:120] + "..." if len(t) > 120 else t for t in texts]
        result["text_snippets"] = snippets
    except Exception as e:
        result["error"] = str(e)
    return result

def print_verification_result(res):
    """Prints human-friendly verification result to console."""
    label = res.get("label")
    print(f"\n🔍 VERIFYING: {label}")
    print("="*60)
    if res.get("error"):
        print("   ❌ ERROR:", res["error"])
        print("="*60)
        return
    print(f"   Original Hash: {res.get('orig_hash')}")
    print(f"   Modified Hash: {res.get('mod_hash')}")
    print("   ✅ Content intact (Hash match)" if res.get("hash_match") else "   ❌ Content modified! (Hash mismatch)")
    if res.get("signatures"):
        for idx, s in enumerate(res["signatures"], start=1):
            print(f"   Signature #{idx}: {'VALID' if s['ok'] else 'INVALID'} | Signer: {s['signer']} | time: {s.get('signing_time')}")
    else:
        print("   ⚠️  No digital signature detected.")
    print(f"   startxref/incremental: {res.get('incremental')}")
    print("\n   Text snippets (first 120 characters per page):")
    for i, sn in enumerate(res.get("text_snippets", []), start=1):
        print(f"      Page {i}: {sn}")
    print("="*60)

def write_html_report(results, outpath):
    """
    Writes a simple HTML report summarizing verification results.
    """
    def color_for(res):
        if res.get("error"): return "#ffcccc"
        if not res.get("signatures"): return "#fff2cc"
        all_ok = all(s.get("ok") for s in res.get("signatures", []))
        if all_ok and res.get("hash_match", True) and not res.get("incremental", False): return "#ccffcc"
        return "#ffd9d9"
    rows = []
    for r in results:
        color = color_for(r)
        signer_info = "<br>".join([f"{s['signer']} ({'OK' if s['ok'] else 'INVALID'})" for s in r.get("signatures", [])]) or "None"
        snippets = "<br>".join([f"Page {i+1}: {s}" for i, s in enumerate(r.get("text_snippets", []))]) or "None"
        rows.append(f"""
        <tr style="background:{color}">
            <td>{r.get('label')}</td>
            <td>{os.path.basename(r.get('original',''))}</td>
            <td>{os.path.basename(r.get('modified',''))}</td>
            <td>{r.get('orig_hash') or 'N/A'}</td>
            <td>{r.get('mod_hash') or 'N/A'}</td>
            <td>{'Yes' if r.get('hash_match') else 'No'}</td>
            <td>{signer_info}</td>
            <td>{'Yes' if r.get('incremental') else 'No'}</td>
            <td>{r.get('error') or ''}</td>
            <td style="max-width:300px; white-space:normal;">{snippets}</td>
        </tr>
        """)
    html = f"""
    <html><head><meta charset="utf-8"><title>Verification Report</title></head>
    <body>
      <h2>Verification Report - {now_ts()}</h2>
      <table border="1" cellpadding="6" cellspacing="0">
        <thead>
          <tr><th>Label</th><th>Original</th><th>Modified</th><th>Orig Hash</th><th>Mod Hash</th>
          <th>Hash Match</th><th>Signatures</th><th>Incremental</th><th>Error</th><th>Text Snippets</th></tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </body></html>
    """
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html)

def inspect_pdf_structure(pdf_path):
    """
    Prints the object tree and internal structure of a PDF for demonstration purposes.
    """
    if not os.path.exists(pdf_path):
        log.error("File not found: %s", pdf_path)
        return

    try:
        log.info("Analyzing PDF structure: %s", pdf_path)
        with pikepdf.open(pdf_path) as pdf:
            print("\n--- PDF Metadata ---")
            for key, value in pdf.trailer.items():
                print(f"  {key}: {value}")

            print("\n--- Cross-references (xref) ---")
            print("Number of objects: ", len(pdf.objects))

            print("\n--- Page Structure ---")
            for i, page in enumerate(pdf.pages):
                print(f"  Page {i+1} (object {page.obj_num})")
                try:
                    if '/Annots' in page:
                        log.info("    Annotations detected: %s", page['/Annots'])
                    if '/AcroForm' in pdf.root and '/Fields' in pdf.root['/AcroForm']:
                        log.info("    Form fields detected.")
                except Exception as e:
                    log.error("    Error inspecting page: %s", e)

            print("\n--- PDF Trailer (last section) ---")
            trailer = pdf.trailer
            pprint(trailer)

            # Detect incremental updates
            with open(pdf_path, 'rb') as f:
                content = f.read()
                startxref_count = content.count(b'startxref')
                eof_count = content.count(b'%%EOF')

            print("\n--- Key Markers ---")
            print(f"  Number of 'startxref': {startxref_count}")
            print(f"  Number of '%%EOF': {eof_count}")
            if startxref_count > 1 or eof_count > 1:
                log.warning("⚠️ Multiple markers detected, suggesting an incremental update.")
            else:
                log.info("✅ Document appears to be a single, non-incremental PDF file.")

    except pikepdf.PdfError as e:
        log.error("Pikepdf error: %s", e)
    except Exception as e:
        log.error("Error inspecting the PDF: %s", e)


# -----------------------
# PDF Generation / Verification Flows
# -----------------------
def generate_sample_documents(outdir="./outputs"):
    """
    Create unsigned, FEA-signed and FEC-signed sample certificates in outdir.
    """
    outdir = ensure_outdir(outdir)
    plain = path_in(outdir, "cert_plain.pdf")
    temp_fea = path_in(outdir, "temp_fea.pdf")
    temp_fec = path_in(outdir, "temp_fec.pdf")
    cert_fea_out = path_in(outdir, "cert_fea.pdf")
    cert_fec_out = path_in(outdir, "cert_fec.pdf")

    create_sample_pdf(name="Carlos Pérez", course="Cybersecurity", grade="16/20", path=plain)
    create_sample_pdf(name="Ana Gómez", course="Blockchain", grade="14/20", path=temp_fea)
    sign_pdf(temp_fea, CERT_FEA, KEY_FEA, cert_fea_out, is_qualified=False)
    create_sample_pdf(name="Luis Fernández", course="Cryptography", grade="18/20", path=temp_fec)
    sign_pdf(temp_fec, CERT_FEC, KEY_FEC, cert_fec_out, is_qualified=True)

    # cleanup temporaries
    for f in [temp_fea, temp_fec]:
        if os.path.exists(f):
            os.remove(f)

    log.info("✅ Certificates generated at %s", os.path.abspath(outdir))
    return {"plain": plain, "fea": cert_fea_out, "fec": cert_fec_out}

def verify_student_modifications(outdir=".", generate_report=False, report_path=None):
    """
    Verify student-edited PDF files inside outdir. Optionally return results list for report.
    """
    outdir = ensure_outdir(outdir)
    checks = [
        (path_in(outdir, "cert_fea.pdf"), path_in(outdir, "cert_fea_EDITED.pdf"), "FEA CERTIFICATE (edited)"),
        (path_in(outdir, "cert_fec.pdf"), path_in(outdir, "cert_fec_EDITED.pdf"), "FEC CERTIFICATE (edited)"),
        (path_in(outdir, "cert_plain.pdf"), path_in(outdir, "cert_plain_EDITED.pdf"), "UNSIGNED CERTIFICATE (edited)"),
    ]
    results = []
    for original, modified, label in checks:
        if not os.path.exists(modified):
            res = {"label": label, "original": original, "modified": modified, "error": "modified file not found"}
            results.append(res)
            print(f"\n⚠️  {label}: File '{modified}' not found. (Edited?)")
            continue
        res = verify_certificate(original, modified, label)
        print_verification_result(res)
        results.append(res)

    # produce HTML report if requested
    if generate_report and report_path:
        try:
            write_html_report(results, report_path)
            log.info("📊 HTML report written to %s", report_path)
        except Exception as e:
            log.error("Failed to write HTML report: %s", e)

    return results


# -----------------------
# Attacks (incremental / rewrite)
# -----------------------
def incremental_rewrite_attack(signed_pdf, out):
    """
    Create a new PDF by appending a crafted page using pypdf + reportlab.
    This produces a new PDF (rewrite) that will generally break the original signature.
    """
    try:
        from pypdf import PdfReader, PdfWriter
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter
        from io import BytesIO
    except Exception as e:
        raise RuntimeError("incremental_rewrite_attack requires pypdf and reportlab. Install them.") from e

    reader = PdfReader(signed_pdf)
    writer = PdfWriter()
    for page in reader.pages:
        writer.add_page(page)

    packet = BytesIO()
    can = canvas.Canvas(packet, pagesize=letter)
    can.setFont("Helvetica-Bold", 24)
    can.drawString(72, 500, "GRADE: 20/20 - ATTACK (rewrite)")
    can.save()
    packet.seek(0)

    overlay_reader = PdfReader(packet)
    writer.add_page(overlay_reader.pages[0])

    with open(out, "wb") as f:
        writer.write(f)

    log.warning("🔴 Rewrite attack produced: %s", out)
    return out

def incremental_pikepdf_attack(signed_pdf, out):
    """
    Append a page as an incremental update using pikepdf (may preserve original bytes).
    """
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter
        from io import BytesIO
    except Exception as e:
        raise RuntimeError("incremental_pikepdf_attack requires reportlab. Install it.") from e

    packet = BytesIO()
    can = canvas.Canvas(packet, pagesize=letter)
    can.setFont("Helvetica-Bold", 24)
    can.drawString(72, 500, "GRADE: 20/20 - ATTACK (incremental)")
    can.save()
    packet.seek(0)

    tmp_path = None
    try:
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
        tmp.write(packet.read())
        tmp.flush()
        tmp.close()
        tmp_path = tmp.name

        with pikepdf.open(signed_pdf, allow_overwriting_input=True) as pdf:
            with pikepdf.open(tmp_path) as mal:
                pdf.pages.extend(mal.pages)
            pdf.save(out)
        log.warning("🔴 PikePDF incremental attack produced: %s", out)
        return out
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except Exception:
                pass

def simulate_attacks(mode, outdir=".", report=False, report_path=None):
    """
    Generate certificates, run attack mode on FEA and FEC, verify and optionally report.
    """
    outdir = ensure_outdir(outdir)
    generated = generate_sample_documents(outdir=outdir)
    targets = [("fea", generated["fea"]), ("fec", generated["fec"])]
    results = []
    for base, orig in targets:
        if mode == "incremental_rewrite":
            attacked = path_in(outdir, f"{base}_attacked_rewrite.pdf")
            incremental_rewrite_attack(orig, attacked)
        elif mode == "incremental_pikepdf":
            attacked = path_in(outdir, f"{base}_attacked_incremental_pikepdf.pdf")
            incremental_pikepdf_attack(orig, attacked)
        else:
            raise ValueError("Unknown attack mode: " + str(mode))
        res = verify_certificate(orig, attacked, f"{base.upper()} attacked ({mode})")
        print_verification_result(res)
        results.append(res)

    if report and report_path:
        write_html_report(results, report_path)
        log.info("📊 HTML report written to %s", report_path)

    return results

# -----------------------
# HTML Report writer
# -----------------------
def write_html_report(results, outpath):
    """
    Write a simple HTML report summarizing verification results.
    """
    def color_for(res):
        if res.get("error"):
            return "#ffcccc"  # light red
        if not res.get("signatures"):
            return "#fff2cc"  # light yellow
        all_ok = all(s.get("ok") for s in res.get("signatures", []))
        if all_ok and res.get("hash_match", True) and not res.get("incremental", False):
            return "#ccffcc"  # light green
        return "#ffd9d9"  # pale red for issues

    rows = []
    for r in results:
        color = color_for(r)
        signer_info = "<br>".join([f"{s['signer']} ({'OK' if s['ok'] else 'INVALID'})" for s in r.get("signatures", [])]) or "None"
        snippets = "<br>".join([f"Page {i+1}: {s}" for i, s in enumerate(r.get("text_snippets", []))]) or "None"
        rows.append(f"""
        <tr style="background:{color}">
            <td>{r.get('label')}</td>
            <td>{os.path.basename(r.get('original',''))}</td>
            <td>{os.path.basename(r.get('modified',''))}</td>
            <td>{r.get('orig_hash') or 'N/A'}</td>
            <td>{r.get('mod_hash') or 'N/A'}</td>
            <td>{'Yes' if r.get('hash_match') else 'No'}</td>
            <td>{signer_info}</td>
            <td>{'Yes' if r.get('incremental') else 'No'}</td>
            <td>{r.get('error') or ''}</td>
            <td style="max-width:300px; white-space:normal;">{snippets}</td>
        </tr>
        """)

    html = f"""
    <html><head><meta charset="utf-8"><title>Verification Report</title></head>
    <body>
      <h2>Verification Report - {now_ts()}</h2>
      <table border="1" cellpadding="6" cellspacing="0">
        <thead>
          <tr><th>Label</th><th>Original</th><th>Modified</th><th>Orig Hash</th><th>Mod Hash</th>
          <th>Hash Match</th><th>Signatures</th><th>Incremental</th><th>Error</th><th>Text Snippets</th></tr>
        </thead>
        <tbody>
          {''.join(rows)}
        </tbody>
      </table>
    </body></html>
    """
    with open(outpath, "w", encoding="utf-8") as f:
        f.write(html)


# -----------------------
# CLI Main
# -----------------------
def main():
    """
    Main entry point for the command-line interface.
    """
    parser = argparse.ArgumentParser(
        description="Workshop 1: Vulnerabilities in Digital Certificates"
    )

    # Parent parser with global options
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument(
        "--outdir",
        default=".",
        help="Output directory for generated/verified files"
    )
    parent_parser.add_argument(
        "--report",
        action="store_true",
        help="Produce an HTML report summarizing results"
    )

    # Root parser with subcommands
    subparsers = parser.add_subparsers(
        dest="action",
        help="Available actions"
    )

    # Subcommands that inherit global arguments
    subparsers.add_parser("generate", parents=[parent_parser], help="Generate unsigned and signed certificates.")
    subparsers.add_parser("verify", parents=[parent_parser], help="Verify student-edited files.")
    sim = subparsers.add_parser("simulate", parents=[parent_parser], help="Simulate attacks against signed PDFs.")
    sim.add_argument(
        "--mode",
        choices=["incremental_rewrite", "incremental_pikepdf"],
        required=True,
        help="Attack mode to simulate."
    )

    # New subcommands that do not use global arguments
    parser_gencert = subparsers.add_parser("gencert", help="Generate a new key pair and a self-signed test certificate.")
    parser_gencert.add_argument("--name", default="Security Workshop", help="Common name for the certificate (e.g., 'University XYZ').")

    parser_inspect = subparsers.add_parser("inspect", help="Inspect the internal structure of a PDF.")
    parser_inspect.add_argument("file", help="Path to the PDF file to inspect.")

    parser_validate = subparsers.add_parser("validate_certs", help="Validate a certificate file.")
    parser_validate.add_argument("file", help="Path to the certificate file to validate.")

    args = parser.parse_args()

    # Preflight check based on the action
    require_attack = (args.action == "simulate")
    require_crypto = (args.action in ["gencert", "validate_certs"])
    missing = preflight_check(require_attack=require_attack, require_crypto=require_crypto)
    if missing:
        print("Preflight check failed. Missing items:")
        for m in missing:
            print(" -", m)
        sys.exit(2)

    # Dispatch actions
    if args.action in ["generate", "verify", "simulate"]:
        outdir = ensure_outdir(args.outdir)
        report_path = path_in(outdir, "verification_report.html") if args.report else None

        if args.action == "generate":
            generate_sample_documents(outdir=outdir)
        elif args.action == "verify":
            verify_student_modifications(outdir=outdir, generate_report=args.report, report_path=report_path)
        elif args.action == "simulate":
            simulate_attacks(
                mode=args.mode,
                outdir=outdir,
                report=args.report,
                report_path=report_path
            )
    elif args.action == "gencert":
        generate_test_certs(common_name=args.name)
    elif args.action == "inspect":
        inspect_pdf_structure(args.file)
    elif args.action == "validate_certs":
        validate_certificate_info(args.file)
    else:
        parser.print_help()

if __name__ == "__main__":
    main()