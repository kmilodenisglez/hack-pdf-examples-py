#!/usr/bin/env python3
"""
Workshop 1 - Vulnerabilities in Digital Certificates (with outdir, HTML report, preflight checks)

Dependencies:
    pip install endesive fpdf2 pikepdf cryptography pypdf reportlab

Required certificates (place in working dir or supply paths via CERT_* env vars):
    - cert_fea.pem / key_fea.pem   -> FEA (simulated advanced signature)
    - cert_fec.pem / key_fec.pem   -> FEC/QES (simulated qualified signature)
"""

import os
import sys
import hashlib
import logging
import argparse
import importlib.util
from datetime import datetime

# optional imports used inside functions (we check preflight)
from fpdf import FPDF
from endesive.pdf.verify import verify
import pikepdf

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger(__name__)

# Default certificate filenames (can be overridden by env vars)
CERT_FEA = os.environ.get("CERT_FEA", "certs/cert_fea.pem")
KEY_FEA = os.environ.get("KEY_FEA", "certs/key_fea.pem")
CERT_FEC = os.environ.get("CERT_FEC", "certs/cert_fec.pem")
KEY_FEC = os.environ.get("KEY_FEC", "certs/key_fec.pem")


# -----------------------
# Preflight / helpers
# -----------------------
def check_python_packages(packages):
    """Return missing packages from the given list."""
    missing = []
    for pkg in packages:
        if importlib.util.find_spec(pkg) is None:
            missing.append(pkg)
    return missing

def preflight_check(require_attack=False):
    """
    Check certificates and optional dependencies.
    If require_attack=True then also validate packages needed for attack simulation.
    """
    missing = []
    # check cert files
    for p in [CERT_FEA, KEY_FEA, CERT_FEC, KEY_FEC]:
        if not os.path.exists(p):
            missing.append(f"missing file: {p}")

    # check core python packages
    pkgs = ["endesive", "fpdf", "pikepdf", "cryptography"]
    if require_attack:
        pkgs += ["pypdf", "reportlab"]
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
    We write original bytes + signature bytes (Endesive returns a suffix designed to be appended).
    """
    from datetime import timezone
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

    # Save original bytes + signature suffix
    with open(output, "wb") as f:
        f.write(data + signed_bytes)

    log.info("🔒 PDF signed and saved: %s", output)
    return output


# -----------------------
# Verification (returns dict for reporting)
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
            for i, page in enumerate(pdf.pages):
                try:
                    text_content.append(page.extract_text())
                except Exception:
                    text_content.append(None)
    except Exception as e:
        log.debug("pikepdf failed to open %s: %s", pdf_path, e)
        return []
    return text_content

def verify_certificate(original_path, modified_path, label=""):
    """
    Verify file and return a result dict used by console output and HTML report.
    """
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

        # signature verification
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
            result["error"] = "signature verification incomplete (incremental updates present)"
        except Exception as e:
            result["error"] = f"signature verification error: {e}"

        # incremental detection
        with open(modified_path, 'rb') as f:
            content = f.read()
        startxref = content.count(b'startxref')
        eof = content.count(b'%%EOF')
        result["incremental"] = (startxref > 1 or eof > 1)

        # text snippets (first 120 chars per page)
        texts = extract_text(modified_path)
        snippets = []
        for t in texts:
            if not t:
                snippets.append("[Empty or not extractable]")
            else:
                snippets.append(t[:120] + ("..." if len(t) > 120 else ""))
        result["text_snippets"] = snippets

    except Exception as e:
        result["error"] = str(e)

    return result

def print_verification_result(res):
    """Print human-friendly verification result to console."""
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
    print("\n   Text snippets (first 120 chars per page):")
    for i, sn in enumerate(res.get("text_snippets", []), start=1):
        print(f"      Page {i}: {sn}")
    print("="*60)


# -----------------------
# Generate / Verify flows
# -----------------------
def generate_certificates(outdir="./outputs"):
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
        import tempfile
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
    generated = generate_certificates(outdir=outdir)
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
        # if signature exists and all ok
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
def ensure_outdir(outdir):
    if not outdir:
        outdir = "."
    os.makedirs(outdir, exist_ok=True)
    return outdir

def path_in(outdir, filename):
    return os.path.join(outdir, filename)

def main():
    import argparse

    # ---------------------------
    # Parent parser with global options
    # ---------------------------
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

    # ---------------------------
    # Root parser with subcommands
    # ---------------------------
    parser = argparse.ArgumentParser(
        description="Workshop 1: Vulnerabilities in Digital Certificates"
    )
    subparsers = parser.add_subparsers(
        dest="action",
        help="Available actions"
    )

    # Subcommands inherit global args from parent_parser
    subparsers.add_parser("generate", parents=[parent_parser], help="Generate unsigned and signed certificates")
    subparsers.add_parser("verify", parents=[parent_parser], help="Verify student edited files")

    # Simulate attacks
    sim = subparsers.add_parser("simulate", parents=[parent_parser], help="Simulate attacks against signed PDFs")
    sim.add_argument(
        "--mode",
        choices=["incremental_rewrite", "incremental_pikepdf"],
        required=True,
        help="Attack mode to simulate"
    )

    # ---------------------------
    # Parse arguments
    # ---------------------------
    args = parser.parse_args()

    # Ensure output directory exists
    outdir = ensure_outdir(args.outdir)
    report_path = path_in(outdir, "verification_report.html") if args.report else None

    # ---------------------------
    # Preflight checks
    # ---------------------------
    require_attack = (args.action == "simulate")
    missing = preflight_check(require_attack=require_attack)
    if missing:
        print("Preflight check failed. Missing items:")
        for m in missing:
            print(" -", m)
        sys.exit(2)

    # ---------------------------
    # Dispatch actions
    # ---------------------------
    if args.action == "generate":
        generate_certificates(outdir=outdir)

    elif args.action == "verify":
        verify_student_modifications(outdir=outdir, generate_report=args.report, report_path=report_path)

    elif args.action == "simulate":
        # Run attack simulation
        results = simulate_attacks(
            mode=args.mode,
            outdir=outdir,
            report=args.report,
            report_path=report_path
        )
        if args.report and not report_path:
            write_html_report(results, path_in(outdir, "verification_report.html"))

    else:
        # No valid action provided
        parser.print_help()



if __name__ == "__main__":
    main()
