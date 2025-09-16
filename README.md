# PDF Signature Attack Examples (Python)

Educational repository with two subprojects to demonstrate and teach digital signature attacks and verification on PDFs.

- `src/pdf_signature_attack/`: simulate incremental attacks on a signed PDF (PikePDF / PyMuPDF) with basic/advanced verification.
- `src/pdf_compare_certificates/`: workshop to generate certificates (unsigned, FEA, FEC), edit them manually, and then verify tampering.

---

## Requirements and installation (centralized here)

1) Create and activate a Python 3.10+ virtual environment (recommended)

```bash
python -m venv ./venv
source ./venv/bin/activate  # Linux/macOS
# or
.\venv\Scripts\activate     # Windows
```

2) Install project dependencies (editable from `pyproject.toml`)

```bash
pip install -e .
```

3) (Optional) System tools for extra operations

```bash
sudo apt install ghostscript qpdf   # Linux
```

4) (Optional) Generate test certificates (if you don’t have your own PEMs)

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 \
  -nodes -subj "/CN=Secure University" -set_serial 1
```

---

## Project structure

```
hack-pdf-examples-py/
├─ README.md                        # Este archivo (instalación y visión general)
├─ pyproject.toml                   # Dependencias y metadata del paquete
├─ src/
│  ├─ pdf_signature_attack/         # Subproyecto 1 (ataques incrementales)
│  │  ├─ README.md                  # Cómo ejecutar el subproyecto
│  │  └─ simulate_*.py              # Scripts de simulación
│  └─ pdf_compare_certificates/     # Subproyecto 2 (taller/verificación)
│     ├─ README.md                  # Cómo ejecutar el subproyecto
│     └─ main.py                    # CLI del taller
└─ venv/                            # Entorno virtual (opcional)
```

---

## Quick usage per subproject

See each subproject’s README for details and options.

### 1) PDF signature attacks (`src/pdf_signature_attack/`)

```bash
# Attack using PyMuPDF
python src/pdf_signature_attack/simulate_pdf_signature_attack_pymupdf.py

# Attack using PikePDF
python src/pdf_signature_attack/simulate_pdf_signature_attack_pikepdf.py
```

Expected outputs: `original.pdf`, `signed.pdf`, `attacked_rewrite.pdf`, `attacked_incremental_*.pdf`, `flattened.pdf`.

### 2) Certificate comparison workshop (`src/pdf_compare_certificates/`)

```bash
# Generate PDFs (unsigned, FEA, FEC)
python src/pdf_compare_certificates/main.py generate --outdir outputs

# Verify *_EDITED.pdf files (after manual edits)
python src/pdf_compare_certificates/main.py verify --outdir outputs --report

# Full flow (generate → manual edit → verify)
python src/pdf_compare_certificates/main.py all --outdir outputs --report

# Simulate attacks on signed PDFs (FEA/FEC)
python src/pdf_compare_certificates/main.py simulate --mode incremental_pikepdf --outdir outputs --report
```

Optional environment variables for PEM certificate paths (if using custom files):

```
CERT_FEA=cert_fea.pem
KEY_FEA=key_fea.pem
CERT_FEC=cert_fec.pem
KEY_FEC=key_fec.pem
```

---

## High-level flow diagram

### ASCII Flowchart

```
+------------------+
|  Create Original |
|      PDF         |
|  (original.pdf)  |
+--------+---------+
         |
         v
+------------------+
|   Sign PDF       |
|  (Endesive)      |
|  signed.pdf      |
+--------+---------+
         |
         v
+-------------------------+
|   Attack Variants       |
+-------------------------+
|                         |
| 1. Incremental Rewrite  |
|    (PyPDF2 + ReportLab) |
|    attacked_rewrite.pdf |
|    Signature Broken     |
|                         |
| 2. Incremental Attack   |
|    (PyMuPDF)            |
|    attacked_incremental_|
|    pymupdf.pdf          |
|    Signature Preserved  |
|                         |
| 3. Incremental Attack   |
|    (PikePDF)            |
|    attacked_incremental_|
|    pikepdf.pdf          |
|    Signature Preserved  |
+-------------------------+
         |
         v
+-------------------------+
| Basic Verification      |
| (Endesive)              |
| Detects signatures      |
+-------------------------+
         |
         v
+-------------------------+
| Advanced Detection      |
| - Compare hashes        |
| - Compare startxref/EOF |
| - Detect modifications  |
+-------------------------+
         |
         v
+-------------------------+
| Flattening              |
| - PyPDF2 / Ghostscript  |
| - Prevent incremental   |
|   attacks               |
+-------------------------+
```

#### How to read the diagram

1. Create original PDF.
2. Sign with Endesive → `signed.pdf`.
3. Attack (rewrite or incremental) → `attacked_*.pdf`.
4. Basic verification (signatures) and advanced checks (hashes, `startxref/%%EOF`).
5. Flattening to prevent incremental attacks (removes signatures).

---

## Notes

- Educational repository; not intended to promote malicious use.
- Results may vary across PDF viewers (Adobe Reader, browsers, etc.).
- Flattening removes digital signatures; use only when content consolidation is desired.
