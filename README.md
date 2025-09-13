# PDF Signature Attack Simulation

This repository demonstrates **PDF signature attacks** using Python, simulating scenarios where an official PDF is signed and then modified. It includes two approaches for simulating **incremental attacks**: one using **PyMuPDF** and another using **PikePDF**.

---

## Quickstart

1. **Create a Python virtual environment (recommended)**

```bash
python -m venv ./venv
source ./venv/bin/activate  # Linux/macOS
# or
.\venv\Scripts\activate     # Windows
```

2. **Generate a test certificate (optional)**

```bash
openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem -days 365 \
-nodes -subj "/CN=Universidad Segura" -set_serial 1
```

3. **Install dependencies**

```bash
pip install -e .
```

4. **Optional: Install Ghostscript for flattening**

```bash
sudo apt install ghostscript   # Linux
```

---

## Workflow Diagram

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

#### How to Read the Diagram

1. **Create Original PDF**: generates a PDF with sample data (e.g., academic certificate).
2. **Sign PDF**: applies a digital signature using Endesive → `signed.pdf`.
3. **Attack Variants**: three simulated modifications:

    * **Incremental Rewrite**: destroys the signature.
    * **PyMuPDF Incremental**: adds a page without overwriting the signature, but full-content validation fails.
    * **PikePDF Incremental**: similar to PyMuPDF, partially preserves the original signature.
4. **Basic Verification**: detects if signatures exist.
5. **Advanced Detection**: compares hashes and internal structures (`startxref/%%EOF`) to detect modifications.
6. **Flattening**: produces a safe, consolidated PDF preventing incremental attacks, but removes signatures.

---

## Usage

```bash
# PyMuPDF attack simulation
python pdf_signature_attack_pymupdf.py

# PikePDF attack simulation
python pdf_signature_attack_pikepdf.py
```

**Output:** Original, signed, attacked, and optionally flattened PDFs. Logs show signature detection, incremental update detection, and hash comparisons.
