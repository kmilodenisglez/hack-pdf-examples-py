# PDF Signature Attack Simulation with PyMuPDF

This document explains in detail how the script `simulate_pdf_signature_attack_pymupdf.py` works, with the goal of:

1. Understanding **PDF digital signatures**.
2. Simulating attacks that modify PDFs **with and without preserving the original signature**.
3. Demonstrating how to detect modifications and apply **flattening** to prevent incremental attacks.

The focus is **educational and demonstrative**, ideal for conferences or workshops.

---

## Differences with [PikePDF](./simulate_pdf_signature_attack_pikepdf.py)

* **PyMuPDF**: Creates a new PDF by combining original and malicious pages.
* **PikePDF**: Performs more authentic incremental modifications to the original PDF.
* **Detection**: Both methods are detectable, but PikePDF better simulates real attacks.
* **Organization**: Both scripts now use the same `outputs/` folder structure.

---

## 1. Script Purpose

`simulate_pdf_signature_attack_pymupdf.py` simulates a full workflow of:

1. Creating an **original PDF** (fictitious academic certificate).
2. Digitally signing it with **Endesive**.
3. Applying two types of attacks:

  * **Incremental Rewrite Attack** → breaks the signature.
  * **Incremental PyMuPDF Attack** → adds a page while partially preserving the signature.
4. Performing basic and advanced integrity checks.
5. Applying **flattening** to prevent future incremental modifications.

**New Feature**: All PDF files are now generated in the `outputs/` folder to keep the working directory clean and organized.

---

## 2. Requirements

Python >= 3.9 and the following packages:

```bash
pip install endesive cryptography pypdf reportlab fpdf2 pymupdf
```

Optional tools:

```bash
sudo apt install ghostscript  # For advanced flattening
```

---

## 3. General Workflow

1. **Create Original PDF** → `outputs/original.pdf`
2. **Sign PDF** → `outputs/signed.pdf`
3. **Attacks**:

  * `outputs/attacked_rewrite.pdf` → destroys the signature
  * `outputs/attacked_incremental_pymupdf.pdf` → partially preserves the original signature
4. **Basic Verification** → detects signatures and prints hashes
5. **Advanced Detection** → compares `startxref/%%EOF` and hashes to detect modifications
6. **Flattening** → `outputs/flattened.pdf` to consolidate the PDF and prevent incremental attacks

---

## 4. Function Details

### 4.1 `create_original_pdf(path=None)`

* **Purpose**: generate a sample PDF with fictitious academic information.
* **Implementation**: uses FPDF to create pages and add fields like name, course, grade, and date.
* **Output**: `outputs/original.pdf` (default).
* **Note**: if the PDF already exists, it is not recreated.
* **New Feature**: Automatically creates the `outputs/` folder if it doesn't exist.

---

### 4.2 `sign_pdf(pdf_in=None, cert_pem_path="certs/cert.pem", key_pem_path="certs/key.pem", out=None)`

* **Purpose**: digitally sign a PDF using **Endesive**.
* **Steps**:

  1. Load certificate (`certs/cert.pem`) and private key (`certs/key.pem`).
  2. Define signature metadata (`reason`, `location`, `contact`, `signingdate`).
  3. Sign the PDF using SHA-256.
  4. Save the signed PDF → `outputs/signed.pdf`.
* **Notes**:

  * Ensures integrity and authenticity of the original content.
  * Handles Endesive versions differences (`udct` vs `dct`).

---

### 4.3 `incremental_rewrite_attack(signed_pdf=None, out=None)`

* **Purpose**: simulate an attack that **adds a malicious page** but **breaks the original signature**.
* **Implementation**:

  1. Read signed PDF using `pypdf`.
  2. Create a malicious page in memory using `reportlab`.
  3. Append the malicious page to a new PDF and save → `outputs/attacked_rewrite.pdf`.
* **Result**: the original signature is invalid.

---

### 4.4 `incremental_pymupdf_attack(signed_pdf=None, out=None)`

* **Purpose**: simulate an **incremental attack** that adds a page **without overwriting original pages**.
* **Implementation**:

  1. Create malicious page in memory with `reportlab`.
  2. Save temporary PDF.
  3. Open signed PDF with `PyMuPDF`.
  4. Copy all original pages + malicious page into a new PDF.
  5. Save → `outputs/attacked_incremental_pymupdf.pdf`.
* **Notes**: original page signatures **remain**, but overall content integrity is compromised.

---

### 4.5 `basic_verification(pdf_path, original_signed=None)`

* **Purpose**: detect if the PDF has signatures and show key information.
* **Includes**:

  * Detect signatures using `endesive.pdf.verify`.
  * Print SHA-256 hashes.
  * Count `startxref` and `%%EOF` markers to detect incremental sections.
* **If `original_signed` is provided**: compares hash of attacked PDF vs original to indicate changes.

---

### 4.6 `detect_incremental_update_advanced(signed=None, attacked=None)`

* **Purpose**: detect **incremental modifications and content changes** more thoroughly.
* **Implementation**:

  * Count `startxref` and `%%EOF` markers in both signed and attacked PDFs.
  * Compute SHA-256 hashes.
  * Alerts if there are additional sections or content differences → likely attack.
* **New Feature**: Uses default paths within the `outputs/` folder.

---

### 4.7 `apply_flattening_pypdf(input_pdf=None, out=None)`

* **Purpose**: consolidate the PDF into a single stream to **prevent incremental attacks**.
* **Implementation**:

  * Read all pages from input PDF.
  * Write a new PDF linearly.
  * Save → `outputs/flattened.pdf`.
* **Note**: this process removes digital signatures.

---

## 5. Main Flow (`main()`)

1. Create original PDF → `outputs/original.pdf`.
2. Sign the PDF → `outputs/signed.pdf`.
3. Apply **rewrite attack** and **PyMuPDF incremental attack**.
4. Perform basic verification of both attacked PDFs.
5. Perform advanced incremental detection.
6. Flatten the attacked PDF → `outputs/flattened.pdf`.

---

## 6. File Structure

```
pdf_signature_attack/
├── outputs/ # 📁 Output folder (auto-created)
│ ├── original.pdf # Generated original PDF
│ ├── signed.pdf # Digitally signed PDF
│ ├── attacked_rewrite.pdf # Attacked PDF (broken signature)
│ ├── attacked_incremental_pymupdf.pdf # PDF with incremental attack
│ └── flattened.pdf # Flattened PDF (no signatures)
├── certs/ # 📁 Signing certificates
│ ├── cert.pem # Public certificate
│ └── key.pem # Private key
└── simulate_pdf_signature_attack_pymupdf.py
```

---

## 7. Conference/Workshop Use

* **Step-by-step demonstration**: run each function individually to show signature effects.
* **Visualizing attacks**: compare files in `outputs/`: `signed.pdf` vs `attacked_rewrite.pdf` and `attacked_incremental_pymupdf.pdf`.
* **Detection and mitigation**: illustrate how hashes and `startxref/%%EOF` reveal tampering, and how flattening protects PDFs.
* **Organization**: the `outputs/` folder keeps all results organized and facilitates demonstration.

---

## 8. Improvements in This Version

* **File organization**: All PDFs are generated in the `outputs/` folder.
* **Automatic creation**: The `outputs/` folder is created automatically if it doesn't exist.
* **Default paths**: Functions use default paths within `outputs/`.
* **Organized certificates**: Certificates are searched in the `certs/` folder.
* **Enhanced logging**: Better information about file and directory creation.
* **Consistency**: Similar structure to the PikePDF script for easy comparisons.

---

## 9. Conclusion

* This script is a **teaching tool for PDF signature security**.
* Highlights differences between **destructive vs incremental attacks**.
* Demonstrates methods for **verification, detection, and mitigation** in academic or administrative environments.
* The new structure with the `outputs/` folder improves organization and facilitates its use in educational settings.