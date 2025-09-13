Here’s the **detailed English version** of the README explaining `simulate_pdf_signature_attack_pymupdf.py`, suitable for a conference or educational presentation:

---

# PDF Signature Attack Simulation with PyMuPDF

This document explains in detail how the script `simulate_pdf_signature_attack_pymupdf.py` works, with the goal of:

1. Understanding **PDF digital signatures**.
2. Simulating attacks that modify PDFs **with and without preserving the original signature**.
3. Demonstrating how to detect modifications and apply **flattening** to prevent incremental attacks.

The focus is **educational and demonstrative**, ideal for conferences or workshops.

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

---

## 2. General Workflow

1. **Create Original PDF** → `original.pdf`
2. **Sign PDF** → `signed.pdf`
3. **Attacks**:

    * `attacked_rewrite.pdf` → destroys the signature
    * `attacked_incremental_pymupdf.pdf` → partially preserves the original signature
4. **Basic Verification** → detects signatures and prints hashes
5. **Advanced Detection** → compares `startxref/%%EOF` and hashes to detect modifications
6. **Flattening** → `flattened.pdf` to consolidate the PDF and prevent incremental attacks

---

## 3. Function Details

### 3.1 `create_original_pdf(path="original.pdf")`

* **Purpose**: generate a sample PDF with fictitious academic information.
* **Implementation**: uses FPDF to create pages and add fields like name, course, grade, and date.
* **Output**: `original.pdf`.
* **Note**: if the PDF already exists, it is not recreated.

---

### 3.2 `sign_pdf(pdf_in, cert_pem_path, key_pem_path, out)`

* **Purpose**: digitally sign a PDF using **Endesive**.
* **Steps**:

    1. Load certificate (`cert.pem`) and private key (`key.pem`).
    2. Define signature metadata (`reason`, `location`, `contact`, `signingdate`).
    3. Sign the PDF using SHA-256.
    4. Save the signed PDF → `signed.pdf`.
* **Notes**:

    * Ensures integrity and authenticity of the original content.
    * Handles Endesive versions differences (`udct` vs `dct`).

---

### 3.3 `incremental_rewrite_attack(signed_pdf, out)`

* **Purpose**: simulate an attack that **adds a malicious page** but **breaks the original signature**.
* **Implementation**:

    1. Read signed PDF using `pypdf`.
    2. Create a malicious page in memory using `reportlab`.
    3. Append the malicious page to a new PDF and save → `attacked_rewrite.pdf`.
* **Result**: the original signature is invalid.

---

### 3.4 `incremental_pymupdf_attack(signed_pdf, out)`

* **Purpose**: simulate an **incremental attack** that adds a page **without overwriting original pages**.
* **Implementation**:

    1. Create malicious page in memory with `reportlab`.
    2. Save temporary PDF.
    3. Open signed PDF with `PyMuPDF`.
    4. Copy all original pages + malicious page into a new PDF.
    5. Save → `attacked_incremental_pymupdf.pdf`.
* **Notes**: original page signatures **remain**, but overall content integrity is compromised.

---

### 3.5 `basic_verification(pdf_path, original_signed=None)`

* **Purpose**: detect if the PDF has signatures and show key information.
* **Includes**:

    * Detect signatures using `endesive.pdf.verify`.
    * Print SHA-256 hashes.
    * Count `startxref` and `%%EOF` markers to detect incremental sections.
* **If `original_signed` is provided**: compares hash of attacked PDF vs original to indicate changes.

---

### 3.6 `detect_incremental_update_advanced(signed, attacked)`

* **Purpose**: detect **incremental modifications and content changes** more thoroughly.
* **Implementation**:

    * Count `startxref` and `%%EOF` markers in both signed and attacked PDFs.
    * Compute SHA-256 hashes.
    * Alerts if there are additional sections or content differences → likely attack.

---

### 3.7 `apply_flattening_pypdf(input_pdf, out)`

* **Purpose**: consolidate the PDF into a single stream to **prevent incremental attacks**.
* **Implementation**:

    * Read all pages from input PDF.
    * Write a new PDF linearly.
    * Save → `flattened.pdf`.
* **Note**: this process removes digital signatures.

---

## 4. Main Flow (`main()`)

1. Create original PDF.
2. Sign the PDF.
3. Apply **rewrite attack** and **PyMuPDF incremental attack**.
4. Perform basic verification of both attacked PDFs.
5. Perform advanced incremental detection.
6. Flatten the attacked PDF.

---

## 5. Conference/Workshop Use

* **Step-by-step demonstration**: run each function individually to show signature effects.
* **Visualizing attacks**: compare `signed.pdf` vs `attacked_rewrite.pdf` and `attacked_incremental_pymupdf.pdf`.
* **Detection and mitigation**: illustrate how hashes and `startxref/%%EOF` reveal tampering, and how flattening protects PDFs.

---

## 6. Conclusion

* This script is a **teaching tool for PDF signature security**.
* Highlights differences between **destructive vs incremental attacks**.
* Demonstrates methods for **verification, detection, and mitigation** in academic or administrative environments.
