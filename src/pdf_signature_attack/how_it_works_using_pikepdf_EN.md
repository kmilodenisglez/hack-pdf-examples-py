# PDF Signature Attack Simulation with PikePDF

This document explains in detail how the script `simulate_pdf_signature_attack_pikepdf.py` works, focusing on **PDF digital signatures, incremental attacks, and detection methods**. It is designed for educational and demonstration purposes.

---

## 1. Script Purpose

`simulate_pdf_signature_attack_pikepdf.py` simulates a complete workflow:

1. Create an **original PDF** (fictitious academic certificate).
2. Digitally sign it with **Endesive**.
3. Apply two types of attacks:

  * **Incremental Rewrite Attack** → overwrites PDF, breaking the signature.
  * **Incremental PikePDF Attack** → adds a page as an incremental update, partially preserving the signature.
4. Perform **basic verification** of signatures.
5. Perform **advanced detection** to identify incremental modifications.
6. Apply **flattening** to prevent further incremental attacks.

---

## 2. Requirements

Python >= 3.9 and the following packages:

```bash
pip install endesive cryptography pypdf reportlab fpdf2 pikepdf
```

Optional tools for flattening or optimization:

```bash
sudo apt install qpdf ghostscript
```

---

## 3. General Workflow

1. **Create Original PDF** → `original.pdf`
2. **Sign PDF** → `signed.pdf`
3. **Apply Attacks**:

  * `attacked_rewrite.pdf` → destroys the signature.
  * `attacked_incremental_pikepdf.pdf` → partially preserves the signature while appending pages.
4. **Basic Verification** → detects signatures, prints hashes and markers.
5. **Advanced Detection** → compares `startxref/%%EOF` markers and SHA-256 hashes.
6. **Flattening** → `flattened.pdf` to consolidate PDF, preventing incremental attacks.

---

## 4. Function Details

### 4.1 `create_original_pdf(path="original.pdf")`

* **Purpose**: Generate a sample academic certificate PDF.
* **Implementation**: Uses `FPDF` to create a single page with fields like name, course, grade, and date.
* **Output**: `original.pdf`
* **Note**: Skips creation if the file already exists.

---

### 4.2 `sign_pdf(pdf_in, cert_pem_path, key_pem_path, out)`

* **Purpose**: Digitally sign a PDF using **Endesive**.
* **Implementation**:

  1. Load PEM certificate and private key.
  2. Define signature metadata: `reason`, `location`, `contact`, `signingdate`.
  3. Sign PDF using SHA-256.
  4. Save → `signed.pdf`.
* **Notes**: Ensures authenticity and integrity; handles variations in Endesive API (`udct` vs `dct`).

---

### 4.3 `incremental_rewrite_attack(signed_pdf, out)`

* **Purpose**: Simulate a destructive attack that adds a malicious page and **breaks the signature**.
* **Implementation**:

  * Read the signed PDF using `pypdf`.
  * Generate malicious page in memory with `reportlab`.
  * Append the page and save → `attacked_rewrite.pdf`.
* **Result**: The original signature becomes invalid.

---

### 4.4 `incremental_pikepdf_attack(signed_pdf, out)`

* **Purpose**: Simulate a **real incremental attack** that adds a page while partially preserving the original signature.
* **Implementation**:

  1. Create a malicious page in memory using `reportlab`.
  2. Save temporary PDF.
  3. Open original signed PDF with `pikepdf` and append the malicious page.
  4. Save → `attacked_incremental_pikepdf.pdf`.
* **Notes**: Signature in the original pages remains detectable, but the content of the new page is untrusted. Some PDF readers will flag incremental modifications.

---

### 4.5 `basic_verification(pdf_path, original_signed=None)`

* **Purpose**: Detect signatures and provide a basic integrity overview.
* **Includes**:

  * Verifies signatures using `endesive.pdf.verify`.
  * Prints SHA-256 hash of the PDF.
  * Counts `startxref` and `%%EOF` markers to detect incremental updates.
* **Comparison**: If `original_signed` is provided, compares hashes to detect changes.

---

### 4.6 `detect_incremental_update_advanced(signed, attacked)`

* **Purpose**: Detect **incremental updates and content changes**.
* **Implementation**:

  * Count `startxref` and `%%EOF` in both signed and attacked PDFs.
  * Compute SHA-256 hashes.
  * Alerts if additional sections exist or content differs → likely tampering.
* **Outcome**: Clearly identifies whether the incremental attack modified the PDF after signing.

---

### 4.7 `apply_flattening_pypdf(input_pdf, out)`

* **Purpose**: Consolidate PDF pages into a **single linearized file**, preventing incremental attacks.
* **Implementation**:

  * Read all pages using `pypdf`.
  * Write a new PDF sequentially.
  * Save → `flattened.pdf`.
* **Note**: Flattening removes all digital signatures.

---

## 5. Main Flow (`main()`)

1. Generate original PDF → `original.pdf`.
2. Sign PDF → `signed.pdf`.
3. Apply **rewrite attack** and **PikePDF incremental attack**.
4. Run basic verification on both attacked PDFs.
5. Run advanced incremental detection for the PikePDF attack.
6. Flatten the attacked PDF → `flattened.pdf`.

---

## 6. Conference/Workshop Use

* **Step-by-step demonstration**: run each function individually to illustrate signature effects.
* **Visual comparison**: compare `signed.pdf`, `attacked_rewrite.pdf`, and `attacked_incremental_pikepdf.pdf`.
* **Detection and mitigation**: show how markers, hashes, and flattening reveal and prevent tampering.

---

## 7. Conclusion

* This script is a **teaching tool for PDF security**, showing differences between **destructive vs incremental attacks**.
* Demonstrates methods for **verification, detection, and mitigation**.
* Useful for academic, administrative, or workshop settings to illustrate **PDF signature risks and defenses**.