# PDF Signature Attack Simulation with PikePDF

This document explains in detail how the script `simulate_pdf_signature_attack_pikepdf.py` works, focusing on **PDF digital signatures, incremental attacks, and detection methods**. It is designed for educational and demonstration purposes.

**Installation**: See the "Requirements and installation" section in the root `README.md`.

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

**New Feature**: All PDF files are now generated in the `outputs/` folder to keep the working directory clean and organized.

---

## 2. General Workflow

1. **Create Original PDF** → `outputs/original.pdf`
2. **Sign PDF** → `outputs/signed.pdf`
3. **Apply Attacks**:

  * `outputs/attacked_rewrite.pdf` → destroys the signature.
  * `outputs/attacked_incremental_pikepdf.pdf` → partially preserves the signature while appending pages.
4. **Basic Verification** → detects signatures, prints hashes and markers.
5. **Advanced Detection** → compares `startxref/%%EOF` markers and SHA-256 hashes.
6. **Flattening** → `outputs/flattened.pdf` to consolidate PDF, preventing incremental attacks.

---

## 3. Function Details

### 3.1 `create_original_pdf(path=None)`

* **Purpose**: Generate a sample academic certificate PDF.
* **Implementation**: Uses `FPDF` to create a single page with fields like name, course, grade, and date.
* **Output**: `outputs/original.pdf` (default)
* **Note**: Skips creation if the file already exists.
* **New Feature**: Automatically creates the `outputs/` folder if it doesn't exist.

---

### 3.2 `sign_pdf(pdf_in=None, cert_pem_path="certs/cert.pem", key_pem_path="certs/key.pem", out=None)`

* **Purpose**: Digitally sign a PDF using **Endesive**.
* **Implementation**:

  1. Load PEM certificate and private key from the `certs/` folder.
  2. Define signature metadata: `reason`, `location`, `contact`, `signingdate`.
  3. Sign PDF using SHA-256.
  4. Save → `outputs/signed.pdf`.
* **Notes**: Ensures authenticity and integrity; handles variations in Endesive API (`udct` vs `dct`).

---

### 3.3 `incremental_rewrite_attack(signed_pdf=None, out=None)`

* **Purpose**: Simulate a destructive attack that adds a malicious page and **breaks the signature**.
* **Implementation**:

  * Read the signed PDF using `pypdf`.
  * Generate malicious page in memory with `reportlab`.
  * Append the page and save → `outputs/attacked_rewrite.pdf`.
* **Result**: The original signature becomes invalid.

---

### 3.4 `incremental_pikepdf_attack(signed_pdf=None, out=None)`

* **Purpose**: Simulate a **real incremental attack** that adds a page while partially preserving the original signature.
* **Implementation**:

  1. Create a malicious page in memory using `reportlab`.
  2. Save temporary PDF.
  3. Open original signed PDF with `pikepdf` and append the malicious page.
  4. Save → `outputs/attacked_incremental_pikepdf.pdf`.
* **Notes**: Signature in the original pages remains detectable, but the content of the new page is untrusted. Some PDF readers will flag incremental modifications.

---

### 3.5 `basic_verification(pdf_path, original_signed=None)`

* **Purpose**: Detect signatures and provide a basic integrity overview.
* **Includes**:

  * Verifies signatures using `endesive.pdf.verify`.
  * Prints SHA-256 hash of the PDF.
  * Counts `startxref` and `%%EOF` markers to detect incremental updates.
* **Comparison**: If `original_signed` is provided, compares hashes to detect changes.

---

### 3.6 `detect_incremental_update_advanced(signed=None, attacked=None)`

* **Purpose**: Detect **incremental updates and content changes**.
* **Implementation**:

  * Count `startxref` and `%%EOF` in both signed and attacked PDFs.
  * Compute SHA-256 hashes.
  * Alerts if additional sections exist or content differs → likely tampering.
* **Outcome**: Clearly identifies whether the incremental attack modified the PDF after signing.
* **New Feature**: Uses default paths within the `outputs/` folder.

---

### 3.7 `apply_flattening_pypdf(input_pdf=None, out=None)`

* **Purpose**: Consolidate PDF pages into a **single linearized file**, preventing incremental attacks.
* **Implementation**:

  * Read all pages using `pypdf`.
  * Write a new PDF sequentially.
  * Save → `outputs/flattened.pdf`.
* **Note**: Flattening removes all digital signatures.

---

## 4. Main Flow (`main()`)

1. Generate original PDF → `outputs/original.pdf`.
2. Sign PDF → `outputs/signed.pdf`.
3. Apply **rewrite attack** and **PikePDF incremental attack**.
4. Run basic verification on both attacked PDFs.
5. Run advanced incremental detection for the PikePDF attack.
6. Flatten the attacked PDF → `outputs/flattened.pdf`.

---

## 5. File Structure

```
pdf_signature_attack/
├── outputs/ # 📁 Output folder (auto-created)
│ ├── original.pdf # Generated original PDF
│ ├── signed.pdf # Digitally signed PDF
│ ├── attacked_rewrite.pdf # Attacked PDF (broken signature)
│ ├── attacked_incremental_pikepdf.pdf # PDF with incremental attack
│ └── flattened.pdf # Flattened PDF (no signatures)
├── certs/ # 📁 Signing certificates
│ ├── cert.pem # Public certificate
│ └── key.pem # Private key
└── simulate_pdf_signature_attack_pikepdf.py
```

---

## 6. Conference/Workshop Use

* **Step-by-step demonstration**: run each function individually to illustrate signature effects.
* **Visual comparison**: compare files in the `outputs/` folder: `signed.pdf`, `attacked_rewrite.pdf`, and `attacked_incremental_pikepdf.pdf`.
* **Detection and mitigation**: show how markers, hashes, and flattening reveal and prevent tampering.
* **Organization**: the `outputs/` folder keeps all results organized and facilitates demonstration.

---

## 8. Improvements in This Version

* **File organization**: All PDFs are generated in the `outputs/` folder.
* **Automatic creation**: The `outputs/` folder is created automatically if it doesn't exist.
* **Default paths**: Functions use default paths within `outputs/`.
* **Organized certificates**: Certificates are searched in the `certs/` folder.
* **Enhanced logging**: Better information about file and directory creation.

---

## 9. Conclusion

* This script is a **teaching tool for PDF security**, showing differences between **destructive vs incremental attacks**.
* Demonstrates methods for **verification, detection, and mitigation**.
* The new structure with the `outputs/` folder improves organization and facilitates its use in academic, administrative, or workshop settings to illustrate **PDF signature risks and defenses**.