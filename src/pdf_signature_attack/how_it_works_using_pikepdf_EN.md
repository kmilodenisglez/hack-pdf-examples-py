# PDF Signature Attack Simulation 🛡️

This document describes the script `simulate_pdf_signature_attack_pikepdf.py`, an educational tool designed for workshops on **digital signature security in PDF documents**. The goal is to demonstrate, in a practical and visual way, how signed documents can be tampered with without invalidating the signature at first glance.

-----

## 1\. Key Concepts for the Workshop 👨‍💻

To understand this script, it is crucial to grasp these three concepts:

### 1.1. What is a Digital Signature in a PDF?

A digital signature isn't just a simple image. It's a block of cryptographic data added to the document. This block includes:

1.  **The signature itself**: A hash (summary) of the original PDF content, encrypted with the signer's **private key**.
2.  **The Certificate**: The signer's "identity card," which contains their public key and is validated by an authority.
    If a single bit of the original content is changed, the hash won't match, and the signature will show as invalid.

### 1.2. The Incremental Update Attack (IUA) 🤯

Unlike other formats, the PDF standard allows new content to be added to the end of a file, like "layers." This is called an **Incremental Update** (IU).
The IUA exploits this feature:

1.  The attacker signs a "clean" document.
2.  Then, they **append new malicious content** to the end of the file in a new layer, without modifying the original signed block.
3.  The PDF reader reads the entire document, including the new content, but the signature for the original block remains cryptographically valid. The result is that the signature appears correct, but the visible document has been tampered with.

### 1.3. Flattening 🥞

Flattening is the process of consolidating all layers (the original, annotations, incremental updates) into a single final document. It's like "baking" all the layers into one image. When an attacked PDF is flattened, the signature is **destroyed**, as the new unified document has a completely different hash than the original signed document.

-----

## 2\. Workshop Workflow with the Refactored Script

The script now uses modular commands, allowing you to run the workshop step-by-step, in a more interactive way.

### 2.1. Requirements and Installation

Make sure you have the necessary libraries installed:
`pip install endesive cryptography pypdf pikepdf reportlab fpdf2`

### 2.2. Step 1: Document Creation ✅

**Command:** `python3 script.py create`

* **Action:** Creates the base PDF (`outputs/original.pdf`).
* **Demonstration:** Show this document to the students. This is the original "academic certificate" we will sign.

### 2.3. Step 2: Document Signing 🖋️

**Command:** `python3 script.py sign`

* **Action:** Signs `original.pdf` and creates `outputs/signed.pdf`.
* **Demonstration:** Ask students to open `signed.pdf` in a PDF reader (like Evince or Adobe Acrobat Reader) and visually validate that the signature is correct and the document hasn't been altered.

### 2.4. Step 3: The Attack (Incremental vs. Rewrite) 💥

**Command:**

* **Rewrite Attack:** `python3 script.py attack rewrite`
* **Incremental Attack:** `python3 script.py attack incremental`
* **Action:** The first command overwrites the file (`attacked_rewrite.pdf`), breaking the signature. The second command (`attacked_incremental_pikepdf.pdf`) appends a new page with the text "GRADE: 20/20" without invalidating the signature.
* **Demonstration:** Show both documents to the students. Compare `attacked_rewrite.pdf` (broken signature) with `attacked_incremental_pikepdf.pdf` (visually valid signature but with modified content). This is the key moment\! Use different PDF readers to show how some (Evince) might fail to detect the attack, while others (Adobe Acrobat Reader) detect it and display a warning.

### 2.5. Step 4: Verification and Detection 🔎

**Command:**

* `python3 script.py verify outputs/signed.pdf`
* `python3 script.py verify outputs/attacked_incremental_pikepdf.pdf`
* **Action:** The script analyzes the files.
* **Demonstration:** Explain the differences in the verification results:
  * **`startxref` and `%%EOF`**: In the attacked PDF, these markers are duplicated, indicating that there are multiple "layers" of content.
  * **SHA-256 Hash**: The hash of the attacked document will be **different** from the original document, confirming that the binary content of the file has changed, even though the signature remains valid.

### 2.6. Step 5: Mitigation (Flattening) 🗜️

**Command:** `python3 script.py flatten`

* **Action:** Converts the attacked PDF into a new flattened file (`outputs/flattened_pypdf.pdf`).
* **Demonstration:** Ask students to open the flattened file. They will see that the digital signature **has completely disappeared**, as the flattening process destroys the structure that contained it. This shows that the signature can only guarantee the integrity of the document in its original state and that any rewrite invalidates it.

-----

## 3\. Workshop File Structure

```
pdf_signature_attack/
├── outputs/                         # 📁 All generated PDFs
│ ├── original.pdf
│ ├── signed.pdf
│ ├── attacked_rewrite.pdf
│ ├── attacked_incremental_pikepdf.pdf
│ └── flattened_pypdf.pdf
├── certs/                           # 📁 Certificates for signing
│ ├── cert.pem
│ └── key.pem
└── simulate_pdf_signature_attack_pikepdf.py # 🐍 Main script
```

-----

## 4\. Conclusion

This workshop provides a solid foundation for understanding PDF document security. It shows that the digital signature itself is robust, but the **vulnerabilities lie in the file format and how readers interpret it**. It's an excellent introduction to digital forensics and the importance of thorough validation in software development.