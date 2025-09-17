# PDF Signature Attack Simulation

This subproject demonstrates incremental attacks on a signed PDF and how to detect them. It generates PDFs in the `outputs/` folder, signs them, applies rewrite and incremental attacks, and shows basic/advanced checks.

**Installation**: See the "Requirements and installation" section in the root `README.md`.

---

## How to run

From the repository root (with dependencies installed):

```bash
cd src/pdf_signature_attack/
```

```bash
# Simulation using PyMuPDF
python simulate_pdf_signature_attack_pymupdf.py

# Simulation using PikePDF
python simulate_pdf_signature_attack_pikepdf.py
```

Generated files (in `outputs/` folder):

- `original.pdf`, `signed.pdf`
- `attacked_rewrite.pdf` (destructive attack: invalidates the signature)
- `attacked_incremental_pikepdf.pdf` or `attacked_incremental_pymupdf.pdf` depending on the script
- `flattened.pdf` (consolidated; removes signatures)

---

## What it shows

- Signature detection using Endesive (basic).
- Hash comparison and counting of `startxref`/`%%EOF` markers.
- Differences between a rewrite attack (breaks the signature) and an incremental attack (preserves original bytes but modifies the document).

---

## Notes

- Some PDF viewers may show different warnings for incremental updates.
- Flattening prevents new incrementals but removes signatures.
- All PDF files are generated in the `outputs/` folder for better organization.