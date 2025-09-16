# PDF Signature Attack Simulation

This subproject demonstrates incremental attacks on a signed PDF and how to detect them. It generates `original.pdf`, signs it (`signed.pdf`), applies rewrite and incremental attacks, and shows basic/advanced checks. See the global installation in the root `README.md`; this file focuses only on how to run the subproject.

---

## How to run

From the repository root (with dependencies installed):

```bash
# Simulation using PyMuPDF
python src/pdf_signature_attack/simulate_pdf_signature_attack_pymupdf.py

# Simulation using PikePDF
python src/pdf_signature_attack/simulate_pdf_signature_attack_pikepdf.py
```

Generated files:

- `original.pdf`, `signed.pdf`
- `attacked_rewrite.pdf` (destructive attack: invalidates the signature)
- `attacked_incremental_pikepdf.pdf` or equivalent depending on the script
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

