# Workshop: Comparing and Verifying PDF Certificates

This subproject generates sample certificates (unsigned, FEA, and FEC), invites manual edits, and then verifies tampering, signatures, and evidence of incremental updates.

See global installation in the root `README.md`. This file focuses only on how to run the subproject.

---

## Quick start

From the repository root (with the environment prepared and installed):

### Generate test certificates (if you don’t have your own PEMs)
```bash
sh ./script-generate-cert-selfsigned.sh 
````

### 1) Generate sample PDFs

```bash
python main.py generate --outdir outputs --report
```

### 2) (Optional) Simulate attacks on signed PDFs (FEA/FEC)

```bash
python main.py simulate --mode incremental_pikepdf --outdir outputs --report
```

### 3) Verify the student-edited files (the \*\_EDITED.pdf files must exist)

```bash
python main.py verify --outdir outputs --report
```

### 4) Assisted flow (generate → manual edit → verify)

```bash
python main.py all --outdir outputs --report
```

**Student instructions (manual edits in the `all` flow):**

1. Open `cert_fea.pdf` in Adobe/Word and change the grade to `20/20`.
2. Try editing `cert_fec.pdf` (this should invalidate the signature in most PDF readers).
3. Edit `cert_plain.pdf` freely (no signature protection).
4. Save the edited files as:

    * `cert_fea_EDITED.pdf`
    * `cert_fec_EDITED.pdf`
    * `cert_plain_EDITED.pdf`

Press ENTER when finished editing the files to continue verification.

---

### Expected files in `--outdir`:

* `cert_plain.pdf`, `cert_fea.pdf`, `cert_fec.pdf`
* User-edited versions: `cert_plain_EDITED.pdf`, `cert_fea_EDITED.pdf`, `cert_fec_EDITED.pdf`
* Optional HTML report: `verification_report.html`

Optional environment variables if you use your own PEM files:

```
CERT_FEA=cert_fea.pem
KEY_FEA=key_fea.pem
CERT_FEC=cert_fec.pem
KEY_FEC=key_fec.pem
```

---

## Functional description

* Generates sample PDFs and signs with Endesive (for FEA/FEC).
* Detects present signatures (basic) and evidence of incremental updates (`startxref`, `%%EOF`).
* Compares hashes and extracts text snippets to help identify changes.
* Provides guided instructions for manual editing to demonstrate signature validation and tampering.

---

## Teaching tips

* Ask students to change grades, names, or insert pages in the `_EDITED.pdf` versions.
* Compare validation across different viewers (Adobe Reader, browsers).
* Discuss why a signature alone may not be sufficient if incremental changes occurred.
