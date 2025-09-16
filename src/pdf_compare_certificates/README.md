# 🎓 Workshop 1: Vulnerabilities in Digital Certificates

This workshop demonstrates how digital university certificates (PDF-based) can be signed, modified, and verified.  
Students will learn how **digital signatures** work, what makes them secure, and how malicious actors could exploit vulnerabilities in PDF handling.

---

## 📦 Requirements

Make sure you have **Python 3.10+** installed.  
Then install dependencies:

```bash
python -m venv venv
source venv/bin/activate   # On Linux/Mac
venv\Scripts\activate      # On Windows

pip install -r requirements.txt
````

**requirements.txt**

```
endesive
cryptography
pikepdf
fpdf2
```

---

## ⚙️ How it works

The workshop simulates three types of PDF certificates:

1. **Plain certificate (unsigned)** → Easy to forge, no authenticity guarantee.
2. **FEA (Advanced Electronic Signature)** → Signed with a certificate but not legally qualified.
3. **FEC/QES (Qualified Electronic Signature)** → Signed with a qualified certificate (stronger legal validity).

Students will try to **edit the files manually** and the script will later **verify manipulations**.

---

## ▶️ Running the workshop

```bash
python main.py
```

You will see:

```
🎓 WORKSHOP 1: VULNERABILITIES IN DIGITAL CERTIFICATES

➡️ Certificates generated:
   - cert_plain.pdf
   - cert_fea.pdf
   - cert_fec.pdf

➡️ Please edit the "_EDITED.pdf" versions of these files (e.g. using a PDF editor).
   Press ENTER when you are done...
```

At this point:

* Students open `cert_plain.pdf`, `cert_fea.pdf`, `cert_fec.pdf`.
* They save **modified copies** as:

    * `cert_plain_EDITED.pdf`
    * `cert_fea_EDITED.pdf`
    * `cert_fec_EDITED.pdf`

---

## 🔍 Verification phase

After pressing ENTER, the script will:

* Detect **incremental updates** inside the PDF (`%%EOF`, `startxref` markers).
* Compare text snippets between original and edited versions.
* Report whether each certificate was manipulated.

Example output:

```
🔎 VERIFICATION RESULTS

⚠️ cert_plain_EDITED.pdf was modified → Anyone could forge it.
⚠️ cert_fea_EDITED.pdf was modified → Signature invalidated.
⚠️ cert_fec_EDITED.pdf was modified → Signature invalidated.

✅ Lesson: Only qualified signatures (QES) provide strong legal guarantees.
```

---

## 🧪 Educational discussion

* Why can unsigned PDFs be easily forged?
* Why does editing an FEA break its signature?
* What makes FEC/QES stronger in real-world legal scenarios?
* How could universities mitigate risks?

---

## 📁 File structure

```
hack-pdf-examples-py/
│── src/pdf_compare_certificates/
│   ├── main.py         # Workshop script
│   ├── cert_fea.pem    # Example certificate
│   ├── key_fea.pem     # Example private key
│   ├── cert_fec.pem    # Example qualified certificate
│   ├── key_fec.pem     # Qualified key
│── README.md
│── requirements.txt
```

---

## 🚀 Next steps

* Extend the workshop with **incremental attack simulation** using PikePDF.
* Show how a malicious user can append hidden content without breaking the original signature.
* Compare results with Adobe Reader / Word when opening PDFs.

---

👨‍🏫 **Instructor tip:**
Encourage students to perform manual modifications (changing names, grades, or inserting pages). Then discuss why verification systems must go beyond simple signature checks.
