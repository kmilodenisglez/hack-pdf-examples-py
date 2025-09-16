#!/usr/bin/env python3
"""
Taller 1 - Vulnerabilidades en certificados digitales (corregido)

Dependencias:
    pip install endesive fpdf2 pikepdf cryptography

Certificados necesarios:
    - cert_fea.pem / key_fea.pem → FEA (normal)
    - cert_fec.pem / key_fec.pem → FEC/QES (simulado)
"""

import os
import hashlib
from datetime import datetime
import logging
from fpdf import FPDF
from endesive.pdf.verify import verify
import pikepdf

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")
log = logging.getLogger(__name__)

# -----------------------
# UTILIDADES
# -----------------------
def create_sample_pdf(name="John Doe", course="Curso", grade="14/20", path="temp.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", size=16, style="B")
    pdf.cell(0, 10, "CERTIFICADO ACADÉMICO OFICIAL", new_x="LMARGIN", new_y="NEXT", align='C')
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 10, f"Nombre: {name}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"Curso: {course}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"Calificación: {grade}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 10, f"Fecha: {datetime.now().strftime('%Y-%m-%d')}", new_x="LMARGIN", new_y="NEXT")
    pdf.output(path)
    log.info("📄 PDF generado: %s", path)
    return path

def sign_pdf(pdf_in, cert_pem, key_pem, output, is_qualified=False):
    """
    Firma un PDF con Endesive (FEA o FEC) y asegura que sea compatible con lectores.
    """
    import os
    import logging
    from datetime import datetime, timezone
    from endesive.pdf import cms
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509 import load_pem_x509_certificate
    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    log = logging.getLogger(__name__)

    # Leer PDF original
    with open(pdf_in, "rb") as f:
        data = f.read()
    # Leer certificado y clave
    with open(cert_pem, "rb") as f:
        cert_bytes = f.read()
    with open(key_pem, "rb") as f:
        key_bytes = f.read()
    cert = load_pem_x509_certificate(cert_bytes, default_backend())
    key = load_pem_private_key(key_bytes, password=None, backend=default_backend())

    # Diccionario de firma
    date = datetime.now(timezone.utc).strftime("D:%Y%m%d%H%M%S+00'00'")
    dct = {
        'sigpage': 0,
        'sigfield': 'Signature1',
        'auto_sigfield': True,
        'signature': 'FIRMA CUALIFICADA' if is_qualified else 'Firma Avanzada',
        'contact': 'security@university.edu',
        'location': 'Lima, Perú',
        'signingdate': date,
        'reason': 'Certificado oficial',
    }

    # Generar bytes de la firma
    signed_bytes = cms.sign(datau=data, udct=dct, key=key, cert=cert, othercerts=[cert], algomd='sha256')

    # Guardar PDF final: concatenar PDF original + firma
    with open(output, "wb") as f:
        f.write(data + signed_bytes)

    log.info("🔒 PDF firmado y compatible guardado: %s", output)
    return output


def compute_hash(pdf_path):
    h = hashlib.sha256()
    with open(pdf_path, 'rb') as f:
        while chunk := f.read(8192):
            h.update(chunk)
    return h.hexdigest()

def extract_text(pdf_path):
    text_content = []
    with pikepdf.open(pdf_path) as pdf:
        for i, page in enumerate(pdf.pages):
            try:
                text_content.append(page.extract_text())
            except Exception:
                text_content.append(f"[Página {i+1} no se pudo extraer]")
    return text_content

def verify_certificate(original_path, modified_path, label=""):
    print(f"\n🔍 VERIFICANDO: {label}")
    print("="*60)

    # Comparación de hashes
    orig_hash = compute_hash(original_path)
    mod_hash = compute_hash(modified_path) if os.path.exists(modified_path) else "N/A"
    print(f"   Hash Original: {orig_hash}")
    print(f"   Hash Modificado: {mod_hash}")
    if orig_hash != mod_hash:
        print("   ❌ ¡Contenido modificado! (Hash no coincide)")
    else:
        print("   ✅ Contenido no modificado (Hash coincide)")

    # Verificación de firmas
    try:
        with open(modified_path, 'rb') as f: data = f.read()
        result = verify(data)
        if result:
            for idx, r in enumerate(result):
                status = "VÁLIDA" if r.get('ok') else "INVÁLIDA"
                signer = r.get('signer_name', 'Desconocido')
                print(f"   Firma #{idx+1}: {status} | Firmante: {signer}")
        else:
            print("   ⚠️  No se detectó firma digital.")
    except Exception as e:
        print(f"   ❌ Error verificando firma: {e}")

    # Detección de modificaciones incrementales
    with open(modified_path, 'rb') as f:
        content = f.read()
    startxref = content.count(b'startxref')
    eof = content.count(b'%%EOF')
    print(f"   startxref: {startxref}, %%EOF: {eof}")
    if startxref > 1 or eof > 1:
        print("   ⚠️  ¡Actualización incremental detectada! (Posible manipulación)")
    else:
        print("   ✅ Sin actualizaciones incrementales detectadas.")

    # Mostrar extracto de texto
    print("\n   Extracto de texto de las primeras 100 letras por página:")
    texts = extract_text(modified_path)
    for i, t in enumerate(texts):
        snippet = t[:100] if t else "[Vacío]"
        print(f"      Página {i+1}: {snippet}")
    print("="*60)

# -----------------------
# GENERAR CERTIFICADOS
# -----------------------
def generate_certificates():
    # Sin firma
    create_sample_pdf(name="Carlos Pérez", course="Ciberseguridad", grade="16/20", path="cert_plain.pdf")
    # FEA
    create_sample_pdf(name="Ana Gómez", course="Blockchain", grade="14/20", path="temp_fea.pdf")
    sign_pdf("temp_fea.pdf", "cert_fea.pem", "key_fea.pem", "cert_fea.pdf", is_qualified=False)
    # FEC/QES
    create_sample_pdf(name="Luis Fernández", course="Criptografía", grade="18/20", path="temp_fec.pdf")
    sign_pdf("temp_fec.pdf", "cert_fec.pem", "key_fec.pem", "cert_fec.pdf", is_qualified=True)

    # Limpiar temporales
    for f in ["temp_fea.pdf", "temp_fec.pdf"]:
        if os.path.exists(f): os.remove(f)

    print("\n✅ Certificados generados:")
    print("   - cert_plain.pdf → Sin firma (editable libremente)")
    print("   - cert_fea.pdf → Firma Electrónica Avanzada (FEA) → Vulnerable")
    print("   - cert_fec.pdf → Firma Electrónica Cualificada (FEC/QES) → Protegida\n")

# -----------------------
# VERIFICAR ARCHIVOS EDITADOS
# -----------------------
def verify_student_modifications():
    print("\n\n🔎 VERIFICANDO MANIPULACIONES HECHAS POR ESTUDIANTES")
    files_to_check = [
        ("cert_fea.pdf", "cert_fea_EDITADO.pdf", "CERTIFICADO FEA MODIFICADO"),
        ("cert_fec.pdf", "cert_fec_EDITADO.pdf", "CERTIFICADO FEC MODIFICADO"),
        ("cert_plain.pdf", "cert_plain_EDITADO.pdf", "CERTIFICADO SIN FIRMA MODIFICADO"),
    ]
    for original, modified, label in files_to_check:
        if not os.path.exists(modified):
            print(f"\n⚠️  {label}: Archivo '{modified}' no encontrado. (¿Lo editaron?)")
            continue
        verify_certificate(original, modified, label)

# -----------------------
# MAIN
# -----------------------
def main():
    print("🎓 TALLER 1: VULNERABILIDADES EN CERTIFICADOS DIGITALES\n")
    generate_certificates()

    print("📌 INSTRUCCIONES PARA ESTUDIANTES:")
    print("1. Abran 'cert_fea.pdf' con Adobe Acrobat o Word y cambien la calificación a '20/20'.")
    print("2. Intenten hacer lo mismo con 'cert_fec.pdf' (debería invalidar la firma).")
    print("3. Editen 'cert_plain.pdf' libremente.")
    print("4. Guarden los archivos modificados como:")
    print("   - cert_fea_EDITADO.pdf")
    print("   - cert_fec_EDITADO.pdf")
    print("   - cert_plain_EDITADO.pdf")
    input("\n➡️ Presionen ENTER cuando hayan terminado de editar los archivos...")

    verify_student_modifications()
    print("\n✅ Taller completado. Discusión en equipos: ¿Qué implica esto para la confianza en certificados educativos?")

if __name__ == "__main__":
    main()


