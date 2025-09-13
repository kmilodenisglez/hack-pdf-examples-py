# Simulación de Ataques a Firmas PDF con PikePDF

Este documento explica en detalle cómo funciona el script `simulate_pdf_signature_attack_pikepdf.py`, enfocándose en **firmas digitales en PDFs, ataques incrementales y métodos de detección**. Está diseñado con fines educativos y demostrativos.

---

## 1. Propósito del Script

`simulate_pdf_signature_attack_pikepdf.py` simula un flujo completo:

1. Crear un **PDF original** (certificado académico ficticio).
2. Firmarlo digitalmente con **Endesive**.
3. Aplicar dos tipos de ataques:

  * **Incremental Rewrite Attack** → sobrescribe el PDF y **rompe la firma**.
  * **Incremental PikePDF Attack** → agrega una página como actualización incremental, preservando parcialmente la firma.
4. Realizar **verificación básica** de firmas.
5. Realizar **detección avanzada** de modificaciones incrementales.
6. Aplicar **flattening** para prevenir ataques incrementales adicionales.

---

## 2. Requisitos

Python >= 3.9 y los siguientes paquetes:

```bash
pip install endesive cryptography pypdf reportlab fpdf2 pikepdf
```

Herramientas opcionales para flattening u optimización:

```bash
sudo apt install qpdf ghostscript
```

---

## 3. Flujo General

1. **Crear PDF original** → `original.pdf`
2. **Firmar PDF** → `signed.pdf`
3. **Aplicar ataques**:

  * `attacked_rewrite.pdf` → destruye la firma.
  * `attacked_incremental_pikepdf.pdf` → preserva parcialmente la firma original mientras añade páginas.
4. **Verificación básica** → detecta firmas, imprime hashes y marcadores.
5. **Detección avanzada** → compara marcadores `startxref/%%EOF` y hashes SHA-256.
6. **Flattening** → `flattened.pdf` para consolidar el PDF y prevenir ataques incrementales.

---

## 4. Detalle de Funciones

### 4.1 `create_original_pdf(path="original.pdf")`

* **Propósito**: Generar un PDF de ejemplo (certificado académico).
* **Implementación**: Usa `FPDF` para crear una página con campos como nombre, curso, calificación y fecha.
* **Salida**: `original.pdf`
* **Nota**: Omite la creación si el archivo ya existe.

---

### 4.2 `sign_pdf(pdf_in, cert_pem_path, key_pem_path, out)`

* **Propósito**: Firmar digitalmente un PDF usando **Endesive**.
* **Implementación**:

  1. Carga el certificado y la llave privada en formato PEM.
  2. Define metadatos de la firma: `reason`, `location`, `contact`, `signingdate`.
  3. Firma el PDF usando SHA-256.
  4. Guarda el resultado → `signed.pdf`.
* **Notas**: Garantiza autenticidad e integridad; maneja variaciones en la API de Endesive (`udct` vs `dct`).

---

### 4.3 `incremental_rewrite_attack(signed_pdf, out)`

* **Propósito**: Simular un ataque destructivo que agrega una página maliciosa y **rompe la firma**.
* **Implementación**:

  * Lee el PDF firmado con `pypdf`.
  * Genera la página maliciosa en memoria con `reportlab`.
  * Añade la página y guarda → `attacked_rewrite.pdf`.
* **Resultado**: La firma original queda inválida.

---

### 4.4 `incremental_pikepdf_attack(signed_pdf, out)`

* **Propósito**: Simular un **ataque incremental real** que agrega una página preservando parcialmente la firma original.
* **Implementación**:

  1. Crea una página maliciosa en memoria usando `reportlab`.
  2. Guarda temporalmente la página en un PDF.
  3. Abre el PDF firmado con `pikepdf` y añade la página maliciosa.
  4. Guarda → `attacked_incremental_pikepdf.pdf`.
* **Notas**: La firma en las páginas originales sigue siendo detectable, pero el contenido de la nueva página no es confiable. Algunos lectores de PDF señalarán la modificación incremental.

---

### 4.5 `basic_verification(pdf_path, original_signed=None)`

* **Propósito**: Detectar firmas y proporcionar una visión básica de integridad.
* **Incluye**:

  * Verificación de firmas con `endesive.pdf.verify`.
  * Impresión del hash SHA-256 del PDF.
  * Conteo de marcadores `startxref` y `%%EOF` para detectar actualizaciones incrementales.
* **Comparación**: Si se proporciona `original_signed`, compara hashes para detectar cambios.

---

### 4.6 `detect_incremental_update_advanced(signed, attacked)`

* **Propósito**: Detectar **actualizaciones incrementales y cambios de contenido**.
* **Implementación**:

  * Cuenta `startxref` y `%%EOF` en ambos PDFs (firmado y atacado).
  * Calcula hashes SHA-256.
  * Genera alertas si existen secciones adicionales o diferencias → probable manipulación.
* **Resultado**: Identifica claramente si el ataque incremental modificó el PDF después de la firma.

---

### 4.7 `apply_flattening_pypdf(input_pdf, out)`

* **Propósito**: Consolidar las páginas del PDF en un **archivo lineal único**, previniendo ataques incrementales.
* **Implementación**:

  * Lee todas las páginas con `pypdf`.
  * Escribe un nuevo PDF de forma secuencial.
  * Guarda → `flattened.pdf`.
* **Nota**: El flattening elimina todas las firmas digitales.

---

## 5. Flujo Principal (`main()`)

1. Generar PDF original → `original.pdf`.
2. Firmar PDF → `signed.pdf`.
3. Aplicar **rewrite attack** y **PikePDF incremental attack**.
4. Ejecutar verificación básica en ambos PDFs atacados.
5. Ejecutar detección avanzada de ataques incrementales en el PDF PikePDF.
6. Flattening → `flattened.pdf`.

---

## 6. Uso en Conferencias/Talleres

* **Demostración paso a paso**: ejecutar cada función individualmente para ilustrar los efectos de la firma.
* **Comparación visual**: comparar `signed.pdf`, `attacked_rewrite.pdf` y `attacked_incremental_pikepdf.pdf`.
* **Detección y mitigación**: mostrar cómo los marcadores, hashes y flattening revelan y previenen manipulaciones.

---

## 7. Conclusión

* Este script es una **herramienta educativa sobre seguridad en PDFs**, mostrando diferencias entre **ataques destructivos vs incrementales**.
* Demuestra métodos de **verificación, detección y mitigación**.
* Útil en entornos académicos, administrativos o talleres para ilustrar **riesgos y defensas de firmas PDF**.
