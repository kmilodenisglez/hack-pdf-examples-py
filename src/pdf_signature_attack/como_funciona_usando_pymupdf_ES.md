# Simulación de Ataques a Firmas PDF con PyMuPDF

Este documento explica **en detalle** cómo funciona el script `simulate_pdf_signature_attack_pymupdf.py`, con el objetivo de:

1. Comprender la **firma digital de PDFs**.
2. Simular ataques que alteran PDFs **sin y con preservación parcial de la firma**.
3. Mostrar cómo detectar modificaciones y aplicar **flattening** para prevenir ataques.

El enfoque es **educativo y demostrativo**, ideal para presentaciones y conferencias.

---

## 1. Propósito del Script

`simulate_pdf_signature_attack_pymupdf.py` simula un flujo completo de:

1. Creación de un **PDF original** (certificado académico ficticio).
2. Firma digital usando **Endesive**.
3. Ataques de dos tipos:

    * **Incremental Rewrite Attack** → destruye la firma.
    * **Incremental PyMuPDF Attack** → agrega una página preservando parcialmente la firma.
4. Verificación básica y avanzada de la integridad del PDF.
5. Flattening para prevenir modificaciones posteriores.

---

## 3. Flujo General

1. **Crear PDF original** → `original.pdf`
2. **Firmar PDF** → `signed.pdf`
3. **Ataques**:

    * `attacked_rewrite.pdf` → destruye firma.
    * `attacked_incremental_pymupdf.pdf` → preserva parcialmente firma.
4. **Verificación básica** → detecta firmas y muestra hashes.
5. **Detección avanzada** → compara `startxref/%%EOF` y hashes para detectar modificaciones.
6. **Flattening** → `flattened.pdf` para consolidar PDF y prevenir ataques incrementales.

---

## 4. Explicación Detallada de Funciones

### 4.1 `create_original_pdf(path="original.pdf")`

* **Objetivo**: generar un PDF de prueba con información académica ficticia.
* **Uso de FPDF**: se crean páginas y se agregan campos como nombre, curso, nota y fecha.
* **Resultado**: `original.pdf`.
* **Notas**: si el PDF ya existe, no se vuelve a generar.

---

### 4.2 `sign_pdf(pdf_in, cert_pem_path, key_pem_path, out)`

* **Objetivo**: firmar digitalmente un PDF usando **Endesive**.
* **Pasos principales**:

    1. Cargar certificado (`cert.pem`) y clave privada (`key.pem`).
    2. Definir metadatos de firma (`reason`, `location`, `contact`, `signingdate`).
    3. Firmar PDF con algoritmo SHA-256.
    4. Guardar PDF firmado → `signed.pdf`.
* **Consideraciones**:

    * La firma asegura integridad y autenticidad del contenido original.
    * Intentos alternativos (`udct` vs `dct`) manejan versiones de Endesive.

---

### 4.3 `incremental_rewrite_attack(signed_pdf, out)`

* **Objetivo**: simular un ataque que **agrega una página maliciosa** pero **rompe la firma**.
* **Cómo funciona**:

    1. Leer PDF firmado con `pypdf`.
    2. Crear un PDF en memoria con `reportlab` que contiene la página maliciosa.
    3. Agregar la página a un nuevo PDF y escribir archivo → `attacked_rewrite.pdf`.
* **Resultado**: la firma original ya no es válida.

---

### 4.4 `incremental_pymupdf_attack(signed_pdf, out)`

* **Objetivo**: simular un ataque **incremental** que agrega una página **sin sobrescribir páginas originales**.
* **Cómo funciona**:

    1. Crear página maliciosa en memoria (`reportlab`).
    2. Guardar temporalmente como PDF.
    3. Abrir PDF firmado con `PyMuPDF`.
    4. Insertar todas las páginas originales + la página maliciosa al final.
    5. Guardar resultado → `attacked_incremental_pymupdf.pdf`.
* **Notas**: la firma de las páginas originales **permanece**, pero la integridad global del PDF queda comprometida.

---

### 4.5 `basic_verification(pdf_path, original_signed=None)`

* **Objetivo**: verificar presencia de firmas y mostrar información clave.
* **Incluye**:

    * Detectar firmas con `endesive.pdf.verify`.
    * Mostrar hashes SHA-256.
    * Contar `startxref` y `%%EOF` para detectar secciones incrementales.
* **Si se pasa `original_signed`**: compara hash del PDF atacado vs original para alertar sobre cambios.

---

### 4.6 `detect_incremental_update_advanced(signed, attacked)`

* **Objetivo**: detectar modificaciones **incrementales y cambios de contenido** de forma más sofisticada.
* **Qué hace**:

    * Cuenta `startxref` y `%%EOF` en PDFs firmado y atacado.
    * Calcula hashes SHA-256 de ambos PDFs.
    * Señala si hay más secciones o contenido diferente → posible ataque.

---

### 4.7 `apply_flattening_pypdf(input_pdf, out)`

* **Objetivo**: consolidar PDF en un solo flujo para **prevenir ataques incrementales**.
* **Cómo funciona**:

    * Lee todas las páginas del PDF original.
    * Escribe un PDF nuevo linealizado.
    * El PDF resultante ya no permite modificaciones incrementales posteriores.
* **Resultado**: `flattened.pdf`.
* **Nota**: elimina firmas digitales.

---

## 5. Flujo Principal (`main()`)

1. Crear PDF original.
2. Firmar PDF.
3. Aplicar **ataque de reescritura** y **ataque incremental PyMuPDF**.
4. Verificación básica de ambos PDFs atacados.
5. Detección avanzada de incrementales.
6. Flattening del PDF atacado.

---

## 6. Uso en Conferencias

* **Demostración paso a paso**: cada función puede ejecutarse individualmente para mostrar efectos sobre la firma.
* **Visualización de ataques**: comparar `signed.pdf` vs `attacked_rewrite.pdf` y `attacked_incremental_pymupdf.pdf`.
* **Detección y mitigación**: mostrar cómo hashes y `startxref/%%EOF` revelan manipulaciones y cómo flattening protege los PDFs.

---

## 7. Conclusión

* Este script sirve para **educar sobre seguridad de firmas PDF**.
* Enseña diferencias entre **ataques destructivos** y **incrementales**.
* Muestra técnicas de **verificación, detección y mitigación** de ataques en entornos académicos o administrativos.

