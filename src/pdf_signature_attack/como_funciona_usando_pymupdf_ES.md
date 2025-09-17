# Simulación de Ataques a Firmas PDF con PyMuPDF

Este documento explica **en detalle** cómo funciona el script `simulate_pdf_signature_attack_pymupdf.py`, con el objetivo de:

1. Comprender la **firma digital de PDFs**.
2. Simular ataques que alteran PDFs **sin y con preservación parcial de la firma**.
3. Mostrar cómo detectar modificaciones y aplicar **flattening** para prevenir ataques.

El enfoque es **educativo y demostrativo**, ideal para presentaciones y conferencias.

**Instalación**: Ver la sección "Requirements and installation" en el `README.md` raíz.

---

## Diferencias con [PikePDF](./simulate_pdf_signature_attack_pikepdf.py)

* **PyMuPDF**: Crea un nuevo PDF combinando páginas originales y maliciosas.
* **PikePDF**: Realiza modificaciones incrementales más auténticas al PDF original.
* **Detección**: Ambos métodos son detectables, pero PikePDF simula mejor ataques reales.
* **Organización**: Ambos scripts ahora usan la misma estructura de carpetas `outputs/`.

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

**Novedad**: Todos los archivos PDF se generan ahora en la carpeta `outputs/` para mantener el directorio de trabajo limpio y organizado.

---

## 2. Flujo General

1. **Crear PDF original** → `outputs/original.pdf`
2. **Firmar PDF** → `outputs/signed.pdf`
3. **Ataques**:

    * `outputs/attacked_rewrite.pdf` → destruye firma.
    * `outputs/attacked_incremental_pymupdf.pdf` → preserva parcialmente firma.
4. **Verificación básica** → detecta firmas y muestra hashes.
5. **Detección avanzada** → compara `startxref/%%EOF` y hashes para detectar modificaciones.
6. **Flattening** → `outputs/flattened.pdf` para consolidar PDF y prevenir ataques incrementales.

---

## 3. Explicación Detallada de Funciones

### 3.1 `create_original_pdf(path=None)`

* **Objetivo**: generar un PDF de prueba con información académica ficticia.
* **Uso de FPDF**: se crean páginas y se agregan campos como nombre, curso, nota y fecha.
* **Resultado**: `outputs/original.pdf` (por defecto).
* **Notas**: si el PDF ya existe, no se vuelve a generar.
* **Novedad**: Crea automáticamente la carpeta `outputs/` si no existe.

---

### 3.2 `sign_pdf(pdf_in=None, cert_pem_path="certs/cert.pem", key_pem_path="certs/key.pem", out=None)`

* **Objetivo**: firmar digitalmente un PDF usando **Endesive**.
* **Pasos principales**:

    1. Cargar certificado (`certs/cert.pem`) y clave privada (`certs/key.pem`).
    2. Definir metadatos de firma (`reason`, `location`, `contact`, `signingdate`).
    3. Firmar PDF con algoritmo SHA-256.
    4. Guardar PDF firmado → `outputs/signed.pdf`.
* **Consideraciones**:

    * La firma asegura integridad y autenticidad del contenido original.
    * Intentos alternativos (`udct` vs `dct`) manejan versiones de Endesive.

---

### 3.3 `incremental_rewrite_attack(signed_pdf=None, out=None)`

* **Objetivo**: simular un ataque que **agrega una página maliciosa** pero **rompe la firma**.
* **Cómo funciona**:

    1. Leer PDF firmado con `pypdf`.
    2. Crear un PDF en memoria con `reportlab` que contiene la página maliciosa.
    3. Agregar la página a un nuevo PDF y escribir archivo → `outputs/attacked_rewrite.pdf`.
* **Resultado**: la firma original ya no es válida.

---

### 3.4 `incremental_pymupdf_attack(signed_pdf=None, out=None)`

* **Objetivo**: simular un ataque **incremental** que agrega una página **sin sobrescribir páginas originales**.
* **Cómo funciona**:

    1. Crear página maliciosa en memoria (`reportlab`).
    2. Guardar temporalmente como PDF.
    3. Abrir PDF firmado con `PyMuPDF`.
    4. Insertar todas las páginas originales + la página maliciosa al final.
    5. Guardar resultado → `outputs/attacked_incremental_pymupdf.pdf`.
* **Notas**: la firma de las páginas originales **permanece**, pero la integridad global del PDF queda comprometida.

---

### 3.5 `basic_verification(pdf_path, original_signed=None)`

* **Objetivo**: verificar presencia de firmas y mostrar información clave.
* **Incluye**:

    * Detectar firmas con `endesive.pdf.verify`.
    * Mostrar hashes SHA-256.
    * Contar `startxref` y `%%EOF` para detectar secciones incrementales.
* **Si se pasa `original_signed`**: compara hash del PDF atacado vs original para alertar sobre cambios.

---

### 3.6 `detect_incremental_update_advanced(signed=None, attacked=None)`

* **Objetivo**: detectar modificaciones **incrementales y cambios de contenido** de forma más sofisticada.
* **Qué hace**:

    * Cuenta `startxref` y `%%EOF` en PDFs firmado y atacado.
    * Calcula hashes SHA-256 de ambos PDFs.
    * Señala si hay más secciones o contenido diferente → posible ataque.
* **Novedad**: Usa rutas por defecto en la carpeta `outputs/`.

---

### 3.7 `apply_flattening_pypdf(input_pdf=None, out=None)`

* **Objetivo**: consolidar PDF en un solo flujo para **prevenir ataques incrementales**.
* **Cómo funciona**:

    * Lee todas las páginas del PDF original.
    * Escribe un PDF nuevo linealizado.
    * El PDF resultante ya no permite modificaciones incrementales posteriores.
* **Resultado**: `outputs/flattened.pdf`.
* **Nota**: elimina firmas digitales.

---

## 4. Flujo Principal (`main()`)

1. Crear PDF original → `outputs/original.pdf`.
2. Firmar PDF → `outputs/signed.pdf`.
3. Aplicar **ataque de reescritura** y **ataque incremental PyMuPDF**.
4. Verificación básica de ambos PDFs atacados.
5. Detección avanzada de incrementales.
6. Flattening del PDF atacado → `outputs/flattened.pdf`.

---

## 5. Estructura de Archivos

```
pdf_signature_attack/
├── outputs/                    # 📁 Carpeta de salida (se crea automáticamente)
│   ├── original.pdf           # PDF original generado
│   ├── signed.pdf            # PDF firmado digitalmente
│   ├── attacked_rewrite.pdf  # PDF atacado (firma rota)
│   ├── attacked_incremental_pymupdf.pdf  # PDF con ataque incremental
│   └── flattened.pdf         # PDF aplanado (sin firmas)
├── certs/                     # 📁 Certificados para firmar
│   ├── cert.pem              # Certificado público
│   └── key.pem               # Llave privada
└── simulate_pdf_signature_attack_pymupdf.py
```

---

## 6. Uso en Conferencias/Talleres

* **Demostración paso a paso**: ejecutar cada función individualmente para ilustrar los efectos de la firma.
* **Comparación visual**: comparar archivos en la carpeta `outputs/`: `signed.pdf`, `attacked_rewrite.pdf` y `attacked_incremental_pymupdf.pdf`.
* **Detección y mitigación**: mostrar cómo los marcadores, hashes y flattening revelan y previenen manipulaciones.
* **Organización**: la carpeta `outputs/` mantiene todos los resultados organizados y facilita la demostración.

---

## 7. Mejoras en Esta Versión

* **Organización de archivos**: Todos los PDFs se generan en la carpeta `outputs/`.
* **Creación automática**: La carpeta `outputs/` se crea automáticamente si no existe.
* **Rutas por defecto**: Las funciones usan rutas por defecto dentro de `outputs/`.
* **Certificados organizados**: Los certificados se buscan en la carpeta `certs/`.
* **Logging mejorado**: Mejor información sobre la creación de archivos y directorios.

---

## 8. Conclusión

* Este script es una **herramienta educativa sobre seguridad en PDFs**, mostrando diferencias entre **ataques destructivos vs incrementales**.
* Demuestra métodos de **verificación, detección y mitigación**.
* La nueva estructura con carpeta `outputs/` mejora la organización y facilita su uso en entornos académicos, administrativos o talleres para ilustrar **riesgos y defensas de firmas PDF**.