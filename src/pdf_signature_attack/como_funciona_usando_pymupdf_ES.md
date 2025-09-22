### README.md (Español)

# Simulación de Ataques a Firmas PDF 🛡️

Este documento describe el script `simulate_pdf_signature_attack_pikepdf.py`, una herramienta educativa diseñada para talleres sobre la **seguridad de firmas digitales en documentos PDF**. El objetivo es demostrar, de forma práctica y visual, cómo se pueden manipular documentos firmados sin invalidar la firma a simple vista.

-----

## 1\. Conceptos Clave para el Taller 👨‍💻

Para comprender este script, es crucial entender estos tres conceptos:

### 1.1. ¿Qué es una Firma Digital en un PDF?

Una firma digital no es una simple imagen. Es un bloque de datos criptográficos que se añade al documento. Este bloque incluye:

1.  **La firma en sí**: Un hash (resumen) del contenido del PDF original, encriptado con la **llave privada** del firmante.
2.  **El Certificado**: La "tarjeta de identidad" del firmante, que contiene su llave pública y es validado por una autoridad.
    Si se cambia un solo bit del contenido original, el hash no coincidirá, y la firma se mostrará como inválida.

### 1.2. El Ataque de Actualización Incremental (IRA) 🤯

A diferencia de otros formatos, el estándar PDF permite añadir nuevo contenido al final de un archivo, como si fueran "capas". Esto se llama **Actualización Incremental** o **Incremental Update** (IU).
El ataque IRA explota esta característica:

1.  El atacante firma un documento "limpio".
2.  Luego, **añade nuevo contenido malicioso** al final del archivo, en una nueva capa, sin modificar el bloque original ya firmado.
3.  El lector de PDF lee el documento completo, incluyendo el nuevo contenido, pero la firma del bloque original sigue siendo criptográficamente válida. El resultado es que la firma parece correcta, pero el documento visible ha sido manipulado.

### 1.3. Aplanamiento (Flattening) 🥞

El aplanamiento es el proceso de consolidar todas las capas (la original, las anotaciones, las actualizaciones incrementales) en un solo documento final. Es como "hornear" todas las capas en una sola imagen. Cuando un PDF atacado se aplana, la firma **se destruye**, ya que el nuevo documento unificado tiene un hash completamente diferente al del documento original firmado.

-----

## 2\. Flujo del Taller con el Script Refactorizado

El script ahora usa comandos modulares, lo que te permite ejecutar el taller paso a paso, de forma más interactiva.

### 2.1. Requisitos e Instalación

Asegúrate de tener las bibliotecas necesarias instaladas:
`pip install endesive cryptography pypdf pikepdf reportlab fpdf2`

### 2.2. Paso 1: Creación del Documento ✅

**Comando:** `python3 script.py create`

* **Acción:** Crea el PDF base (`outputs/original.pdf`).
* **Demostración:** Muestra este documento a los estudiantes. Es el "certificado académico" original que firmaremos.

### 2.3. Paso 2: Firma del Documento 🖋️

**Comando:** `python3 script.py sign`

* **Acción:** Firma `original.pdf` y crea `outputs/signed.pdf`.
* **Demostración:** Pide a los estudiantes que abran `signed.pdf` en un lector de PDF (como Evince o Adobe Acrobat Reader) y validen visualmente que la firma es correcta y el documento no ha sido alterado.

### 2.4. Paso 3: El Ataque (Incremental vs. Reescritura) 💥

**Comando:**

* **Ataque de Reescritura:** `python3 script.py attack rewrite`
* **Ataque Incremental:** `python3 script.py attack incremental`
* **Acción:** El primer comando sobrescribe el archivo (`attacked_rewrite.pdf`), rompiendo la firma. El segundo comando (`attacked_incremental_pikepdf.pdf`) añade una nueva página con el texto "GRADE: 20/20" sin invalidar la firma.
* **Demostración:** Muestra ambos documentos a los estudiantes. Compara `attacked_rewrite.pdf` (firma rota) con `attacked_incremental_pikepdf.pdf` (firma visualmente válida pero con contenido modificado). ¡Este es el momento clave\! Usa diferentes lectores de PDF para mostrar cómo algunos (Evince) pueden fallar en detectar el ataque, mientras que otros (Adobe Acrobat Reader) lo detectan y muestran una advertencia.

### 2.5. Paso 4: Verificación y Detección 🔎

**Comando:**

* `python3 script.py verify outputs/signed.pdf`
* `python3 script.py verify outputs/attacked_incremental_pikepdf.pdf`
* **Acción:** El script analiza los archivos.
* **Demostración:** Explica las diferencias en los resultados de la verificación:
  * **`startxref` y `%%EOF`**: En el PDF atacado, estos marcadores se duplican, lo que indica que hay múltiples "capas" de contenido.
  * **Hash SHA-256**: El hash del documento atacado será **diferente** al del documento original, confirmando que el contenido binario del archivo ha cambiado, a pesar de que la firma siga siendo válida.

### 2.6. Paso 5: Mitigación (Aplanamiento) 🗜️

**Comando:** `python3 script.py flatten`

* **Acción:** Convierte el PDF atacado en un nuevo archivo aplanado (`outputs/flattened_pypdf.pdf`).
* **Demostración:** Pide a los estudiantes que abran el archivo aplanado. Verán que la firma digital **ha desaparecido por completo**, ya que el proceso de aplanamiento destruye la estructura que la contenía. Esto demuestra que la firma solo puede garantizar la integridad del documento en su estado original y que cualquier reescritura la invalida.

-----

## 3\. Estructura de Archivos del Taller

```
pdf_signature_attack/
├── outputs/                         # 📁 Todos los PDFs generados
│ ├── original.pdf
│ ├── signed.pdf
│ ├── attacked_rewrite.pdf
│ ├── attacked_incremental_pikepdf.pdf
│ └── flattened_pypdf.pdf
├── certs/                           # 📁 Certificados para la firma
│ ├── cert.pem
│ └── key.pem
└── simulate_pdf_signature_attack_pikepdf.py # 🐍 Script principal
```

-----

## 4\. Conclusión

Este taller proporciona una base sólida para entender la seguridad de los documentos PDF. Muestra que la firma digital es robusta, pero las **vulnerabilidades residen en el formato del archivo y en cómo los lectores lo interpretan**. Es una excelente introducción a la seguridad forense y a la importancia de la validación completa en el desarrollo de software.
