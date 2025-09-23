# 📄 ¿Qué es "Flattening" en un PDF?

### 🔹 1. La idea básica

Cuando un PDF se firma, esa firma se **añade como un "capa extra"** (incremental update).

* Es como poner un **post-it transparente encima del documento**.
* El contenido original queda debajo, **intacto**, y solo se agrega la información de la firma encima.

---

### 🔹 2. ¿Por qué es importante?

* Este diseño permite que el documento siga siendo **válido y verificable** sin reescribirlo completo.
* Pero también significa que alguien **puede intentar añadir más “post-its” después de la firma** (otro incremental update), para ocultar o modificar información.

---

### 🔹 3. Entonces, ¿qué es “flattening”?

👉 **Flattening** significa **aplanar todas esas capas** y **fusionarlas en un solo contenido estático**.

* Imagina un **sándwich de varias hojas transparentes** (el PDF con incrementales).
* Flattening sería **pasarle la plancha encima** 🔥 y dejarlo convertido en **una sola hoja fija**.

---

### 🔹 4. Ventajas

✅ El documento ya **no tiene capas ocultas** ni incrementales sospechosos.
✅ Se reduce el riesgo de **manipulaciones posteriores**.
✅ Lo que ves es exactamente lo que hay, sin “trucos debajo de la mesa”.

---

### 🔹 5. Desventajas

⚠️ Al hacer flattening, **se pierde la firma digital original** porque ya no existe como objeto separado.
⚠️ El PDF resultante ya no puede ser verificado criptográficamente, solo sirve como **copia legible y segura**, no como documento firmado electrónicamente.

---

### 🔹 6. Ejemplo visual para estudiantes

* **PDF firmado sin flattening**:

    * Página original ✅
    * * Capa de firma 🔒
    * * Capa sospechosa 🚨 (ataque incremental)

* **PDF aplanado (flattened)**:

    * Todo convertido en una sola imagen 📸, sin capas extras.
    * Fácil de leer, pero ya no es un PDF “firmado electrónicamente”.

---

👉 En pocas palabras:
**Flattening ≈ hacerle una foto al PDF firmado**: nadie lo puede alterar después, pero tampoco se puede verificar la firma digital.

---

El **flattening no “resuelve” la seguridad criptográfica**, pero **sí puede ser útil en contextos prácticos** cuando hay sospechas de manipulación en un PDF firmado.

# 📌 ¿Por qué el flattening puede ser útil si sospechamos de un PDF?

### 🔹 1. Los PDFs firmados permiten *incrementales*
- Cada firma en un PDF se añade como una “capa extra” (incremental update).
- Esto es legal y normal ✔️.
- El problema es que **los atacantes también pueden añadir incrementales maliciosos**: por ejemplo, una capa que tape una nota de 10/20 con una de 20/20.

---

### 🔹 2. El problema cuando sospechamos
- A simple vista, el PDF puede parecer correcto ✅.
- Pero detrás, puede tener **capas ocultas, texto invisible, o imágenes superpuestas** que se cargan dependiendo del lector de PDF.
- Es lo que se conoce como **ataques de visualización**.

---

### 🔹 3. ¿Qué hace el flattening?
👉 Convierte todo el documento en **un único contenido estático**:
- **Se destruyen las capas ocultas y los incrementales sospechosos**.
- Lo que queda es exactamente lo que ves en pantalla 👀.
- Así evitas que alguien abra el mismo PDF en otro lector y vea un contenido distinto.

---

### 🔹 4. Ejemplo para estudiantes
- **Sin flattening**:
    - El profesor abre el PDF y ve *20/20*.
    - El jurado abre el mismo PDF en otro lector y ve *10/20*.
    - 🤯 ¡Un mismo documento, dos versiones distintas!

- **Con flattening**:
    - El documento queda como una foto fija 📸.
    - Ambos verán lo mismo siempre.

---

### 🔹 5. La limitación
⚠️ Ojo: Flattening **no conserva la firma original**, por lo que ya no se puede verificar legalmente quién firmó el documento.  
⚠️ Es útil como **medida forense o de saneamiento**, no como reemplazo de la verificación criptográfica.

---

👉 En resumen para tus estudiantes:
- **Si sospechamos de un PDF firmado**, lo correcto es **verificar su firma con software especializado**.
- Pero si queremos **evitar engaños visuales y ver qué hay realmente en el documento**, entonces el flattening nos da un **“rayos X del PDF”**: lo que ves es lo que hay, sin capas escondidas.

---

