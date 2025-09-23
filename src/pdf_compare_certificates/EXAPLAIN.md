### **Cómo Funciona `incremental_pikepdf_attack` 🕵️‍♂️**

La función `incremental_pikepdf_attack` es la pieza central de la demostración. Su objetivo es alterar un PDF firmado digitalmente **sin invalidar la firma a los ojos de los validadores más antiguos o menos rigurosos**. A continuación, se detalla el proceso paso a paso.

#### **Paso 1: Generación del Contenido de Ataque** 📄➡️💻

En lugar de editar el PDF original directamente, el script primero crea el "contenido malicioso" en la memoria. Utiliza la librería `reportlab` para generar un PDF temporal con la nueva información que quieres añadir, como la página con la nota alterada de "GRADE: 20/20". Este contenido se guarda en un archivo temporal para poder leer sus bytes completos más adelante.

#### **Paso 2: La Lógica Clave de la Actualización Incremental 📁**

Aquí reside la esencia de la vulnerabilidad que estamos explotando. A diferencia de reescribir todo el archivo (lo que rompería la firma), la función realiza una actualización incremental.

* **¿Qué es una actualización incremental?** Es una característica del formato PDF que permite añadir cambios a un documento **sin modificar el contenido original**. Los cambios se añaden como una nueva sección de datos al final del archivo. La estructura del PDF tiene marcadores especiales como `startxref` y `%%EOF` que indican dónde termina una versión y dónde comienza la siguiente.

* **Implementación del Ataque**: El código abre el archivo de salida en modo de "adjuntar bytes" (`'ab'`). Esto significa que, en lugar de borrar el contenido existente, simplemente añade los bytes de la nueva página al final del documento.

#### **Paso 3: Verificación de la Vulnerabilidad** ✅

Al final del proceso, el PDF resultante contiene tanto el contenido original firmado como la nueva página con la nota de 20/20. Cuando un lector de PDF lo abre, este es el comportamiento esperado:

* **Lector Robusto (ej. Adobe Acrobat moderno)**: Detectará que se ha añadido contenido después de la firma original y emitirá una advertencia, como "La firma es inválida" o "El documento ha sido alterado". Esta es la respuesta correcta y demuestra que el ataque fue detectado.
* **Lector Vulnerable (aplicaciones más antiguas o simplificadas)**: Podría mostrar la nueva página sin una advertencia clara, o con una advertencia que el usuario podría ignorar fácilmente.

El hecho de que tu código obtenga el mensaje de "Signature INVALID" es la prueba de que el ataque funcionó como se esperaba y demostró la vulnerabilidad.

#### **En Resumen**

La función `incremental_pikepdf_attack` no busca pasar desapercibida para todos los validadores, sino demostrar que es posible **añadir contenido a un PDF firmado sin romper su estructura original**, lo cual es una grave debilidad de seguridad en los lectores de PDF que no validan los cambios incrementales.

La función `incremental_rewrite_attack` es un **contraejemplo** diseñado para demostrar un método de ataque diferente y menos efectivo.

Su propósito es mostrar qué sucede cuando un atacante ignora la función de actualización incremental y, en su lugar, intenta **reescribir todo el archivo PDF desde cero**.

---

### **Cómo Funciona `incremental_rewrite_attack` 🕵️‍♂️**

### **Cómo Funciona `incremental_rewrite_attack` 🛠️**

1.  **Abre el PDF Firmado**: Lee el contenido del PDF original firmado.
2.  **Crea un Nuevo PDF desde Cero**: Utiliza `pypdf` para crear un nuevo documento.
3.  **Añade las Páginas Viejas**: Copia las páginas del documento original al nuevo documento.
4.  **Añade la Página de Ataque**: Inserta la nueva página ("GRADE: 20/20") al final del nuevo documento.
5.  **Guarda el Nuevo PDF**: Escribe el documento completo en un nuevo archivo de salida.

---

### **¿Por Qué Es un Contraejemplo? 🚫**

El problema de este enfoque es que **invalida la firma digital**.

Las firmas digitales en PDF son sensibles a cada byte del archivo. Al reescribir el documento por completo, se cambia la estructura interna, los `offsets` de los objetos y, por lo tanto, la integridad del archivo. La firma digital, que fue calculada sobre la estructura y los bytes originales, ya no coincide con el nuevo archivo.

Un lector de PDF, al intentar verificar la firma de este nuevo archivo, detectará inmediatamente que el documento ha sido alterado y mostrará una alerta de "firma inválida", "documento alterado" o un error similar. Esto no demuestra la vulnerabilidad del guardado incremental, sino la robustez de la verificación de firmas digitales frente a una reescritura completa del documento.

En resumen, la función `incremental_rewrite_attack` existe para que puedas compararla con `incremental_pikepdf_attack` y **demostrar la diferencia** entre un ataque que rompe la firma y un ataque que se aprovecha de la función de guardado incremental para mantener la firma aparentemente válida.

¡Excelente idea! Un `README` claro es crucial para un taller. Aquí tienes una explicación detallada de cómo funciona la función `incremental_pikepdf_attack` que puedes usar para los estudiantes. Está diseñada para ser precisa y fácil de entender.

---

