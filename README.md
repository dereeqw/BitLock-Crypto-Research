# BitLock: Investigación sobre Criptografía y Persistencia en Memoria (PoC)

### ⚠️ Únicamente para fines educativos
**Aviso Legal:** Este proyecto ha sido desarrollado con fines de investigación académica y pruebas de seguridad autorizadas. El autor no se hace responsable del mal uso de este software. Utilícelo solo en entornos controlados y aislados (Sandboxes).

---

## 🔬 Resumen del Proyecto
Este framework es una Prueba de Concepto (PoC) que demuestra una arquitectura de comando y control (C2) modular. El enfoque principal es el estudio de criptografía avanzada y técnicas de ejecución "fileless" (sin archivos) para comprender cómo las amenazas modernas evaden la detección basada en firmas.

### Componentes Clave:
* **Servidor C2 Seguro:** Un backend en Python que gestiona una bóveda de llaves cifrada y registros (logs) protegidos mediante **AES-256-GCM**.
* **Loader de Memoria:** Un inyector especializado que descarga, descifra y ejecuta payloads directamente en la RAM, sin dejar rastros en el disco físico.
* **Motor Criptográfico:** Implementación del estándar de cifrado autenticado **AES-256-GCM** con intercambio de llaves híbrido.

---

## 🛠️ Detalles Técnicos

### 1. Intercambio de Llaves Híbrido (ECDHE + RSA)
El framework implementa un modelo de **Seguridad Proyectada (PFS)**:
* **ECDHE (Curva P-384):** Utilizado para la derivación de llaves de sesión, garantizando que incluso si la llave maestra se ve comprometida, las sesiones anteriores permanezcan seguras.
* **HKDF:** Función de derivación de llaves utilizada para transformar el secreto compartido en una llave simétrica de 256 bits.

### 2. Flujo de Ejecución en Memoria
El cargador (`load.py`) utiliza un enfoque de "Etapa-0":
1. Genera una llave AES efímera.
2. Descarga el payload cifrado desde el servidor C2.
3. Descifra y compila el payload a *bytecode* de Python directamente en la RAM.
4. Utiliza `exec()` para iniciar la ejecución sin escribir nunca el archivo `.py` en el almacenamiento local.

### 3. Capacidades Anti-Forense
El servidor incluye un módulo avanzado `--del` que realiza un **borrado seguro de 7 pasadas** (shredding) de los logs y bases de datos sensibles, utilizando `os.fsync` y `secrets.token_bytes` para sobrescribir los sectores físicos del disco.

---

## 🚀 Instalación (Entorno de Laboratorio)
1. **Iniciar Servidor C2:**
   ```bash
   python3 BitLockC2Server.py
