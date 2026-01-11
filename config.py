import os


class Config:
    SECRET_KEY = os.getenv('SECRET_KEY')
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Strict'
    PERMANENT_SESSION_LIFETIME = 300  # seconds (5 minutes)


class DevelopmentConfig(Config):
    DEBUG = True
    SESSION_COOKIE_SECURE = False


class ProductionConfig(Config):
    DEBUG = False
    SESSION_COOKIE_SECURE = True
import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes, hmac
from typing import Optional, Tuple, Dict, Callable
import time
from utils import secure_delete

# Regras para organização automática de arquivos
ORGANIZATION_RULES = {
    ".jpg": "Imagens",
    ".png": "Imagens",
    ".docx": "Documentos",
    ".pdf": "Documentos",
    ".txt": "Textos",
    ".mp4": "Vídeos"
}

def generate_file_hash(file_path: str) -> Optional[str]:
    """
    Gera um hash SHA-256 de um arquivo para verificação de integridade.
    """
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(8192), b''):
                hasher.update(chunk)
    except Exception as e:
        print(f"Erro ao gerar hash do arquivo {file_path}: {e}")
        return None
    return hasher.hexdigest()

class CamelliaCryptor:
    """
    Classe para criptografia e descriptografia usando o algoritmo Camellia.
    """
    def __init__(self, password: bytes):
        self.password = password

    def _derive_keys(self, salt: bytes) -> Tuple[bytes, bytes]:
        """
        Deriva chaves de criptografia e HMAC a partir da senha usando PBKDF2.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=64, # 32 bytes for Enc Key, 32 bytes for HMAC Key
            salt=salt,
            iterations=100000
        )
        derived = kdf.derive(self.password)
        return derived[:32], derived[32:]

    def encrypt(self, msg: bytes) -> Tuple[bytes, bytes, bytes, bytes]:
        """
        Criptografa uma mensagem e gera HMAC.
        Returns: Salt, IV, Ciphertext, HMAC
        """
        salt = os.urandom(16)
        iv = os.urandom(16)
        key, hmac_key = self._derive_keys(salt)
        
        camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
        encryptor = camellia_cipher.encryptor()
        ciphertext = encryptor.update(msg) + encryptor.finalize()
        
        # Calculate HMAC
        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(salt + iv + ciphertext)
        mac = h.finalize()
        
        return salt, iv, ciphertext, mac

    def decrypt(self, salt: bytes, iv: bytes, ciphertext: bytes, mac: bytes) -> bytes:
        """
        Verifica HMAC e descriptografa.
        """
        key, hmac_key = self._derive_keys(salt)
        
        # Verify HMAC first
        h = hmac.HMAC(hmac_key, hashes.SHA256())
        h.update(salt + iv + ciphertext)
        h.verify(mac) # Raises InvalidSignature if failed
        
        camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
        decryptor = camellia_cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

def process_file(file_path: str, password: str, encrypt: bool = True, progress_callback: Optional[Callable[[int, str], None]] = None, check_state: Optional[Callable[[], bool]] = None) -> dict:
    """
    Processa um arquivo (criptografa ou descriptografa) com integridade HMAC.
    """
    if not os.path.exists(file_path):
        return {"success": False, "message": "Arquivo não encontrado"}

    if isinstance(password, str):
        password = password.encode('utf-8')
    cryptor = CamelliaCryptor(password)

    # Format Config
    # Encrypted File Structure: [Salt(16)][IV(16)][HMAC(32)][Ciphertext(N)]
    HEADER_SIZE = 16 + 16 + 32 

    try:
        file_size = os.path.getsize(file_path)
        processed = 0
        start_time = time.time()

        output_path = file_path + '.enc' if encrypt else file_path.replace('.enc', '')
        if not encrypt and not file_path.endswith('.enc'):
             output_path += '.dec' # Prevent overwrite if not .enc
             
        temp_path = file_path + '.tmp'

        with open(file_path, 'rb') as f_in, open(temp_path, 'wb') as f_out:
            if encrypt:
                salt = os.urandom(16)
                iv = os.urandom(16)
                key, hmac_key = cryptor._derive_keys(salt)
                
                camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
                encryptor = camellia_cipher.encryptor()
                
                # We calculate HMAC on the fly? No, we need whole ciphertext for simple HMAC.
                # For stream processing, we usually update HMAC chunk by chunk.
                h = hmac.HMAC(hmac_key, hashes.SHA256())
                
                # Write placeholders
                f_out.write(salt + iv + (b'\0' * 32)) 
                
                # Feed HMAC with header data available so far
                h.update(salt + iv)
                
                processed += HEADER_SIZE
                if progress_callback: progress_callback(0, "Iniciando...")

                while True:
                    if check_state and not check_state():
                        return {"success": False, "message": "Cancelado"}
                    chunk = f_in.read(8192)
                    if not chunk: break
                    
                    ct_chunk = encryptor.update(chunk)
                    f_out.write(ct_chunk)
                    h.update(ct_chunk) # Update HMAC
                    
                    processed += len(chunk)
                    if progress_callback:
                        pct = int((processed / (file_size + HEADER_SIZE)) * 100) if file_size > 0 else 0
                        progress_callback(pct, f"Criptografando...")
                        
                ct_final = encryptor.finalize()
                f_out.write(ct_final)
                h.update(ct_final)
                
                mac = h.finalize()
                
                # Go back and write MAC
                f_out.seek(32)
                f_out.write(mac)
                
            else:
                # Decrypt
                if file_size < HEADER_SIZE:
                    return {"success": False, "message": "Arquivo inválido/corrompido"}
                
                salt = f_in.read(16)
                iv = f_in.read(16)
                mac = f_in.read(32)
                
                key, hmac_key = cryptor._derive_keys(salt)
                h = hmac.HMAC(hmac_key, hashes.SHA256())
                h.update(salt + iv)
                
                # First Pass: Verify HMAC (Security Critical)
                # We must read entire file to verify HMAC before writing ANY plaintext to disk.
                # Ideally we do 2 passes or decrypt to memory. For large files, 2 passes is safer for RAM.
                progress_callback(0, "Verificando integridade...")
                current_pos = f_in.tell()
                
                while True:
                    if check_state and not check_state(): return {"success": False, "message": "Cancelado"}
                    chunk = f_in.read(8192)
                    if not chunk: break
                    h.update(chunk)
                
                try:
                    h.verify(mac)
                except:
                    return {"success": False, "message": "ERRO DE INTEGRIDADE: Senha incorreta ou arquivo modificado!"}
                
                # Second Pass: Decrypt
                f_in.seek(current_pos)
                camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
                decryptor = camellia_cipher.decryptor()
                
                processed = HEADER_SIZE
                
                while True:
                    if check_state and not check_state(): return {"success": False, "message": "Cancelado"}
                    chunk = f_in.read(8192)
                    if not chunk: break
                    f_out.write(decryptor.update(chunk))
                    processed += len(chunk)
                    if progress_callback:
                         pct = int((processed / file_size) * 100)
                         progress_callback(pct, "Descriptografando...")
                         
                f_out.write(decryptor.finalize())

        os.replace(temp_path, output_path)
        
        # Secure Delete Original if Encrypting
        if encrypt:
            secure_delete(file_path) # Shred it!
        elif file_path.endswith('.enc'):
            secure_delete(file_path) # Shred encrypted container after success decryption

        file_hash = generate_file_hash(output_path)
        return {"success": True, "message": "Processado com sucesso", "hash": file_hash}
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return {"success": False, "message": f"Erro: {str(e)}"}

def process_folder(folder_path, password, encrypt, progress_callback=None, check_state=None):
    if not os.path.isdir(folder_path):
        return {"success": False, "message": "Pasta não encontrada"}

    results = []
    total_files = sum(len(files) for _, _, files in os.walk(folder_path))
    processed_files = 0

    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if check_state and not check_state():
                return {"success": False, "message": "Cancelado", "results": results}
            result = process_file(file_path, password, encrypt, None, check_state)
            results.append({"file": file_path, **result})
            processed_files += 1
            if progress_callback:
                percent = int((processed_files / total_files) * 100)
                progress_callback(percent, f"Arquivos {processed_files}/{total_files}")

    success = all(r["success"] for r in results)
    return {"success": success, "message": "Concluído", "results": results}

def organize_files(folder_path: str, rules: dict = ORGANIZATION_RULES) -> dict:
    if not os.path.isdir(folder_path):
        return {"success": False, "message": "Pasta não encontrada"}

    results = []
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            ext = os.path.splitext(file)[1].lower()
            if ext in rules:
                dest_folder = os.path.join(folder_path, rules[ext])
                os.makedirs(dest_folder, exist_ok=True)
                new_path = os.path.join(dest_folder, file)
                try:
                    if file_path != new_path:
                        os.rename(file_path, new_path)
                        results.append({"file": file_path, "new_path": new_path, "success": True})
                except Exception as e:
                    results.append({"file": file_path, "message": str(e), "success": False})
    
    success = all(r["success"] for r in results) if results else True
    return {"success": success, "message": "Organizado", "results": results}

def format_eta(seconds):
    seconds = int(seconds)
    return f"{seconds//3600:02d}:{(seconds%3600)//60:02d}:{seconds%60:02d}"