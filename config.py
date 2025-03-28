import hashlib
import os
from pymongo import MongoClient
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from typing import Optional, Tuple, Dict, Callable
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
import random
import time

load_dotenv()

MONGO_URI = os.getenv('MONGO_URI')
MONGO_DB = os.getenv('MONGO_DB')
MONGO_COLLECTION = os.getenv('MONGO_COLLECTION')
USER_DATA_FILE = os.getenv('USER_DATA_FILE')
TWILIO_ACCOUNT_SID = os.getenv('TWILIO_ACCOUNT_SID')
TWILIO_AUTH_TOKEN = os.getenv('TWILIO_AUTH_TOKEN')
TWILIO_PHONE_NUMBER = os.getenv('TWILIO_PHONE_NUMBER')

VERIFICATION_CODE_EXPIRY = 300

def generate_file_hash(file_path: str) -> Optional[str]:
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
    def __init__(self, password: bytes):
        self.password = password

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        return kdf.derive(self.password)

    def encrypt(self, msg: bytes) -> Tuple[bytes, bytes, bytes]:
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = self._derive_key(salt)
        camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
        encryptor = camellia_cipher.encryptor()
        ciphertext = encryptor.update(msg) + encryptor.finalize()
        return salt, iv, ciphertext

    def decrypt(self, salt: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        key = self._derive_key(salt)
        camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
        decryptor = camellia_cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

class UserAuth:
    def __init__(self):
        self.db_client = MongoClient(MONGO_URI)
        self.db = self.db_client[MONGO_DB]
        self.collection = self.db[MONGO_COLLECTION]
        if not TWILIO_ACCOUNT_SID or not TWILIO_AUTH_TOKEN or not TWILIO_PHONE_NUMBER:
            raise ValueError("Credenciais do Twilio não configuradas corretamente. Verifique o arquivo .env")
        self.twilio_client = Client(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        self.pending_verifications: Dict[str, Tuple[str, float]] = {}

    def hash_password(self, password: str) -> str:
        return hashlib.sha256(password.encode()).hexdigest()

    def register(self, email: str, password: str, phone_number: str) -> dict:
        if not all([email, password, phone_number]):
            return {"success": False, "message": "Todos os campos são obrigatórios"}

        if self.collection.find_one({"email": email}):
            return {"success": False, "message": "Este email já está registrado"}

        hashed_password = self.hash_password(password)
        user_data = {
            "email": email,
            "password": hashed_password,
            "phone_number": phone_number,
            "verified": False,
            "created_at": time.time()
        }

        try:
            self.collection.insert_one(user_data)
            with open(USER_DATA_FILE, 'a') as file:
                file.write(f"{email},{hashed_password},{phone_number},registered\n")
            
            verification_code = self.send_verification_sms(phone_number)
            if verification_code:
                self.pending_verifications[email] = (verification_code, time.time())
                return {"success": True, "message": "Registro realizado! Verifique o código enviado ao seu telefone"}
            return {"success": False, "message": "Falha ao enviar SMS de verificação"}
        except Exception as e:
            return {"success": False, "message": f"Erro no registro: {str(e)}"}

    def send_verification_sms(self, phone_number: str) -> Optional[str]:
        if not phone_number:
            print("Número de telefone não fornecido")
            return None
        verification_code = str(random.randint(100000, 999999))
        try:
            message = self.twilio_client.messages.create(
                body=f"Seu código de verificação QuickCrypt é: {verification_code}",
                from_=TWILIO_PHONE_NUMBER,
                to=phone_number
            )
            print(f"SMS enviado para {phone_number} - SID: {message.sid}")
            return verification_code
        except TwilioRestException as e:
            print(f"Falha ao enviar SMS: {str(e)}")
            return None

    def verify_code(self, email: str, code: str) -> dict:
        if email not in self.pending_verifications:
            return {"success": False, "message": "Nenhum código pendente para este email"}

        stored_code, timestamp = self.pending_verifications[email]
        if time.time() - timestamp > VERIFICATION_CODE_EXPIRY:
            del self.pending_verifications[email]
            return {"success": False, "message": "Código expirado"}

        if code == stored_code:
            try:
                self.collection.update_one(
                    {"email": email},
                    {"$set": {"verified": True}}
                )
                del self.pending_verifications[email]
                with open(USER_DATA_FILE, 'a') as file:
                    file.write(f"{email},verified\n")
                return {"success": True, "message": "Verificação concluída com sucesso"}
            except Exception as e:
                return {"success": False, "message": f"Erro ao verificar: {str(e)}"}
        return {"success": False, "message": "Código inválido"}

    def login(self, email: str, password: str) -> dict:
        hashed_password = self.hash_password(password)
        user = self.collection.find_one({"email": email, "password": hashed_password})

        if not user:
            return {"success": False, "message": "Credenciais inválidas"}

        if not user.get("verified", False):
            phone_number = user.get("phone_number")
            if not phone_number:
                return {"success": False, "message": "Número de telefone não registrado para esta conta. Registre-se novamente."}
            
            verification_code = self.send_verification_sms(phone_number)
            if verification_code:
                self.pending_verifications[email] = (verification_code, time.time())
                return {"success": False, "message": "Conta não verificada. Novo código enviado ao seu telefone"}
            return {"success": False, "message": "Conta não verificada e falha ao enviar SMS"}

        try:
            with open(USER_DATA_FILE, 'a') as file:
                file.write(f"{email},{hashed_password},login\n")
            return {
                "success": True,
                "message": "Login bem-sucedido",
                "user": {
                    "email": user["email"],
                    "phone_number": user.get("phone_number", "Não informado")
                }
            }
        except Exception as e:
            return {"success": False, "message": f"Erro no login: {str(e)}"}

def process_file(file_path: str, password: str, encrypt: bool = True, progress_callback: Optional[Callable[[int, str], None]] = None) -> dict:
    if not os.path.exists(file_path):
        return {"success": False, "message": "Arquivo não encontrado"}

    if isinstance(password, str):
        password = password.encode('utf-8')
    cryptor = CamelliaCryptor(password)

    try:
        file_size = os.path.getsize(file_path)
        processed = 0
        start_time = time.time()

        with open(file_path, 'rb') as f, open(file_path + '.tmp', 'wb') as out_file:
            if encrypt:
                salt = os.urandom(16)
                iv = os.urandom(16)
                key = cryptor._derive_key(salt)
                camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
                encryptor = camellia_cipher.encryptor()

                out_file.write(salt + iv)
                processed += 32  # Salt + IV
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    out_file.write(encryptor.update(chunk))
                    processed += len(chunk)
                    if progress_callback:
                        percent = int((processed / file_size) * 100)
                        elapsed = time.time() - start_time
                        eta = (elapsed / (processed / file_size)) - elapsed if processed > 0 else 0
                        progress_callback(percent, f"{percent}% - ETA: {format_eta(eta)}")
                out_file.write(encryptor.finalize())
            else:
                salt = f.read(16)
                iv = f.read(16)
                processed += 32
                key = cryptor._derive_key(salt)
                camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
                decryptor = camellia_cipher.decryptor()

                if progress_callback:
                    percent = int((processed / file_size) * 100)
                    progress_callback(percent, f"{percent}% - Iniciando...")
                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    out_file.write(decryptor.update(chunk))
                    processed += len(chunk)
                    if progress_callback:
                        percent = int((processed / file_size) * 100)
                        elapsed = time.time() - start_time
                        eta = (elapsed / (processed / file_size)) - elapsed if processed > 0 else 0
                        progress_callback(percent, f"{percent}% - ETA: {format_eta(eta)}")
                out_file.write(decryptor.finalize())

        os.replace(file_path + '.tmp', file_path)
        file_hash = generate_file_hash(file_path)
        return {"success": True, "message": "Arquivo processado com sucesso", "hash": file_hash}
    except Exception as e:
        return {"success": False, "message": f"Erro ao processar arquivo: {str(e)}"}

def process_folder(folder_path: str, password: str, encrypt: bool = True, progress_callback: Optional[Callable[[int, str], None]] = None) -> dict:
    if not os.path.isdir(folder_path):
        return {"success": False, "message": "Pasta não encontrada"}

    results = []
    total_files = sum(len(files) for _, _, files in os.walk(folder_path))
    processed_files = 0
    start_time = time.time()

    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            result = process_file(file_path, password, encrypt, None)  # Não passa callback para arquivos individuais aqui
            results.append({"file": file_path, **result})
            processed_files += 1
            if progress_callback:
                percent = int((processed_files / total_files) * 100)
                elapsed = time.time() - start_time
                eta = (elapsed / (processed_files / total_files)) - elapsed if processed_files > 0 else 0
                progress_callback(percent, f"Arquivo {processed_files}/{total_files} - ETA: {format_eta(eta)}")

    success = all(r["success"] for r in results)
    return {
        "success": success,
        "message": "Processamento da pasta concluído" if success else "Erro em alguns arquivos",
        "results": results
    }

def format_eta(seconds):
    seconds = int(seconds)
    hrs = seconds // 3600
    mins = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hrs:02d}:{mins:02d}:{secs:02d}"