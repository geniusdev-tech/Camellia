import os
import hashlib
from pymongo import MongoClient
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

# Configurações do MongoDB
MONGO_URI = 'mongodb://localhost:27017/'
MONGO_DB = 'user_auth'
MONGO_COLLECTION = 'users'

class UserAuth:
    def __init__(self):
        # Conecta ao MongoDB
        self.db_client = MongoClient(MONGO_URI)
        self.db = self.db_client[MONGO_DB]
        self.collection = self.db[MONGO_COLLECTION]
    
    def hash_password(self, password):
        # Gera o hash da senha
        return hashlib.sha256(password.encode()).hexdigest()
    
    def register(self, email, password):
        # Verifica se o email já está registrado
        if self.collection.find_one({"email": email}):
            return "Este email já está registrado!"
        # Insere novo usuário com senha hasheada
        hashed_password = self.hash_password(password)
        self.collection.insert_one({"email": email, "password": hashed_password})
        return "Registro realizado com sucesso! Agora você pode fazer o login."
    
    def login(self, email, password):
        # Tenta encontrar o usuário com o email e senha fornecidos
        hashed_password = self.hash_password(password)
        user = self.collection.find_one({"email": email, "password": hashed_password})
        if user:
            return user
        return None

# Lógica de criptografia e descriptografia
def generate_file_hash(file_path):
    # Gera o hash de um arquivo
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
    except Exception as e:
        print(f"Erro ao gerar hash do arquivo {file_path}: {e}")
        return None
    return hasher.hexdigest()

def encrypt_Camellia(msg, password):
    # Gera salt e IV
    salt = os.urandom(16)
    iv = os.urandom(16)
    # Deriva chave a partir da senha
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = kdf.derive(password.encode())
    
    camelliaCipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
    encryptor = camelliaCipher.encryptor()
    ciphertext = encryptor.update(msg) + encryptor.finalize()
    
    return salt, iv, ciphertext

def decrypt_Camellia(salt, iv, ciphertext, password):
    # Deriva chave a partir do salt e senha
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = kdf.derive(password.encode())
    
    camelliaCipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
    decryptor = camelliaCipher.decryptor()
    
    return decryptor.update(ciphertext) + decryptor.finalize()

def process_file(file_path, password, encrypt=True):
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
        
        if encrypt:
            # Encripta e salva o arquivo
            salt, iv, ciphertext = encrypt_Camellia(data, password)
            with open(file_path, 'wb') as f:
                f.write(salt + b' ' + iv + b' ' + ciphertext)
        else:
            try:
                # Desencripta e salva o arquivo
                salt, iv, ciphertext = data.split(b' ', 2)
                plaintext = decrypt_Camellia(salt, iv, ciphertext, password)
                with open(file_path, 'wb') as f:
                    f.write(plaintext)
            except ValueError:
                print(f"O arquivo {file_path} parece estar corrompido ou no formato errado.")
                return False
    except Exception as e:
        print(f"Erro ao processar o arquivo {file_path}: {e}")
        return False
    return True

def process_folder(folder_path, password, encrypt=True):
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if not process_file(file_path, password, encrypt):
                print(f"Erro ao processar o arquivo {file_path}")
