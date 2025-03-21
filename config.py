import hashlib
import os
from pymongo import MongoClient
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from typing import Optional, Tuple
from tqdm import tqdm  # Biblioteca para barra de progresso

# Carrega variáveis de ambiente
load_dotenv()

# Configurações do MongoDB a partir das variáveis de ambiente
MONGO_URI = os.getenv('MONGO_URI')
MONGO_DB = os.getenv('MONGO_DB')
MONGO_COLLECTION = os.getenv('MONGO_COLLECTION')
USER_DATA_FILE = os.getenv('USER_DATA_FILE')


def generate_file_hash(file_path: str) -> Optional[str]:
    """Gera o hash SHA256 de um arquivo processando-o em chunks."""
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
    """Classe para encriptação e desencriptação usando Camellia"""

    def __init__(self, password: bytes):
        self.password = password

    def _derive_key(self, salt: bytes) -> bytes:
        """Gera a chave derivada da senha"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        return kdf.derive(self.password)

    def encrypt(self, msg: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encripta uma mensagem usando Camellia"""
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = self._derive_key(salt)

        camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
        encryptor = camellia_cipher.encryptor()
        ciphertext = encryptor.update(msg) + encryptor.finalize()

        return salt, iv, ciphertext

    def decrypt(self, salt: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """Desencripta uma mensagem usando Camellia"""
        key = self._derive_key(salt)

        camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
        decryptor = camellia_cipher.decryptor()

        return decryptor.update(ciphertext) + decryptor.finalize()


class UserAuth:
    def __init__(self):
        # Conecta ao MongoDB
        self.db_client = MongoClient(MONGO_URI)
        self.db = self.db_client[MONGO_DB]
        self.collection = self.db[MONGO_COLLECTION]

    def hash_password(self, password: str) -> str:
        # Gera o hash da senha
        return hashlib.sha256(password.encode()).hexdigest()

    def register(self, email: str, password: str) -> str:
        # Verifica se o email já está registrado
        if self.collection.find_one({"email": email}):
            return "Este email já está registrado!"
        # Insere novo usuário com senha hasheada
        hashed_password = self.hash_password(password)
        self.collection.insert_one({"email": email, "password": hashed_password})
        # Salva o registro no arquivo
        with open(USER_DATA_FILE, 'a') as file:
            file.write(f"{email},{hashed_password}\n")
        return "Registro realizado com sucesso! Agora você pode fazer o login."

    def login(self, email: str, password: str) -> Optional[dict]:
        # Tenta encontrar o usuário com o email e senha fornecidos
        hashed_password = self.hash_password(password)
        user = self.collection.find_one({"email": email, "password": hashed_password})
        if user:
            # Salva o login no arquivo
            with open(USER_DATA_FILE, 'a') as file:
                file.write(f"{email},{hashed_password},login\n")
            return user
        return None


def process_file(file_path: str, password: str, encrypt: bool = True) -> bool:
    """
    Processa (encripta ou desencripta) um arquivo em chunks, exibindo uma barra de progresso
    baseada na quantidade de bytes processados.
    """
    if isinstance(password, str):
        password = password.encode('utf-8')
    cryptor = CamelliaCryptor(password)

    try:
        file_size = os.path.getsize(file_path)
        # Abre o arquivo de entrada e um arquivo temporário de saída;
        # a barra de progresso é iniciada com o tamanho total do arquivo.
        with open(file_path, 'rb') as f, \
             open(file_path + '.tmp', 'wb') as out_file, \
             tqdm(total=file_size, unit='B', unit_scale=True, desc=os.path.basename(file_path)) as pbar:

            if encrypt:
                salt = os.urandom(16)
                iv = os.urandom(16)
                key = cryptor._derive_key(salt)
                camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
                encryptor = camellia_cipher.encryptor()

                # Grava salt e IV na saída (eles não são contados como parte do processamento do arquivo original)
                out_file.write(salt + iv)

                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    out_file.write(encryptor.update(chunk))
                    pbar.update(len(chunk))
                out_file.write(encryptor.finalize())
            else:
                # Leitura dos dados iniciais: salt (16) e IV (16)
                salt = f.read(16)
                iv = f.read(16)
                pbar.update(32)  # Atualiza a barra com os 32 bytes lidos
                key = cryptor._derive_key(salt)
                camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
                decryptor = camellia_cipher.decryptor()

                while True:
                    chunk = f.read(8192)
                    if not chunk:
                        break
                    out_file.write(decryptor.update(chunk))
                    pbar.update(len(chunk))
                out_file.write(decryptor.finalize())

        # Substitui o arquivo original pelo arquivo processado
        os.replace(file_path + '.tmp', file_path)
    except Exception as e:
        print(f"Erro ao processar o arquivo {file_path}: {e}")
        return False

    return True


def process_folder(folder_path: str, password: str, encrypt: bool = True):
    """Processa (encripta ou desencripta) todos os arquivos de uma pasta."""
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            print(f"Processando: {file_path}")
            if not process_file(file_path, password, encrypt):
                print(f"Erro ao processar o arquivo {file_path}")
