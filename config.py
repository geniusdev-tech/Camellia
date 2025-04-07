import os
import hashlib
from pymongo import MongoClient
from dotenv import load_dotenv
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from typing import Optional, Tuple, Dict, Callable
import time

load_dotenv()

# Variáveis de ambiente
MONGO_URI = os.getenv('MONGO_URI')
MONGO_DB = os.getenv('MONGO_DB')
MONGO_COLLECTION = os.getenv('MONGO_COLLECTION')
USER_DATA_FILE = os.getenv('USER_DATA_FILE')

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

    Args:
        file_path (str): Caminho do arquivo.

    Returns:
        Optional[str]: Hash hexadecimal ou None se houver erro.
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

    def _derive_key(self, salt: bytes) -> bytes:
        """
        Deriva uma chave de criptografia a partir da senha usando PBKDF2.

        Args:
            salt (bytes): Sal para fortalecimento da chave.

        Returns:
            bytes: Chave derivada.
        """
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000
        )
        return kdf.derive(self.password)

    def encrypt(self, msg: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Criptografa uma mensagem.

        Args:
            msg (bytes): Mensagem a ser criptografada.

        Returns:
            Tuple[bytes, bytes, bytes]: Sal, IV (vetor de inicialização) e texto cifrado.
        """
        salt = os.urandom(16)
        iv = os.urandom(16)
        key = self._derive_key(salt)
        camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
        encryptor = camellia_cipher.encryptor()
        ciphertext = encryptor.update(msg) + encryptor.finalize()
        return salt, iv, ciphertext

    def decrypt(self, salt: bytes, iv: bytes, ciphertext: bytes) -> bytes:
        """
        Descriptografa uma mensagem.

        Args:
            salt (bytes): Sal usado na derivação da chave.
            iv (bytes): Vetor de inicialização.
            ciphertext (bytes): Texto cifrado.

        Returns:
            bytes: Mensagem descriptografada.
        """
        key = self._derive_key(salt)
        camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
        decryptor = camellia_cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()

class UserAuth:
    """
    Classe para autenticação de usuários com MongoDB.
    """
    def __init__(self):
        self.db_client = MongoClient(MONGO_URI)
        self.db = self.db_client[MONGO_DB]
        self.collection = self.db[MONGO_COLLECTION]

    def hash_password(self, password: str) -> str:
        """
        Gera um hash SHA-256 da senha.

        Args:
            password (str): Senha em texto simples.

        Returns:
            str: Hash da senha.
        """
        return hashlib.sha256(password.encode()).hexdigest()

    def register(self, email: str, password: str, phone_number: str) -> dict:
        """
        Registra um novo usuário.

        Args:
            email (str): Email do usuário.
            password (str): Senha do usuário.
            phone_number (str): Número de telefone (opcional, não usado para SMS).

        Returns:
            dict: Resultado do registro (success, message).
        """
        if not all([email, password]):
            return {"success": False, "message": "Email e senha são obrigatórios"}

        if self.collection.find_one({"email": email}):
            return {"success": False, "message": "Este email já está registrado"}

        hashed_password = self.hash_password(password)
        user_data = {
            "email": email,
            "password": hashed_password,
            "phone_number": phone_number if phone_number else "Não informado",
            "verified": True,  # Verificação automática sem SMS
            "created_at": time.time()
        }

        try:
            self.collection.insert_one(user_data)
            with open(USER_DATA_FILE, 'a') as file:
                file.write(f"{email},{hashed_password},{phone_number if phone_number else 'N/A'},registered\n")
            return {"success": True, "message": "Registro realizado com sucesso!"}
        except Exception as e:
            return {"success": False, "message": f"Erro no registro: {str(e)}"}

    def login(self, email: str, password: str) -> dict:
        """
        Realiza o login de um usuário.

        Args:
            email (str): Email do usuário.
            password (str): Senha do usuário.

        Returns:
            dict: Resultado do login (success, message, user).
        """
        hashed_password = self.hash_password(password)
        user = self.collection.find_one({"email": email, "password": hashed_password})

        if not user:
            return {"success": False, "message": "Credenciais inválidas"}

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

def process_file(file_path: str, password: str, encrypt: bool = True, progress_callback: Optional[Callable[[int, str], None]] = None, check_state: Optional[Callable[[], bool]] = None) -> dict:
    """
    Processa um arquivo (criptografa ou descriptografa).

    Args:
        file_path (str): Caminho do arquivo.
        password (str): Senha para criptografia/descriptografia.
        encrypt (bool): True para criptografar, False para descriptografar.
        progress_callback (Callable): Função para atualizar o progresso.
        check_state (Callable): Função para verificar estado (pausa/cancelamento).

    Returns:
        dict: Resultado do processamento (success, message, hash).
    """
    if not os.path.exists(file_path):
        return {"success": False, "message": "Arquivo não encontrado"}

    if isinstance(password, str):
        password = password.encode('utf-8')
    cryptor = CamelliaCryptor(password)

    try:
        file_size = os.path.getsize(file_path)
        processed = 0
        start_time = time.time()

        output_path = file_path + '.enc' if encrypt else file_path.replace('.enc', '')
        temp_path = file_path + '.tmp'

        with open(file_path, 'rb') as f_in, open(temp_path, 'wb') as f_out:
            if encrypt:
                salt = os.urandom(16)
                iv = os.urandom(16)
                key = cryptor._derive_key(salt)
                camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
                encryptor = camellia_cipher.encryptor()

                f_out.write(salt + iv)
                processed += 32
                if progress_callback:
                    percent = int((processed / file_size) * 100)
                    progress_callback(percent, f"{percent}% - Iniciando...")

                while True:
                    if check_state and not check_state():
                        return {"success": False, "message": "Processamento cancelado"}
                    chunk = f_in.read(8192)
                    if not chunk:
                        break
                    f_out.write(encryptor.update(chunk))
                    processed += len(chunk)
                    if progress_callback:
                        percent = int((processed / file_size) * 100)
                        elapsed = time.time() - start_time
                        eta = (elapsed / (processed / file_size)) - elapsed if processed > 0 else 0
                        progress_callback(percent, f"{percent}% - ETA: {format_eta(eta)}")
                f_out.write(encryptor.finalize())
            else:
                f_in.seek(0)
                salt = f_in.read(16)
                iv = f_in.read(16)
                processed += 32
                key = cryptor._derive_key(salt)
                camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
                decryptor = camellia_cipher.decryptor()

                if progress_callback:
                    percent = int((processed / file_size) * 100)
                    progress_callback(percent, f"{percent}% - Iniciando...")

                while True:
                    if check_state and not check_state():
                        return {"success": False, "message": "Processamento cancelado"}
                    chunk = f_in.read(8192)
                    if not chunk:
                        break
                    f_out.write(decryptor.update(chunk))
                    processed += len(chunk)
                    if progress_callback:
                        percent = int((processed / file_size) * 100)
                        elapsed = time.time() - start_time
                        eta = (elapsed / (processed / file_size)) - elapsed if processed > 0 else 0
                        progress_callback(percent, f"{percent}% - ETA: {format_eta(eta)}")
                f_out.write(decryptor.finalize())

        os.replace(temp_path, output_path)
        if not encrypt and file_path.endswith('.enc'):
            os.remove(file_path)

        file_hash = generate_file_hash(output_path)
        return {"success": True, "message": "Arquivo processado com sucesso", "hash": file_hash}
    except Exception as e:
        if os.path.exists(temp_path):
            os.remove(temp_path)
        return {"success": False, "message": f"Erro ao processar arquivo: {str(e)}"}

def process_folder(folder_path: str, password: str, encrypt: bool = True, progress_callback: Optional[Callable[[int, str], None]] = None, check_state: Optional[Callable[[], bool]] = None) -> dict:
    """
    Processa todos os arquivos em uma pasta (criptografa ou descriptografa).

    Args:
        folder_path (str): Caminho da pasta.
        password (str): Senha para criptografia/descriptografia.
        encrypt (bool): True para criptografar, False para descriptografar.
        progress_callback (Callable): Função para atualizar o progresso.
        check_state (Callable): Função para verificar estado (pausa/cancelamento).

    Returns:
        dict: Resultado do processamento (success, message, results).
    """
    if not os.path.isdir(folder_path):
        return {"success": False, "message": "Pasta não encontrada"}

    results = []
    total_files = sum(len(files) for _, _, files in os.walk(folder_path))
    processed_files = 0
    start_time = time.time()

    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            if check_state and not check_state():
                return {"success": False, "message": "Processamento cancelado pelo usuário", "results": results}
            result = process_file(file_path, password, encrypt, None, check_state)
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

def organize_files(folder_path: str, rules: dict = ORGANIZATION_RULES) -> dict:
    """
    Organiza arquivos em uma pasta com base em regras predefinidas.

    Args:
        folder_path (str): Caminho da pasta a ser organizada.
        rules (dict): Dicionário mapeando extensões para nomes de pastas.

    Returns:
        dict: Resultado da organização (success, message, results).
    """
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
                    if file_path != new_path:  # Evita mover para o mesmo local
                        os.rename(file_path, new_path)
                        results.append({"file": file_path, "new_path": new_path, "success": True})
                except Exception as e:
                    results.append({"file": file_path, "message": f"Erro: {str(e)}", "success": False})
    
    success = all(r["success"] for r in results) if results else True
    return {
        "success": success,
        "message": "Organização concluída" if success else "Erro em alguns arquivos",
        "results": results
    }

def format_eta(seconds):
    """
    Formata o tempo estimado restante (ETA) em hh:mm:ss.

    Args:
        seconds (float): Segundos restantes.

    Returns:
        str: Tempo formatado.
    """
    seconds = int(seconds)
    hrs = seconds // 3600
    mins = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hrs:02d}:{mins:02d}:{secs:02d}"

if __name__ == "__main__":
    # Exemplo de uso standalone para testes
    test_file = "test.txt"
    with open(test_file, "w") as f:
        f.write("Conteúdo de teste")
    
    result = process_file(test_file, "Teste123", True)
    print(result)
    
    result = organize_files(".", {"txt": "Textos"})
    print(result)