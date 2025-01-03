import hashlib
import os  # Certifique-se de que esta linha está presente
from pymongo import MongoClient
from dotenv import load_dotenv

# Carrega variáveis de ambiente
load_dotenv()

# Configurações do MongoDB a partir das variáveis de ambiente
MONGO_URI = os.getenv('MONGO_URI')
MONGO_DB = os.getenv('MONGO_DB')
MONGO_COLLECTION = os.getenv('MONGO_COLLECTION')
USER_DATA_FILE = os.getenv('USER_DATA_FILE')

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
        # Salva o registro no arquivo
        with open(USER_DATA_FILE, 'a') as file:
            file.write(f"{email},{hashed_password}\n")
        return "Registro realizado com sucesso! Agora você pode fazer o login."
    
    def login(self, email, password):
        # Tenta encontrar o usuário com o email e senha fornecidos
        hashed_password = self.hash_password(password)
        user = self.collection.find_one({"email": email, "password": hashed_password})
        if user:
            # Salva o login no arquivo
            with open(USER_DATA_FILE, 'a') as file:
                file.write(f"{email},{hashed_password},login\n")
            return user
        return None
