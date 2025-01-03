import os
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

def generate_file_hash(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            hasher.update(chunk)
    return hasher.hexdigest()

def encrypt_Camellia(msg, password):
    salt = os.urandom(16)
    iv = os.urandom(16)
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = kdf.derive(password)
    
    camelliaCipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
    encryptor = camelliaCipher.encryptor()
    ciphertext = encryptor.update(msg) + encryptor.finalize()
    
    return salt, iv, ciphertext

def decrypt_Camellia(salt, iv, ciphertext, password):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = kdf.derive(password)
    
    camelliaCipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
    decryptor = camelliaCipher.decryptor()
    
    return decryptor.update(ciphertext) + decryptor.finalize()

def process_folder(folder_path, password, encrypt=True):
    for root, _, files in os.walk(folder_path):
        for file in files:
            file_path = os.path.join(root, file)
            with open(file_path, 'rb') as f:
                data = f.read()
            
            if encrypt:
                salt, iv, ciphertext = encrypt_Camellia(data, password)
                with open(file_path, 'wb') as f:
                    f.write(salt + b' ' + iv + b' ' + ciphertext)
            else:
                try:
                    salt, iv, ciphertext = data.split(b' ', 2)
                    plaintext = decrypt_Camellia(salt, iv, ciphertext, password)
                    with open(file_path, 'wb') as f:
                        f.write(plaintext)
                except ValueError:
                    print(f"O arquivo {file_path} parece estar corrompido ou no formato errado.")
                    continue
