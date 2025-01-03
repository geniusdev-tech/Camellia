# Encryption and Decryption with Camellia

## Features

This project implements a simple graphical application for file encryption and decryption using the Camellia algorithm. The graphical interface is made with PyQt5, and the encryption/decryption code uses the `cryptography` library.

### Features

- **Encryption**: Encrypts files using Camellia with a password provided by the user.
- **Decryption**: Decrypts previously encrypted files using the same password.
- **Hash**: Generates a SHA-256 hash of the encrypted or decrypted file to verify the integrity of the file.
- **Padlock Icons**: Displays closed padlock icons for encryption and open padlock icons for decryption.

## Installation Requirements

Make sure you have the following dependencies installed:

-Python 3.x
- Python Libraries:
  - `cryptography`
  - `PyQt5`

### Install Dependencies on Linux

```sh
sudo apt update
sudo apt install python3 python3-pip
pip install cryptography pyqt5 
```

### Install Dependencies on Windows and MacOS

```sh
brew install python3
pip3 install cryptography pyqt5
```

### How to run on Linux, MacOS or Windows

```sh
git clone https://github.com/user/repositorio.git
cd repository
python3 crypt.py
```