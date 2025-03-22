import sys
import os
import time
import hashlib
from PySide6.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QFileDialog,
    QLineEdit, QLabel, QRadioButton, QMessageBox, QFormLayout, QProgressBar,
    QGroupBox, QHBoxLayout, QTreeView, QSplitter, QFileSystemModel, QTextEdit
)
from PySide6.QtCore import Qt, QThread, Signal, QDir
from PySide6.QtGui import QIcon, QShortcut, QKeySequence

from config import UserAuth, generate_file_hash, CamelliaCryptor

def format_eta(seconds):
    seconds = int(seconds)
    hrs = seconds // 3600
    mins = (seconds % 3600) // 60
    secs = seconds % 60
    return f"{hrs:02d}:{mins:02d}:{secs:02d}"

class FileProcessorThread(QThread):
    progressChanged = Signal(int, str)
    finishedProcessing = Signal(bool, str)
    logMessage = Signal(str)  # Novo sinal para mensagens de log

    def __init__(self, file_path: str, password: bytes, encrypt: bool = True, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.password = password
        self.encrypt = encrypt

    def run(self):
        try:
            self.logMessage.emit(f"Iniciando {'criptografia' if self.encrypt else 'descriptografia'} de {self.file_path}")
            file_size = os.path.getsize(self.file_path)
            processed = 0
            start_time = time.time()
            cryptor = CamelliaCryptor(self.password)
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

            if self.encrypt:
                salt = os.urandom(16)
                iv = os.urandom(16)
                key = cryptor._derive_key(salt)
                camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
                encryptor = camellia_cipher.encryptor()
                with open(self.file_path, 'rb') as f, open(self.file_path + '.tmp', 'wb') as out_file:
                    out_file.write(salt + iv)
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        out_file.write(encryptor.update(chunk))
                        processed += len(chunk)
                        percent = int((processed / file_size) * 100)
                        elapsed = time.time() - start_time
                        if processed == 0 or percent == 0:
                            formatted_eta = "Calculando..."
                        else:
                            total_estimated = elapsed / (processed / file_size)
                            eta = total_estimated - elapsed
                            formatted_eta = format_eta(eta)
                        self.progressChanged.emit(percent, f"{percent}% - ETA: {formatted_eta}")
                    out_file.write(encryptor.finalize())
            else:
                with open(self.file_path, 'rb') as f, open(self.file_path + '.tmp', 'wb') as out_file:
                    salt = f.read(16)
                    iv = f.read(16)
                    processed = 32
                    self.progressChanged.emit(int((processed / file_size) * 100), "Calculando ETA...")
                    key = cryptor._derive_key(salt)
                    camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
                    decryptor = camellia_cipher.decryptor()
                    while True:
                        chunk = f.read(8192)
                        if not chunk:
                            break
                        out_file.write(decryptor.update(chunk))
                        processed += len(chunk)
                        percent = int((processed / file_size) * 100)
                        elapsed = time.time() - start_time
                        if processed == 0 or percent == 0:
                            formatted_eta = "Calculando..."
                        else:
                            total_estimated = elapsed / (processed / file_size)
                            eta = total_estimated - elapsed
                            formatted_eta = format_eta(eta)
                        self.progressChanged.emit(percent, f"{percent}% - ETA: {formatted_eta}")
                    out_file.write(decryptor.finalize())

            os.replace(self.file_path + '.tmp', self.file_path)
            file_hash = generate_file_hash(self.file_path) or "N/A"
            self.logMessage.emit(f"Concluído: {self.file_path} - Hash: {file_hash}")
            self.finishedProcessing.emit(True, file_hash)
        except Exception as e:
            self.logMessage.emit(f"Erro ao processar {self.file_path}: {str(e)}")
            self.finishedProcessing.emit(False, str(e))

class FolderProcessorThread(QThread):
    progressChanged = Signal(int, str)
    finishedProcessing = Signal(bool, str)
    logMessage = Signal(str)  # Novo sinal para mensagens de log

    def __init__(self, folder_path: str, password: bytes, encrypt: bool = True, parent=None):
        super().__init__(parent)
        self.folder_path = folder_path
        self.password = password
        self.encrypt = encrypt

    def run(self):
        try:
            self.logMessage.emit(f"Iniciando {'criptografia' if self.encrypt else 'descriptografia'} da pasta {self.folder_path}")
            files = []
            for root, _, fs in os.walk(self.folder_path):
                for f in fs:
                    files.append(os.path.join(root, f))
            total_files = len(files)
            if total_files == 0:
                self.logMessage.emit("Pasta vazia.")
                self.finishedProcessing.emit(False, "Pasta vazia.")
                return

            start_time = time.time()
            for i, file in enumerate(files):
                self.logMessage.emit(f"Processando arquivo {i + 1}/{total_files}: {file}")
                cryptor = CamelliaCryptor(self.password)
                from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
                if self.encrypt:
                    salt = os.urandom(16)
                    iv = os.urandom(16)
                    key = cryptor._derive_key(salt)
                    camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
                    encryptor = camellia_cipher.encryptor()
                    with open(file, 'rb') as f, open(file + '.tmp', 'wb') as out_file:
                        out_file.write(salt + iv)
                        while True:
                            chunk = f.read(8192)
                            if not chunk:
                                break
                            out_file.write(encryptor.update(chunk))
                        out_file.write(encryptor.finalize())
                else:
                    with open(file, 'rb') as f, open(file + '.tmp', 'wb') as out_file:
                        salt = f.read(16)
                        iv = f.read(16)
                        key = cryptor._derive_key(salt)
                        camellia_cipher = Cipher(algorithms.Camellia(key), modes.CFB(iv))
                        decryptor = camellia_cipher.decryptor()
                        while True:
                            chunk = f.read(8192)
                            if not chunk:
                                break
                            out_file.write(decryptor.update(chunk))
                        out_file.write(decryptor.finalize())
                os.replace(file + '.tmp', file)

                overall_percent = int(((i + 1) / total_files) * 100)
                elapsed = time.time() - start_time
                estimated_total = elapsed / ((i + 1) / total_files)
                eta = estimated_total - elapsed
                formatted_eta = format_eta(eta)
                self.progressChanged.emit(overall_percent, f"Arquivo {i + 1}/{total_files} - ETA: {formatted_eta}")
            self.logMessage.emit(f"Processamento da pasta {self.folder_path} concluído!")
            self.finishedProcessing.emit(True, "Processamento de pasta concluído!")
        except Exception as e:
            self.logMessage.emit(f"Erro ao processar a pasta {self.folder_path}: {str(e)}")
            self.finishedProcessing.emit(False, str(e))

class EncryptDecryptApp(QWidget):
    def __init__(self):
        super().__init__()
        self.auth = UserAuth()
        self.user_info = None
        self.worker_thread = None
        self.initUI()
        self.createShortcuts()
        self.disable_file_processing()
        self.apply_styles()

    def apply_styles(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #121212; 
                color: #E0E0E0;
                font-family: 'Orbitron', sans-serif;
            }
            QGroupBox {
                border: 1px solid #2E9AFE;
                border-radius: 10px;
                margin-top: 20px;
                font-size: 14px;
                color: #7FDBFF;
            }
            QPushButton {
                background-color: #444444;
                color: #FFFFFF;
                border: 1px solid #2E9AFE;
                border-radius: 5px;
                padding: 5px;
                font-size: 12px;
                min-width: 120px;
            }
            QPushButton:hover {
                background-color: #2E9AFE;
                color: #000000;
            }
            QLineEdit {
                background-color: #222222;
                color: #FFFFFF;
                border: 1px solid #444444;
                border-radius: 5px;
                padding: 5px;
            }
            QProgressBar {
                background: #333333;
                color: #FFFFFF;
                border: 1px solid #444444;
                border-radius: 5px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #2E9AFE;
            }
            QLabel {
                color: #FFFFFF;
            }
            QRadioButton {
                color: #E0E0E0;
            }
            QTreeView {
                background-color: #222222;
                color: #FFFFFF;
                border: 1px solid #444444;
                border-radius: 5px;
            }
            QTextEdit {
                background-color: #222222;
                color: #FFFFFF;
                border: 1px solid #444444;
                border-radius: 5px;
                font-size: 12px;
            }
        """)

    def createShortcuts(self):
        QShortcut(QKeySequence('Ctrl+O'), self).activated.connect(self.browse_file)
        QShortcut(QKeySequence('Ctrl+Q'), self).activated.connect(self.close)

    def initUI(self):
        self.setWindowTitle('QuickCrypt 1.0')
        self.setGeometry(1000, 1000, 950, 600)  # Aumentei a altura para acomodar o log
        
        main_layout = QHBoxLayout()
        
        # Explorador de arquivos
        self.file_explorer = QTreeView(self)
        self.file_model = QFileSystemModel()
        self.file_model.setRootPath(QDir.rootPath())
        self.file_model.setFilter(QDir.NoDotAndDotDot | QDir.AllDirs | QDir.Files)
        self.file_explorer.setModel(self.file_model)
        self.file_explorer.setRootIndex(self.file_model.index(QDir.homePath()))
        self.file_explorer.setColumnWidth(0, 250)
        self.file_explorer.hideColumn(1)
        self.file_explorer.hideColumn(2)
        self.file_explorer.hideColumn(3)
        self.file_explorer.clicked.connect(self.on_file_explorer_clicked)
        
        # Layout de controles
        controls_layout = QVBoxLayout()
        controls_layout.setSpacing(10)
        
        # Grupo de autenticação
        auth_group = QGroupBox("Autenticação")
        auth_layout = QFormLayout()
        auth_layout.setLabelAlignment(Qt.AlignLeft)
        auth_layout.setSpacing(10)
        
        self.email_label = QLabel('Email:')
        self.email_entry = QLineEdit(self)
        
        self.password_label = QLabel('Senha:')
        self.password_entry = QLineEdit(self)
        self.password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        
        self.login_button = QPushButton('Login', self)
        self.login_button.clicked.connect(self.login)
        
        self.register_button = QPushButton('Registrar', self)
        self.register_button.clicked.connect(self.register)
        
        email_layout = QHBoxLayout()
        email_layout.addWidget(self.email_entry)
        email_layout.addWidget(self.login_button)
        
        password_layout = QHBoxLayout()
        password_layout.addWidget(self.password_entry)
        password_layout.addWidget(self.register_button)
        
        auth_layout.addRow(self.email_label, email_layout)
        auth_layout.addRow(self.password_label, password_layout)
        auth_group.setLayout(auth_layout)
        
        # Grupo de processamento de arquivos
        file_group = QGroupBox("Processamento de Arquivos")
        file_layout = QVBoxLayout()
        file_layout.setSpacing(10)
        
        self.file_label = QLabel('Arquivo Alvo:')
        self.file_path_display = QLineEdit(self)
        self.file_path_display.setReadOnly(True)
        self.browse_file_button = QPushButton('Selecionar Arquivo', self)
        self.browse_file_button.clicked.connect(self.browse_file)
        
        file_input_layout = QHBoxLayout()
        file_input_layout.addWidget(self.file_path_display)
        file_input_layout.addWidget(self.browse_file_button)
        
        self.folder_label = QLabel('Pasta Alvo:')
        self.folder_path_display = QLineEdit(self)
        self.folder_path_display.setReadOnly(True)
        self.browse_folder_button = QPushButton('Selecionar Pasta', self)
        self.browse_folder_button.clicked.connect(self.browse_folder)
        
        folder_input_layout = QHBoxLayout()
        folder_input_layout.addWidget(self.folder_path_display)
        folder_input_layout.addWidget(self.browse_folder_button)
        
        self.encrypt_radio = QRadioButton('Criptografar', self)
        self.encrypt_radio.setIcon(QIcon('img/closed_lock_icon.png'))
        self.decrypt_radio = QRadioButton('Descriptografar', self)
        self.decrypt_radio.setIcon(QIcon('img/open_lock_icon.png'))
        self.encrypt_radio.setChecked(True)
        
        self.process_button = QPushButton('Processar', self)
        self.process_button.clicked.connect(self.process)
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        
        file_layout.addWidget(self.file_label)
        file_layout.addLayout(file_input_layout)
        file_layout.addWidget(self.folder_label)
        file_layout.addLayout(folder_input_layout)
        file_layout.addWidget(self.encrypt_radio)
        file_layout.addWidget(self.decrypt_radio)
        file_layout.addWidget(self.process_button)
        file_layout.addWidget(self.progress_bar)
        
        file_group.setLayout(file_layout)
        
        # Área de log na parte inferior
        self.log_label = QLabel("Log de Processos:")
        self.log_display = QTextEdit(self)
        self.log_display.setReadOnly(True)
        self.log_display.setMinimumHeight(150)  # Altura mínima para visibilidade
        
        # Adicionando ao layout de controles
        controls_layout.addWidget(auth_group)
        controls_layout.addWidget(file_group)
        controls_layout.addWidget(self.log_label)
        controls_layout.addWidget(self.log_display)
        
        # Splitter para explorador e controles
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.file_explorer)
        splitter.addWidget(QWidget())
        splitter.widget(1).setLayout(controls_layout)
        splitter.setSizes([250, 550])
        
        main_layout.addWidget(splitter)
        self.setLayout(main_layout)

    def on_file_explorer_clicked(self, index):
        path = self.file_model.filePath(index)
        if os.path.isfile(path):
            self.file_path_display.setText(path)
            self.folder_path_display.clear()
        elif os.path.isdir(path):
            self.folder_path_display.setText(path)
            self.file_path_display.clear()

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Selecionar Arquivo')
        if file_path:
            self.file_path_display.setText(file_path)
            self.folder_path_display.clear()

    def browse_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, 'Selecionar Pasta')
        if folder_path:
            self.folder_path_display.setText(folder_path)
            self.file_path_display.clear()

    def update_progress(self, value, info):
        self.progress_bar.setValue(value)
        self.progress_bar.setFormat(info)

    def log_message(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_display.append(f"[{timestamp}] {message}")
        self.log_display.ensureCursorVisible()  # Rola para o final automaticamente
    
    def process(self):
        file_path = self.file_path_display.text()
        folder_path = self.folder_path_display.text()
        password = self.password_entry.text()
        
        if not (file_path or folder_path):
            QMessageBox.warning(self, "Atenção", "Por favor, selecione um arquivo ou pasta!")
            return

        self.process_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("0% - Iniciando...")
        
        if file_path:
            self.worker_thread = FileProcessorThread(file_path, password.encode(), self.encrypt_radio.isChecked())
            self.worker_thread.progressChanged.connect(self.update_progress)
            self.worker_thread.finishedProcessing.connect(self.file_processing_finished)
            self.worker_thread.logMessage.connect(self.log_message)  # Conectando o log
            self.worker_thread.start()
        elif folder_path:
            self.worker_thread = FolderProcessorThread(folder_path, password.encode(), self.encrypt_radio.isChecked())
            self.worker_thread.progressChanged.connect(self.update_progress)
            self.worker_thread.finishedProcessing.connect(self.folder_processing_finished)
            self.worker_thread.logMessage.connect(self.log_message)  # Conectando o log
            self.worker_thread.start()
    
    def file_processing_finished(self, success: bool, message: str):
        self.process_button.setEnabled(True)
        if success:
            QMessageBox.information(self, "Sucesso", f"Arquivo processado com sucesso!\n Chave Hash para resgatar o arquivo - salve essa chave em um lugar segura: {message}")
        else:
            QMessageBox.critical(self, "Erro", f"Erro ao processar o arquivo: {message}")
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("100% - Concluído")
    
    def folder_processing_finished(self, success: bool, message: str):
        self.process_button.setEnabled(True)
        if success:
            QMessageBox.information(self, "Sucesso", message)
        else:
            QMessageBox.critical(self, "Erro", message)
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("100% - Concluído")
    
    def login(self):
        email = self.email_entry.text()
        password = self.password_entry.text()
        user = self.auth.login(email, password)
        if user:
            self.user_info = user
            self.enable_file_processing()
            self.log_message(f"Login bem-sucedido: {user['email']}")
            QMessageBox.information(self, "Sucesso", f"Bem-vindo, {user['email']}!")
        else:
            self.log_message("Erro de login: Email ou senha incorretos")
            QMessageBox.critical(self, "Erro", "Email ou senha incorretos.")
    
    def register(self):
        email = self.email_entry.text()
        password = self.password_entry.text()
        message = self.auth.register(email, password)
        if "sucesso" in message.lower():
            self.log_message(f"Registro bem-sucedido: {email}")
            QMessageBox.information(self, "Sucesso", message)
        else:
            self.log_message(f"Erro no registro: {message}")
            QMessageBox.warning(self, "Atenção", message)
    
    def disable_file_processing(self):
        self.file_path_display.setEnabled(False)
        self.folder_path_display.setEnabled(False)
        self.browse_file_button.setEnabled(False)
        self.browse_folder_button.setEnabled(False)
        self.encrypt_radio.setEnabled(False)
        self.decrypt_radio.setEnabled(False)
        self.process_button.setEnabled(False)
        self.progress_bar.setEnabled(False)
        self.file_explorer.setEnabled(False)
    
    def enable_file_processing(self):
        self.file_path_display.setEnabled(True)
        self.folder_path_display.setEnabled(True)
        self.browse_file_button.setEnabled(True)
        self.browse_folder_button.setEnabled(True)
        self.encrypt_radio.setEnabled(True)
        self.decrypt_radio.setEnabled(True)
        self.process_button.setEnabled(True)
        self.progress_bar.setEnabled(True)
        self.file_explorer.setEnabled(True)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = EncryptDecryptApp()
    ex.show()
    sys.exit(app.exec())