import sys
from PySide6.QtWidgets import (QApplication, QWidget, QPushButton, QVBoxLayout, QFileDialog,
                               QLineEdit, QLabel, QRadioButton, QMessageBox, QFormLayout, QProgressBar, QGroupBox, QSplitter, QHBoxLayout)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon, QShortcut, QKeySequence
from config import UserAuth
from config import generate_file_hash, process_file, process_folder

class EncryptDecryptApp(QWidget):
    def __init__(self):
        super().__init__()
        self.auth = UserAuth()
        self.user_info = None
        self.initUI()
        self.createShortcuts()
        self.disable_file_processing()
    
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
        """)


    def createShortcuts(self):
        
        QShortcut(QKeySequence('Ctrl+O'), self).activated.connect(self.browse_file)
        QShortcut(QKeySequence('Ctrl+Q'), self).activated.connect(self.close)
    
    def initUI(self):
        self.setWindowTitle('Quick Cryptography 1.0')
        self.setGeometry(200, 200, 650, 450)
        
        main_layout = QVBoxLayout()
        
        # Grupo de autenticação
        auth_group = QGroupBox("Autenticação")
        auth_layout = QFormLayout()
        
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
        
        self.file_label = QLabel('Arquivo Alvo:')
        self.folder_label = QLabel('Pasta Alvo:')
        
        self.file_path_display = QLineEdit(self)
        self.file_path_display.setReadOnly(True)
        
        self.folder_path_display = QLineEdit(self)
        self.folder_path_display.setReadOnly(True)
        
        self.browse_file_button = QPushButton('Selecionar Arquivo', self)
        self.browse_file_button.clicked.connect(self.browse_file)
        
        self.browse_folder_button = QPushButton('Selecionar Pasta', self)
        self.browse_folder_button.clicked.connect(self.browse_folder)
        
        self.encrypt_radio = QRadioButton('Criptografar', self)
        self.encrypt_radio.setIcon(QIcon('img/closed_lock_icon.png'))
        
        self.decrypt_radio = QRadioButton('Descriptografar', self)
        self.decrypt_radio.setIcon(QIcon('img/open_lock_icon.png'))
        
        self.encrypt_radio.setChecked(True)
        
        self.process_button = QPushButton('Processar', self)
        self.process_button.clicked.connect(self.process)
        
        self.progress_bar = QProgressBar(self)
        
        file_layout.addWidget(self.file_label)
        file_layout.addWidget(self.file_path_display)
        file_layout.addWidget(self.browse_file_button)
        file_layout.addWidget(self.folder_label)
        file_layout.addWidget(self.folder_path_display)
        file_layout.addWidget(self.browse_folder_button)
        file_layout.addWidget(self.encrypt_radio)
        file_layout.addWidget(self.decrypt_radio)
        file_layout.addWidget(self.process_button)
        file_layout.addWidget(self.progress_bar)
        
        file_group.setLayout(file_layout)
        
        main_layout.addWidget(auth_group)
        main_layout.addWidget(file_group)
        
        container = QWidget()
        container.setLayout(main_layout)
        
        main_layout_final = QVBoxLayout()
        main_layout_final.addWidget(container)
        self.setLayout(main_layout_final)
    
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Selecionar Arquivo')
        if file_path:
            self.file_path_display.setText(file_path)
    
    def browse_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, 'Selecionar Pasta')
        if folder_path:
            self.folder_path_display.setText(folder_path)
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def process(self):
        file_path = self.file_path_display.text()
        folder_path = self.folder_path_display.text()
        password = self.password_entry.text().encode()
        
        if not (file_path or folder_path):
            QMessageBox.warning(self, "Atenção", "Por favor, selecione um arquivo ou pasta!")
            return
        
        if file_path:
            success = process_file(file_path, password, self.encrypt_radio.isChecked())
            if success:
                file_hash = generate_file_hash(file_path)
                QMessageBox.information(self, "Sucesso", f"Arquivo processado com sucesso!\nHash: {file_hash}")
            else:
                QMessageBox.critical(self, "Erro", "Erro ao processar o arquivo.")
        
        if folder_path:
            process_folder(folder_path, password, self.encrypt_radio.isChecked())
            QMessageBox.information(self, "Sucesso", "Pasta processada com sucesso!")
        
        self.update_progress(100)
    
    def login(self):
        email = self.email_entry.text()
        password = self.password_entry.text()
        
        user = self.auth.login(email, password)
        
        if user:
            self.user_info = user
            self.enable_file_processing()
            QMessageBox.information(self, "Sucesso", f"Bem-vindo, {user['email']}!")
        else:
            QMessageBox.critical(self, "Erro", "Email ou senha incorretos.")
    
    def register(self):
        email = self.email_entry.text()
        password = self.password_entry.text()
        
        message = self.auth.register(email, password)
        if "sucesso" in message.lower():
            QMessageBox.information(self, "Sucesso", message)
        else:
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
    
    def enable_file_processing(self):
        self.file_path_display.setEnabled(True)
        self.folder_path_display.setEnabled(True)
        self.browse_file_button.setEnabled(True)
        self.browse_folder_button.setEnabled(True)
        self.encrypt_radio.setEnabled(True)
        self.decrypt_radio.setEnabled(True)
        self.process_button.setEnabled(True)
        self.progress_bar.setEnabled(True)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = EncryptDecryptApp()
    ex.show()
    sys.exit(app.exec())
