import sys
from PySide6.QtWidgets import (QApplication, QWidget, QPushButton, QVBoxLayout, QFileDialog,
                               QLineEdit, QLabel, QRadioButton, QMessageBox, QFormLayout, QHBoxLayout, QProgressBar, QGroupBox)
from PySide6.QtCore import Qt
from PySide6.QtGui import QIcon, QShortcut, QKeySequence
from login import UserAuth
from logic import generate_file_hash, process_file, process_folder

class EncryptDecryptApp(QWidget):
    def __init__(self):
        super().__init__()
        self.auth = UserAuth()
        self.user_info = None
        self.initUI()
        self.createShortcuts()
    
    def createShortcuts(self):
        QShortcut(QKeySequence('Ctrl+O'), self).activated.connect(self.browse_file)
        QShortcut(QKeySequence('Ctrl+Q'), self).activated.connect(self.close)
    
    def initUI(self):
        self.setWindowTitle('Quick Cryptography 1.0')
        self.setGeometry(200, 200, 600, 400)
        
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
        
        auth_layout.addRow(self.email_label, self.email_entry)
        auth_layout.addRow(self.password_label, self.password_entry)
        auth_layout.addRow(self.login_button, self.register_button)
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
        self.encrypt_radio.setIcon(QIcon('closed_lock_icon.png'))
        
        self.decrypt_radio = QRadioButton('Descriptografar', self)
        self.decrypt_radio.setIcon(QIcon('open_lock_icon.png'))
        
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
        
        self.setLayout(main_layout)
        
        # Inicialmente, desabilitar componentes
        self.enable_components(False)
    
    def enable_components(self, enable):
        self.file_path_display.setEnabled(enable)
        self.folder_path_display.setEnabled(enable)
        self.browse_file_button.setEnabled(enable)
        self.browse_folder_button.setEnabled(enable)
        self.encrypt_radio.setEnabled(enable)
        self.decrypt_radio.setEnabled(enable)
        self.process_button.setEnabled(enable)
    
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
        if not self.user_info:
            QMessageBox.warning(self, "Atenção", "Por favor, faça o login para usar a aplicação!")
            return
        
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
        password = self.auth.hash_password(self.password_entry.text())
        
        user = self.auth.login(email, password)
        
        if user:
            self.user_info = user
            QMessageBox.information(self, "Sucesso", f"Bem-vindo, {user['email']}!")
            self.enable_components(True)  # Habilitar componentes após login bem-sucedido
        else:
            QMessageBox.critical(self, "Erro", "Email ou senha incorretos.")
    
    def register(self):
        email = self.email_entry.text()
        password = self.auth.hash_password(self.password_entry.text())
        
        message = self.auth.register(email, password)
        if "sucesso" in message.lower():
            QMessageBox.information(self, "Sucesso", message)
            self.enable_components(True)  # Habilitar componentes após registro bem-sucedido
        else:
            QMessageBox.warning(self, "Atenção", message)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = EncryptDecryptApp()
    ex.show()
    sys.exit(app.exec())
