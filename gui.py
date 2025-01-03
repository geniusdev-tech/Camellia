import sys
from PyQt6.QtWidgets import (QApplication, QWidget, QPushButton, QVBoxLayout, QFileDialog, 
                             QLineEdit, QLabel, QRadioButton, QCheckBox, QMessageBox, QFormLayout, QHBoxLayout, QProgressBar)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QShortcut, QKeySequence
from logic import generate_file_hash, encrypt_Camellia, decrypt_Camellia, process_folder

class EncryptDecryptApp(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.createShortcuts()
    
    def createShortcuts(self):
        QShortcut(QKeySequence('Ctrl+O'), self).activated.connect(self.browse_file)
        QShortcut(QKeySequence('Ctrl+Q'), self).activated.connect(self.close)
    
    def initUI(self):
        self.setWindowTitle('Quick Cryptography 1.0')
        self.setGeometry(200, 200, 500, 400)
        
  
        self.file_label = QLabel('Target File:', self)
        self.folder_label = QLabel('Target Folder:', self)
        
        self.file_path_display = QLineEdit(self)
        self.file_path_display.setReadOnly(True)
        
        self.folder_path_display = QLineEdit(self)
        self.folder_path_display.setReadOnly(True)
        
        self.browse_file_button = QPushButton('Browse File', self)
        self.browse_file_button.clicked.connect(self.browse_file)
        
        self.browse_folder_button = QPushButton('Browse Folder', self)
        self.browse_folder_button.clicked.connect(self.browse_folder)
        
        self.encrypt_radio = QRadioButton('Encrypt', self)
        self.decrypt_radio = QRadioButton('Decrypt', self)
        self.encrypt_radio.setChecked(True)
        
        self.password_label = QLabel('Password:', self)
        self.password_entry = QLineEdit(self)
        self.password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        
        self.confirm_password_label = QLabel('Confirm Password:', self)
        self.confirm_password_entry = QLineEdit(self)
        self.confirm_password_entry.setEchoMode(QLineEdit.EchoMode.Password)
        
        self.password_hint_label = QLabel('Password Hint (Optional):', self)
        self.password_hint_entry = QLineEdit(self)
        
        self.erase_file_checkbox = QCheckBox('Erase Target after Encryption', self)
        
        self.process_button = QPushButton('Process', self)
        self.process_button.clicked.connect(self.process)
        
        self.progress_bar = QProgressBar(self)
        self.progress_bar.setGeometry(30, 40, 200, 25)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        
        file_layout = QHBoxLayout()
        file_layout.addWidget(self.file_label)
        file_layout.addWidget(self.file_path_display)
        file_layout.addWidget(self.browse_file_button)
        layout.addLayout(file_layout)
        
        folder_layout = QHBoxLayout()
        folder_layout.addWidget(self.folder_label)
        folder_layout.addWidget(self.folder_path_display)
        folder_layout.addWidget(self.browse_folder_button)
        layout.addLayout(folder_layout)
        
        layout.addWidget(self.encrypt_radio)
        layout.addWidget(self.decrypt_radio)
        
        form_layout = QFormLayout()
        form_layout.addRow(self.password_label, self.password_entry)
        form_layout.addRow(self.confirm_password_label, self.confirm_password_entry)
        form_layout.addRow(self.password_hint_label, self.password_hint_entry)
        layout.addLayout(form_layout)
        
        layout.addWidget(self.erase_file_checkbox)
        layout.addWidget(self.process_button)
        layout.addWidget(self.progress_bar)
        
        self.setLayout(layout)
    
    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Select File')
        if file_path:
            self.file_path_display.setText(file_path)
    
    def browse_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, 'Select Folder')
        if folder_path:
            self.folder_path_display.setText(folder_path)
    
    def update_progress(self, value):
        self.progress_bar.setValue(value)
    
    def process(self):
        file_path = self.file_path_display.text()
        folder_path = self.folder_path_display.text()
        password = self.password_entry.text().encode()
        confirm_password = self.confirm_password_entry.text().encode()
        
        if not (file_path or folder_path):
            QMessageBox.warning(self, "Atenção", "Por favor, selecione um arquivo ou pasta!")
            return
        if not password:
            QMessageBox.warning(self, "Atenção", "Por favor, insira uma senha!")
            return
        if password != confirm_password:
            QMessageBox.warning(self, "Atenção", "As senhas não coincidem!")
            return
        
        if file_path:
            self.process_single_file(file_path, password)
        elif folder_path:
            self.process_single_folder(folder_path, password)
    
    def process_single_file(self, file_path, password):
        if self.encrypt_radio.isChecked():
            with open(file_path, 'rb') as f:
                data = f.read()
            
            salt, iv, ciphertext = encrypt_Camellia(data, password)
            with open(file_path, 'wb') as f:
                f.write(salt + b' ' + iv + b' ' + ciphertext)
            
            if self.erase_file_checkbox.isChecked():
                os.remove(file_path)
            
            file_hash = generate_file_hash(file_path)
            self.update_progress(100)
            QMessageBox.information(self, "Success", f"Arquivo encriptado com sucesso!\nHash: {file_hash}")
        else:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            try:
                salt, iv, ciphertext = data.split(b' ', 2)
            except ValueError:
                QMessageBox.critical(self, "Error", "O arquivo parece estar corrompido ou no formato errado.")
                return
            
            try:
                plaintext = decrypt_Camellia(salt, iv, ciphertext, password)
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Falha na desencriptação: {e}")
                return
            
            with open(file_path, 'wb') as f:
                f.write(plaintext)
            
            file_hash = generate_file_hash(file_path)
            self.update_progress(100)
            QMessageBox.information(self, "Success", f"Arquivo desencriptado com sucesso!\nHash: {file_hash}")
    
    def process_single_folder(self, folder_path, password):
        if self.encrypt_radio.isChecked():
            process_folder(folder_path, password, encrypt=True)
            QMessageBox.information(self, "Success", "Pasta encriptada com sucesso!")
        else:
            process_folder(folder_path, password, encrypt=False)
            QMessageBox.information(self, "Success", "Pasta desencriptada com sucesso!")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = EncryptDecryptApp()
    ex.show()
    sys.exit(app.exec())
