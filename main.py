import sys
import os
import time
from PySide6.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QFileDialog,
    QLineEdit, QLabel, QRadioButton, QMessageBox, QFormLayout, QProgressBar,
    QGroupBox, QHBoxLayout, QTreeView, QSplitter, QFileSystemModel, QTextEdit,
    QComboBox, QMenu
)
from PySide6.QtCore import Qt, QThread, Signal, QDir, QTimer, QUrl
from PySide6.QtGui import QIcon, QShortcut, QKeySequence, QDesktopServices, QAction

from config import UserAuth, generate_file_hash, CamelliaCryptor, process_file, process_folder, format_eta

class FileProcessorThread(QThread):
    progressChanged = Signal(int, str)
    finishedProcessing = Signal(dict)
    logMessage = Signal(str)

    def __init__(self, file_path: str, password: str, encrypt: bool = True, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.password = password
        self.encrypt = encrypt

    def run(self):
        self.logMessage.emit(f"Iniciando {'criptografia' if self.encrypt else 'descriptografia'} de {self.file_path}")
        result = process_file(self.file_path, self.password, self.encrypt, self.progress_callback)
        self.logMessage.emit(result["message"])
        self.finishedProcessing.emit(result)

    def progress_callback(self, percent: int, info: str):
        self.progressChanged.emit(percent, info)

class FolderProcessorThread(QThread):
    progressChanged = Signal(int, str)
    finishedProcessing = Signal(dict)
    logMessage = Signal(str)

    def __init__(self, folder_path: str, password: str, encrypt: bool = True, parent=None):
        super().__init__(parent)
        self.folder_path = folder_path
        self.password = password
        self.encrypt = encrypt

    def run(self):
        self.logMessage.emit(f"Iniciando {'criptografia' if self.encrypt else 'descriptografia'} da pasta {self.folder_path}")
        result = process_folder(self.folder_path, self.password, self.encrypt, self.progress_callback)
        self.logMessage.emit(result["message"])
        self.finishedProcessing.emit(result)

    def progress_callback(self, percent: int, info: str):
        self.progressChanged.emit(percent, info)

class EncryptDecryptApp(QWidget):
    def __init__(self):
        super().__init__()
        try:
            self.auth = UserAuth()
        except ValueError as e:
            QMessageBox.critical(None, "Erro de Configuração", str(e))
            sys.exit(1)
        self.user_info = None
        self.worker_thread = None
        self.recent_paths = []
        self.verification_code = None
        self.initUI()
        self.createShortcuts()
        self.disable_file_processing()
        self.apply_styles()
        self.setup_file_explorer_context_menu()

    def apply_styles(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #1A1A1A;
                color: #E0E0E0;
                font-family: 'Segoe UI', sans-serif;
            }
            QGroupBox {
                border: 1px solid #4A90E2;
                border-radius: 8px;
                margin-top: 15px;
                font-size: 14px;
                color: #4A90E2;
                padding: 10px;
            }
            QPushButton {
                background-color: #2D2D2D;
                color: #FFFFFF;
                border: 1px solid #4A90E2;
                border-radius: 4px;
                padding: 6px;
                font-size: 12px;
                min-width: 100px;
            }
            QPushButton:hover {
                background-color: #4A90E2;
                color: #FFFFFF;
            }
            QLineEdit {
                background-color: #252525;
                color: #FFFFFF;
                border: 1px solid #404040;
                border-radius: 4px;
                padding: 4px;
            }
            QProgressBar {
                border: 1px solid #404040;
                border-radius: 4px;
                background: #252525;
                text-align: center;
                color: #FFFFFF;
            }
            QProgressBar::chunk {
                background-color: #4A90E2;
            }
            QTreeView {
                background-color: #252525;
                color: #FFFFFF;
                border: 1px solid #404040;
                border-radius: 4px;
                padding: 2px;
            }
            QTextEdit {
                background-color: #252525;
                color: #FFFFFF;
                border: 1px solid #404040;
                border-radius: 4px;
            }
            QComboBox {
                background-color: #252525;
                color: #FFFFFF;
                border: 1px solid #404040;
                border-radius: 4px;
                padding: 4px;
            }
            QComboBox:hover {
                border: 1px solid #4A90E2;
            }
        """)

    def createShortcuts(self):
        QShortcut(QKeySequence('Ctrl+O'), self).activated.connect(self.browse_file)
        QShortcut(QKeySequence('Ctrl+F'), self).activated.connect(self.browse_folder)
        QShortcut(QKeySequence('Ctrl+Q'), self).activated.connect(self.close)
        QShortcut(QKeySequence('Ctrl+R'), self).activated.connect(self.refresh_explorer)

    def initUI(self):
        self.setWindowTitle('EnigmaShield')
        self.setGeometry(100, 100, 1500, 700)

        main_layout = QHBoxLayout()

        left_panel = QVBoxLayout()
        left_panel.setSpacing(10)

        auth_group = QGroupBox("Authentication")
        auth_layout = QFormLayout()
        self.email_entry = QLineEdit(self)
        self.password_entry = QLineEdit(self)
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.phone_entry = QLineEdit(self)
        self.phone_entry.setPlaceholderText("+5511999999999")
        self.code_entry = QLineEdit(self)
        self.code_entry.setPlaceholderText("Código SMS")

        auth_button_layout = QHBoxLayout()
        self.register_button = QPushButton('Register', self)
        self.register_button.clicked.connect(self.register)
        self.login_button = QPushButton('Login', self)
        self.login_button.clicked.connect(self.login)
        self.verify_button = QPushButton('Verify Code', self)
        self.verify_button.clicked.connect(self.verify_and_send_code)
        self.verify_button.setEnabled(False)

        auth_button_layout.addWidget(self.register_button)
        auth_button_layout.addWidget(self.login_button)
        auth_button_layout.addWidget(self.verify_button)

        auth_layout.addRow(QLabel('Email:'), self.email_entry)
        auth_layout.addRow(QLabel('Password:'), self.password_entry)
        auth_layout.addRow(QLabel('Phone:'), self.phone_entry)
        auth_layout.addRow(QLabel('Verification Code:'), self.code_entry)
        auth_layout.addRow(auth_button_layout)
        auth_group.setLayout(auth_layout)
        left_panel.addWidget(auth_group)

        selection_group = QGroupBox("Selection")
        selection_layout = QVBoxLayout()
        self.file_path_display = QLineEdit(self)
        self.file_path_display.setReadOnly(True)
        self.browse_file_button = QPushButton('Browse File', self)
        self.browse_file_button.clicked.connect(self.browse_file)
        self.folder_path_display = QLineEdit(self)
        self.folder_path_display.setReadOnly(True)
        self.browse_folder_button = QPushButton('Browse Folder', self)
        self.browse_folder_button.clicked.connect(self.browse_folder)
        selection_layout.addWidget(QLabel('Target File:'))
        selection_layout.addWidget(self.file_path_display)
        selection_layout.addWidget(self.browse_file_button)
        selection_layout.addWidget(QLabel('Target Folder:'))
        selection_layout.addWidget(self.folder_path_display)
        selection_layout.addWidget(self.browse_folder_button)
        selection_group.setLayout(selection_layout)
        left_panel.addWidget(selection_group)
        left_panel.addStretch()

        explorer_layout = QVBoxLayout()
        self.path_selector = QComboBox(self)
        self.path_selector.addItems([QDir.homePath(), QDir.rootPath(), "Recent Locations"])
        self.path_selector.currentTextChanged.connect(self.change_explorer_path)
        self.file_explorer = QTreeView(self)
        self.file_model = QFileSystemModel()
        self.file_model.setRootPath(QDir.homePath())
        self.file_model.setFilter(QDir.NoDotAndDotDot | QDir.AllDirs | QDir.Files)
        self.file_explorer.setModel(self.file_model)
        self.file_explorer.setRootIndex(self.file_model.index(QDir.homePath()))
        self.file_explorer.setColumnWidth(0, 300)
        self.file_explorer.setSortingEnabled(True)
        self.file_explorer.clicked.connect(self.on_file_explorer_clicked)
        self.file_explorer.doubleClicked.connect(self.on_file_explorer_double_clicked)
        explorer_layout.addWidget(self.path_selector)
        explorer_layout.addWidget(self.file_explorer)

        right_panel = QVBoxLayout()
        right_panel.setSpacing(10)

        process_group = QGroupBox("Processing")
        process_layout = QVBoxLayout()
        radio_layout = QHBoxLayout()
        self.encrypt_radio = QRadioButton('Encrypt', self)
        self.decrypt_radio = QRadioButton('Decrypt', self)
        self.encrypt_radio.setChecked(True)
        radio_layout.addWidget(self.encrypt_radio)
        radio_layout.addWidget(self.decrypt_radio)
        self.process_button = QPushButton('Process', self)
        self.process_button.clicked.connect(self.process)
        self.progress_bar = QProgressBar(self)
        process_layout.addLayout(radio_layout)
        process_layout.addWidget(self.process_button)
        process_layout.addWidget(self.progress_bar)
        process_group.setLayout(process_layout)
        right_panel.addWidget(process_group)

        log_group = QGroupBox("Process Log")
        log_layout = QVBoxLayout()
        self.log_display = QTextEdit(self)
        self.log_display.setReadOnly(True)
        log_layout.addWidget(self.log_display)
        log_group.setLayout(log_layout)
        right_panel.addWidget(log_group)
        right_panel.addStretch()

        splitter = QSplitter(Qt.Horizontal)
        left_widget = QWidget()
        left_widget.setLayout(left_panel)
        splitter.addWidget(left_widget)
        explorer_widget = QWidget()
        explorer_widget.setLayout(explorer_layout)
        splitter.addWidget(explorer_widget)
        right_widget = QWidget()
        right_widget.setLayout(right_panel)
        splitter.addWidget(right_widget)
        splitter.setSizes([300, 500, 300])

        main_layout.addWidget(splitter)
        self.setLayout(main_layout)

    def setup_file_explorer_context_menu(self):
        self.file_explorer.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_explorer.customContextMenuRequested.connect(self.show_context_menu)

    def show_context_menu(self, pos):
        index = self.file_explorer.indexAt(pos)
        if not index.isValid():
            return

        path = self.file_model.filePath(index)
        menu = QMenu(self)
        
        open_action = QAction("Open", self)
        open_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(path)))
        menu.addAction(open_action)
        
        if os.path.isfile(path):
            encrypt_action = QAction("Encrypt", self)
            encrypt_action.triggered.connect(lambda: self.quick_process(path, True))
            decrypt_action = QAction("Decrypt", self)
            decrypt_action.triggered.connect(lambda: self.quick_process(path, False))
            menu.addAction(encrypt_action)
            menu.addAction(decrypt_action)
        
        refresh_action = QAction("Refresh", self)
        refresh_action.triggered.connect(self.refresh_explorer)
        menu.addAction(refresh_action)

        menu.exec_(self.file_explorer.viewport().mapToGlobal(pos))

    def quick_process(self, path, encrypt):
        self.file_path_display.setText(path)
        self.encrypt_radio.setChecked(encrypt)
        self.decrypt_radio.setChecked(not encrypt)
        self.process()

    def change_explorer_path(self, path):
        if path == "Recent Locations":
            self.path_selector.clear()
            self.path_selector.addItems([QDir.homePath(), QDir.rootPath()] + self.recent_paths)
            return
        self.file_explorer.setRootIndex(self.file_model.index(path))
        if path not in self.recent_paths and path not in [QDir.homePath(), QDir.rootPath()]:
            self.recent_paths.append(path)
            self.path_selector.addItem(path)

    def refresh_explorer(self):
        current_path = self.file_model.filePath(self.file_explorer.rootIndex())
        self.file_model.setRootPath('')
        QTimer.singleShot(100, lambda: self.file_explorer.setRootIndex(self.file_model.index(current_path)))

    def on_file_explorer_clicked(self, index):
        path = self.file_model.filePath(index)
        if os.path.isfile(path):
            self.file_path_display.setText(path)
            self.folder_path_display.clear()
        elif os.path.isdir(path):
            self.folder_path_display.setText(path)
            self.file_path_display.clear()

    def on_file_explorer_double_clicked(self, index):
        path = self.file_model.filePath(index)
        if os.path.isdir(path):
            self.file_explorer.setRootIndex(self.file_model.index(path))
            self.change_explorer_path(path)

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
        self.log_display.ensureCursorVisible()

    def process(self):
        if not self.user_info or not self.user_info.get("success"):
            QMessageBox.warning(self, "Atenção", "Por favor, faça login primeiro!")
            return

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
            self.worker_thread = FileProcessorThread(file_path, password, self.encrypt_radio.isChecked())
            self.worker_thread.progressChanged.connect(self.update_progress)
            self.worker_thread.finishedProcessing.connect(self.file_processing_finished)
            self.worker_thread.logMessage.connect(self.log_message)
            self.worker_thread.start()
        elif folder_path:
            self.worker_thread = FolderProcessorThread(folder_path, password, self.encrypt_radio.isChecked())
            self.worker_thread.progressChanged.connect(self.update_progress)
            self.worker_thread.finishedProcessing.connect(self.folder_processing_finished)
            self.worker_thread.logMessage.connect(self.log_message)
            self.worker_thread.start()

    def file_processing_finished(self, result: dict):
        self.process_button.setEnabled(True)
        if result["success"]:
            message = f"Arquivo processado com sucesso!\nHash: {result.get('hash', 'N/A')}"
            QMessageBox.information(self, "Sucesso", message)
        else:
            QMessageBox.critical(self, "Erro", result["message"])
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("100% - Concluído")

    def folder_processing_finished(self, result: dict):
        self.process_button.setEnabled(True)
        if result["success"]:
            QMessageBox.information(self, "Sucesso", result["message"])
        else:
            details = "\n".join([f"{r['file']}: {r['message']}" for r in result["results"]])
            QMessageBox.critical(self, "Erro", f"{result['message']}\n\nDetalhes:\n{details}")
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("100% - Concluído")

    def register(self):
        email = self.email_entry.text()
        password = self.password_entry.text()
        phone = self.phone_entry.text()
        
        result = self.auth.register(email, password, phone)
        self.log_message(result["message"])
        if result["success"]:
            QMessageBox.information(self, "Sucesso", result["message"])
            self.verify_button.setEnabled(True)
            self.login_button.setEnabled(False)
            self.register_button.setEnabled(False)
            self.verification_code = self.auth.pending_verifications.get(email, (None, None))[0]
            if self.verification_code:
                self.code_entry.setText(self.verification_code)
        else:
            QMessageBox.warning(self, "Atenção", result["message"])

    def login(self):
        email = self.email_entry.text()
        password = self.password_entry.text()
        
        result = self.auth.login(email, password)
        self.log_message(result["message"])
        
        if result["success"]:
            self.user_info = result
            self.enable_file_processing()
            QMessageBox.information(self, "Sucesso", f"Bem-vindo, {result['user']['email']}!")
            self.verify_button.setEnabled(False)
            self.login_button.setEnabled(True)
            self.register_button.setEnabled(True)
            self.code_entry.clear()
        elif "Conta não verificada" in result["message"]:
            if "Número de telefone não registrado" in result["message"]:
                QMessageBox.critical(self, "Erro", "Número de telefone não registrado. Por favor, registre-se novamente com um número válido.")
            else:
                QMessageBox.warning(self, "Atenção", result["message"])
                self.verify_button.setEnabled(True)
                self.login_button.setEnabled(False)
                self.register_button.setEnabled(False)
                self.verification_code = self.auth.pending_verifications.get(email, (None, None))[0]
                if self.verification_code:
                    self.code_entry.setText(self.verification_code)
        else:
            QMessageBox.critical(self, "Erro", result["message"])

    def verify_and_send_code(self):
        email = self.email_entry.text()
        phone = self.phone_entry.text()
        
        if not email or not phone:
            QMessageBox.warning(self, "Atenção", "Por favor, preencha email e telefone!")
            return

        code = self.code_entry.text()
        if code:
            result = self.auth.verify_code(email, code)
            self.log_message(result["message"])
            
            if result["success"]:
                QMessageBox.information(self, "Sucesso", "Verificação concluída! Por favor, faça login.")
                self.verify_button.setEnabled(False)
                self.login_button.setEnabled(True)
                self.register_button.setEnabled(True)
                self.code_entry.clear()
                return
            else:
                self.log_message("Código inválido, enviando novo SMS...")

        self.verification_code = self.auth.send_verification_sms(phone)
        if self.verification_code:
            self.code_entry.setText(self.verification_code)
            self.log_message(f"Novo código SMS enviado para {phone}")
            QMessageBox.information(self, "Sucesso", "Novo código enviado ao seu telefone!")
        else:
            self.log_message("Falha ao enviar SMS - Verifique as credenciais do Twilio")
            QMessageBox.critical(self, "Erro", "Falha ao enviar SMS de verificação. Verifique as credenciais do Twilio no arquivo .env")

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