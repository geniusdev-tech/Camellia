import sys
import os
import time
from PySide6.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QFileDialog,
    QLineEdit, QLabel, QRadioButton, QMessageBox, QFormLayout, QProgressBar,
    QGroupBox, QHBoxLayout, QTreeView, QSplitter, QFileSystemModel, QTextEdit,
    QComboBox, QMenu, QInputDialog
)
from PySide6.QtCore import Qt, QThread, Signal, QDir, QTimer, QUrl
from PySide6.QtGui import QIcon, QShortcut, QKeySequence, QDesktopServices, QAction

from config import UserAuth, generate_file_hash, CamelliaCryptor, process_file, process_folder, format_eta
from dotenv import load_dotenv
import dropbox
from pydrive2.auth import GoogleAuth
from pydrive2.drive import GoogleDrive
from dropbox.exceptions import AuthError

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
        
        # Configuração para serviços de nuvem
        load_dotenv()
        self.google_drive_credentials_path = os.getenv("GOOGLE_DRIVE_CREDENTIALS_PATH")
        print(f'caminho: {self.google_drive_credentials_path}')
        self.dropbox_access_token = os.getenv("DROPBOX_ACCESS_TOKEN")
        self.google_drive = None
        self.dropbox_client = None
        
        self.initUI()
        self.createShortcuts()
        self.disable_file_processing()
        self.apply_styles()
        self.setup_file_explorer_context_menu()
        self.setup_cloud_services()

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

    def setup_cloud_services(self):
        # Configurar Google Drive
        try:
            gauth = GoogleAuth()
            # Especificar o caminho do arquivo client_secrets.json
            if not self.google_drive_credentials_path or not os.path.exists(self.google_drive_credentials_path):
                self.log_message("Arquivo client_secrets.json não encontrado. Integração com Google Drive desativada.")
                self.google_drive = None
            else:
                gauth.LoadClientConfigFile(self.google_drive_credentials_path)
                gauth.LocalWebserverAuth()  # Autenticação via navegador
                self.google_drive = GoogleDrive(gauth)
                self.log_message("Conexão com Google Drive estabelecida com sucesso.")
        except Exception as e:
            self.log_message(f"Erro ao conectar ao Google Drive: {str(e)}")
            self.google_drive = None

        # Configurar Dropbox
        if not self.dropbox_access_token:
            self.log_message("Token de acesso do Dropbox não configurado. Integração com Dropbox desativada.")
            self.dropbox_client = None
        else:
            try:
                self.dropbox_client = dropbox.Dropbox(self.dropbox_access_token)
                self.log_message("Conexão com Dropbox estabelecida com sucesso.")
            except AuthError as e:
                self.log_message(f"Erro ao conectar ao Dropbox: {str(e)}")
                self.dropbox_client = None

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

        # Radio buttons para Encrypt/Decrypt
        radio_layout = QHBoxLayout()
        self.encrypt_radio = QRadioButton('Encrypt', self)
        self.decrypt_radio = QRadioButton('Decrypt', self)
        self.encrypt_radio.setChecked(True)
        radio_layout.addWidget(self.encrypt_radio)
        radio_layout.addWidget(self.decrypt_radio)

        # Botão Process
        self.process_button = QPushButton('Process', self)
        self.process_button.clicked.connect(self.process)

        # Barra de progresso
        self.progress_bar = QProgressBar(self)

        # Seção de integração com a nuvem
        cloud_layout = QVBoxLayout()
        cloud_label = QLabel("Cloud Storage:")
        self.cloud_service_combo = QComboBox(self)
        self.cloud_service_combo.addItems(["Select Service", "Google Drive", "Dropbox"])
        cloud_layout.addWidget(cloud_label)
        cloud_layout.addWidget(self.cloud_service_combo)

        # Botões para upload e download
        cloud_buttons_layout = QHBoxLayout()
        self.upload_cloud_button = QPushButton('Upload to Cloud', self)
        self.upload_cloud_button.clicked.connect(self.upload_to_cloud)
        self.upload_cloud_button.setEnabled(False)  # Desativado até que um arquivo seja processado
        self.download_cloud_button = QPushButton('Download from Cloud', self)
        self.download_cloud_button.clicked.connect(self.download_from_cloud)
        cloud_buttons_layout.addWidget(self.upload_cloud_button)
        cloud_buttons_layout.addWidget(self.download_cloud_button)
        cloud_layout.addLayout(cloud_buttons_layout)

        # Adicionar todos os elementos ao layout
        process_layout.addLayout(radio_layout)
        process_layout.addWidget(self.process_button)
        process_layout.addWidget(self.progress_bar)
        process_layout.addLayout(cloud_layout)
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
        self.upload_cloud_button.setEnabled(False)  # Desativar o botão de upload até o processamento terminar
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
            self.upload_cloud_button.setEnabled(True)  # Habilitar o botão de upload
        else:
            QMessageBox.critical(self, "Erro", result["message"])
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("100% - Concluído")

    def folder_processing_finished(self, result: dict):
        self.process_button.setEnabled(True)
        if result["success"]:
            QMessageBox.information(self, "Sucesso", result["message"])
            self.upload_cloud_button.setEnabled(True)  # Habilitar o botão de upload
        else:
            details = "\n".join([f"{r['file']}: {r['message']}" for r in result["results"]])
            QMessageBox.critical(self, "Erro", f"{result['message']}\n\nDetalhes:\n{details}")
        self.progress_bar.setValue(100)
        self.progress_bar.setFormat("100% - Concluído")

    def upload_to_cloud(self):
        if not self.user_info or not self.user_info.get("success"):
            QMessageBox.warning(self, "Atenção", "Por favor, faça login primeiro!")
            return

        file_path = self.file_path_display.text()
        if not file_path:
            QMessageBox.warning(self, "Atenção", "Por favor, processe um arquivo antes de fazer upload!")
            return

        service = self.cloud_service_combo.currentText()
        if service == "Select Service":
            QMessageBox.warning(self, "Atenção", "Por favor, selecione um serviço de nuvem!")
            return

        try:
            if service == "Google Drive" and self.google_drive:
                file_name = os.path.basename(file_path)
                gfile = self.google_drive.CreateFile({'title': file_name})
                gfile.SetContentFile(file_path)
                gfile.Upload()
                self.log_message(f"Arquivo {file_name} enviado para o Google Drive com sucesso.")
                QMessageBox.information(self, "Sucesso", f"Arquivo {file_name} enviado para o Google Drive!")

            elif service == "Dropbox" and self.dropbox_client:
                file_name = os.path.basename(file_path)
                with open(file_path, 'rb') as f:
                    self.dropbox_client.files_upload(f.read(), f"/{file_name}", mute=True)
                self.log_message(f"Arquivo {file_name} enviado para o Dropbox com sucesso.")
                QMessageBox.information(self, "Sucesso", f"Arquivo {file_name} enviado para o Dropbox!")

            else:
                QMessageBox.critical(self, "Erro", f"Serviço {service} não está disponível ou não foi configurado corretamente.")
        except Exception as e:
            self.log_message(f"Erro ao fazer upload para {service}: {str(e)}")
            QMessageBox.critical(self, "Erro", f"Erro ao fazer upload para {service}: {str(e)}")

    def download_from_cloud(self):
        if not self.user_info or not self.user_info.get("success"):
            QMessageBox.warning(self, "Atenção", "Por favor, faça login primeiro!")
            return

        service = self.cloud_service_combo.currentText()
        if service == "Select Service":
            QMessageBox.warning(self, "Atenção", "Por favor, selecione um serviço de nuvem!")
            return

        try:
            if service == "Google Drive" and self.google_drive:
                file_list = self.google_drive.ListFile({'q': "'root' in parents and trashed=false"}).GetList()
                if not file_list:
                    QMessageBox.information(self, "Informação", "Nenhum arquivo encontrado no Google Drive.")
                    return

                # Mostrar uma lista de arquivos para o usuário selecionar
                file_names = [f['title'] for f in file_list]
                file_name, ok = QInputDialog.getItem(self, "Selecionar Arquivo", "Escolha um arquivo para baixar:", file_names, 0, False)
                if ok and file_name:
                    selected_file = next(f for f in file_list if f['title'] == file_name)
                    download_path = os.path.join(QDir.homePath(), file_name)
                    selected_file.GetContentFile(download_path)
                    self.file_path_display.setText(download_path)
                    self.log_message(f"Arquivo {file_name} baixado do Google Drive para {download_path}.")
                    QMessageBox.information(self, "Sucesso", f"Arquivo {file_name} baixado! Você pode agora descriptografá-lo.")

            elif service == "Dropbox" and self.dropbox_client:
                result = self.dropbox_client.files_list_folder("")
                if not result.entries:
                    QMessageBox.information(self, "Informação", "Nenhum arquivo encontrado no Dropbox.")
                    return

                # Mostrar uma lista de arquivos para o usuário selecionar
                file_names = [entry.name for entry in result.entries if isinstance(entry, dropbox.files.FileMetadata)]
                file_name, ok = QInputDialog.getItem(self, "Selecionar Arquivo", "Escolha um arquivo para baixar:", file_names, 0, False)
                if ok and file_name:
                    download_path = os.path.join(QDir.homePath(), file_name)
                    self.dropbox_client.files_download_to_file(download_path, f"/{file_name}")
                    self.file_path_display.setText(download_path)
                    self.log_message(f"Arquivo {file_name} baixado do Dropbox para {download_path}.")
                    QMessageBox.information(self, "Sucesso", f"Arquivo {file_name} baixado! Você pode agora descriptografá-lo.")

            else:
                QMessageBox.critical(self, "Erro", f"Serviço {service} não está disponível ou não foi configurado corretamente.")
        except Exception as e:
            self.log_message(f"Erro ao baixar de {service}: {str(e)}")
            QMessageBox.critical(self, "Erro", f"Erro ao baixar de {service}: {str(e)}")

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
        self.upload_cloud_button.setEnabled(False)
        self.download_cloud_button.setEnabled(False)

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
        self.download_cloud_button.setEnabled(True)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = EncryptDecryptApp()
    ex.show()
    sys.exit(app.exec())