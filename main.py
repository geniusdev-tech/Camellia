import sys
import os
import time
import json
import requests
import qrcode
import unittest
import pyotp
from PIL import Image
from PySide6.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QFileDialog,
    QLineEdit, QLabel, QRadioButton, QMessageBox, QFormLayout, QProgressBar,
    QGroupBox, QHBoxLayout, QTreeView, QSplitter, QFileSystemModel, QTextEdit,
    QComboBox, QMenu, QInputDialog, QMenuBar, QDialog
)
from PySide6.QtCore import Qt, QThread, Signal, QDir, QTimer, QUrl, QPropertyAnimation
from PySide6.QtGui import QIcon, QShortcut, QKeySequence, QDesktopServices, QAction, QPixmap
from config import generate_file_hash, CamelliaCryptor, process_file, process_folder, format_eta
from dotenv import load_dotenv
import dropbox
from dropbox.exceptions import AuthError
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
import io

class QRCodeDialog(QDialog):
    def __init__(self, qr_image_path, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Escaneie o QR Code")
        layout = QVBoxLayout()
        
        qr_label = QLabel(self)
        pixmap = QPixmap(qr_image_path)
        if pixmap.isNull():
            QMessageBox.critical(self, "Erro", "Não foi possível carregar o QR code.")
            self.close()
            return
        qr_label.setPixmap(pixmap)
        qr_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(qr_label)
        
        instructions = QLabel("Escaneie o QR code com seu celular para autenticar.")
        instructions.setAlignment(Qt.AlignCenter)
        layout.addWidget(instructions)
        
        self.waiting_label = QLabel("Aguardando autenticação...")
        self.waiting_label.setAlignment(Qt.AlignCenter)
        self.waiting_label.setStyleSheet("color: #4A90E2; font-style: italic;")
        layout.addWidget(self.waiting_label)
        
        cancel_button = QPushButton("Cancelar", self)
        cancel_button.clicked.connect(self.on_cancel)
        cancel_button.setStyleSheet("background-color: #FF5555; color: #FFFFFF; border: 1px solid #FF3333; border-radius: 4px; padding: 6px;")
        layout.addWidget(cancel_button)
        
        self.setLayout(layout)
        
        self.setWindowOpacity(0.0)
        self.animation = QPropertyAnimation(self, b"windowOpacity")
        self.animation.setDuration(500)
        self.animation.setStartValue(0.0)
        self.animation.setEndValue(1.0)
        self.animation.start()

    def on_cancel(self):
        self.animation = QPropertyAnimation(self, b"windowOpacity")
        self.animation.setDuration(500)
        self.animation.setStartValue(1.0)
        self.animation.setEndValue(0.0)
        self.animation.finished.connect(self.reject)
        self.animation.start()

class AuthPollingThread(QThread):
    auth_success = Signal(dict)
    auth_failed = Signal(str)
    polling_stopped = Signal()

    def __init__(self, client_id, client_secret, device_code, interval, timeout=300, parent=None):
        super().__init__(parent)
        self.client_id = client_id
        self.client_secret = client_secret
        self.device_code = device_code
        self.interval = interval
        self.timeout = timeout
        self.running = True
        self.start_time = time.time()

    def run(self):
        token_endpoint = "https://oauth2.googleapis.com/token"
        token_params = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "device_code": self.device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
        }

        while self.running:
            elapsed_time = time.time() - self.start_time
            if elapsed_time > self.timeout:
                self.auth_failed.emit("Tempo de autenticação esgotado. Tente novamente.")
                break

            time.sleep(self.interval)
            token_response = requests.post(token_endpoint, data=token_params)
            token_data = token_response.json()

            if token_response.status_code == 200:
                self.auth_success.emit(token_data)
                break
            elif "error" in token_data:
                error = token_data["error"]
                if error == "authorization_pending":
                    continue
                elif error == "slow_down":
                    self.interval += 1
                    continue
                else:
                    self.auth_failed.emit(f"Erro na autenticação: {error}")
                    break

        self.polling_stopped.emit()

    def stop(self):
        self.running = False

class FileProcessorThread(QThread):
    progressChanged = Signal(int, str)
    finishedProcessing = Signal(dict)
    logMessage = Signal(str)

    def __init__(self, file_path: str, password: str, encrypt: bool = True, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self.password = password
        self.encrypt = encrypt
        self.paused = False
        self.canceled = False

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False

    def cancel(self):
        self.canceled = True

    def run(self):
        self.logMessage.emit(f"Iniciando {'criptografia' if self.encrypt else 'descriptografia'} de {self.file_path}")
        result = process_file(self.file_path, self.password, self.encrypt, self.progress_callback, self.check_state)
        self.logMessage.emit(result["message"])
        self.finishedProcessing.emit(result)

    def progress_callback(self, percent: int, info: str):
        self.progressChanged.emit(percent, info)

    def check_state(self):
        while self.paused and not self.canceled:
            time.sleep(0.1)
        return not self.canceled

class FolderProcessorThread(QThread):
    progressChanged = Signal(int, str)
    finishedProcessing = Signal(dict)
    logMessage = Signal(str)

    def __init__(self, folder_path: str, password: str, encrypt: bool = True, parent=None):
        super().__init__(parent)
        self.folder_path = folder_path
        self.password = password
        self.encrypt = encrypt
        self.paused = False
        self.canceled = False

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False

    def cancel(self):
        self.canceled = True

    def run(self):
        self.logMessage.emit(f"Iniciando {'criptografia' if self.encrypt else 'descriptografia'} da pasta {self.folder_path}")
        result = process_folder(self.folder_path, self.password, self.encrypt, self.progress_callback, self.check_state)
        self.logMessage.emit(result["message"])
        self.finishedProcessing.emit(result)

    def progress_callback(self, percent: int, info: str):
        self.progressChanged.emit(percent, info)

    def check_state(self):
        while self.paused and not self.canceled:
            time.sleep(0.1)
        return not self.canceled

class EncryptDecryptApp(QWidget):
    def __init__(self):
        super().__init__()
        self.user_info = None
        self.worker_thread = None
        self.recent_paths = []
        self.auth_thread = None
        self.qr_dialog = None
        self.totp_secret = None
        
        load_dotenv()
        self.google_drive_credentials_path = os.getenv("GOOGLE_DRIVE_CREDENTIALS_PATH")
        self.dropbox_access_token = os.getenv("DROPBOX_ACCESS_TOKEN")
        self.google_drive_service = None
        self.dropbox_client = None
        self.google_credentials = None
        self.client_id = None
        self.client_secret = None
        
        self.setAcceptDrops(True)
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
            QPushButton#themeToggle {
                background-color: #FFD700;
                color: #000000;
                border: 1px solid #DAA520;
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
        if not self.google_drive_credentials_path or not os.path.exists(self.google_drive_credentials_path):
            self.log_message("Arquivo client_secrets.json não encontrado. Integração com Google Drive desativada.")
            self.google_drive_service = None
            self.google_drive_status.setText("Google Drive: Desconectado")
            self.google_drive_status.setStyleSheet("color: red;")
            self.auth_google_button.setEnabled(False)
        else:
            with open(self.google_drive_credentials_path, "r") as f:
                client_secrets = json.load(f)
                self.client_id = client_secrets["installed"]["client_id"]
                self.client_secret = client_secrets["installed"]["client_secret"]

            if os.path.exists("credentials.json"):
                with open("credentials.json", "r") as f:
                    creds_dict = json.load(f)
                    self.google_credentials = Credentials.from_authorized_user_info(creds_dict)
                if self.google_credentials.expired:
                    self.log_message("Credenciais do Google expiraram. Autentique novamente.")
                    self.google_drive_status.setText("Google Drive: Desconectado")
                    self.google_drive_status.setStyleSheet("color: red;")
                    self.auth_google_button.setEnabled(True)
                else:
                    self.google_drive_service = build("drive", "v3", credentials=self.google_credentials)
                    self.log_message("Conexão com Google Drive estabelecida com sucesso usando credenciais salvas.")
                    self.google_drive_status.setText("Google Drive: Conectado")
                    self.google_drive_status.setStyleSheet("color: green;")
                    self.auth_google_button.setEnabled(False)
                    self.authenticate_user_with_existing_credentials()
            else:
                self.google_drive_status.setText("Google Drive: Desconectado")
                self.google_drive_status.setStyleSheet("color: red;")

        if not self.dropbox_access_token:
            self.log_message("Token de acesso do Dropbox não configurado. Integração com Dropbox desativada.")
            self.dropbox_client = None
            self.dropbox_status.setText("Dropbox: Desconectado")
            self.dropbox_status.setStyleSheet("color: red;")
        else:
            try:
                self.dropbox_client = dropbox.Dropbox(self.dropbox_access_token)
                self.log_message("Conexão com Dropbox estabelecida com sucesso.")
                self.dropbox_status.setText("Dropbox: Conectado")
                self.dropbox_status.setStyleSheet("color: green;")
            except AuthError as e:
                self.log_message(f"Erro ao conectar ao Dropbox: {str(e)}")
                self.dropbox_client = None
                self.dropbox_status.setText("Dropbox: Desconectado")
                self.dropbox_status.setStyleSheet("color: red;")

    def authenticate_user_with_existing_credentials(self):
        try:
            user_info_service = build("oauth2", "v2", credentials=self.google_credentials)
            user_info = user_info_service.userinfo().get().execute()
            self.user_info = {"success": True, "email": user_info.get("email")}
            self.log_message(f"Usuário autenticado automaticamente: {self.user_info['email']}")
            self.enable_file_processing()
            self.login_button.setEnabled(False)
            QMessageBox.information(self, "Sucesso", f"Bem-vindo, {self.user_info['email']}!")
            # Gerar TOTP secreto se não existir
            if not self.totp_secret:
                self.totp_secret = pyotp.random_base32()
                with open("totp_secret.txt", "w") as f:
                    f.write(self.totp_secret)
        except Exception as e:
            self.log_message(f"Erro ao obter informações do usuário: {str(e)}")
            self.user_info = None
            self.login_button.setEnabled(True)

    def authenticate_user(self):
        try:
            device_endpoint = "https://oauth2.googleapis.com/device/code"
            device_params = {
                "client_id": self.client_id,
                "scope": "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/drive.file"
            }
            response = requests.post(device_endpoint, data=device_params)
            response.raise_for_status()
            device_data = response.json()

            user_code = device_data["user_code"]
            verification_url = device_data["verification_url"]
            device_code = device_data["device_code"]
            interval = device_data["interval"]

            qr_url = f"{verification_url}?user_code={user_code}"
            qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=10, border=4)
            qr.add_data(qr_url)
            qr.make(fit=True)
            qr_img = qr.make_image(fill_color="black", back_color="white")
            qr_image_path = "qrcode.png"
            qr_img.save(qr_image_path)

            self.qr_dialog = QRCodeDialog(qr_image_path, self)
            self.qr_dialog.rejected.connect(lambda: self.on_qr_dialog_canceled(qr_image_path))
            self.qr_dialog.show()

            self.log_message("Escaneie o QR code para autenticar.")

            self.auth_thread = AuthPollingThread(self.client_id, self.client_secret, device_code, interval, timeout=300)
            self.auth_thread.auth_success.connect(lambda token_data: self.on_auth_success(token_data, qr_image_path))
            self.auth_thread.auth_failed.connect(lambda error: self.on_auth_failed(error, qr_image_path))
            self.auth_thread.polling_stopped.connect(self.on_polling_stopped)
            self.auth_thread.start()

            # Solicitar 2FA
            if self.totp_secret:
                totp = pyotp.TOTP(self.totp_secret)
                code = QInputDialog.getText(self, "2FA", "Digite o código TOTP gerado no seu aplicativo de autenticação:")[0]
                if not code or not totp.verify(code):
                    QMessageBox.warning(self, "Erro", "Código TOTP inválido. Autenticação falhou.")
                    self.on_qr_dialog_canceled(qr_image_path)
                    return

        except Exception as e:
            self.log_message(f"Erro ao iniciar autenticação com o Google: {str(e)}")
            QMessageBox.critical(self, "Erro", f"Erro ao iniciar autenticação: {str(e)}")
            if self.qr_dialog:
                self.qr_dialog.close()
                self.qr_dialog = None
            if os.path.exists("qrcode.png"):
                os.remove("qrcode.png")

    def on_qr_dialog_canceled(self, qr_image_path):
        if self.auth_thread:
            self.auth_thread.stop()
        self.log_message("Autenticação cancelada pelo usuário.")
        if self.qr_dialog:
            self.qr_dialog.close()
            self.qr_dialog = None
        if os.path.exists(qr_image_path):
            os.remove(qr_image_path)

    def on_auth_success(self, token_data, qr_image_path):
        try:
            access_token = token_data["access_token"]
            refresh_token = token_data.get("refresh_token")
            expires_in = token_data["expires_in"]
            self.google_credentials = Credentials(
                token=access_token,
                refresh_token=refresh_token,
                token_uri="https://oauth2.googleapis.com/token",
                client_id=self.client_id,
                client_secret=self.client_secret,
                scopes=["https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/drive.file"]
            )
            with open("credentials.json", "w") as f:
                json.dump({
                    "token": access_token,
                    "refresh_token": refresh_token,
                    "token_uri": "https://oauth2.googleapis.com/token",
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                    "scopes": ["https://www.googleapis.com/auth/userinfo.email", "https://www.googleapis.com/auth/drive.file"]
                }, f)

            user_info_service = build("oauth2", "v2", credentials=self.google_credentials)
            user_info = user_info_service.userinfo().get().execute()
            self.user_info = {"success": True, "email": user_info.get("email")}
            self.log_message(f"Usuário autenticado: {self.user_info['email']}")
            self.enable_file_processing()
            self.login_button.setEnabled(False)
            QMessageBox.information(self, "Sucesso", f"Bem-vindo, {self.user_info['email']}!")

            self.google_drive_service = build("drive", "v3", credentials=self.google_credentials)
            self.google_drive_status.setText("Google Drive: Conectado")
            self.google_drive_status.setStyleSheet("color: green;")
            self.auth_google_button.setEnabled(False)

        except Exception as e:
            self.log_message(f"Erro ao processar autenticação: {str(e)}")
            QMessageBox.critical(self, "Erro", f"Erro ao processar autenticação: {str(e)}")

        finally:
            if self.qr_dialog:
                self.qr_dialog.close()
                self.qr_dialog = None
            if os.path.exists(qr_image_path):
                os.remove(qr_image_path)

    def on_auth_failed(self, error, qr_image_path):
        self.log_message(error)
        QMessageBox.critical(self, "Erro", error)
        if self.qr_dialog:
            self.qr_dialog.close()
            self.qr_dialog = None
        if os.path.exists(qr_image_path):
            os.remove(qr_image_path)

    def on_polling_stopped(self):
        self.auth_thread = None

    def authenticate_google(self):
        if not self.google_drive_service:
            self.authenticate_user()

    def initUI(self):
        self.setWindowTitle('EnigmaShield')
        self.setGeometry(100, 100, 1500, 850)

        main_layout = QHBoxLayout()

        left_panel = QVBoxLayout()
        left_panel.setSpacing(10)

        auth_group = QGroupBox("Authentication")
        auth_layout = QVBoxLayout()
        self.login_button = QPushButton('Login com Google', self)
        self.login_button.clicked.connect(self.authenticate_user)
        self.login_button.setToolTip("Login com Google (Ctrl+G)")
        auth_layout.addWidget(self.login_button)
        self.theme_button = QPushButton("Alternar Tema", self)
        self.theme_button.setObjectName("themeToggle")
        self.theme_button.clicked.connect(self.toggle_theme)
        auth_layout.addWidget(self.theme_button)
        auth_group.setLayout(auth_layout)
        left_panel.addWidget(auth_group)

        selection_group = QGroupBox("Selection")
        selection_layout = QVBoxLayout()
        self.file_path_display = QLineEdit(self)
        self.file_path_display.setReadOnly(True)
        self.folder_path_display = QLineEdit(self)
        self.folder_path_display.setReadOnly(True)
        self.browse_file_button = QPushButton('Browse File', self)
        self.browse_file_button.setIcon(QIcon.fromTheme("document-open"))
        self.browse_file_button.setToolTip("Selecionar arquivo (Ctrl+O)")
        self.browse_file_button.clicked.connect(self.browse_file)
        self.browse_folder_button = QPushButton('Browse Folder', self)
        self.browse_folder_button.setIcon(QIcon.fromTheme("folder-open"))
        self.browse_folder_button.setToolTip("Selecionar pasta (Ctrl+F)")
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

        self.password_entry = QLineEdit(self)
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.password_entry.setPlaceholderText("Digite a senha (mín. 8 caracteres, 1 maiúscula, 1 número)")

        self.process_button = QPushButton('Process', self)
        self.process_button.setIcon(QIcon.fromTheme("system-run"))
        self.process_button.setToolTip("Iniciar processamento (Ctrl+P)")
        self.process_button.clicked.connect(self.process)

        self.pause_button = QPushButton("Pausar", self)
        self.pause_button.clicked.connect(self.pause_processing)
        self.cancel_button = QPushButton("Cancelar", self)
        self.cancel_button.clicked.connect(self.cancel_processing)

        self.progress_bar = QProgressBar(self)

        cloud_layout = QVBoxLayout()
        cloud_label = QLabel("Cloud Storage:")
        self.cloud_service_combo = QComboBox(self)
        self.cloud_service_combo.addItems(["Select Service", "Google Drive", "Dropbox"])
        self.google_drive_status = QLabel("Google Drive: Desconectado", self)
        self.google_drive_status.setStyleSheet("color: red;")
        self.dropbox_status = QLabel("Dropbox: Desconectado", self)
        self.dropbox_status.setStyleSheet("color: red;")
        cloud_layout.addWidget(cloud_label)
        cloud_layout.addWidget(self.cloud_service_combo)
        cloud_layout.addWidget(self.google_drive_status)
        cloud_layout.addWidget(self.dropbox_status)

        self.auth_google_button = QPushButton("Autenticar Google Drive", self)
        self.auth_google_button.clicked.connect(self.authenticate_google)
        cloud_layout.addWidget(self.auth_google_button)

        cloud_buttons_layout = QHBoxLayout()
        self.upload_cloud_button = QPushButton('Upload to Cloud', self)
        self.upload_cloud_button.setIcon(QIcon.fromTheme("go-up"))
        self.upload_cloud_button.clicked.connect(self.upload_to_cloud)
        self.upload_cloud_button.setEnabled(False)
        self.download_cloud_button = QPushButton('Download from Cloud', self)
        self.download_cloud_button.setIcon(QIcon.fromTheme("go-down"))
        self.download_cloud_button.clicked.connect(self.download_from_cloud)
        cloud_buttons_layout.addWidget(self.upload_cloud_button)
        cloud_buttons_layout.addWidget(self.download_cloud_button)
        cloud_layout.addLayout(cloud_buttons_layout)

        process_layout.addLayout(radio_layout)
        process_layout.addWidget(QLabel("Password:"))
        process_layout.addWidget(self.password_entry)
        process_layout.addWidget(self.process_button)
        process_layout.addWidget(self.pause_button)
        process_layout.addWidget(self.cancel_button)
        process_layout.addWidget(self.progress_bar)
        process_layout.addLayout(cloud_layout)
        process_group.setLayout(process_layout)
        right_panel.addWidget(process_group)

        log_group = QGroupBox("Process Log")
        log_layout = QVBoxLayout()
        self.log_display = QTextEdit(self)
        self.log_display.setReadOnly(True)
        self.clear_log_button = QPushButton("Limpar Log", self)
        self.clear_log_button.clicked.connect(self.clear_log)
        self.view_history_button = QPushButton("Ver Histórico", self)
        self.view_history_button.clicked.connect(self.view_history)
        log_layout.addWidget(self.log_display)
        log_layout.addWidget(self.clear_log_button)
        log_layout.addWidget(self.view_history_button)
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

        menu.exec(self.file_explorer.viewport().mapToGlobal(pos))

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
            if path.endswith(('.txt', '.md')):
                with open(path, 'r', encoding='utf-8') as f:
                    content = f.read()[:500]
                    self.log_display.append(f"Pré-visualização de {path}:\n{content}\n---")
            elif path.endswith(('.png', '.jpg', '.jpeg')):
                pixmap = QPixmap(path)
                if not pixmap.isNull():
                    preview_dialog = QDialog(self)
                    layout = QVBoxLayout()
                    label = QLabel()
                    label.setPixmap(pixmap.scaled(300, 300, Qt.KeepAspectRatio))
                    layout.addWidget(label)
                    preview_dialog.setLayout(layout)
                    preview_dialog.setWindowTitle(f"Pré-visualização de {os.path.basename(path)}")
                    preview_dialog.exec()
        elif os.path.isdir(path):
            self.folder_path_display.setText(path)
            self.file_path_display.clear()

    def on_file_explorer_double_clicked(self, index):
        path = self.file_model.filePath(index)
        if os.path.isdir(path):
            self.file_explorer.setRootIndex(self.file_model.index(path))
            self.change_explorer_path(path)

    def browse_file(self):
        file_paths, _ = QFileDialog.getOpenFileNames(self, 'Selecionar Arquivos')
        if file_paths:
            self.file_path_display.setText("; ".join(file_paths))
            self.folder_path_display.clear()

    def browse_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, 'Selecionar Pasta')
        if folder_path:
            self.folder_path_display.setText(folder_path)
            self.file_path_display.clear()

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if os.path.isfile(path):
                self.file_path_display.setText(path)
                self.folder_path_display.clear()
            elif os.path.isdir(path):
                self.folder_path_display.setText(path)
                self.file_path_display.clear()

    def update_progress(self, value, info):
        self.progress_bar.setValue(value)
        self.progress_bar.setFormat(f"{info} %p%")

    def log_message(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        self.log_display.append(f"[{timestamp}] {message}")
        self.log_display.ensureCursorVisible()

    def clear_log(self):
        self.log_display.clear()
        self.log_message("Log limpo.")

    def save_to_history(self, action, target, status):
        history_entry = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "action": action,
            "target": target,
            "status": status
        }
        history_file = "history.json"
        history = []
        if os.path.exists(history_file):
            with open(history_file, "r") as f:
                history = json.load(f)
        history.append(history_entry)
        with open(history_file, "w") as f:
            json.dump(history, f, indent=4)

    def view_history(self):
        history_file = "history.json"
        if not os.path.exists(history_file):
            QMessageBox.information(self, "Histórico", "Nenhum histórico disponível.")
            return
        with open(history_file, "r") as f:
            history = json.load(f)
        history_text = "\n".join([f"[{entry['timestamp']}] {entry['action']} de {entry['target']}: {entry['status']}" for entry in history])
        QMessageBox.information(self, "Histórico de Processos", history_text)

    def process(self):
        if not self.user_info or not self.user_info.get("success"):
            QMessageBox.warning(self, "Atenção", "Por favor, faça login com o Google primeiro!")
            return

        file_path = self.file_path_display.text()
        folder_path = self.folder_path_display.text()
        password = self.password_entry.text()
        
        if not (file_path or folder_path):
            QMessageBox.warning(self, "Atenção", "Por favor, selecione um arquivo ou pasta!")
            return

        if not password:
            QMessageBox.warning(self, "Atenção", "Por favor, insira uma senha para criptografia/descriptografia!")
            return
        if len(password) < 8:
            QMessageBox.warning(self, "Atenção", "A senha deve ter pelo menos 8 caracteres!")
            return
        if not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
            QMessageBox.warning(self, "Atenção", "A senha deve conter pelo menos uma letra maiúscula e um número!")
            return

        action = "criptografar" if self.encrypt_radio.isChecked() else "descriptografar"
        target = file_path if file_path else folder_path
        reply = QMessageBox.question(self, "Confirmação", f"Deseja {action} {target}?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.No:
            return

        self.process_button.setEnabled(False)
        self.upload_cloud_button.setEnabled(False)
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Processando... 0%")
        
        if file_path:
            file_paths = file_path.split("; ")
            for fp in file_paths:
                self.worker_thread = FileProcessorThread(fp, password, self.encrypt_radio.isChecked())
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

    def pause_processing(self):
        if self.worker_thread:
            self.worker_thread.pause()
            self.pause_button.setText("Retomar")
            self.pause_button.clicked.disconnect()
            self.pause_button.clicked.connect(self.resume_processing)

    def resume_processing(self):
        if self.worker_thread:
            self.worker_thread.resume()
            self.pause_button.setText("Pausar")
            self.pause_button.clicked.disconnect()
            self.pause_button.clicked.connect(self.pause_processing)

    def cancel_processing(self):
        if self.worker_thread:
            self.worker_thread.cancel()

    def file_processing_finished(self, result: dict):
        self.process_button.setEnabled(True)
        action = "criptografia" if self.encrypt_radio.isChecked() else "descriptografia"
        target = self.file_path_display.text()
        status = "Sucesso" if result["success"] else "Falha"
        self.save_to_history(action, target, status)
        if result["success"]:
            if not self.encrypt_radio.isChecked():
                original_hash = generate_file_hash(self.file_path_display.text() + ".orig")
                decrypted_hash = generate_file_hash(self.file_path_display.text())
                if original_hash == decrypted_hash:
                    self.log_message("Verificação de integridade: Arquivo descriptografado com sucesso!")
                else:
                    self.log_message("Verificação de integridade: Arquivo descriptografado não corresponde ao original!")
            message = f"Arquivo processado com sucesso!\nHash: {result.get('hash', 'N/A')}"
            self.progress_bar.setFormat("Concluído com sucesso! 100%")
            QMessageBox.information(self, "Sucesso", message)
            self.upload_cloud_button.setEnabled(True)
        else:
            self.progress_bar.setFormat("Erro: 100%")
            QMessageBox.critical(self, "Erro", result["message"])
        self.progress_bar.setValue(100)
        self.password_entry.clear()

    def folder_processing_finished(self, result: dict):
        self.process_button.setEnabled(True)
        action = "criptografia" if self.encrypt_radio.isChecked() else "descriptografia"
        target = self.folder_path_display.text()
        status = "Sucesso" if result["success"] else "Falha"
        self.save_to_history(action, target, status)
        if result["success"]:
            self.progress_bar.setFormat("Concluído com sucesso! 100%")
            QMessageBox.information(self, "Sucesso", result["message"])
            self.upload_cloud_button.setEnabled(True)
        else:
            self.progress_bar.setFormat("Erro: 100%")
            details = "\n".join([f"{r['file']}: {r['message']}" for r in result["results"]])
            QMessageBox.critical(self, "Erro", f"{result['message']}\n\nDetalhes:\n{details}")
        self.progress_bar.setValue(100)
        self.password_entry.clear()

    def upload_to_cloud(self):
        if not self.user_info or not self.user_info.get("success"):
            QMessageBox.warning(self, "Atenção", "Por favor, faça login com o Google primeiro!")
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
            if service == "Google Drive" and self.google_drive_service:
                file_name = os.path.basename(file_path)
                file_metadata = {"name": file_name}
                media = MediaFileUpload(file_path)
                file = self.google_drive_service.files().create(
                    body=file_metadata, media_body=media, fields="id"
                ).execute()
                self.log_message(f"Arquivo {file_name} enviado para o Google Drive com sucesso. ID: {file.get('id')}")
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
            QMessageBox.warning(self, "Atenção", "Por favor, faça login com o Google primeiro!")
            return

        service = self.cloud_service_combo.currentText()
        if service == "Select Service":
            QMessageBox.warning(self, "Atenção", "Por favor, selecione um serviço de nuvem!")
            return

        try:
            if service == "Google Drive" and self.google_drive_service:
                results = self.google_drive_service.files().list(
                    q="'root' in parents and trashed=false",
                    fields="files(id, name)"
                ).execute()
                file_list = results.get("files", [])
                if not file_list:
                    QMessageBox.information(self, "Informação", "Nenhum arquivo encontrado no Google Drive.")
                    return

                file_names = [f["name"] for f in file_list]
                file_name, ok = QInputDialog.getItem(self, "Selecionar Arquivo", "Escolha um arquivo para baixar:", file_names, 0, False)
                if ok and file_name:
                    file_id = next(f["id"] for f in file_list if f["name"] == file_name)
                    download_path = os.path.join(QDir.homePath(), file_name)
                    request = self.google_drive_service.files().get_media(fileId=file_id)
                    with open(download_path, "wb") as f:
                        downloader = MediaIoBaseDownload(f, request)
                        done = False
                        while not done:
                            status, done = downloader.next_chunk()
                    self.file_path_display.setText(download_path)
                    self.log_message(f"Arquivo {file_name} baixado do Google Drive para {download_path}.")
                    QMessageBox.information(self, "Sucesso", f"Arquivo {file_name} baixado! Você pode agora descriptografá-lo.")

            elif service == "Dropbox" and self.dropbox_client:
                result = self.dropbox_client.files_list_folder("")
                if not result.entries:
                    QMessageBox.information(self, "Informação", "Nenhum arquivo encontrado no Dropbox.")
                    return

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

    def disable_file_processing(self):
        self.file_path_display.setEnabled(False)
        self.folder_path_display.setEnabled(False)
        self.browse_file_button.setEnabled(False)
        self.browse_folder_button.setEnabled(False)
        self.encrypt_radio.setEnabled(False)
        self.decrypt_radio.setEnabled(False)
        self.password_entry.setEnabled(False)
        self.process_button.setEnabled(False)
        self.progress_bar.setEnabled(False)
        self.file_explorer.setEnabled(False)
        self.upload_cloud_button.setEnabled(False)
        self.download_cloud_button.setEnabled(False)
        self.pause_button.setEnabled(False)
        self.cancel_button.setEnabled(False)

    def enable_file_processing(self):
        self.file_path_display.setEnabled(True)
        self.folder_path_display.setEnabled(True)
        self.browse_file_button.setEnabled(True)
        self.browse_folder_button.setEnabled(True)
        self.encrypt_radio.setEnabled(True)
        self.decrypt_radio.setEnabled(True)
        self.password_entry.setEnabled(True)
        self.process_button.setEnabled(True)
        self.progress_bar.setEnabled(True)
        self.file_explorer.setEnabled(True)
        self.download_cloud_button.setEnabled(True)
        self.pause_button.setEnabled(True)
        self.cancel_button.setEnabled(True)

    def toggle_theme(self):
        if self.styleSheet().startswith("QWidget { background-color: #1A1A1A;"):
            self.setStyleSheet("""
                QWidget {
                    background-color: #FFFFFF;
                    color: #000000;
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
                    background-color: #E0E0E0;
                    color: #000000;
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
                QPushButton#themeToggle {
                    background-color: #FFD700;
                    color: #000000;
                    border: 1px solid #DAA520;
                }
                QLineEdit {
                    background-color: #F0F0F0;
                    color: #000000;
                    border: 1px solid #404040;
                    border-radius: 4px;
                    padding: 4px;
                }
                QProgressBar {
                    border: 1px solid #404040;
                    border-radius: 4px;
                    background: #F0F0F0;
                    text-align: center;
                    color: #000000;
                }
                QProgressBar::chunk {
                    background-color: #4A90E2;
                }
                QTreeView {
                    background-color: #F0F0F0;
                    color: #000000;
                    border: 1px solid #404040;
                    border-radius: 4px;
                    padding: 2px;
                }
                QTextEdit {
                    background-color: #F0F0F0;
                    color: #000000;
                    border: 1px solid #404040;
                    border-radius: 4px;
                }
                QComboBox {
                    background-color: #F0F0F0;
                    color: #000000;
                    border: 1px solid #404040;
                    border-radius: 4px;
                    padding: 4px;
                }
                QComboBox:hover {
                    border: 1px solid #4A90E2;
                }
            """)
        else:
            self.apply_styles()

class TestEncryption(unittest.TestCase):
    def setUp(self):
        self.test_file = "test.txt"
        with open(self.test_file, "w") as f:
            f.write("Test content")

    def tearDown(self):
        for ext in ["", ".enc", ".tmp", ".orig"]:
            file_path = self.test_file + ext
            if os.path.exists(file_path):
                os.remove(file_path)

    def test_encrypt_decrypt(self):
        password = "Test1234!"
        print("Iniciando teste de criptografia...")
        result_encrypt = process_file(self.test_file, password, True, lambda p, i: print(f"Progresso: {p}% - {i}"))
        print(f"Resultado da criptografia: {result_encrypt}")
        self.assertTrue(result_encrypt["success"], f"Falha na criptografia: {result_encrypt.get('message', 'Mensagem de erro não fornecida')}")
        
        # Verificar se o arquivo criptografado existe
        encrypted_file = self.test_file + ".enc"
        self.assertTrue(os.path.exists(encrypted_file), f"Arquivo criptografado {encrypted_file} não foi criado")

        print("Iniciando teste de descriptografia...")
        result_decrypt = process_file(encrypted_file, password, False, lambda p, i: print(f"Progresso: {p}% - {i}"))
        print(f"Resultado da descriptografia: {result_decrypt}")
        self.assertTrue(result_decrypt["success"], f"Falha na descriptografia: {result_decrypt.get('message', 'Mensagem de erro não fornecida')}")
        
        # Verificar se o arquivo descriptografado existe
        decrypted_file = self.test_file
        self.assertTrue(os.path.exists(decrypted_file), f"Arquivo descriptografado {decrypted_file} não foi criado")

        with open(decrypted_file, "r") as f:
            content = f.read()
        self.assertEqual(content, "Test content", "O conteúdo do arquivo descriptografado não corresponde ao original")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = EncryptDecryptApp()
    ex.show()
    # Executar testes unitários
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
    sys.exit(app.exec())