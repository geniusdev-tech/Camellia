import sys
import os
import time
import json
import requests
import qrcode
import unittest
import sqlite3
import hashlib
from PySide6.QtWidgets import (
    QApplication, QWidget, QPushButton, QVBoxLayout, QFileDialog,
    QLineEdit, QLabel, QRadioButton, QMessageBox, QFormLayout, QProgressBar,
    QGroupBox, QHBoxLayout, QTreeView, QSplitter, QFileSystemModel, QTextEdit,
    QComboBox, QMenu, QInputDialog, QMenuBar, QDialog, QTabWidget, QSpinBox, QComboBox as QComboBoxWidget
)
from PySide6.QtCore import Qt, QThread, Signal, QDir, QTimer, QUrl, QPropertyAnimation
from PySide6.QtGui import QIcon, QShortcut, QKeySequence, QDesktopServices, QAction, QPixmap
from config import generate_file_hash, CamelliaCryptor, process_file, process_folder, format_eta, organize_files
from cloud_services import CloudServices
from components.conversion import ConversionThread
from dotenv import load_dotenv
import shutil

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
    progressChanged = Signal(int, str, str)
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
        self.progressChanged.emit(percent, info, self.file_path)

    def check_state(self):
        while self.paused and not self.canceled:
            time.sleep(0.1)
        return not self.canceled

class FolderProcessorThread(QThread):
    progressChanged = Signal(int, str, str)
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
        self.progressChanged.emit(percent, info, self.folder_path)

    def check_state(self):
        while self.paused and not self.canceled:
            time.sleep(0.1)
        return not self.canceled

class ConversionSettingsDialog(QDialog):
    def __init__(self, file_type, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configurações de Conversão")
        layout = QVBoxLayout()

        self.quality_spin = None
        self.bitrate_combo = None

        if file_type == "Imagens":
            layout.addWidget(QLabel("Qualidade da Imagem (1-100):"))
            self.quality_spin = QSpinBox(self)
            self.quality_spin.setRange(1, 100)
            self.quality_spin.setValue(85)
            layout.addWidget(self.quality_spin)
        elif file_type == "Áudio":
            layout.addWidget(QLabel("Taxa de Bits (Bitrate):"))
            self.bitrate_combo = QComboBoxWidget(self)
            self.bitrate_combo.addItems(["64k", "128k", "192k", "256k", "320k"])
            self.bitrate_combo.setCurrentText("192k")
            layout.addWidget(self.bitrate_combo)

        self.ok_button = QPushButton("OK", self)
        self.ok_button.clicked.connect(self.accept)
        layout.addWidget(self.ok_button)

        self.cancel_button = QPushButton("Cancelar", self)
        self.cancel_button.clicked.connect(self.reject)
        layout.addWidget(self.cancel_button)

        self.setLayout(layout)

    def get_settings(self):
        return {
            "quality": self.quality_spin.value() if self.quality_spin else None,
            "bitrate": self.bitrate_combo.currentText() if self.bitrate_combo else None
        }

class EncryptDecryptApp(QWidget):
    def __init__(self):
        super().__init__()
        self.user_info = None
        self.worker_threads = {}
        self.progress_bars = {}
        self.conversion_threads = {}
        self.conversion_progress_bars = {}
        self.recent_paths = []
        self.auth_thread = None
        self.qr_dialog = None
        self.progress_animation = None
        self.db_connection = sqlite3.connect("users.db")
        self.db_cursor = self.db_connection.cursor()
        self.init_db()
        
        load_dotenv()
        self.cloud_services = CloudServices(self.log_message)
        self.setAcceptDrops(True)
        self.initUI()
        self.createShortcuts()
        self.disable_file_processing()
        self.apply_styles()
        self.setup_file_explorer_context_menu()
        self.setup_cloud_services()

    def init_db(self):
        self.db_cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )''')
        self.db_connection.commit()

    def apply_styles(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #1A1A1A;
                color: #E0E0E0;
                font-family: 'Segoe UI', sans-serif;
            }
            QTabWidget::pane {
                border: 1px solid #4A90E2;
                background: #252525;
            }
            QTabBar::tab {
                background: #2D2D2D;
                color: #E0E0E0;
                padding: 8px;
                border: 1px solid #404040;
            }
            QTabBar::tab:selected {
                background: #4A90E2;
                color: #FFFFFF;
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
                font-size: 12px;
            }
            QProgressBar::chunk {
                background-color: #4A90E2;
                border-radius: 4px;
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
        self.cloud_services.setup_cloud_services(
            self.google_drive_status,
            self.dropbox_status,
            self.auth_google_button
        )

    def is_online(self):
        try:
            requests.get("https://www.google.com", timeout=5)
            return True
        except requests.ConnectionError:
            return False

    def local_login(self):
        email, ok1 = QInputDialog.getText(self, "Login Local", "Email:")
        if not ok1 or not email:
            return

        password, ok2 = QInputDialog.getText(self, "Login Local", "Senha:", QLineEdit.Password)
        if not ok2 or not password:
            return

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        self.db_cursor.execute("SELECT email FROM users WHERE email=? AND password=?", (email, hashed_password))
        user = self.db_cursor.fetchone()

        if user:
            self.user_info = {"success": True, "email": email, "local": True}
            self.log_message(f"Login local bem-sucedido: {email}")
            self.enable_file_processing()
            self.login_button.setEnabled(False)
            self.local_login_button.setEnabled(False)
            QMessageBox.information(self, "Sucesso", f"Bem-vindo, {email} (Login Local)!")
        else:
            QMessageBox.warning(self, "Erro", "Credenciais inválidas ou usuário não registrado.")

    def local_register(self):
        email, ok1 = QInputDialog.getText(self, "Registrar Local", "Email:")
        if not ok1 or not email:
            return

        password, ok2 = QInputDialog.getText(self, "Registrar Local", "Senha:", QLineEdit.Password)
        if not ok2 or not password:
            return

        if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
            QMessageBox.warning(self, "Erro", "A senha deve ter pelo menos 8 caracteres, com uma letra maiúscula e um número.")
            return

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        try:
            self.db_cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
            self.db_connection.commit()
            self.log_message(f"Usuário local registrado: {email}")
            QMessageBox.information(self, "Sucesso", "Usuário registrado com sucesso! Faça login agora.")
        except sqlite3.IntegrityError:
            QMessageBox.warning(self, "Erro", "Este email já está registrado.")

    def authenticate_user(self):
        if self.is_online():
            try:
                with open(os.getenv("GOOGLE_DRIVE_CREDENTIALS_PATH"), "r") as f:
                    client_secrets = json.load(f)
                    self.client_id = client_secrets["installed"]["client_id"]
                    self.client_secret = client_secrets["installed"]["client_secret"]

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

            except Exception as e:
                self.log_message(f"Erro ao iniciar autenticação com o Google: {str(e)}")
                QMessageBox.critical(self, "Erro", f"Erro ao iniciar autenticação: {str(e)}. Use o login local se estiver offline.")
                if self.qr_dialog:
                    self.qr_dialog.close()
                    self.qr_dialog = None
                if os.path.exists("qrcode.png"):
                    os.remove("qrcode.png")
        else:
            self.log_message("Sem conexão com a internet. Use o login local.")
            QMessageBox.warning(self, "Offline", "Sem conexão com a internet. Use o login local ou registre-se localmente.")

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
            from google.oauth2.credentials import Credentials
            from googleapiclient.discovery import build
            access_token = token_data["access_token"]
            refresh_token = token_data.get("refresh_token")
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
            self.local_login_button.setEnabled(False)
            QMessageBox.information(self, "Sucesso", f"Bem-vindo, {self.user_info['email']}!")
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

    def initUI(self):
        self.setWindowTitle('EnigmaShield - Gerenciador de Arquivos')
        self.setGeometry(100, 100, 1500, 850)

        main_layout = QHBoxLayout()

        left_panel = QVBoxLayout()
        left_panel.setSpacing(10)

        auth_group = QGroupBox("Autenticação")
        auth_layout = QVBoxLayout()
        self.login_button = QPushButton('Login com Google', self)
        self.login_button.clicked.connect(self.authenticate_user)
        self.login_button.setToolTip("Login com Google (Ctrl+G)")
        auth_layout.addWidget(self.login_button)

        self.local_login_button = QPushButton('Login Local', self)
        self.local_login_button.clicked.connect(self.local_login)
        auth_layout.addWidget(self.local_login_button)

        self.local_register_button = QPushButton('Registrar Local', self)
        self.local_register_button.clicked.connect(self.local_register)
        auth_layout.addWidget(self.local_register_button)

        self.theme_button = QPushButton("Alternar Tema", self)
        self.theme_button.setObjectName("themeToggle")
        self.theme_button.clicked.connect(self.toggle_theme)
        auth_layout.addWidget(self.theme_button)
        auth_group.setLayout(auth_layout)
        left_panel.addWidget(auth_group)

        selection_group = QGroupBox("Seleção")
        selection_layout = QVBoxLayout()
        self.file_path_display = QLineEdit(self)
        self.file_path_display.setReadOnly(True)
        self.folder_path_display = QLineEdit(self)
        self.folder_path_display.setReadOnly(True)
        self.browse_file_button = QPushButton('Procurar Arquivo', self)
        self.browse_file_button.setIcon(QIcon.fromTheme("document-open"))
        self.browse_file_button.setToolTip("Selecionar arquivo (Ctrl+O)")
        self.browse_file_button.clicked.connect(self.browse_file)
        self.browse_folder_button = QPushButton('Procurar Pasta', self)
        self.browse_folder_button.setIcon(QIcon.fromTheme("folder-open"))
        self.browse_folder_button.setToolTip("Selecionar pasta (Ctrl+F)")
        self.browse_folder_button.clicked.connect(self.browse_folder)
        selection_layout.addWidget(QLabel('Arquivo Alvo:'))
        selection_layout.addWidget(self.file_path_display)
        selection_layout.addWidget(self.browse_file_button)
        selection_layout.addWidget(QLabel('Pasta Alvo:'))
        selection_layout.addWidget(self.folder_path_display)
        selection_layout.addWidget(self.browse_folder_button)
        selection_group.setLayout(selection_layout)
        left_panel.addWidget(selection_group)
        left_panel.addStretch()

        explorer_layout = QVBoxLayout()
        self.path_selector = QComboBox(self)
        self.path_selector.addItems([QDir.homePath(), QDir.rootPath(), "Locais Recentes"])
        self.path_selector.currentTextChanged.connect(self.change_explorer_path)
        self.search_bar = QLineEdit(self)
        self.search_bar.setPlaceholderText("Pesquisar arquivos (nome, extensão, data)...")
        self.search_bar.textChanged.connect(self.search_files)
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
        explorer_layout.addWidget(self.search_bar)
        explorer_layout.addWidget(self.file_explorer)

        right_panel = QVBoxLayout()
        right_panel.setSpacing(10)

        self.tab_widget = QTabWidget(self)
        right_panel.addWidget(self.tab_widget)

        self.process_tab = QWidget()
        self.process_layout = QVBoxLayout()

        radio_layout = QHBoxLayout()
        self.encrypt_radio = QRadioButton('Criptografar', self)
        self.decrypt_radio = QRadioButton('Descriptografar', self)
        self.encrypt_radio.setChecked(True)
        radio_layout.addWidget(self.encrypt_radio)
        radio_layout.addWidget(self.decrypt_radio)

        self.password_entry = QLineEdit(self)
        self.password_entry.setEchoMode(QLineEdit.Password)
        self.password_entry.setPlaceholderText("Digite a senha (mín. 8 caracteres, 1 maiúscula, 1 número)")

        self.process_button = QPushButton('Processar', self)
        self.process_button.setIcon(QIcon.fromTheme("system-run"))
        self.process_button.setToolTip("Iniciar processamento (Ctrl+P)")
        self.process_button.clicked.connect(self.process)

        control_buttons_layout = QHBoxLayout()
        self.pause_button = QPushButton("Pausar", self)
        self.pause_button.clicked.connect(self.pause_processing)
        self.cancel_button = QPushButton("Cancelar", self)
        self.cancel_button.clicked.connect(self.cancel_processing)
        control_buttons_layout.addWidget(self.pause_button)
        control_buttons_layout.addWidget(self.cancel_button)

        self.organize_button = QPushButton("Organizar Arquivos", self)
        self.organize_button.clicked.connect(self.organize_files)

        cloud_layout = QVBoxLayout()
        cloud_label = QLabel("Armazenamento em Nuvem:")
        self.cloud_service_combo = QComboBox(self)
        self.cloud_service_combo.addItems(["Selecionar Serviço", "Google Drive", "Dropbox"])
        self.google_drive_status = QLabel("Google Drive: Desconectado", self)
        self.google_drive_status.setStyleSheet("color: red;")
        self.dropbox_status = QLabel("Dropbox: Desconectado", self)
        self.dropbox_status.setStyleSheet("color: red;")
        cloud_layout.addWidget(cloud_label)
        cloud_layout.addWidget(self.cloud_service_combo)
        cloud_layout.addWidget(self.google_drive_status)
        cloud_layout.addWidget(self.dropbox_status)

        self.auth_google_button = QPushButton("Autenticar Google Drive", self)
        self.auth_google_button.clicked.connect(lambda: self.cloud_services.authenticate_google(self, self.auth_google_button, self.google_drive_status))
        cloud_layout.addWidget(self.auth_google_button)

        cloud_buttons_layout = QHBoxLayout()
        self.upload_cloud_button = QPushButton('Upload para Nuvem', self)
        self.upload_cloud_button.setIcon(QIcon.fromTheme("go-up"))
        self.upload_cloud_button.clicked.connect(self.upload_to_cloud)
        self.upload_cloud_button.setEnabled(False)
        self.download_cloud_button = QPushButton('Download da Nuvem', self)
        self.download_cloud_button.setIcon(QIcon.fromTheme("go-down"))
        self.download_cloud_button.clicked.connect(self.download_from_cloud)
        cloud_buttons_layout.addWidget(self.upload_cloud_button)
        cloud_buttons_layout.addWidget(self.download_cloud_button)
        cloud_layout.addLayout(cloud_buttons_layout)

        self.process_layout.addLayout(radio_layout)
        self.process_layout.addWidget(QLabel("Senha:"))
        self.process_layout.addWidget(self.password_entry)
        self.process_layout.addWidget(self.process_button)
        self.process_layout.addLayout(control_buttons_layout)
        self.process_layout.addWidget(self.organize_button)
        self.process_layout.addLayout(cloud_layout)
        self.process_tab.setLayout(self.process_layout)
        self.tab_widget.addTab(self.process_tab, "Processamento")

        self.conversion_tab = QWidget()
        self.conversion_layout = QVBoxLayout()

        self.conversion_input = QLineEdit(self)
        self.conversion_input.setReadOnly(True)
        self.conversion_browse_button = QPushButton("Selecionar Arquivo", self)
        self.conversion_browse_button.clicked.connect(self.browse_conversion_file)

        self.conversion_type_combo = QComboBox(self)
        self.conversion_type_combo.addItems(["Imagens", "Documentos", "Áudio"])
        self.conversion_type_combo.currentTextChanged.connect(self.update_conversion_formats)

        self.conversion_format_combo = QComboBox(self)
        self.update_conversion_formats("Imagens")

        self.conversion_output_dir = QLineEdit(self)
        self.conversion_output_dir.setReadOnly(True)
        self.conversion_output_browse_button = QPushButton("Selecionar Diretório de Saída", self)
        self.conversion_output_browse_button.clicked.connect(self.browse_conversion_output_dir)

        self.conversion_button = QPushButton("Converter", self)
        self.conversion_button.clicked.connect(self.convert_file)

        self.conversion_pause_button = QPushButton("Pausar Conversão", self)
        self.conversion_pause_button.clicked.connect(self.pause_conversion)

        self.conversion_cancel_button = QPushButton("Cancelar Conversão", self)
        self.conversion_cancel_button.clicked.connect(self.cancel_conversion)

        self.conversion_layout.addWidget(QLabel("Arquivo de Entrada:"))
        self.conversion_layout.addWidget(self.conversion_input)
        self.conversion_layout.addWidget(self.conversion_browse_button)
        self.conversion_layout.addWidget(QLabel("Tipo de Conversão:"))
        self.conversion_layout.addWidget(self.conversion_type_combo)
        self.conversion_layout.addWidget(QLabel("Formato de Saída:"))
        self.conversion_layout.addWidget(self.conversion_format_combo)
        self.conversion_layout.addWidget(QLabel("Diretório de Saída:"))
        self.conversion_layout.addWidget(self.conversion_output_dir)
        self.conversion_layout.addWidget(self.conversion_output_browse_button)
        self.conversion_layout.addWidget(self.conversion_button)
        self.conversion_layout.addWidget(self.conversion_pause_button)
        self.conversion_layout.addWidget(self.conversion_cancel_button)
        self.conversion_tab.setLayout(self.conversion_layout)
        self.tab_widget.addTab(self.conversion_tab, "Conversão")

        log_group = QGroupBox("Log de Processos")
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

    def update_conversion_formats(self, conversion_type):
        self.conversion_format_combo.clear()
        formats = ConversionThread.SUPPORTED_FORMATS.get(conversion_type, {}).get("output", [])
        self.conversion_format_combo.addItems(formats)

    def browse_conversion_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Selecionar Arquivo para Conversão")
        if file_path:
            self.conversion_input.setText(file_path)
            default_output_dir = os.path.dirname(file_path)
            self.conversion_output_dir.setText(default_output_dir)
            thread = ConversionThread(file_path, "", "")  # Apenas para detecção
            file_type, formats = thread.detect_file_type()
            if file_type:
                self.conversion_type_combo.setCurrentText(file_type)
                self.conversion_format_combo.clear()
                self.conversion_format_combo.addItems(formats)
            else:
                QMessageBox.warning(self, "Erro", "Formato de arquivo não suportado!")

    def browse_conversion_output_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Selecionar Diretório de Saída")
        if dir_path:
            self.conversion_output_dir.setText(dir_path)

    def convert_file(self):
        input_path = self.conversion_input.text()
        output_dir = self.conversion_output_dir.text()
        output_format = self.conversion_format_combo.currentText()
        conversion_type = self.conversion_type_combo.currentText()

        if not input_path:
            QMessageBox.warning(self, "Atenção", "Selecione um arquivo de entrada!")
            return
        if not output_dir:
            output_dir = os.path.dirname(input_path)
            self.conversion_output_dir.setText(output_dir)

        output_filename = f"{os.path.splitext(os.path.basename(input_path))[0]}.{output_format}"
        output_path = os.path.join(output_dir, output_filename)

        reply = QMessageBox.question(self, "Confirmação", f"Converter {input_path} para {output_format} em {output_path}?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.No:
            return

        settings_dialog = ConversionSettingsDialog(conversion_type, self)
        if settings_dialog.exec() == QDialog.Accepted:
            settings = settings_dialog.get_settings()
        else:
            return

        progress_bar = QProgressBar(self)
        progress_bar.setValue(0)
        progress_bar.setMaximum(100)
        progress_bar.setFormat(f"{os.path.basename(input_path)}: Convertendo... 0%")
        self.conversion_layout.insertWidget(self.conversion_layout.count() - 3, progress_bar)
        self.conversion_progress_bars[input_path] = progress_bar
        animation = self.start_progress_animation(progress_bar)

        thread = ConversionThread(input_path, output_path, output_format, quality=settings["quality"], bitrate=settings["bitrate"])
        thread.progressChanged.connect(self.update_conversion_progress)
        thread.finishedProcessing.connect(lambda result, p=input_path, a=animation: self.conversion_finished(result, p, a))
        thread.logMessage.connect(self.log_message)
        self.conversion_threads[input_path] = thread
        thread.start()

    def pause_conversion(self):
        for thread in self.conversion_threads.values():
            thread.pause()
        self.conversion_pause_button.setText("Retomar Conversão")
        self.conversion_pause_button.clicked.disconnect()
        self.conversion_pause_button.clicked.connect(self.resume_conversion)

    def resume_conversion(self):
        for thread in self.conversion_threads.values():
            thread.resume()
        self.conversion_pause_button.setText("Pausar Conversão")
        self.conversion_pause_button.clicked.disconnect()
        self.conversion_pause_button.clicked.connect(self.pause_conversion)

    def cancel_conversion(self):
        for thread in self.conversion_threads.values():
            thread.cancel()

    def update_conversion_progress(self, value, info, path):
        if path in self.conversion_progress_bars:
            progress_bar = self.conversion_progress_bars[path]
            progress_bar.setValue(value)
            progress_bar.setFormat(f"{os.path.basename(path)}: {info}")

    def conversion_finished(self, result, path, animation):
        if path in self.conversion_progress_bars:
            progress_bar = self.conversion_progress_bars[path]
            self.stop_progress_animation(animation)
            if result["success"]:
                progress_bar.setFormat(f"{os.path.basename(path)}: Concluído com sucesso! 100%")
                QMessageBox.information(self, "Sucesso", result["message"])
            else:
                progress_bar.setFormat(f"{os.path.basename(path)}: Erro: 100%")
                QMessageBox.critical(self, "Erro", result["message"])
            progress_bar.setValue(100)
            QTimer.singleShot(2000, lambda: self.remove_conversion_progress_bar(path))

        if path in self.conversion_threads:
            del self.conversion_threads[path]
        self.conversion_input.clear()
        self.conversion_output_dir.clear()

    def remove_conversion_progress_bar(self, path):
        if path in self.conversion_progress_bars:
            progress_bar = self.conversion_progress_bars[path]
            self.conversion_layout.removeWidget(progress_bar)
            progress_bar.deleteLater()
            del self.conversion_progress_bars[path]

    def setup_file_explorer_context_menu(self):
        self.file_explorer.setContextMenuPolicy(Qt.CustomContextMenu)
        self.file_explorer.customContextMenuRequested.connect(self.show_context_menu)

    def show_context_menu(self, pos):
        index = self.file_explorer.indexAt(pos)
        if not index.isValid():
            return

        path = self.file_model.filePath(index)
        menu = QMenu(self)
        
        open_action = QAction("Abrir", self)
        open_action.triggered.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(path)))
        menu.addAction(open_action)
        
        if os.path.isfile(path):
            encrypt_action = QAction("Criptografar", self)
            encrypt_action.triggered.connect(lambda: self.quick_process(path, True))
            decrypt_action = QAction("Descriptografar", self)
            decrypt_action.triggered.connect(lambda: self.quick_process(path, False))
            menu.addAction(encrypt_action)
            menu.addAction(decrypt_action)
            convert_action = QAction("Converter", self)
            convert_action.triggered.connect(lambda: self.quick_convert(path))
            menu.addAction(convert_action)
        
        rename_action = QAction("Renomear", self)
        rename_action.triggered.connect(lambda: self.rename_file(path))
        menu.addAction(rename_action)
        
        move_action = QAction("Mover", self)
        move_action.triggered.connect(lambda: self.move_file(path))
        menu.addAction(move_action)
        
        copy_action = QAction("Copiar", self)
        copy_action.triggered.connect(lambda: self.copy_file(path))
        menu.addAction(copy_action)
        
        refresh_action = QAction("Atualizar", self)
        refresh_action.triggered.connect(self.refresh_explorer)
        menu.addAction(refresh_action)

        menu.exec(self.file_explorer.viewport().mapToGlobal(pos))

    def quick_process(self, path, encrypt):
        self.file_path_display.setText(path)
        self.encrypt_radio.setChecked(encrypt)
        self.decrypt_radio.setChecked(not encrypt)
        self.tab_widget.setCurrentWidget(self.process_tab)
        self.process()

    def quick_convert(self, path):
        self.conversion_input.setText(path)
        self.tab_widget.setCurrentWidget(self.conversion_tab)

    def rename_file(self, path):
        new_name, ok = QInputDialog.getText(self, "Renomear", "Digite o novo nome:", text=os.path.basename(path))
        if ok and new_name:
            try:
                new_path = os.path.join(os.path.dirname(path), new_name)
                os.rename(path, new_path)
                self.log_message(f"Arquivo renomeado de {path} para {new_path}")
                self.refresh_explorer()
            except Exception as e:
                self.log_message(f"Erro ao renomear arquivo: {str(e)}")
                QMessageBox.critical(self, "Erro", f"Erro ao renomear: {str(e)}")

    def move_file(self, path):
        dest_folder = QFileDialog.getExistingDirectory(self, "Selecionar Pasta de Destino")
        if dest_folder:
            try:
                new_path = os.path.join(dest_folder, os.path.basename(path))
                os.rename(path, new_path)
                self.log_message(f"Arquivo movido de {path} para {new_path}")
                self.refresh_explorer()
            except Exception as e:
                self.log_message(f"Erro ao mover arquivo: {str(e)}")
                QMessageBox.critical(self, "Erro", f"Erro ao mover: {str(e)}")

    def copy_file(self, path):
        dest_folder = QFileDialog.getExistingDirectory(self, "Selecionar Pasta de Destino")
        if dest_folder:
            try:
                new_path = os.path.join(dest_folder, os.path.basename(path))
                shutil.copy2(path, new_path)
                self.log_message(f"Arquivo copiado de {path} para {new_path}")
                self.refresh_explorer()
            except Exception as e:
                self.log_message(f"Erro ao copiar arquivo: {str(e)}")
                QMessageBox.critical(self, "Erro", f"Erro ao copiar: {str(e)}")

    def change_explorer_path(self, path):
        if path == "Locais Recentes":
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

    def search_files(self, query):
        if not query:
            self.file_model.setNameFilters([])
            return
        
        terms = query.lower().split()
        name_filter = []
        ext_filter = []
        
        for term in terms:
            something = term.strip()
            if something.startswith("."):
                ext_filter.append(f"*{something}")
            else:
                name_filter.append(f"*{something}*")
        
        if name_filter or ext_filter:
            self.file_model.setNameFilters(name_filter + ext_filter)
        else:
            self.file_model.setNameFilters([])

        if self.cloud_service_combo.currentText() != "Selecionar Serviço":
            self.search_cloud_files(query)

    def search_cloud_files(self, query):
        service = self.cloud_service_combo.currentText()
        try:
            if service == "Google Drive" and self.cloud_services.google_drive_service:
                results = self.cloud_services.google_drive_service.files().list(
                    q=f"{query} in:root -in:trash",
                    fields="files(id, name)"
                ).execute()
                files = results.get("files", [])
                self.log_message(f"Pesquisa no Google Drive encontrou {len(files)} arquivos: {[f['name'] for f in files]}")
            elif service == "Dropbox" and self.cloud_services.dropbox_client:
                results = self.cloud_services.dropbox_client.files_search_v2(query)
                files = [match.metadata.name for match in results.matches]
                self.log_message(f"Pesquisa no Dropbox encontrou {len(files)} arquivos: {files}")
        except Exception as e:
            self.log_message(f"Erro ao pesquisar na nuvem: {str(e)}")

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

    def update_progress(self, value, info, path):
        if path in self.progress_bars:
            progress_bar = self.progress_bars[path]
            progress_bar.setValue(value)
            progress_bar.setFormat(f"{os.path.basename(path)}: {info} %p%")

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

    def start_progress_animation(self, progress_bar):
        animation = QPropertyAnimation(progress_bar, b"windowOpacity")
        animation.setDuration(1000)
        animation.setStartValue(0.5)
        animation.setEndValue(1.0)
        animation.setLoopCount(-1)
        animation.start()
        return animation

    def stop_progress_animation(self, animation):
        if animation:
            animation.stop()

    def process(self):
        if not self.user_info or not self.user_info.get("success"):
            QMessageBox.warning(self, "Atenção", "Por favor, faça login primeiro (Google ou Local)!")
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

        if file_path:
            file_paths = file_path.split("; ")
            for fp in file_paths:
                progress_bar = QProgressBar(self)
                progress_bar.setValue(0)
                progress_bar.setMaximum(100)
                progress_bar.setFormat(f"{os.path.basename(fp)}: Processando... 0%")
                self.process_layout.insertWidget(3, progress_bar)
                self.progress_bars[fp] = progress_bar
                animation = self.start_progress_animation(progress_bar)

                thread = FileProcessorThread(fp, password, self.encrypt_radio.isChecked())
                thread.progressChanged.connect(self.update_progress)
                thread.finishedProcessing.connect(lambda result, p=fp, a=animation: self.file_processing_finished(result, p, a))
                thread.logMessage.connect(self.log_message)
                self.worker_threads[fp] = thread
                thread.start()
        elif folder_path:
            progress_bar = QProgressBar(self)
            progress_bar.setValue(0)
            progress_bar.setMaximum(100)
            progress_bar.setFormat(f"{os.path.basename(folder_path)}: Processando... 0%")
            self.process_layout.insertWidget(3, progress_bar)
            self.progress_bars[folder_path] = progress_bar
            animation = self.start_progress_animation(progress_bar)

            thread = FolderProcessorThread(folder_path, password, self.encrypt_radio.isChecked())
            thread.progressChanged.connect(self.update_progress)
            thread.finishedProcessing.connect(lambda result, p=folder_path, a=animation: self.folder_processing_finished(result, p, a))
            thread.logMessage.connect(self.log_message)
            self.worker_threads[folder_path] = thread
            thread.start()

    def pause_processing(self):
        for thread in self.worker_threads.values():
            thread.pause()
        self.pause_button.setText("Retomar")
        self.pause_button.clicked.disconnect()
        self.pause_button.clicked.connect(self.resume_processing)

    def resume_processing(self):
        for thread in self.worker_threads.values():
            thread.resume()
        self.pause_button.setText("Pausar")
        self.pause_button.clicked.disconnect()
        self.pause_button.clicked.connect(self.pause_processing)

    def cancel_processing(self):
        for thread in self.worker_threads.values():
            thread.cancel()

    def file_processing_finished(self, result: dict, path: str, animation):
        self.process_button.setEnabled(True)
        action = "criptografia" if self.encrypt_radio.isChecked() else "descriptografia"
        status = "Sucesso" if result["success"] else "Falha"
        self.save_to_history(action, path, status)
        
        if path in self.progress_bars:
            progress_bar = self.progress_bars[path]
            self.stop_progress_animation(animation)
            if result["success"]:
                if not self.encrypt_radio.isChecked():
                    original_hash = generate_file_hash(path + ".orig")
                    decrypted_hash = generate_file_hash(path)
                    if original_hash == decrypted_hash:
                        self.log_message("Verificação de integridade: Arquivo descriptografado com sucesso!")
                    else:
                        self.log_message("Verificação de integridade: Arquivo descriptografado não corresponde ao original!")
                progress_bar.setFormat(f"{os.path.basename(path)}: Concluído com sucesso! 100%")
                QMessageBox.information(self, "Sucesso", f"Arquivo {path} processado com sucesso!\nHash: {result.get('hash', 'N/A')}")
                self.upload_cloud_button.setEnabled(True)
            else:
                progress_bar.setFormat(f"{os.path.basename(path)}: Erro: 100%")
                QMessageBox.critical(self, "Erro", result["message"])
            progress_bar.setValue(100)
            QTimer.singleShot(2000, lambda: self.remove_progress_bar(path))

        if path in self.worker_threads:
            del self.worker_threads[path]
        self.password_entry.clear()

    def folder_processing_finished(self, result: dict, path: str, animation):
        self.process_button.setEnabled(True)
        action = "criptografia" if self.encrypt_radio.isChecked() else "descriptografia"
        status = "Sucesso" if result["success"] else "Falha"
        self.save_to_history(action, path, status)
        
        if path in self.progress_bars:
            progress_bar = self.progress_bars[path]
            self.stop_progress_animation(animation)
            if result["success"]:
                progress_bar.setFormat(f"{os.path.basename(path)}: Concluído com sucesso! 100%")
                QMessageBox.information(self, "Sucesso", result["message"])
                self.upload_cloud_button.setEnabled(True)
            else:
                progress_bar.setFormat(f"{os.path.basename(path)}: Erro: 100%")
                details = "\n".join([f"{r['file']}: {r['message']}" for r in result["results"]])
                QMessageBox.critical(self, "Erro", f"{result['message']}\n\nDetalhes:\n{details}")
            progress_bar.setValue(100)
            QTimer.singleShot(2000, lambda: self.remove_progress_bar(path))

        if path in self.worker_threads:
            del self.worker_threads[path]
        self.password_entry.clear()

    def remove_progress_bar(self, path):
        if path in self.progress_bars:
            progress_bar = self.progress_bars[path]
            self.process_layout.removeWidget(progress_bar)
            progress_bar.deleteLater()
            del self.progress_bars[path]

    def upload_to_cloud(self):
        if not self.user_info or not self.user_info.get("success"):
            QMessageBox.warning(self, "Atenção", "Por favor, faça login primeiro!")
            return
        if self.user_info.get("local") and not self.is_online():
            QMessageBox.warning(self, "Atenção", "Upload para a nuvem requer conexão com a internet!")
            return

        file_path = self.file_path_display.text()
        service = self.cloud_service_combo.currentText()
        self.cloud_services.upload_to_cloud(file_path, service, self)

    def download_from_cloud(self):
        if not self.user_info or not self.user_info.get("success"):
            QMessageBox.warning(self, "Atenção", "Por favor, faça login primeiro!")
            return
        if self.user_info.get("local") and not self.is_online():
            QMessageBox.warning(self, "Atenção", "Download da nuvem requer conexão com a internet!")
            return

        service = self.cloud_service_combo.currentText()
        self.cloud_services.download_from_cloud(service, self, self.file_path_display.setText)

    def organize_files(self):
        folder_path = self.folder_path_display.text()
        if not folder_path:
            QMessageBox.warning(self, "Atenção", "Selecione uma pasta para organizar!")
            return
        
        reply = QMessageBox.question(self, "Confirmação", f"Organizar arquivos em {folder_path}?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.Yes:
            result = organize_files(folder_path)
            if result["success"]:
                self.log_message("Arquivos organizados com sucesso!")
                self.refresh_explorer()
            else:
                details = "\n".join([f"{r['file']}: {r.get('message', 'Sucesso')}" for r in result["results"]])
                self.log_message(f"Erro ao organizar alguns arquivos:\n{details}")
                QMessageBox.critical(self, "Erro", f"Erro ao organizar:\n{details}")

    def disable_file_processing(self):
        self.file_path_display.setEnabled(False)
        self.folder_path_display.setEnabled(False)
        self.browse_file_button.setEnabled(False)
        self.browse_folder_button.setEnabled(False)
        self.encrypt_radio.setEnabled(False)
        self.decrypt_radio.setEnabled(False)
        self.password_entry.setEnabled(False)
        self.process_button.setEnabled(False)
        self.file_explorer.setEnabled(False)
        self.upload_cloud_button.setEnabled(False)
        self.download_cloud_button.setEnabled(False)
        self.pause_button.setEnabled(False)
        self.cancel_button.setEnabled(False)
        self.organize_button.setEnabled(False)
        self.conversion_input.setEnabled(False)
        self.conversion_browse_button.setEnabled(False)
        self.conversion_type_combo.setEnabled(False)
        self.conversion_format_combo.setEnabled(False)
        self.conversion_output_dir.setEnabled(False)
        self.conversion_output_browse_button.setEnabled(False)
        self.conversion_button.setEnabled(False)
        self.conversion_cancel_button.setEnabled(False)

    def enable_file_processing(self):
        self.file_path_display.setEnabled(True)
        self.folder_path_display.setEnabled(True)
        self.browse_file_button.setEnabled(True)
        self.browse_folder_button.setEnabled(True)
        self.encrypt_radio.setEnabled(True)
        self.decrypt_radio.setEnabled(True)
        self.password_entry.setEnabled(True)
        self.process_button.setEnabled(True)
        self.file_explorer.setEnabled(True)
        self.download_cloud_button.setEnabled(True)
        self.pause_button.setEnabled(True)
        self.cancel_button.setEnabled(True)
        self.organize_button.setEnabled(True)
        self.conversion_input.setEnabled(True)
        self.conversion_browse_button.setEnabled(True)
        self.conversion_type_combo.setEnabled(True)
        self.conversion_format_combo.setEnabled(True)
        self.conversion_output_dir.setEnabled(True)
        self.conversion_output_browse_button.setEnabled(True)
        self.conversion_button.setEnabled(True)
        self.conversion_cancel_button.setEnabled(True)

    def toggle_theme(self):
        if self.styleSheet().startswith("QWidget { background-color: #1A1A1A;"):
            self.setStyleSheet("""
                QWidget {
                    background-color: #FFFFFF;
                    color: #000000;
                    font-family: 'Segoe UI', sans-serif;
                }
                QTabWidget::pane {
                    border: 1px solid #4A90E2;
                    background: #F0F0F0;
                }
                QTabBar::tab {
                    background: #E0E0E0;
                    color: #000000;
                    padding: 8px;
                    border: 1px solid #404040;
                }
                QTabBar::tab:selected {
                    background: #4A90E2;
                    color: #FFFFFF;
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
                    font-size: 12px;
                }
                QProgressBar::chunk {
                    background-color: #4A90E2;
                    border-radius: 4px;
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
        
        encrypted_file = self.test_file + ".enc"
        self.assertTrue(os.path.exists(encrypted_file), f"Arquivo criptografado {encrypted_file} não foi criado")

        print("Iniciando teste de descriptografia...")
        result_decrypt = process_file(encrypted_file, password, False, lambda p, i: print(f"Progresso: {p}% - {i}"))
        print(f"Resultado da descriptografia: {result_decrypt}")
        self.assertTrue(result_decrypt["success"], f"Falha na descriptografia: {result_decrypt.get('message', 'Mensagem de erro não fornecida')}")
        
        decrypted_file = self.test_file
        self.assertTrue(os.path.exists(decrypted_file), f"Arquivo descriptografado {decrypted_file} não foi criado")

        with open(decrypted_file, "r") as f:
            content = f.read()
        self.assertEqual(content, "Test content", "O conteúdo do arquivo descriptografado não corresponde ao original")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = EncryptDecryptApp()
    ex.show()
    unittest.main(argv=['first-arg-is-ignored'], exit=False)
    sys.exit(app.exec())