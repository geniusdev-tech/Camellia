import sys
import os
import time
import json
import requests
import sqlite3
import hashlib
import shutil
from PySide6.QtWidgets import QApplication, QWidget, QFileDialog, QInputDialog, QDialog, QMessageBox
from PySide6.QtCore import Qt, QDir, QTimer, QUrl, QPoint
from PySide6.QtGui import QShortcut, QKeySequence, QDesktopServices, QPixmap
from dotenv import load_dotenv
from config import organize_files
from cloud_services import CloudServices
from styles import get_styles
from auth import QRCodeDialog, AuthPollingThread
from file_processing import FileProcessorThread, FolderProcessorThread, ConversionSettingsDialog
from utils import create_progress_bar, remove_progress_bar, show_message_box
from ui import setup_ui

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
        self.db_connection = sqlite3.connect("users.db")
        self.db_cursor = self.db_connection.cursor()
        self.old_pos = QPoint()
        
        load_dotenv()
        self.cloud_services = CloudServices(self.log_message)
        self.setAcceptDrops(True)
        self.setWindowFlags(Qt.FramelessWindowHint)
        
        self.init_db()
        setup_ui(self)
        self.create_connections()
        self.create_shortcuts()
        self.disable_file_processing()
        self.apply_styles()
        self.setup_cloud_services()

    def init_db(self):
        """Inicializa o banco de dados para usuários locais."""
        self.db_cursor.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )''')
        self.db_connection.commit()

    def apply_styles(self):
        """Aplica os estilos QSS ao aplicativo."""
        self.setStyleSheet(get_styles())

    def create_shortcuts(self):
        """Configura os atalhos de teclado."""
        QShortcut(QKeySequence('Ctrl+O'), self).activated.connect(self.browse_file)
        QShortcut(QKeySequence('Ctrl+F'), self).activated.connect(self.browse_folder)
        QShortcut(QKeySequence('Ctrl+Q'), self).activated.connect(self.close)
        QShortcut(QKeySequence('Ctrl+R'), self).activated.connect(self.refresh_explorer)

    def create_connections(self):
        """Conecta os sinais e slots dos widgets."""
        # Autenticação
        self.login_button.clicked.connect(self.authenticate_user)
        self.local_login_button.clicked.connect(self.local_login)
        self.local_register_button.clicked.connect(self.local_register)

        # Seleção de arquivos/pastas
        self.browse_file_button.clicked.connect(self.browse_file)
        self.browse_folder_button.clicked.connect(self.browse_folder)

        # Explorador de arquivos
        self.path_selector.currentTextChanged.connect(self.change_explorer_path)
        self.search_bar.textChanged.connect(self.search_files)
        self.file_explorer.clicked.connect(self.on_file_explorer_clicked)
        self.file_explorer.doubleClicked.connect(self.on_file_explorer_double_clicked)
        self.file_explorer.customContextMenuRequested.connect(self.show_context_menu)

        # Processamento
        self.process_button.clicked.connect(self.process)
        self.pause_button.clicked.connect(self.pause_processing)
        self.cancel_button.clicked.connect(self.cancel_processing)
        self.organize_button.clicked.connect(self.organize_files)

        # Nuvem
        self.auth_google_button.clicked.connect(lambda: self.cloud_services.authenticate_google(self, self.auth_google_button, self.google_drive_status))
        self.upload_cloud_button.clicked.connect(self.upload_to_cloud)
        self.download_cloud_button.clicked.connect(self.download_from_cloud)

        # Conversão
        self.conversion_browse_button.clicked.connect(self.browse_conversion_file)
        self.conversion_type_combo.currentTextChanged.connect(self.update_conversion_formats)
        self.conversion_output_browse_button.clicked.connect(self.browse_conversion_output_dir)
        self.conversion_button.clicked.connect(self.convert_file)
        self.conversion_pause_button.clicked.connect(self.pause_conversion)
        self.conversion_cancel_button.clicked.connect(self.cancel_conversion)

        # Log
        self.clear_log_button.clicked.connect(self.clear_log)
        self.view_history_button.clicked.connect(self.view_history)

    def setup_cloud_services(self):
        """Configura os serviços de nuvem."""
        self.cloud_services.setup_cloud_services(
            self.google_drive_status,
            self.dropbox_status,
            self.auth_google_button
        )

    # Métodos de Autenticação
    def is_online(self):
        """Verifica se há conexão com a internet."""
        try:
            requests.get("https://www.google.com", timeout=5)
            return True
        except requests.ConnectionError:
            return False

    def local_login(self):
        """Realiza login local com email e senha."""
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
            show_message_box(self, "Sucesso", f"Bem-vindo, {email} (Login Local)!")
        else:
            show_message_box(self, "Erro", "Credenciais inválidas ou usuário não registrado.", QMessageBox.Warning)

    def local_register(self):
        """Registra um novo usuário local."""
        email, ok1 = QInputDialog.getText(self, "Registrar Local", "Email:")
        if not ok1 or not email:
            return

        password, ok2 = QInputDialog.getText(self, "Registrar Local", "Senha:", QLineEdit.Password)
        if not ok2 or not password:
            return

        if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
            show_message_box(self, "Erro", "A senha deve ter pelo menos 8 caracteres, com uma letra maiúscula e um número.", QMessageBox.Warning)
            return

        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        try:
            self.db_cursor.execute("INSERT INTO users (email, password) VALUES (?, ?)", (email, hashed_password))
            self.db_connection.commit()
            self.log_message(f"Usuário local registrado: {email}")
            show_message_box(self, "Sucesso", "Usuário registrado com sucesso! Faça login agora.")
        except sqlite3.IntegrityError:
            show_message_box(self, "Erro", "Este email já está registrado.", QMessageBox.Warning)

    def authenticate_user(self):
        """Inicia o processo de autenticação com o Google."""
        if not self.is_online():
            self.log_message("Sem conexão com a internet. Use o login local.")
            show_message_box(self, "Offline", "Sem conexão com a internet. Use o login local ou registre-se localmente.", QMessageBox.Warning)
            return

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
            show_message_box(self, "Erro", f"Erro ao iniciar autenticação: {str(e)}. Use o login local se estiver offline.", QMessageBox.Critical)
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
            show_message_box(self, "Sucesso", f"Bem-vindo, {self.user_info['email']}!")
        except Exception as e:
            self.log_message(f"Erro ao processar autenticação: {str(e)}")
            show_message_box(self, "Erro", f"Erro ao processar autenticação: {str(e)}", QMessageBox.Critical)
        finally:
            if self.qr_dialog:
                self.qr_dialog.close()
                self.qr_dialog = None
            if os.path.exists(qr_image_path):
                os.remove(qr_image_path)

    def on_auth_failed(self, error, qr_image_path):
        self.log_message(error)
        show_message_box(self, "Erro", error, QMessageBox.Critical)
        if self.qr_dialog:
            self.qr_dialog.close()
            self.qr_dialog = None
        if os.path.exists(qr_image_path):
            os.remove(qr_image_path)

    def on_polling_stopped(self):
        self.auth_thread = None

    # Métodos de Interface
    def mousePressEvent(self, event):
        if event.button() == Qt.LeftButton:
            self.old_pos = event.globalPosition().toPoint()

    def mouseMoveEvent(self, event):
        if self.old_pos is not None:
            delta = event.globalPosition().toPoint() - self.old_pos
            self.move(self.x() + delta.x(), self.y() + delta.y())
            self.old_pos = event.globalPosition().toPoint()

    def mouseReleaseEvent(self, event):
        self.old_pos = None

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

    # Métodos de Explorador de Arquivos
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
                    q=f"'{query}' in:root -in:trash",
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
                show_message_box(self, "Erro", f"Erro ao renomear: {str(e)}", QMessageBox.Critical)

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
                show_message_box(self, "Erro", f"Erro ao mover: {str(e)}", QMessageBox.Critical)

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
                show_message_box(self, "Erro", f"Erro ao copiar: {str(e)}", QMessageBox.Critical)

    # Métodos de Processamento de Arquivos
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

    def update_progress(self, value, info, path):
        if path in self.progress_bars:
            progress_bar = self.progress_bars[path]
            progress_bar.setValue(value)
            progress_bar.setFormat(f"{os.path.basename(path)}: {info} %p%")

    def process(self):
        if not self.user_info or not self.user_info.get("success"):
            show_message_box(self, "Atenção", "Por favor, faça login primeiro (Google ou Local)!", QMessageBox.Warning)
            return

        file_path = self.file_path_display.text()
        folder_path = self.folder_path_display.text()
        password = self.password_entry.text()
        
        if not (file_path or folder_path):
            show_message_box(self, "Atenção", "Por favor, selecione um arquivo ou pasta!", QMessageBox.Warning)
            return

        if not password:
            show_message_box(self, "Atenção", "Por favor, insira uma senha para criptografia/descriptografia!", QMessageBox.Warning)
            return
        if len(password) < 8:
            show_message_box(self, "Atenção", "A senha deve ter pelo menos 8 caracteres!", QMessageBox.Warning)
            return
        if not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
            show_message_box(self, "Atenção", "A senha deve conter pelo menos uma letra maiúscula e um número!", QMessageBox.Warning)
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
                progress_bar = create_progress_bar(self, fp, self.process_layout, 3)
                self.progress_bars[fp] = progress_bar

                thread = FileProcessorThread(fp, password, self.encrypt_radio.isChecked())
                thread.progressChanged.connect(self.update_progress)
                thread.finishedProcessing.connect(lambda result, p=fp: self.file_processing_finished(result, p))
                thread.logMessage.connect(self.log_message)
                self.worker_threads[fp] = thread
                thread.start()
        elif folder_path:
            progress_bar = create_progress_bar(self, folder_path, self.process_layout, 3)
            self.progress_bars[folder_path] = progress_bar

            thread = FolderProcessorThread(folder_path, password, self.encrypt_radio.isChecked())
            thread.progressChanged.connect(self.update_progress)
            thread.finishedProcessing.connect(lambda result, p=folder_path: self.folder_processing_finished(result, p))
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

    def file_processing_finished(self, result, path):
        if path in self.progress_bars:
            progress_bar = self.progress_bars[path]
            if result["success"]:
                progress_bar.setFormat(f"{os.path.basename(path)}: Concluído com sucesso! 100%")
                show_message_box(self, "Sucesso", result["message"])
            else:
                progress_bar.setFormat(f"{os.path.basename(path)}: Erro: 100%")
                show_message_box(self, "Erro", result["message"], QMessageBox.Critical)
            progress_bar.setValue(100)
            remove_progress_bar(progress_bar, self.progress_bars, path)

        if path in self.worker_threads:
            del self.worker_threads[path]
        self.process_button.setEnabled(True)
        self.upload_cloud_button.setEnabled(True)
        self.save_to_history("Criptografia" if self.encrypt_radio.isChecked() else "Descriptografia", path, "Sucesso" if result["success"] else "Falha")

    def folder_processing_finished(self, result, path):
        if path in self.progress_bars:
            progress_bar = self.progress_bars[path]
            if result["success"]:
                progress_bar.setFormat(f"{os.path.basename(path)}: Concluído com sucesso! 100%")
                show_message_box(self, "Sucesso", result["message"])
            else:
                progress_bar.setFormat(f"{os.path.basename(path)}: Erro: 100%")
                show_message_box(self, "Erro", result["message"], QMessageBox.Critical)
            progress_bar.setValue(100)
            remove_progress_bar(progress_bar, self.progress_bars, path)

        if path in self.worker_threads:
            del self.worker_threads[path]
        self.process_button.setEnabled(True)
        self.upload_cloud_button.setEnabled(True)
        self.save_to_history("Criptografia" if self.encrypt_radio.isChecked() else "Descriptografia", path, "Sucesso" if result["success"] else "Falha")

    def organize_files(self):
        folder_path = self.folder_path_display.text()
        if not folder_path:
            show_message_box(self, "Atenção", "Por favor, selecione uma pasta para organizar!", QMessageBox.Warning)
            return

        reply = QMessageBox.question(self, "Confirmação", f"Deseja organizar os arquivos em {folder_path}?",
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        if reply == QMessageBox.No:
            return

        self.log_message(f"Organizando arquivos em {folder_path}")
        organize_files(folder_path)
        self.log_message(f"Organização concluída em {folder_path}")
        show_message_box(self, "Sucesso", "Arquivos organizados com sucesso!")
        self.save_to_history("Organização", folder_path, "Sucesso")

    # Métodos de Conversão
    def update_conversion_formats(self, conversion_type):
        from conversion import ConversionThread
        self.conversion_format_combo.clear()
        formats = ConversionThread.SUPPORTED_FORMATS.get(conversion_type, {}).get("output", [])
        self.conversion_format_combo.addItems(formats)

    def browse_conversion_file(self):
        from conversion import ConversionThread
        file_path, _ = QFileDialog.getOpenFileName(self, "Selecionar Arquivo para Conversão")
        if file_path:
            self.conversion_input.setText(file_path)
            default_output_dir = os.path.dirname(file_path)
            self.conversion_output_dir.setText(default_output_dir)
            thread = ConversionThread(file_path, "", "")
            file_type, formats = thread.detect_file_type()
            if file_type:
                self.conversion_type_combo.setCurrentText(file_type)
                self.conversion_format_combo.clear()
                self.conversion_format_combo.addItems(formats)
            else:
                show_message_box(self, "Erro", "Formato de arquivo não suportado!", QMessageBox.Warning)

    def browse_conversion_output_dir(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Selecionar Diretório de Saída")
        if dir_path:
            self.conversion_output_dir.setText(dir_path)

    def convert_file(self):
        from conversion import ConversionThread
        input_path = self.conversion_input.text()
        output_dir = self.conversion_output_dir.text()
        output_format = self.conversion_format_combo.currentText()
        conversion_type = self.conversion_type_combo.currentText()

        if not input_path:
            show_message_box(self, "Atenção", "Selecione um arquivo de entrada!", QMessageBox.Warning)
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

        progress_bar = create_progress_bar(self, input_path, self.conversion_layout, self.conversion_layout.count() - 3, "Convertendo... 0%")
        self.conversion_progress_bars[input_path] = progress_bar

        thread = ConversionThread(input_path, output_path, output_format, quality=settings["quality"], bitrate=settings["bitrate"])
        thread.progressChanged.connect(self.update_conversion_progress)
        thread.finishedProcessing.connect(lambda result, p=input_path: self.conversion_finished(result, p))
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

    def conversion_finished(self, result, path):
        if path in self.conversion_progress_bars:
            progress_bar = self.conversion_progress_bars[path]
            if result["success"]:
                progress_bar.setFormat(f"{os.path.basename(path)}: Concluído com sucesso! 100%")
                show_message_box(self, "Sucesso", result["message"])
            else:
                progress_bar.setFormat(f"{os.path.basename(path)}: Erro: 100%")
                show_message_box(self, "Erro", result["message"], QMessageBox.Critical)
            progress_bar.setValue(100)
            remove_progress_bar(progress_bar, self.conversion_progress_bars, path)

        if path in self.conversion_threads:
            del self.conversion_threads[path]
        self.conversion_input.clear()
        self.conversion_output_dir.clear()

    # Métodos de Nuvem
    def upload_to_cloud(self):
        file_path = self.file_path_display.text()
        folder_path = self.folder_path_display.text()
        service = self.cloud_service_combo.currentText()

        if not (file_path or folder_path):
            show_message_box(self, "Atenção", "Selecione um arquivo ou pasta para upload!", QMessageBox.Warning)
            return
        if service == "Selecionar Serviço":
            show_message_box(self, "Atenção", "Selecione um serviço de nuvem!", QMessageBox.Warning)
            return

        target = file_path if file_path else folder_path
        self.log_message(f"Iniciando upload de {target} para {service}")
        try:
            if service == "Google Drive" and self.cloud_services.google_drive_service:
                self.cloud_services.upload_to_google_drive(target)
            elif service == "Dropbox" and self.cloud_services.dropbox_client:
                self.cloud_services.upload_to_dropbox(target)
            self.log_message(f"Upload de {target} para {service} concluído")
            show_message_box(self, "Sucesso", f"Upload para {service} concluído!")
            self.save_to_history("Upload", target, "Sucesso")
        except Exception as e:
            self.log_message(f"Erro ao fazer upload para {service}: {str(e)}")
            show_message_box(self, "Erro", f"Erro ao fazer upload: {str(e)}", QMessageBox.Critical)
            self.save_to_history("Upload", target, "Falha")

    def download_from_cloud(self):
        service = self.cloud_service_combo.currentText()
        if service == "Selecionar Serviço":
            show_message_box(self, "Atenção", "Selecione um serviço de nuvem!", QMessageBox.Warning)
            return

        file_name, ok = QInputDialog.getText(self, "Download da Nuvem", "Digite o nome do arquivo para download:")
        if not ok or not file_name:
            return

        dest_folder = QFileDialog.getExistingDirectory(self, "Selecionar Pasta de Destino")
        if not dest_folder:
            return

        self.log_message(f"Iniciando download de {file_name} de {service}")
        try:
            if service == "Google Drive" and self.cloud_services.google_drive_service:
                self.cloud_services.download_from_google_drive(file_name, dest_folder)
            elif service == "Dropbox" and self.cloud_services.dropbox_client:
                self.cloud_services.download_from_dropbox(file_name, dest_folder)
            self.log_message(f"Download de {file_name} de {service} concluído")
            show_message_box(self, "Sucesso", f"Download de {file_name} concluído!")
            self.save_to_history("Download", file_name, "Sucesso")
        except Exception as e:
            self.log_message(f"Erro ao fazer download de {service}: {str(e)}")
            show_message_box(self, "Erro", f"Erro ao fazer download: {str(e)}", QMessageBox.Critical)
            self.save_to_history("Download", file_name, "Falha")

    # Métodos de Log e Histórico
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
            show_message_box(self, "Histórico", "Nenhum histórico disponível.")
            return
        with open(history_file, "r") as f:
            history = json.load(f)
        history_text = "\n".join([f"[{entry['timestamp']}] {entry['action']} de {entry['target']}: {entry['status']}" for entry in history])
        show_message_box(self, "Histórico de Processos", history_text)

    # Métodos de Controle de Estado
    def disable_file_processing(self):
        self.browse_file_button.setEnabled(False)
        self.browse_folder_button.setEnabled(False)
        self.process_button.setEnabled(False)
        self.upload_cloud_button.setEnabled(False)
        self.download_cloud_button.setEnabled(False)
        self.organize_button.setEnabled(False)
        self.conversion_button.setEnabled(False)

    def enable_file_processing(self):
        self.browse_file_button.setEnabled(True)
        self.browse_folder_button.setEnabled(True)
        self.process_button.setEnabled(True)
        self.upload_cloud_button.setEnabled(True)
        self.download_cloud_button.setEnabled(True)
        self.organize_button.setEnabled(True)
        self.conversion_button.setEnabled(True)

if __name__ == '__main__':
    app = QApplication(sys.argv)
    ex = EncryptDecryptApp()
    ex.show()
    sys.exit(app.exec())