import os
import json
import time
import requests
from dotenv import load_dotenv
import dropbox
from dropbox.exceptions import AuthError
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
from PySide6.QtWidgets import QMessageBox, QInputDialog
from PySide6.QtCore import QDir

class CloudServices:
    def __init__(self, log_callback):
        load_dotenv()
        self.google_drive_credentials_path = os.getenv("GOOGLE_DRIVE_CREDENTIALS_PATH")
        self.dropbox_access_token = os.getenv("DROPBOX_ACCESS_TOKEN")
        self.google_drive_service = None
        self.dropbox_client = None
        self.google_credentials = None
        self.log = log_callback  # Callback para logging

    def setup_cloud_services(self, google_status_widget, dropbox_status_widget, auth_google_button):
        # Configurar Google Drive
        if not self.google_drive_credentials_path or not os.path.exists(self.google_drive_credentials_path):
            self.log("Arquivo client_secrets.json não encontrado. Integração com Google Drive desativada.")
            google_status_widget.setText("Google Drive: Desconectado")
            google_status_widget.setStyleSheet("color: red;")
            auth_google_button.setEnabled(False)
        else:
            if os.path.exists("credentials.json"):
                with open("credentials.json", "r") as f:
                    creds_dict = json.load(f)
                    self.google_credentials = Credentials.from_authorized_user_info(creds_dict)
                if self.google_credentials.expired:
                    self.log("Credenciais do Google Drive expiraram. Autentique novamente.")
                    google_status_widget.setText("Google Drive: Desconectado")
                    google_status_widget.setStyleSheet("color: red;")
                else:
                    self.google_drive_service = build("drive", "v3", credentials=self.google_credentials)
                    self.log("Conexão com Google Drive estabelecida com sucesso usando credenciais salvas.")
                    google_status_widget.setText("Google Drive: Conectado")
                    google_status_widget.setStyleSheet("color: green;")
                    auth_google_button.setEnabled(False)
            else:
                google_status_widget.setText("Google Drive: Desconectado")
                google_status_widget.setStyleSheet("color: red;")

        # Configurar Dropbox
        if not self.dropbox_access_token:
            self.log("Token de acesso do Dropbox não configurado. Integração com Dropbox desativada.")
            dropbox_status_widget.setText("Dropbox: Desconectado")
            dropbox_status_widget.setStyleSheet("color: red;")
        else:
            try:
                self.dropbox_client = dropbox.Dropbox(self.dropbox_access_token)
                self.log("Conexão com Dropbox estabelecida com sucesso.")
                dropbox_status_widget.setText("Dropbox: Conectado")
                dropbox_status_widget.setStyleSheet("color: green;")
            except AuthError as e:
                self.log(f"Erro ao conectar ao Dropbox: {str(e)}")
                dropbox_status_widget.setText("Dropbox: Desconectado")
                dropbox_status_widget.setStyleSheet("color: red;")

    def authenticate_google(self, parent, auth_google_button, google_status_widget):
        try:
            with open(self.google_drive_credentials_path, 'r') as f:
                client_config = json.load(f)['installed']
            
            client_id = client_config['client_id']
            client_secret = client_config['client_secret']
            scopes = ["https://www.googleapis.com/auth/drive.file"]

            # Solicitar código de dispositivo
            device_endpoint = "https://oauth2.googleapis.com/device/code"
            device_response = requests.post(device_endpoint, data={
                "client_id": client_id,
                "scope": " ".join(scopes)
            }).json()

            if 'error' in device_response:
                raise Exception(f"Erro ao obter código de dispositivo: {device_response['error_description']}")

            user_code = device_response['user_code']
            verification_url = device_response['verification_url']
            device_code = device_response['device_code']
            interval = device_response['interval']

            self.log(f"Código de autenticação: {user_code}")
            self.log(f"Acesse este URL no seu celular: {verification_url}")
            QMessageBox.information(
                parent, 
                "Autenticação do Google Drive",
                f"1. Acesse este URL no seu celular: {verification_url}\n\n"
                f"2. Insira este código: {user_code}\n\n"
                "3. Você receberá uma notificação no seu dispositivo para confirmar.\n"
                "4. Após confirmar, a autenticação será concluída aqui."
            )

            # Polling para obter o token
            token_endpoint = "https://oauth2.googleapis.com/token"
            while True:
                token_response = requests.post(token_endpoint, data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "device_code": device_code,
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code"
                })
                
                token_data = token_response.json()
                
                if token_response.status_code == 200:
                    self.google_credentials = Credentials(
                        token=token_data["access_token"],
                        refresh_token=token_data.get("refresh_token"),
                        token_uri="https://oauth2.googleapis.com/token",
                        client_id=client_id,
                        client_secret=client_secret,
                        scopes=scopes
                    )
                    break
                elif token_data.get("error") == "authorization_pending":
                    time.sleep(interval)
                    continue
                else:
                    raise Exception(f"Erro na autenticação: {token_data.get('error_description', 'Unknown error')}")

            # Salvar as credenciais
            with open("credentials.json", "w") as f:
                json.dump({
                    "token": self.google_credentials.token,
                    "refresh_token": self.google_credentials.refresh_token,
                    "token_uri": self.google_credentials.token_uri,
                    "client_id": self.google_credentials.client_id,
                    "client_secret": self.google_credentials.client_secret,
                    "scopes": self.google_credentials.scopes
                }, f)

            self.google_drive_service = build("drive", "v3", credentials=self.google_credentials)
            self.log("Conexão com Google Drive estabelecida com sucesso.")
            google_status_widget.setText("Google Drive: Conectado")
            google_status_widget.setStyleSheet("color: green;")
            auth_google_button.setEnabled(False)

        except Exception as e:
            self.log(f"Erro ao autenticar com o Google Drive: {str(e)}")
            QMessageBox.critical(parent, "Erro", f"Erro ao autenticar: {str(e)}")

    def upload_to_cloud(self, file_path, service_name, parent):
        if not file_path:
            QMessageBox.warning(parent, "Atenção", "Por favor, processe um arquivo antes de fazer upload!")
            return

        try:
            if service_name == "Google Drive" and self.google_drive_service:
                file_name = os.path.basename(file_path)
                file_metadata = {"name": file_name}
                media = MediaFileUpload(file_path)
                file = self.google_drive_service.files().create(
                    body=file_metadata, media_body=media, fields="id"
                ).execute()
                self.log(f"Arquivo {file_name} enviado para o Google Drive com sucesso. ID: {file.get('id')}")
                QMessageBox.information(parent, "Sucesso", f"Arquivo {file_name} enviado para o Google Drive!")

            elif service_name == "Dropbox" and self.dropbox_client:
                file_name = os.path.basename(file_path)
                with open(file_path, 'rb') as f:
                    self.dropbox_client.files_upload(f.read(), f"/{file_name}", mute=True)
                self.log(f"Arquivo {file_name} enviado para o Dropbox com sucesso.")
                QMessageBox.information(parent, "Sucesso", f"Arquivo {file_name} enviado para o Dropbox!")

            else:
                raise Exception(f"Serviço {service_name} não está disponível ou não foi configurado corretamente.")
        except Exception as e:
            self.log(f"Erro ao fazer upload para {service_name}: {str(e)}")
            QMessageBox.critical(parent, "Erro", f"Erro ao fazer upload para {service_name}: {str(e)}")

    def download_from_cloud(self, service_name, parent, file_path_callback):
        try:
            if service_name == "Google Drive" and self.google_drive_service:
                results = self.google_drive_service.files().list(
                    q="'root' in parents and trashed=false",
                    fields="files(id, name)"
                ).execute()
                file_list = results.get("files", [])
                if not file_list:
                    QMessageBox.information(parent, "Informação", "Nenhum arquivo encontrado no Google Drive.")
                    return

                file_names = [f["name"] for f in file_list]
                file_name, ok = QInputDialog.getItem(parent, "Selecionar Arquivo", "Escolha um arquivo para baixar:", file_names, 0, False)
                if ok and file_name:
                    file_id = next(f["id"] for f in file_list if f["name"] == file_name)
                    download_path = os.path.join(QDir.homePath(), file_name)
                    request = self.google_drive_service.files().get_media(fileId=file_id)
                    with open(download_path, "wb") as f:
                        downloader = MediaIoBaseDownload(f, request)
                        done = False
                        while not done:
                            status, done = downloader.next_chunk()
                    file_path_callback(download_path)
                    self.log(f"Arquivo {file_name} baixado do Google Drive para {download_path}.")
                    QMessageBox.information(parent, "Sucesso", f"Arquivo {file_name} baixado! Você pode agora descriptografá-lo.")

            elif service_name == "Dropbox" and self.dropbox_client:
                result = self.dropbox_client.files_list_folder("")
                if not result.entries:
                    QMessageBox.information(parent, "Informação", "Nenhum arquivo encontrado no Dropbox.")
                    return

                file_names = [entry.name for entry in result.entries if isinstance(entry, dropbox.files.FileMetadata)]
                file_name, ok = QInputDialog.getItem(parent, "Selecionar Arquivo", "Escolha um arquivo para baixar:", file_names, 0, False)
                if ok and file_name:
                    download_path = os.path.join(QDir.homePath(), file_name)
                    self.dropbox_client.files_download_to_file(download_path, f"/{file_name}")
                    file_path_callback(download_path)
                    self.log(f"Arquivo {file_name} baixado do Dropbox para {download_path}.")
                    QMessageBox.information(parent, "Sucesso", f"Arquivo {file_name} baixado! Você pode agora descriptografá-lo.")

            else:
                raise Exception(f"Serviço {service_name} não está disponível ou não foi configurado corretamente.")
        except Exception as e:
            self.log(f"Erro ao baixar de {service_name}: {str(e)}")
            QMessageBox.critical(parent, "Erro", f"Erro ao baixar de {service_name}: {str(e)}")