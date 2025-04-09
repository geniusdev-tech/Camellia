import os
import json
import io
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload, MediaIoBaseDownload
import dropbox
from dropbox.exceptions import AuthError
from dotenv import load_dotenv

class CloudServices:
    def __init__(self, log_callback):
        self.google_drive_service = None
        self.dropbox_client = None
        self.log_callback = log_callback
        load_dotenv()

    def setup_cloud_services(self, google_drive_status_label, dropbox_status_label, auth_google_button):
        """Configura os serviços de nuvem e atualiza os status."""
        self.google_drive_status_label = google_drive_status_label
        self.dropbox_status_label = dropbox_status_label
        self.auth_google_button = auth_google_button

        # Verificar Google Drive
        if os.path.exists("credentials.json"):
            self.google_drive_service = self._init_google_drive_service()
            if self.google_drive_service:
                self.google_drive_status_label.setText("Google Drive: Conectado")
                self.google_drive_status_label.setStyleSheet("color: green;")
                self.auth_google_button.setEnabled(False)
            else:
                self.google_drive_status_label.setText("Google Drive: Desconectado")
                self.google_drive_status_label.setStyleSheet("color: red;")
        else:
            self.google_drive_status_label.setText("Google Drive: Desconectado")
            self.google_drive_status_label.setStyleSheet("color: red;")

        # Verificar Dropbox
        dropbox_token = os.getenv("DROPBOX_TOKEN")
        if dropbox_token:
            try:
                self.dropbox_client = dropbox.Dropbox(dropbox_token)
                self.dropbox_status_label.setText("Dropbox: Conectado")
                self.dropbox_status_label.setStyleSheet("color: green;")
            except AuthError as e:
                self.log_callback(f"Erro ao conectar ao Dropbox: {str(e)}")
                self.dropbox_status_label.setText("Dropbox: Desconectado")
                self.dropbox_status_label.setStyleSheet("color: red;")
        else:
            self.dropbox_status_label.setText("Dropbox: Desconectado")
            self.dropbox_status_label.setStyleSheet("color: red;")

    def _init_google_drive_service(self):
        """Inicializa o serviço do Google Drive."""
        try:
            with open("credentials.json", "r") as f:
                creds_data = json.load(f)
            credentials = Credentials(
                token=creds_data["token"],
                refresh_token=creds_data["refresh_token"],
                token_uri=creds_data["token_uri"],
                client_id=creds_data["client_id"],
                client_secret=creds_data["client_secret"],
                scopes=creds_data["scopes"]
            )
            return build("drive", "v3", credentials=credentials)
        except Exception as e:
            self.log_callback(f"Erro ao inicializar Google Drive: {str(e)}")
            return None

    def authenticate_google(self, parent, auth_button, status_label):
        """Autentica o usuário no Google Drive."""
        try:
            flow = InstalledAppFlow.from_client_secrets_file(
                os.getenv("GOOGLE_DRIVE_CREDENTIALS_PATH"),
                scopes=["https://www.googleapis.com/auth/drive.file"]
            )
            credentials = flow.run_local_server(port=0)
            with open("credentials.json", "w") as f:
                json.dump({
                    "token": credentials.token,
                    "refresh_token": credentials.refresh_token,
                    "token_uri": credentials.token_uri,
                    "client_id": credentials.client_id,
                    "client_secret": credentials.client_secret,
                    "scopes": credentials.scopes
                }, f)

            self.google_drive_service = build("drive", "v3", credentials=credentials)
            status_label.setText("Google Drive: Conectado")
            status_label.setStyleSheet("color: green;")
            auth_button.setEnabled(False)
            self.log_callback("Autenticação com Google Drive bem-sucedida.")
        except Exception as e:
            self.log_callback(f"Erro ao autenticar com Google Drive: {str(e)}")
            status_label.setText("Google Drive: Desconectado")
            status_label.setStyleSheet("color: red;")

    def upload_to_google_drive(self, file_path):
        """Faz upload de um arquivo ou pasta para o Google Drive."""
        if not self.google_drive_service:
            raise Exception("Google Drive não está autenticado.")

        if os.path.isfile(file_path):
            file_metadata = {"name": os.path.basename(file_path)}
            media = MediaFileUpload(file_path)
            self.google_drive_service.files().create(
                body=file_metadata,
                media_body=media,
                fields="id"
            ).execute()
        elif os.path.isdir(file_path):
            folder_metadata = {"name": os.path.basename(file_path), "mimeType": "application/vnd.google-apps.folder"}
            folder = self.google_drive_service.files().create(
                body=folder_metadata,
                fields="id"
            ).execute()
            folder_id = folder.get("id")
            for item in os.listdir(file_path):
                item_path = os.path.join(file_path, item)
                if os.path.isfile(item_path):
                    file_metadata = {"name": item, "parents": [folder_id]}
                    media = MediaFileUpload(item_path)
                    self.google_drive_service.files().create(
                        body=file_metadata,
                        media_body=media,
                        fields="id"
                    ).execute()

    def download_from_google_drive(self, file_name, dest_folder):
        """Faz download de um arquivo do Google Drive."""
        if not self.google_drive_service:
            raise Exception("Google Drive não está autenticado.")

        # Procurar o arquivo no Google Drive
        results = self.google_drive_service.files().list(
            q=f"name='{file_name}' and trashed=false",
            fields="files(id, name)"
        ).execute()
        files = results.get("files", [])

        if not files:
            raise Exception(f"Arquivo '{file_name}' não encontrado no Google Drive.")

        file_id = files[0]["id"]
        request = self.google_drive_service.files().get_media(fileId=file_id)
        file_path = os.path.join(dest_folder, file_name)

        with open(file_path, "wb") as f:
            downloader = MediaIoBaseDownload(f, request)
            done = False
            while not done:
                status, done = downloader.next_chunk()
                self.log_callback(f"Download de {file_name}: {int(status.progress() * 100)}% concluído.")

    def upload_to_dropbox(self, file_path):
        """Faz upload de um arquivo ou pasta para o Dropbox."""
        if not self.dropbox_client:
            raise Exception("Dropbox não está autenticado.")

        if os.path.isfile(file_path):
            with open(file_path, "rb") as f:
                self.dropbox_client.files_upload(
                    f.read(),
                    f"/{os.path.basename(file_path)}",
                    mute=True
                )
        elif os.path.isdir(file_path):
            for item in os.listdir(file_path):
                item_path = os.path.join(file_path, item)
                if os.path.isfile(item_path):
                    with open(item_path, "rb") as f:
                        self.dropbox_client.files_upload(
                            f.read(),
                            f"/{os.path.basename(file_path)}/{item}",
                            mute=True
                        )

    def download_from_dropbox(self, file_name, dest_folder):
        """Faz download de um arquivo do Dropbox."""
        if not self.dropbox_client:
            raise Exception("Dropbox não está autenticado.")

        file_path = f"/{file_name}"
        dest_path = os.path.join(dest_folder, file_name)

        try:
            metadata, response = self.dropbox_client.files_download(file_path)
            with open(dest_path, "wb") as f:
                f.write(response.content)
            self.log_callback(f"Download de {file_name} do Dropbox concluído.")
        except dropbox.exceptions.ApiError as e:
            raise Exception(f"Erro ao baixar {file_name} do Dropbox: {str(e)}")