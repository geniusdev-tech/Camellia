import os
import time
import json
import requests
import qrcode
from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QPushButton, QMessageBox
from PySide6.QtCore import QThread, Signal, QPropertyAnimation
from PySide6.QtGui import QPixmap

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