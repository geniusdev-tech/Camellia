import time
from PySide6.QtWidgets import QDialog, QVBoxLayout, QLabel, QSpinBox, QPushButton, QComboBox as QComboBoxWidget
from PySide6.QtCore import QThread, Signal
from config import process_file, process_folder

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