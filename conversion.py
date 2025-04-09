import os
from PySide6.QtCore import QThread, Signal
from PIL import Image
from pydub import AudioSegment
import shutil

class ConversionThread(QThread):
    progressChanged = Signal(int, str, str)
    finishedProcessing = Signal(dict)
    logMessage = Signal(str)

    SUPPORTED_FORMATS = {
        "Imagens": {
            "input": [".jpg", ".jpeg", ".png", ".bmp"],
            "output": ["jpg", "png", "bmp"]
        },
        "Documentos": {
            "input": [".txt"],
            "output": ["txt"]
        },
        "Áudio": {
            "input": [".mp3", ".wav"],
            "output": ["mp3", "wav"]
        }
    }

    def __init__(self, input_path: str, output_path: str, output_format: str, quality=None, bitrate=None, parent=None):
        super().__init__(parent)
        self.input_path = input_path
        self.output_path = output_path
        self.output_format = output_format
        self.quality = quality
        self.bitrate = bitrate
        self.paused = False
        self.canceled = False

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False

    def cancel(self):
        self.canceled = True

    def detect_file_type(self):
        """Detecta o tipo de arquivo e retorna os formatos de saída suportados."""
        ext = os.path.splitext(self.input_path)[1].lower()
        for file_type, formats in self.SUPPORTED_FORMATS.items():
            if ext in formats["input"]:
                return file_type, formats["output"]
        return None, []

    def run(self):
        """Executa a conversão do arquivo."""
        try:
            if not os.path.exists(self.input_path):
                self.logMessage.emit(f"Arquivo {self.input_path} não encontrado.")
                self.finishedProcessing.emit({"success": False, "message": f"Arquivo {self.input_path} não encontrado."})
                return

            file_type, _ = self.detect_file_type()
            if not file_type:
                self.logMessage.emit(f"Formato de arquivo não suportado: {self.input_path}")
                self.finishedProcessing.emit({"success": False, "message": "Formato de arquivo não suportado."})
                return

            if file_type == "Imagens":
                self.convert_image()
            elif file_type == "Áudio":
                self.convert_audio()
            elif file_type == "Documentos":
                self.convert_document()
            else:
                self.finishedProcessing.emit({"success": False, "message": "Tipo de conversão não suportado."})
                return

        except Exception as e:
            self.logMessage.emit(f"Erro ao converter arquivo: {str(e)}")
            self.finishedProcessing.emit({"success": False, "message": f"Erro ao converter arquivo: {str(e)}"})

    def convert_image(self):
        """Converte uma imagem para o formato especificado."""
        img = Image.open(self.input_path)
        file_size = os.path.getsize(self.input_path)
        processed_size = 0

        # Simula progresso
        for i in range(1, 101):
            if self.canceled:
                self.finishedProcessing.emit({"success": False, "message": "Conversão cancelada."})
                return
            while self.paused:
                if self.canceled:
                    self.finishedProcessing.emit({"success": False, "message": "Conversão cancelada."})
                    return
                QThread.msleep(100)

            processed_size = (file_size * i) // 100
            self.progressChanged.emit(i, f"Convertendo imagem... {i}%", self.input_path)
            QThread.msleep(50)  # Simula tempo de processamento

        quality = self.quality if self.quality is not None else 85
        if self.output_format == "jpg":
            img = img.convert("RGB")  # Remove canal alfa para JPEG
            img.save(self.output_path, "JPEG", quality=quality)
        else:
            img.save(self.output_path, self.output_format.upper())
        self.finishedProcessing.emit({"success": True, "message": f"Imagem convertida com sucesso para {self.output_path}"})

    def convert_audio(self):
        """Converte um arquivo de áudio para o formato especificado."""
        audio = AudioSegment.from_file(self.input_path)
        file_size = os.path.getsize(self.input_path)
        processed_size = 0

        # Simula progresso
        for i in range(1, 101):
            if self.canceled:
                self.finishedProcessing.emit({"success": False, "message": "Conversão cancelada."})
                return
            while self.paused:
                if self.canceled:
                    self.finishedProcessing.emit({"success": False, "message": "Conversão cancelada."})
                    return
                QThread.msleep(100)

            processed_size = (file_size * i) // 100
            self.progressChanged.emit(i, f"Convertendo áudio... {i}%", self.input_path)
            QThread.msleep(50)  # Simula tempo de processamento

        bitrate = self.bitrate if self.bitrate else "192k"
        audio.export(self.output_path, format=self.output_format, bitrate=bitrate)
        self.finishedProcessing.emit({"success": True, "message": f"Áudio convertido com sucesso para {self.output_path}"})

    def convert_document(self):
        """Converte um documento (simples cópia para este exemplo)."""
        file_size = os.path.getsize(self.input_path)
        processed_size = 0

        # Simula progresso
        for i in range(1, 101):
            if self.canceled:
                self.finishedProcessing.emit({"success": False, "message": "Conversão cancelada."})
                return
            while self.paused:
                if self.canceled:
                    self.finishedProcessing.emit({"success": False, "message": "Conversão cancelada."})
                    return
                QThread.msleep(100)

            processed_size = (file_size * i) // 100
            self.progressChanged.emit(i, f"Convertendo documento... {i}%", self.input_path)
            QThread.msleep(50)  # Simula tempo de processamento

        # Para documentos, apenas copiamos o arquivo (exemplo simplificado)
        shutil.copy(self.input_path, self.output_path)
        self.finishedProcessing.emit({"success": True, "message": f"Documento convertido com sucesso para {self.output_path}"})