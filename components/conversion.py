import os
import time
from PySide6.QtCore import QThread, Signal
from PIL import Image
import pypandoc
from pydub import AudioSegment
from pydub.exceptions import CouldntDecodeError
import mimetypes
import shutil

class ConversionThread(QThread):
    progressChanged = Signal(int, str, str)
    finishedProcessing = Signal(dict)
    logMessage = Signal(str)

    SUPPORTED_FORMATS = {
        "Imagens": {
            "input": ['.png', '.jpg', '.jpeg', '.webp', '.bmp', '.gif', '.tiff'],
            "output": ['png', 'jpg', 'webp', 'bmp', 'gif', 'tiff']
        },
        "Documentos": {
            "input": ['.docx', '.pdf', '.md', '.txt', '.odt', '.rtf', '.html'],
            "output": ['docx', 'pdf', 'md', 'txt', 'odt', 'rtf', 'html']
        },
        "Áudio": {
            "input": ['.mp3', '.wav', '.ogg', '.flac', '.aac', '.m4a'],
            "output": ['mp3', 'wav', 'ogg', 'flac', 'aac', 'm4a']
        }
    }

    def __init__(self, input_path: str, output_path: str, output_format: str, quality=None, bitrate=None, parent=None):
        super().__init__(parent)
        self.input_path = input_path
        self.output_path = output_path
        self.output_format = output_format
        self.quality = quality  # Para imagens
        self.bitrate = bitrate  # Para áudio
        self.canceled = False
        self.paused = False

    def pause(self):
        self.paused = True
        self.logMessage.emit(f"Conversão pausada: {self.input_path}")

    def resume(self):
        self.paused = False
        self.logMessage.emit(f"Conversão retomada: {self.input_path}")

    def cancel(self):
        self.canceled = True
        self.logMessage.emit(f"Conversão cancelada: {self.input_path}")
        if os.path.exists(self.output_path):
            os.remove(self.output_path)  # Limpeza ao cancelar

    def check_state(self):
        while self.paused and not self.canceled:
            time.sleep(0.1)
        return not self.canceled

    def run(self):
        self.logMessage.emit(f"Iniciando conversão de {self.input_path} para {self.output_format}")
        try:
            ext = os.path.splitext(self.input_path)[1].lower()
            file_type, _ = self.detect_file_type()
            if file_type == "Imagens":
                self.convert_image()
            elif file_type == "Documentos":
                if not self.check_pandoc():
                    raise RuntimeError("Pandoc não está instalado. Instale-o para converter documentos.")
                self.convert_document()
            elif file_type == "Áudio":
                if not self.check_ffmpeg():
                    raise RuntimeError("FFmpeg não está instalado. Instale-o para converter áudio.")
                self.convert_audio()
            else:
                raise ValueError(f"Formato de entrada não suportado: {ext}")
            if not self.canceled:
                self.finishedProcessing.emit({"success": True, "message": f"Conversão concluída: {self.output_path}"})
        except FileNotFoundError:
            self.finishedProcessing.emit({"success": False, "message": f"Arquivo {self.input_path} não encontrado"})
        except PermissionError:
            self.finishedProcessing.emit({"success": False, "message": "Permissão negada para acessar o arquivo"})
        except pypandoc.PandocError as e:
            self.finishedProcessing.emit({"success": False, "message": f"Erro no Pandoc: {str(e)}"})
        except CouldntDecodeError:
            self.finishedProcessing.emit({"success": False, "message": "Erro ao decodificar áudio. Verifique o FFmpeg."})
        except Exception as e:
            self.finishedProcessing.emit({"success": False, "message": f"Erro inesperado na conversão: {str(e)}"})
            if os.path.exists(self.output_path):
                os.remove(self.output_path)

    def detect_file_type(self):
        mime_type, _ = mimetypes.guess_type(self.input_path)
        ext = os.path.splitext(self.input_path)[1].lower()
        if mime_type:
            if mime_type.startswith("image/") or ext in self.SUPPORTED_FORMATS["Imagens"]["input"]:
                return "Imagens", self.SUPPORTED_FORMATS["Imagens"]["output"]
            elif mime_type.startswith("audio/") or ext in self.SUPPORTED_FORMATS["Áudio"]["input"]:
                return "Áudio", self.SUPPORTED_FORMATS["Áudio"]["output"]
            elif (mime_type.startswith("text/") or mime_type in ["application/pdf", "application/msword", "application/vnd.oasis.opendocument.text", "application/rtf"]) or ext in self.SUPPORTED_FORMATS["Documentos"]["input"]:
                return "Documentos", self.SUPPORTED_FORMATS["Documentos"]["output"]
        return None, []

    def check_pandoc(self):
        try:
            pypandoc.get_pandoc_version()
            return True
        except OSError:
            return False

    def check_ffmpeg(self):
        try:
            AudioSegment.from_file(self.input_path, duration=1)  # Teste básico com limite de duração
            return True
        except CouldntDecodeError:
            return False

    def convert_image(self):
        img = Image.open(self.input_path)
        total_size = os.path.getsize(self.input_path)
        processed = 0
        for i in range(0, 101, 10):
            if not self.check_state():
                return
            self.progressChanged.emit(i, f"Convertendo imagem ({i}%)", self.input_path)
            time.sleep(0.05)  # Simulação reduzida para melhor responsividade
        img.save(self.output_path, self.output_format.upper(), quality=self.quality or 85)
        processed = total_size
        self.progressChanged.emit(100, "Convertendo imagem (100%)", self.input_path)

    def convert_document(self):
        total_size = os.path.getsize(self.input_path)
        processed = 0
        chunk_size = total_size // 10 or 1  # Divisão em 10 partes ou mínimo de 1 byte
        temp_output = self.output_path + ".tmp"

        with open(self.input_path, 'rb') as f_in:
            for i in range(0, 101, 10):
                if not self.check_state():
                    if os.path.exists(temp_output):
                        os.remove(temp_output)
                    return
                processed += chunk_size
                percent = min(int((processed / total_size) * 100), 100)
                self.progressChanged.emit(percent, f"Convertendo documento ({percent}%)", self.input_path)
                time.sleep(0.05)  # Simulação reduzida

        pypandoc.convert_file(self.input_path, self.output_format, outputfile=temp_output)
        shutil.move(temp_output, self.output_path)
        self.progressChanged.emit(100, "Convertendo documento (100%)", self.input_path)

    def convert_audio(self):
        audio = AudioSegment.from_file(self.input_path)
        total_duration = len(audio)  # Em milissegundos
        chunk_size = total_duration // 10 or 1000  # 10 partes ou mínimo de 1 segundo
        processed_duration = 0
        temp_output = self.output_path + ".tmp"

        output_audio = AudioSegment.empty()
        for i in range(0, total_duration, chunk_size):
            if not self.check_state():
                if os.path.exists(temp_output):
                    os.remove(temp_output)
                return
            chunk = audio[i:i + chunk_size]
            output_audio += chunk
            processed_duration += len(chunk)
            percent = min(int((processed_duration / total_duration) * 100), 100)
            self.progressChanged.emit(percent, f"Convertendo áudio ({percent}%)", self.input_path)

        output_audio.export(temp_output, format=self.output_format, bitrate=self.bitrate or "192k")
        shutil.move(temp_output, self.output_path)
        self.progressChanged.emit(100, "Convertendo áudio (100%)", self.input_path)