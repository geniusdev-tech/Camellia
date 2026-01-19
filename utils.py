import os
import secrets
from PySide6.QtWidgets import QProgressBar, QMessageBox, QVBoxLayout

def create_progress_bar(parent, associated_file, layout, index=0):
    pb = QProgressBar(parent)
    pb.setFormat(f"{os.path.basename(associated_file)}: 0%")
    pb.setValue(0)
    layout.insertWidget(index, pb)
    return pb

def remove_progress_bar(pb, tracker_dict, key):
    pb.deleteLater()
    if key in tracker_dict:
        del tracker_dict[key]

def show_message_box(parent, title, text, icon=QMessageBox.Information):
    msg = QMessageBox(parent)
    msg.setWindowTitle(title)
    msg.setText(text)
    msg.setIcon(icon)
    msg.exec()

def secure_delete(path, passes=3):
    """
    Overwrites the file with random data before deleting it (Shredding).
    Processes in chunks to handle large files safely.
    """
    if not os.path.exists(path): return
    
    file_size = os.path.getsize(path)
    chunk_size = 65536
    
    try:
        with open(path, "br+") as f:
            for _ in range(passes):
                f.seek(0)
                remaining = file_size
                while remaining > 0:
                    current_chunk = min(remaining, chunk_size)
                    f.write(secrets.token_bytes(current_chunk))
                    remaining -= current_chunk
                f.flush()
                os.fsync(f.fileno())
    except (OSError, IOError):
        pass # Fallback to normal delete if overwrite fails (e.g. read-only fs)
            
    os.remove(path)