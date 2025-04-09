from PySide6.QtWidgets import QProgressBar, QMessageBox
from PySide6.QtCore import QTimer

def create_progress_bar(parent, path, layout, position, initial_text="Processando... 0%"):
    """Cria e adiciona uma barra de progresso ao layout."""
    progress_bar = QProgressBar(parent)
    progress_bar.setValue(0)
    progress_bar.setMaximum(100)
    progress_bar.setFormat(f"{os.path.basename(path)}: {initial_text}")
    layout.insertWidget(position, progress_bar)
    return progress_bar

def remove_progress_bar(progress_bar, progress_bars, path, delay=2000):
    """Remove uma barra de progresso após um atraso."""
    QTimer.singleShot(delay, lambda: _remove_progress_bar(progress_bar, progress_bars, path))

def _remove_progress_bar(progress_bar, progress_bars, path):
    progress_bar.parent().layout().removeWidget(progress_bar)
    progress_bar.deleteLater()
    if path in progress_bars:
        del progress_bars[path]

def show_message_box(parent, title, message, icon=QMessageBox.Information):
    """Exibe uma mensagem em uma caixa de diálogo."""
    msg_box = QMessageBox(parent)
    msg_box.setWindowTitle(title)
    msg_box.setText(message)
    msg_box.setIcon(icon)
    msg_box.exec()