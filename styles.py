def get_styles():
    return """
        QWidget {
            background-color: #000000;
            color: #E0E0E0;
            font-family: 'Segoe UI', sans-serif;
            border-radius: 10px;
        }
        QTabWidget::pane {
            border: 1px solid #4A90E2;
            background: #1A1A1A;
            border-radius: 8px;
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
            background: #1A1A1A;
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
        QPushButton#minimizeButton {
            background-color: #2D2D2D;
            border: none;
            border-radius: 4px;
            min-width: 24px;
            max-width: 24px;
            min-height: 24px;
            max-height: 24px;
        }
        QPushButton#minimizeButton:hover {
            background-color: #4A90E2;
        }
        QPushButton#closeButton {
            background-color: #2D2D2D;
            border: none;
            border-radius: 4px;
            min-width: 24px;
            max-width: 24px;
            min-height: 24px;
            max-height: 24px;
        }
        QPushButton#closeButton:hover {
            background-color: #FF5555;
        }
        QLineEdit {
            background-color: #1A1A1A;
            color: #FFFFFF;
            border: 1px solid #404040;
            border-radius: 4px;
            padding: 4px;
        }
        QProgressBar {
            border: 1px solid #404040;
            border-radius: 4px;
            background: #1A1A1A;
            text-align: center;
            color: #FFFFFF;
            font-size: 12px;
        }
        QProgressBar::chunk {
            background-color: #4A90E2;
            border-radius: 4px;
        }
        QTreeView {
            background-color: #1A1A1A;
            color: #FFFFFF;
            border: 1px solid #404040;
            border-radius: 4px;
            padding: 2px;
        }
        QTextEdit {
            background-color: #1A1A1A;
            color: #FFFFFF;
            border: 1px solid #404040;
            border-radius: 4px;
        }
        QComboBox {
            background-color: #1A1A1A;
            color: #FFFFFF;
            border: 1px solid #404040;
            border-radius: 4px;
            padding: 4px;
        }
        QComboBox:hover {
            border: 1px solid #4A90E2;
        }
    """