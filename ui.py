from PySide6.QtWidgets import (
    QWidget, QPushButton, QVBoxLayout, QLineEdit, QLabel, QRadioButton,
    QGroupBox, QHBoxLayout, QTreeView, QSplitter, QFileSystemModel, QTextEdit,
    QComboBox, QTabWidget, QMenu
)
from PySide6.QtCore import Qt, QDir
from PySide6.QtGui import QIcon, QAction

def setup_ui(app):
    """Configura a interface gráfica do aplicativo."""
    app.setGeometry(100, 100, 1500, 850)

    # Layout principal
    main_layout = QVBoxLayout()
    main_layout.setContentsMargins(10, 10, 10, 10)

    # Barra de título personalizada
    title_bar = QHBoxLayout()
    title_label = QLabel("EnigmaShield - Gerenciador de Arquivos")
    title_label.setStyleSheet("font-size: 16px; color: #E0E0E0; padding: 5px;")
    title_bar.addWidget(title_label)
    title_bar.addStretch()

    minimize_button = QPushButton("", app)
    minimize_button.setObjectName("minimizeButton")
    minimize_button.setIcon(QIcon.fromTheme("window-minimize"))
    minimize_button.clicked.connect(app.showMinimized)
    minimize_button.setToolTip("Minimizar")
    close_button = QPushButton("", app)
    close_button.setObjectName("closeButton")
    close_button.setIcon(QIcon.fromTheme("window-close"))
    close_button.clicked.connect(app.close)
    close_button.setToolTip("Fechar")
    title_bar.addWidget(minimize_button)
    title_bar.addWidget(close_button)
    main_layout.addLayout(title_bar)

    # Layout do conteúdo
    content_layout = QHBoxLayout()

    # Painel esquerdo
    left_panel = QVBoxLayout()
    left_panel.setSpacing(10)

    auth_group = QGroupBox("Autenticação")
    auth_layout = QVBoxLayout()
    app.login_button = QPushButton('Login com Google', app)
    app.login_button.setToolTip("Login com Google (Ctrl+G)")
    auth_layout.addWidget(app.login_button)

    app.local_login_button = QPushButton('Login Local', app)
    auth_layout.addWidget(app.local_login_button)

    app.local_register_button = QPushButton('Registrar Local', app)
    auth_layout.addWidget(app.local_register_button)

    auth_group.setLayout(auth_layout)
    left_panel.addWidget(auth_group)

    selection_group = QGroupBox("Seleção")
    selection_layout = QVBoxLayout()
    app.file_path_display = QLineEdit(app)
    app.file_path_display.setReadOnly(True)
    app.folder_path_display = QLineEdit(app)
    app.folder_path_display.setReadOnly(True)
    app.browse_file_button = QPushButton('Procurar Arquivo', app)
    app.browse_file_button.setIcon(QIcon.fromTheme("document-open"))
    app.browse_file_button.setToolTip("Selecionar arquivo (Ctrl+O)")
    app.browse_folder_button = QPushButton('Procurar Pasta', app)
    app.browse_folder_button.setIcon(QIcon.fromTheme("folder-open"))
    app.browse_folder_button.setToolTip("Selecionar pasta (Ctrl+F)")
    selection_layout.addWidget(QLabel('Arquivo Alvo:'))
    selection_layout.addWidget(app.file_path_display)
    selection_layout.addWidget(app.browse_file_button)
    selection_layout.addWidget(QLabel('Pasta Alvo:'))
    selection_layout.addWidget(app.folder_path_display)
    selection_layout.addWidget(app.browse_folder_button)
    selection_group.setLayout(selection_layout)
    left_panel.addWidget(selection_group)
    left_panel.addStretch()

    # Explorador de arquivos
    explorer_layout = QVBoxLayout()
    app.path_selector = QComboBox(app)
    app.path_selector.addItems([QDir.homePath(), QDir.rootPath(), "Locais Recentes"])
    app.search_bar = QLineEdit(app)
    app.search_bar.setPlaceholderText("Pesquisar arquivos (nome, extensão, data)...")
    app.file_explorer = QTreeView(app)
    app.file_model = QFileSystemModel()
    app.file_model.setRootPath(QDir.homePath())
    app.file_model.setFilter(QDir.NoDotAndDotDot | QDir.AllDirs | QDir.Files)
    app.file_explorer.setModel(app.file_model)
    app.file_explorer.setRootIndex(app.file_model.index(QDir.homePath()))
    app.file_explorer.setColumnWidth(0, 300)
    app.file_explorer.setSortingEnabled(True)
    explorer_layout.addWidget(app.path_selector)
    explorer_layout.addWidget(app.search_bar)
    explorer_layout.addWidget(app.file_explorer)

    # Painel direito
    right_panel = QVBoxLayout()
    right_panel.setSpacing(10)

    app.tab_widget = QTabWidget(app)
    right_panel.addWidget(app.tab_widget)

    # Aba de Processamento
    app.process_tab = QWidget()
    app.process_layout = QVBoxLayout()

    radio_layout = QHBoxLayout()
    app.encrypt_radio = QRadioButton('Criptografar', app)
    app.decrypt_radio = QRadioButton('Descriptografar', app)
    app.encrypt_radio.setChecked(True)
    radio_layout.addWidget(app.encrypt_radio)
    radio_layout.addWidget(app.decrypt_radio)

    app.password_entry = QLineEdit(app)
    app.password_entry.setEchoMode(QLineEdit.Password)
    app.password_entry.setPlaceholderText("Digite a senha (mín. 8 caracteres, 1 maiúscula, 1 número)")

    app.process_button = QPushButton('Processar', app)
    app.process_button.setIcon(QIcon.fromTheme("system-run"))
    app.process_button.setToolTip("Iniciar processamento (Ctrl+P)")

    control_buttons_layout = QHBoxLayout()
    app.pause_button = QPushButton("Pausar", app)
    app.cancel_button = QPushButton("Cancelar", app)
    control_buttons_layout.addWidget(app.pause_button)
    control_buttons_layout.addWidget(app.cancel_button)

    app.organize_button = QPushButton("Organizar Arquivos", app)

    cloud_layout = QVBoxLayout()
    cloud_label = QLabel("Armazenamento em Nuvem:")
    app.cloud_service_combo = QComboBox(app)
    app.cloud_service_combo.addItems(["Selecionar Serviço", "Google Drive", "Dropbox"])
    app.google_drive_status = QLabel("Google Drive: Desconectado", app)
    app.google_drive_status.setStyleSheet("color: red;")
    app.dropbox_status = QLabel("Dropbox: Desconectado", app)
    app.dropbox_status.setStyleSheet("color: red;")
    cloud_layout.addWidget(cloud_label)
    cloud_layout.addWidget(app.cloud_service_combo)
    cloud_layout.addWidget(app.google_drive_status)
    cloud_layout.addWidget(app.dropbox_status)

    app.auth_google_button = QPushButton("Autenticar Google Drive", app)
    cloud_layout.addWidget(app.auth_google_button)

    cloud_buttons_layout = QHBoxLayout()
    app.upload_cloud_button = QPushButton('Upload para Nuvem', app)
    app.upload_cloud_button.setIcon(QIcon.fromTheme("go-up"))
    app.upload_cloud_button.setEnabled(False)
    app.download_cloud_button = QPushButton('Download da Nuvem', app)
    app.download_cloud_button.setIcon(QIcon.fromTheme("go-down"))
    cloud_buttons_layout.addWidget(app.upload_cloud_button)
    cloud_buttons_layout.addWidget(app.download_cloud_button)
    cloud_layout.addLayout(cloud_buttons_layout)

    app.process_layout.addLayout(radio_layout)
    app.process_layout.addWidget(QLabel("Senha:"))
    app.process_layout.addWidget(app.password_entry)
    app.process_layout.addWidget(app.process_button)
    app.process_layout.addLayout(control_buttons_layout)
    app.process_layout.addWidget(app.organize_button)
    app.process_layout.addLayout(cloud_layout)
    app.process_tab.setLayout(app.process_layout)
    app.tab_widget.addTab(app.process_tab, "Processamento")

    # Aba de Conversão
    app.conversion_tab = QWidget()
    app.conversion_layout = QVBoxLayout()

    app.conversion_input = QLineEdit(app)
    app.conversion_input.setReadOnly(True)
    app.conversion_browse_button = QPushButton("Selecionar Arquivo", app)

    app.conversion_type_combo = QComboBox(app)
    app.conversion_type_combo.addItems(["Imagens", "Documentos", "Áudio"])

    app.conversion_format_combo = QComboBox(app)
    app.update_conversion_formats("Imagens")

    app.conversion_output_dir = QLineEdit(app)
    app.conversion_output_dir.setReadOnly(True)
    app.conversion_output_browse_button = QPushButton("Selecionar Diretório de Saída", app)

    app.conversion_button = QPushButton("Converter", app)
    app.conversion_pause_button = QPushButton("Pausar Conversão", app)
    app.conversion_cancel_button = QPushButton("Cancelar Conversão", app)

    app.conversion_layout.addWidget(QLabel("Arquivo de Entrada:"))
    app.conversion_layout.addWidget(app.conversion_input)
    app.conversion_layout.addWidget(app.conversion_browse_button)
    app.conversion_layout.addWidget(QLabel("Tipo de Conversão:"))
    app.conversion_layout.addWidget(app.conversion_type_combo)
    app.conversion_layout.addWidget(QLabel("Formato de Saída:"))
    app.conversion_layout.addWidget(app.conversion_format_combo)
    app.conversion_layout.addWidget(QLabel("Diretório de Saída:"))
    app.conversion_layout.addWidget(app.conversion_output_dir)
    app.conversion_layout.addWidget(app.conversion_output_browse_button)
    app.conversion_layout.addWidget(app.conversion_button)
    app.conversion_layout.addWidget(app.conversion_pause_button)
    app.conversion_layout.addWidget(app.conversion_cancel_button)
    app.conversion_tab.setLayout(app.conversion_layout)
    app.tab_widget.addTab(app.conversion_tab, "Conversão")

    # Log de Processos
    log_group = QGroupBox("Log de Processos")
    log_layout = QVBoxLayout()
    app.log_display = QTextEdit(app)
    app.log_display.setReadOnly(True)
    app.clear_log_button = QPushButton("Limpar Log", app)
    app.view_history_button = QPushButton("Ver Histórico", app)
    log_layout.addWidget(app.log_display)
    log_layout.addWidget(app.clear_log_button)
    log_layout.addWidget(app.view_history_button)
    log_group.setLayout(log_layout)
    right_panel.addWidget(log_group)
    right_panel.addStretch()

    # Splitter
    splitter = QSplitter(Qt.Horizontal)
    left_widget = QWidget()
    left_widget.setLayout(left_panel)
    splitter.addWidget(left_widget)
    explorer_widget = QWidget()
    explorer_widget.setLayout(explorer_layout)
    splitter.addWidget(explorer_widget)
    right_widget = QWidget()
    right_widget.setLayout(right_panel)
    splitter.addWidget(right_widget)
    splitter.setSizes([300, 500, 300])

    content_layout.addWidget(splitter)
    main_layout.addLayout(content_layout)
    app.setLayout(main_layout)

    # Configurar menu de contexto do explorador de arquivos
    app.file_explorer.setContextMenuPolicy(Qt.CustomContextMenu)