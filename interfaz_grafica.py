from PyQt5.QtCore import Qt, pyqtSignal
import logging
from PyQt5.QtWidgets import (
    QComboBox,
    QLabel,
    QMainWindow,
    QPushButton,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class MainWindow(QMainWindow):
    packet_received_signal = pyqtSignal(str)
    anomaly_detected_signal = pyqtSignal(str)
    hosts_found_signal = pyqtSignal(list)

    def __init__(self):
        super().__init__()
        self.capture_paused = False
        self.packet_count = 0
        self.protocol_counts = {}
        self.anomaly_detected = False

        self.hosts_text_edit = QTextEdit()
        self.setWindowTitle("Sistema de Detección de Amenazas en Redes Locales")
        self.init_ui()

        self.packet_received_signal.connect(self.update_packet_display)
        self.anomaly_detected_signal.connect(self.update_anomaly_display)
        self.hosts_found_signal.connect(self.update_hosts_display)

        self._pause_callback = None
        self._continue_callback = None
        self._stop_callback = None
        self._find_hosts_callback = None
        self._block_host_callback = None

    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        tab_widget = QTabWidget()

        capture_tab = QWidget()
        capture_layout = QVBoxLayout(capture_tab)

        self.capture_interface_label = QLabel("Interfaz de captura")
        capture_layout.addWidget(self.capture_interface_label)

        self.capture_interface_combo_box = QComboBox()
        self.capture_interface_combo_box.currentIndexChanged.connect(self.on_interface_selected)
        capture_layout.addWidget(self.capture_interface_combo_box)

        self.packet_text_edit = QTextEdit()
        self.packet_text_edit.setReadOnly(True)
        capture_layout.addWidget(self.packet_text_edit)

        self.anomaly_label = QLabel()
        capture_layout.addWidget(self.anomaly_label)

        self.attacker_ip_label = QLabel()
        capture_layout.addWidget(self.attacker_ip_label)

        self.pause_button = QPushButton("Pausar")
        self.continue_button = QPushButton("Continuar")
        self.stop_button = QPushButton("Detener")

        self.pause_button.clicked.connect(self.pause_capture)
        self.continue_button.clicked.connect(self.continue_capture)
        self.stop_button.clicked.connect(self.stop_capture)

        capture_layout.addWidget(self.pause_button)
        capture_layout.addWidget(self.continue_button)
        capture_layout.addWidget(self.stop_button)

        capture_tab.setLayout(capture_layout)
        tab_widget.addTab(capture_tab, "Captura de Paquetes")

        find_hosts_tab = QWidget()
        find_hosts_layout = QVBoxLayout(find_hosts_tab)

        self.hosts_text_edit = QTextEdit()
        self.hosts_text_edit.setReadOnly(True)
        self.hosts_text_edit.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.hosts_text_edit.setStyleSheet("QTextEdit::selection { background-color: blue; color: white; }")
        find_hosts_layout.addWidget(self.hosts_text_edit)

        self.hosts_combo_box = QComboBox()
        find_hosts_layout.addWidget(self.hosts_combo_box)

        self.block_connection_button = QPushButton("Cortar Conexión")
        self.block_connection_button.clicked.connect(self.block_selected_connection)
        find_hosts_layout.addWidget(self.block_connection_button)

        self.find_hosts_button = QPushButton("Buscar Hosts")
        self.find_hosts_button.clicked.connect(self.find_hosts)
        find_hosts_layout.addWidget(self.find_hosts_button)

        find_hosts_tab.setLayout(find_hosts_layout)
        tab_widget.addTab(find_hosts_tab, "Buscar Hosts en la Red")

        main_layout.addWidget(tab_widget)
        self.setCentralWidget(main_widget)

    def set_capture_interfaces(self, interfaces):
        self.capture_interface_combo_box.clear()
        for friendly_name, real_name in interfaces:
            self.capture_interface_combo_box.addItem(friendly_name, real_name)

    def on_interface_selected(self):
        visible_name = self.capture_interface_combo_box.currentText()
        real_identifier = self.capture_interface_combo_box.currentData()
        logging.debug(
            "Interfaz seleccionada por usuario -> visible='%s' real='%s'",
            visible_name,
            real_identifier,
        )

    def get_selected_capture_interface(self):
        if self.capture_interface_combo_box.count() == 0:
            return None
        return self.capture_interface_combo_box.currentData()

    def set_selected_capture_interface(self, real_name):
        for index in range(self.capture_interface_combo_box.count()):
            if self.capture_interface_combo_box.itemData(index) == real_name:
                self.capture_interface_combo_box.setCurrentIndex(index)
                return

    def bind_actions(self, pause_callback, continue_callback, stop_callback, find_hosts_callback, block_host_callback):
        self._pause_callback = pause_callback
        self._continue_callback = continue_callback
        self._stop_callback = stop_callback
        self._find_hosts_callback = find_hosts_callback
        self._block_host_callback = block_host_callback

    def handle_alert(self, message):
        self.anomaly_detected_signal.emit(message)

    def pause_capture(self):
        self.capture_paused = True
        if self._pause_callback:
            self._pause_callback()

    def continue_capture(self):
        self.capture_paused = False
        if self._continue_callback:
            self._continue_callback()

    def stop_capture(self):
        if self._stop_callback:
            self._stop_callback()

    def find_hosts(self):
        if self._find_hosts_callback:
            self._find_hosts_callback()

    def block_selected_connection(self):
        selected_text = self.hosts_text_edit.textCursor().selectedText().strip()
        if "IP:" not in selected_text:
            return

        attacker_ip = selected_text.split("IP: ")[-1].split(",")[0]
        if self._block_host_callback:
            self._block_host_callback(attacker_ip)

    def update_packet_display(self, packet_summary):
        self.packet_text_edit.append(packet_summary)

    def update_anomaly_display(self, anomaly_message):
        self.anomaly_label.setText(anomaly_message)
        self.attacker_ip_label.setText("Atacante: " + anomaly_message.split()[-1])

    def update_hosts_display(self, hosts):
        self.hosts_text_edit.clear()
        self.hosts_combo_box.clear()
        for host in hosts:
            text = f"IP: {host['ip']}, MAC: {host['mac']}"
            self.hosts_text_edit.append(text)
            self.hosts_combo_box.addItem(text)
