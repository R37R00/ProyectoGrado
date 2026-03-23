import logging
from datetime import datetime

from PyQt5.QtCore import Qt, pyqtSignal
from PyQt5.QtGui import QColor
from PyQt5.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QSlider,
    QTableWidget,
    QTableWidgetItem,
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

        self.hosts = {}
        self.active_alerts = {}
        self.total_alerts = 0

        self.setWindowTitle("Sistema de Deteccion de Amenazas en Redes Locales")
        self.init_ui()

        self.packet_received_signal.connect(self.update_packet_display)
        self.anomaly_detected_signal.connect(self.update_anomaly_display)
        self.hosts_found_signal.connect(self.update_hosts_display)

        self._pause_callback = None
        self._continue_callback = None
        self._stop_callback = None
        self._find_hosts_callback = None
        self._block_host_callback = None
        self._unblock_host_callback = None

    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)

        self._build_status_bar(main_layout)

        self.tab_widget = QTabWidget()
        self._build_dashboard_tab()
        self._build_alerts_tab()
        self._build_hosts_tab()
        self._build_protection_tab()
        self._build_settings_tab()

        main_layout.addWidget(self.tab_widget)
        self.setCentralWidget(main_widget)

    def _build_status_bar(self, parent_layout):
        status_frame = QFrame()
        status_frame.setFrameShape(QFrame.StyledPanel)
        status_layout = QHBoxLayout(status_frame)

        self.monitoring_status_label = QLabel("MONITORING")
        self.interface_status_label = QLabel("Interface: N/A")
        self.host_count_status_label = QLabel("Hosts: 0")
        self.protection_status_label = QLabel("Protection: ON")

        status_layout.addWidget(self.monitoring_status_label)
        status_layout.addWidget(self.interface_status_label)
        status_layout.addWidget(self.host_count_status_label)
        status_layout.addWidget(self.protection_status_label)
        status_layout.addStretch()

        parent_layout.addWidget(status_frame)

    def _build_dashboard_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.current_status_label = QLabel("Current status: Monitoring")
        self.last_alert_label = QLabel("Last alert: None")
        self.total_hosts_label = QLabel("Total hosts detected: 0")
        self.threat_level_label = QLabel("Threat level: LOW")

        self.packet_text_edit = QTextEdit()
        self.packet_text_edit.setReadOnly(True)

        layout.addWidget(self.current_status_label)
        layout.addWidget(self.last_alert_label)
        layout.addWidget(self.total_hosts_label)
        layout.addWidget(self.threat_level_label)
        layout.addWidget(self.packet_text_edit)

        self.tab_widget.addTab(tab, "Dashboard")

    def _build_alerts_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.anomaly_label = QLabel("Network Anomaly Detected")
        self.anomaly_text = QTextEdit()
        self.anomaly_text.setReadOnly(True)
        self.anomaly_text.document().setMaximumBlockCount(200)

        self.alerts_table = QTableWidget(0, 5)
        self.alerts_table.setHorizontalHeaderLabels(["Timestamp", "Type", "Attacker", "Victim", "Status"])
        self.alerts_table.horizontalHeader().setStretchLastSection(True)

        layout.addWidget(self.anomaly_label)
        layout.addWidget(self.anomaly_text)
        layout.addWidget(self.alerts_table)

        self.tab_widget.addTab(tab, "Alerts (0)")

    def _build_hosts_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.hosts_table = QTableWidget(0, 5)
        self.hosts_table.setHorizontalHeaderLabels(["IP", "MAC", "Status", "Type", "Activity"])
        self.hosts_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.hosts_table)

        self.hosts_text_edit = QTextEdit()
        self.hosts_text_edit.setReadOnly(True)
        self.hosts_text_edit.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.hosts_text_edit.setStyleSheet("QTextEdit::selection { background-color: blue; color: white; }")
        layout.addWidget(self.hosts_text_edit)

        self.hosts_combo_box = QComboBox()
        layout.addWidget(self.hosts_combo_box)

        self.block_connection_button = QPushButton("Cortar Conexion")
        self.block_connection_button.clicked.connect(self.block_selected_connection)
        layout.addWidget(self.block_connection_button)

        self.unblock_connection_button = QPushButton("Permitir conexion")
        self.unblock_connection_button.clicked.connect(self.unblock_selected_connection)
        layout.addWidget(self.unblock_connection_button)

        self.find_hosts_button = QPushButton("Buscar Hosts")
        self.find_hosts_button.clicked.connect(self.find_hosts)
        layout.addWidget(self.find_hosts_button)

        self.tab_widget.addTab(tab, "Hosts")

    def _build_protection_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.mitigation_enabled_checkbox = QCheckBox("Enable automatic mitigation")
        self.mitigation_enabled_checkbox.setChecked(True)
        self.periodic_restoration_checkbox = QCheckBox("Periodic ARP restoration")
        self.lock_gateway_checkbox = QCheckBox("Lock gateway ARP entry")
        self.aggressive_defense_checkbox = QCheckBox("Aggressive defense mode")

        layout.addWidget(self.mitigation_enabled_checkbox)
        layout.addWidget(self.periodic_restoration_checkbox)
        layout.addWidget(self.lock_gateway_checkbox)
        layout.addWidget(self.aggressive_defense_checkbox)
        layout.addStretch()

        self.tab_widget.addTab(tab, "Protection")

    def _build_settings_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)

        self.capture_interface_label = QLabel("Interfaz de captura")
        self.capture_interface_combo_box = QComboBox()
        self.capture_interface_combo_box.currentIndexChanged.connect(self.on_interface_selected)

        self.sensitivity_label = QLabel("Detection sensitivity")
        self.sensitivity_slider = QSlider(Qt.Horizontal)
        self.sensitivity_slider.setMinimum(1)
        self.sensitivity_slider.setMaximum(10)
        self.sensitivity_slider.setValue(5)

        self.pause_button = QPushButton("Pausar")
        self.continue_button = QPushButton("Continuar")
        self.stop_button = QPushButton("Detener")
        self.pause_button.clicked.connect(self.pause_capture)
        self.continue_button.clicked.connect(self.continue_capture)
        self.stop_button.clicked.connect(self.stop_capture)

        layout.addWidget(self.capture_interface_label)
        layout.addWidget(self.capture_interface_combo_box)
        layout.addWidget(self.sensitivity_label)
        layout.addWidget(self.sensitivity_slider)
        layout.addWidget(self.pause_button)
        layout.addWidget(self.continue_button)
        layout.addWidget(self.stop_button)
        layout.addStretch()

        self.tab_widget.addTab(tab, "Settings")

    def set_capture_interfaces(self, interfaces):
        self.capture_interface_combo_box.clear()
        for friendly_name, real_name in interfaces:
            self.capture_interface_combo_box.addItem(friendly_name, real_name)
        self.update_status(interface=self.capture_interface_combo_box.currentText())

    def on_interface_selected(self):
        visible_name = self.capture_interface_combo_box.currentText()
        real_identifier = self.capture_interface_combo_box.currentData()
        logging.debug(
            "Interfaz seleccionada por usuario -> visible='%s' real='%s'",
            visible_name,
            real_identifier,
        )
        self.update_status(interface=visible_name)

    def get_selected_capture_interface(self):
        if self.capture_interface_combo_box.count() == 0:
            return None
        return self.capture_interface_combo_box.currentData()

    def set_selected_capture_interface(self, real_name):
        for index in range(self.capture_interface_combo_box.count()):
            if self.capture_interface_combo_box.itemData(index) == real_name:
                self.capture_interface_combo_box.setCurrentIndex(index)
                return

    def get_mitigation_options(self):
        return {
            "mitigation_enabled": self.mitigation_enabled_checkbox.isChecked(),
            "periodic_enabled": self.periodic_restoration_checkbox.isChecked(),
            "lock_gateway_enabled": self.lock_gateway_checkbox.isChecked(),
            "aggressive_mode": self.aggressive_defense_checkbox.isChecked(),
        }

    def bind_actions(
        self,
        pause_callback,
        continue_callback,
        stop_callback,
        find_hosts_callback,
        block_host_callback,
        unblock_host_callback,
    ):
        self._pause_callback = pause_callback
        self._continue_callback = continue_callback
        self._stop_callback = stop_callback
        self._find_hosts_callback = find_hosts_callback
        self._block_host_callback = block_host_callback
        self._unblock_host_callback = unblock_host_callback

    def handle_alert(self, message):
        self.anomaly_detected_signal.emit(message)

    def pause_capture(self):
        self.capture_paused = True
        self.update_status(monitoring_on=False)
        if self._pause_callback:
            self._pause_callback()

    def continue_capture(self):
        self.capture_paused = False
        self.update_status(monitoring_on=True)
        if self._continue_callback:
            self._continue_callback()

    def stop_capture(self):
        self.update_status(monitoring_on=False)
        if self._stop_callback:
            self._stop_callback()

    def find_hosts(self):
        if self._find_hosts_callback:
            self._find_hosts_callback()

    def _parse_host_descriptor(self, text):
        if not text:
            return None, None

        ip_address = None
        mac_address = None
        for segment in text.split(","):
            segment = segment.strip()
            if segment.startswith("IP:"):
                ip_address = segment.split(":", 1)[1].strip()
            elif segment.startswith("MAC:"):
                mac_address = segment.split(":", 1)[1].strip()

        return ip_address, mac_address

    def _get_selected_host(self):
        current_row = self.hosts_table.currentRow()
        if current_row >= 0:
            ip_item = self.hosts_table.item(current_row, 0)
            mac_item = self.hosts_table.item(current_row, 1)
            ip_address = ip_item.text().strip() if ip_item else None
            mac_address = mac_item.text().strip() if mac_item else None
            if ip_address or mac_address:
                return ip_address, mac_address

        selected_text = self.hosts_text_edit.textCursor().selectedText().strip()
        ip_address, mac_address = self._parse_host_descriptor(selected_text)
        if ip_address or mac_address:
            return ip_address, mac_address

        combo_text = self.hosts_combo_box.currentText().strip()
        return self._parse_host_descriptor(combo_text)

    def block_selected_connection(self):
        attacker_ip, attacker_mac = self._get_selected_host()
        if not attacker_ip and not attacker_mac:
            logging.warning("No se pudo extraer un host valido para bloquear")
            return

        if self._block_host_callback:
            self._block_host_callback(attacker_ip, attacker_mac)

    def unblock_selected_connection(self):
        attacker_ip, attacker_mac = self._get_selected_host()
        if not attacker_ip and not attacker_mac:
            logging.warning("No se pudo extraer un host valido para desbloquear")
            return

        if self._unblock_host_callback:
            self._unblock_host_callback(attacker_ip, attacker_mac)

    def get_mac_for_ip(self, ip_address):
        data = self.hosts.get(ip_address, {})
        return data.get("mac")

    def update_packet_display(self, packet_summary):
        self.packet_text_edit.append(packet_summary)

    def add_alert(self, alert_type, attacker, victim, status, raw_message, severity="LOW"):
        key = f"{alert_type}|{attacker}|{victim}"
        is_new = key not in self.active_alerts

        if is_new:
            row = self.alerts_table.rowCount()
            self.alerts_table.insertRow(row)
            self.active_alerts[key] = row
            self.total_alerts += 1
        else:
            row = self.active_alerts[key]

        timestamp = datetime.now().strftime("%H:%M:%S")
        self.alerts_table.setItem(row, 0, QTableWidgetItem(timestamp))
        self.alerts_table.setItem(row, 1, QTableWidgetItem(alert_type))
        self.alerts_table.setItem(row, 2, QTableWidgetItem(attacker))
        self.alerts_table.setItem(row, 3, QTableWidgetItem(victim))
        self.alerts_table.setItem(row, 4, QTableWidgetItem(status))

        if severity == "HIGH":
            for col in range(5):
                item = self.alerts_table.item(row, col)
                if item:
                    item.setBackground(QColor("#ffcccc"))
            self.tab_widget.setCurrentIndex(1)

        self.tab_widget.setTabText(1, f"Alerts ({self.total_alerts})")
        self.last_alert_label.setText(f"Last alert: {alert_type} | {attacker} -> {victim}")
        self.current_status_label.setText(
            "Current status: Attack detected" if severity == "HIGH" else "Current status: Monitoring"
        )
        self.threat_level_label.setText(f"Threat level: {severity}")
        self.anomaly_text.append(raw_message)

    def update_hosts(self, ip, mac, status="Unknown", host_type="Host", activity="Normal"):
        self.hosts[ip] = {
            "mac": mac,
            "status": status,
            "type": host_type,
            "activity": activity,
        }

        self.hosts_table.setRowCount(0)
        for row, (host_ip, data) in enumerate(self.hosts.items()):
            self.hosts_table.insertRow(row)
            self.hosts_table.setItem(row, 0, QTableWidgetItem(host_ip))
            self.hosts_table.setItem(row, 1, QTableWidgetItem(data["mac"]))
            self.hosts_table.setItem(row, 2, QTableWidgetItem(data["status"]))
            self.hosts_table.setItem(row, 3, QTableWidgetItem(data["type"]))
            self.hosts_table.setItem(row, 4, QTableWidgetItem(data["activity"]))

            color = QColor("#ccffcc")
            if data["status"] == "Unknown":
                color = QColor("#fff3cd")
            elif data["status"] == "Suspicious":
                color = QColor("#ffcccc")
            elif data["status"] == "Blocked":
                color = QColor("#ff8a8a")

            for col in range(5):
                item = self.hosts_table.item(row, col)
                if item:
                    item.setBackground(color)

        self.update_status(host_count=len(self.hosts))
        self.total_hosts_label.setText(f"Total hosts detected: {len(self.hosts)}")

    def update_status(self, monitoring_on=None, interface=None, host_count=None, protection_on=None):
        if monitoring_on is not None:
            self.monitoring_status_label.setText("MONITORING" if monitoring_on else "STOPPED")
        if interface is not None:
            self.interface_status_label.setText(f"Interface: {interface}")
        if host_count is not None:
            self.host_count_status_label.setText(f"Hosts: {host_count}")
        if protection_on is not None:
            self.protection_status_label.setText("Protection: ON" if protection_on else "Protection: OFF")

    def update_anomaly_display(self, anomaly_message):
        self.anomaly_label.setText("Network Anomaly Detected")

        lines = anomaly_message.splitlines()
        alert_type = "Anomaly"
        attacker = "Unknown"
        victim = "Unknown"
        status = "Detected"
        severity = "LOW"

        if lines:
            first_line = lines[0]
            if "ARP" in first_line:
                alert_type = "ARP Spoofing"
                severity = "HIGH"
            elif "[BLOCKED]" in first_line:
                alert_type = "Blocked"
                status = "Blocked"
                severity = "HIGH"
            elif "[UNBLOCKED]" in first_line:
                alert_type = "Unblocked"
                status = "Allowed"

            if "MITIGATION" in anomaly_message:
                status = "Mitigated"

        for line in lines:
            if line.startswith("Attacker MAC:"):
                attacker = line.split(":", 1)[1].strip()
            elif line.startswith("Attacker IP:"):
                attacker = line.split(":", 1)[1].strip()
            elif line.startswith("Victim IP:"):
                victim = line.split(":", 1)[1].strip()
            elif line.startswith("Spoofed IP:") and victim == "Unknown":
                victim = line.split(":", 1)[1].strip()
            elif line.startswith("IP atacante posible:"):
                attacker = line.split(":", 1)[1].strip()

        self.add_alert(alert_type, attacker, victim, status, anomaly_message, severity=severity)

        if alert_type == "ARP Spoofing" and attacker != "Unknown":
            self.update_hosts(attacker, "unknown", status="Suspicious", host_type="Host", activity=alert_type)
        if victim != "Unknown" and victim in self.hosts:
            data = self.hosts[victim]
            self.update_hosts(victim, data["mac"], status=data["status"], host_type=data["type"], activity=alert_type)

    def update_hosts_display(self, hosts):
        self.hosts_text_edit.clear()
        self.hosts_combo_box.clear()

        for host in hosts:
            ip_address = host["ip"]
            mac_address = host["mac"]
            existing = self.hosts.get(ip_address, {})
            self.update_hosts(
                ip_address,
                mac_address,
                status=existing.get("status", "Trusted"),
                host_type=existing.get("type", "Host"),
                activity=existing.get("activity", "Normal"),
            )

            text = f"IP: {ip_address}, MAC: {mac_address}"
            self.hosts_text_edit.append(text)
            self.hosts_combo_box.addItem(text)
