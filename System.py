import sys
import threading
from PyQt5.QtWidgets import QApplication, QMainWindow, QVBoxLayout, QWidget, QTextEdit, QPushButton, QLabel, QTabWidget, QComboBox
from PyQt5.QtCore import pyqtSignal, QTimer
from scapy.all import sniff, ARP, Ether, srp, get_if_list
from scapy.layers.inet import IP, ICMP, TCP
import socket
import ipaddress
from scapy.all import conf
from PyQt5.QtCore import Qt


conf.verb = 1  # Habilitar la salida detallada de Scapy

class DetectionEngine:
    def __init__(self):
        # Contadores generales
        self.packet_counter = 0
        self.syn_counter = 0

        # Contador por IP (para DoS por origen)
        self.ip_packet_count = {}

        # Tabla ARP observada (para detectar inconsistencias)
        self.arp_table = {}

        # Callback para enviar alertas a la interfaz
        self.alert_callback = None

    def set_alert_callback(self, callback):
        self.alert_callback = callback

    def process_packet(self, packet):
        try:
            if IP in packet:
                src_ip = packet[IP].src
                self.packet_counter += 1

                # Conteo por IP
                if src_ip not in self.ip_packet_count:
                    self.ip_packet_count[src_ip] = 0
                self.ip_packet_count[src_ip] += 1

                # SYN detection
                if TCP in packet and packet[TCP].flags & 0x02:
                    self.syn_counter += 1

                # ICMP Echo detection
                if ICMP in packet and packet[ICMP].type == 8:
                    self.trigger_alert(f"Actividad ICMP sospechosa desde {src_ip}")

            # Detección básica ARP
            if ARP in packet and packet[ARP].op == 2:
                self.detect_arp_spoof(packet)

        except Exception as e:
            print("Error en process_packet:", e)

    def detect_arp_spoof(self, packet):
        ip = packet[ARP].psrc
        mac = packet[ARP].hwsrc

        if ip in self.arp_table:
            if self.arp_table[ip] != mac:
                self.trigger_alert(f"Posible ARP Spoofing detectado desde {ip}")
        else:
            self.arp_table[ip] = mac

    def check_dos(self):
        for ip, count in self.ip_packet_count.items():
            if count > 500:  # Umbral básico
                self.trigger_alert(f"Posible DoS desde {ip}")

        # Reiniciar contadores cada segundo
        self.packet_counter = 0
        self.syn_counter = 0
        self.ip_packet_count = {}

    def trigger_alert(self, message):
        if self.alert_callback:
            self.alert_callback(message)

class MainWindow(QMainWindow):
    packet_received_signal = pyqtSignal(str)
    anomaly_detected_signal = pyqtSignal(str)
    hosts_found_signal = pyqtSignal(list)

    capture_stopped = False


    def handle_alert(self, message):
        self.anomaly_detected_signal.emit(message)

    def __init__(self):
        super().__init__()

        self.hosts_text_edit = QTextEdit()
        self.setWindowTitle("Sistema de Detección de Amenazas en Redes Locales")
        self.init_ui()

        self.detection_engine = DetectionEngine()
        self.detection_engine.set_alert_callback(self.handle_alert)

        self.capture_paused = False
        self.packet_count = 0
        self.protocol_counts = {}
        self.anomaly_detected = False
        self.capture_interface = None

        self.packet_received_signal.connect(self.update_packet_display)
        self.anomaly_detected_signal.connect(self.update_anomaly_display)
        self.hosts_found_signal.connect(self.update_hosts_display)

        self.load_network_interfaces()

    def init_ui(self):
        main_widget = QWidget()
        main_layout = QVBoxLayout(main_widget)
        tab_widget = QTabWidget()

        capture_tab = QWidget()
        capture_layout = QVBoxLayout(capture_tab)

        self.packet_text_edit = QTextEdit()
        self.packet_text_edit.setReadOnly(True)
        self.hosts_text_edit.setTextInteractionFlags(Qt.TextSelectableByMouse)  # Permitir selección de texto
        self.hosts_text_edit.setStyleSheet("QTextEdit::selection { background-color: blue; color: white; }")
        capture_layout.addWidget(self.packet_text_edit)

        self.anomaly_label = QLabel()
        capture_layout.addWidget(self.anomaly_label)

        # Agrega un QLabel para mostrar la IP del atacante
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

        # Crea self.hosts_text_edit para la pestaña "Buscar Hosts en la Red"
        self.hosts_text_edit = QTextEdit()
        self.hosts_text_edit.setReadOnly(True)
        self.hosts_text_edit.setTextInteractionFlags(Qt.TextSelectableByMouse)  # Permitir selección de texto
        find_hosts_layout.addWidget(self.hosts_text_edit)

        # Agregar elementos a la interfaz de usuario para seleccionar un host
        self.hosts_combo_box = QComboBox()
        find_hosts_layout.addWidget(self.hosts_combo_box)

        self.interface_combo_box = QComboBox()
        self.interface_combo_box.currentTextChanged.connect(self.on_interface_selected)
        find_hosts_layout.addWidget(self.interface_combo_box)

        self.block_connection_button = QPushButton("Cortar Conexión")
        self.block_connection_button.clicked.connect(self.block_selected_connection)
        find_hosts_layout.addWidget(self.block_connection_button)

        self.find_hosts_button = QPushButton("Buscar Hosts")
        self.find_hosts_button.clicked.connect(self.find_hosts)
        find_hosts_layout.addWidget(self.find_hosts_button)

        self.interface_status_label = QLabel("Interfaz de captura: detectando...")
        find_hosts_layout.addWidget(self.interface_status_label)

        self.refresh_interfaces_button = QPushButton("Actualizar interfaces")
        self.refresh_interfaces_button.clicked.connect(self.load_network_interfaces)
        find_hosts_layout.addWidget(self.refresh_interfaces_button)

        find_hosts_tab.setLayout(find_hosts_layout)
        tab_widget.addTab(find_hosts_tab, "Buscar Hosts en la Red")

        main_layout.addWidget(tab_widget)
        self.setCentralWidget(main_widget)

    def block_selected_connection(self):

        try:
            # Obtener el texto seleccionado en el QTextEdit (lista de hosts)
            selected_text = self.hosts_text_edit.textCursor().selectedText().strip()

            # Extraer la IP del host seleccionado del texto
            attacker_ip = selected_text.split("IP: ")[-1].split(",")[0]

            # Llamar a la función para bloquear la conexión
            self.block_attacker_connection(attacker_ip)
        except Exception as e:
            print(f"Error al cortar la conexión al host seleccionado: {e}")

    def update_packet_display(self, packet_summary):
        self.packet_text_edit.append(packet_summary)

    def on_interface_selected(self, interface_name):
        if interface_name:
            self.capture_interface = interface_name
            self.interface_status_label.setText(f"Interfaz seleccionada: {interface_name}")

    def load_network_interfaces(self):
        try:
            interfaces = [iface for iface in get_if_list() if iface and iface.lower() != "lo"]
            self.interface_combo_box.clear()

            if not interfaces:
                self.capture_interface = None
                self.interface_status_label.setText("No se detectaron interfaces de red disponibles")
                return

            self.interface_combo_box.addItems(interfaces)

            # Si solo hay una, usarla automáticamente.
            if len(interfaces) == 1:
                self.capture_interface = interfaces[0]
                self.interface_combo_box.setCurrentIndex(0)
                self.interface_status_label.setText(f"Interfaz detectada automáticamente: {self.capture_interface}")
                return

            # Si hay más de una, priorizar la de Scapy (ruta por defecto) y como fallback la primera.
            default_iface = str(conf.iface) if conf.iface else None
            if default_iface in interfaces:
                self.capture_interface = default_iface
                self.interface_combo_box.setCurrentText(default_iface)
            else:
                self.capture_interface = interfaces[0]
                self.interface_combo_box.setCurrentIndex(0)

            self.interface_status_label.setText(
                f"Varias interfaces detectadas. Se usará por defecto: {self.capture_interface}"
            )

        except Exception as e:
            self.capture_interface = None
            self.interface_status_label.setText(f"Error al detectar interfaces: {e}")

    def update_anomaly_display(self, anomaly_message):
        self.anomaly_label.setText(anomaly_message)
        # Muestra la IP del atacante en un QLabel
        self.attacker_ip_label.setText("Atacante: " + anomaly_message.split()[-1])  # Toma la última palabra (la IP)

    def pause_capture(self):
        self.capture_paused = True

    def continue_capture(self):
        self.capture_paused = False

    def stop_capture(self):
        self.capture_stopped = True
        self.capture_thread.join()

    def start_capture_thread(self):
        def packet_handler(packet):
            try:
                if IP in packet:
                    self.packet_count += 1
                    self.packet_received_signal.emit(packet.summary())
                    self.detection_engine.process_packet(packet)
            except Exception as e:
                print("Error al manejar el paquete:", e)

        self.capture_thread = threading.Thread(target=self.start_capture, args=(packet_handler,))
        self.capture_thread.start()

    def should_stop(self, packet):
        return self.capture_stopped

    def start_capture(self, packet_handler):
        try:
            if not self.capture_interface:
                self.load_network_interfaces()

            if not self.capture_interface:
                raise RuntimeError("No hay interfaz de red disponible para capturar")

            sniff(iface=self.capture_interface, prn=packet_handler, stop_filter=self.should_stop)
        except Exception as e:
            print("Error en la captura de paquetes:", e)

    def find_hosts(self):
        try:
            print("Buscando hosts en la red...")

            # Obtener IP local
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)

            # Asumimos red /24 (estándar en redes locales pequeñas)
            network = ipaddress.IPv4Network(local_ip + "/24", strict=False)

            arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(network))
            result = srp(arp_request, timeout=3, verbose=False)[0]

            hosts = [{'ip': received.psrc, 'mac': received.hwsrc} for sent, received in result]

            self.hosts_found_signal.emit(hosts)

        except Exception as e:
            print("Error al buscar hosts en la red:", e)

    def check_dos_attack(self):
        self.detection_engine.check_dos()

    def update_hosts_display(self, hosts):
        self.hosts_text_edit.clear()
        for host in hosts:
            self.hosts_text_edit.append(f"IP: {host['ip']}, MAC: {host['mac']}")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    window.start_capture_thread()
    sys.exit(app.exec_())
