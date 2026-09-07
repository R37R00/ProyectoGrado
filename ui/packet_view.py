from collections import deque
from datetime import datetime
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText


class PacketView(ttk.Frame):
    MAX_ROWS = 1000

    def __init__(self, parent, on_pause, on_resume, on_stop, on_unblock_host=None, on_block_host=None):
        super().__init__(parent, style="App.TFrame")
        self.on_pause = on_pause
        self.on_resume = on_resume
        self.on_stop = on_stop
        self.on_unblock_host = on_unblock_host
        self.on_block_host = on_block_host
        self.packet_rows = deque()
        self.host_state_by_ip = {}
        self.alert_rows = deque()
        self.event_rows = deque()

        self._build_layout()

    def _translate_attack_type(self, value):
        text = str(value or "").strip()
        normalized = text.upper().replace("_", " ")
        if not text or normalized == "UNKNOWN":
            return "Desconocido"
        if "ARP" in normalized:
            return "Suplantación ARP"
        if "PORT" in normalized or "SCAN" in normalized:
            return "Escaneo de puertos"
        if "DOS" in normalized:
            return "Denegación de servicio"
        if "ICMP" in normalized and "FLOOD" in normalized:
            return "Inundación ICMP"
        if "SYN" in normalized and "FLOOD" in normalized:
            return "Inundación SYN"
        if normalized == "MANUAL":
            return "Manual"
        return text

    def _translate_status(self, value):
        text = str(value or "").strip()
        normalized = text.lower()
        translations = {
            "active": "Activo",
            "detected": "Detectado",
            "blocked": "Bloqueado",
            "blocked (manual)": "Bloqueado (Manual)",
            "suspicious": "Sospechoso",
            "queued": "En cola",
            "resolved": "Resuelto",
            "unblocked": "Desbloqueado",
            "mitigated": "Mitigado",
            "block failed": "Bloqueo fallido",
            "running": "En ejecución",
            "paused": "Pausado",
            "stopped": "Detenido",
            "unknown": "Desconocido",
        }
        if normalized.startswith("blocked (") and normalized.endswith(")"):
            attack_name = text[text.find("(") + 1 : -1]
            return f"Bloqueado ({self._translate_attack_type(attack_name)})"
        return translations.get(normalized, text or "Desconocido")

    def _translate_severity(self, value):
        text = str(value or "").strip()
        translations = {
            "critical": "Crítica",
            "warning": "Advertencia",
            "suspicious": "Sospechosa",
            "resolved": "Resuelta",
            "failed": "Fallida",
        }
        return translations.get(text.lower(), text or "Desconocida")

    def _translate_placeholder(self, value):
        text = str(value or "").strip()
        if not text or text.lower() in {"unknown", "n/a"}:
            return "Desconocido"
        return text

    def _build_layout(self):
        outer = ttk.Frame(self, style="Card.TFrame", padding=18)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer, style="Card.TFrame")
        header.pack(fill="x")

        ttk.Label(header, text="Captura de paquetes", style="SectionTitle.TLabel").pack(side="left")

        controls = ttk.Frame(header, style="Card.TFrame")
        controls.pack(side="right")
        self.pause_button = ttk.Button(controls, text="Pausar", style="Secondary.TButton", command=self.on_pause)
        self.pause_button.pack(side="left")
        self.resume_button = ttk.Button(controls, text="Reanudar", style="Secondary.TButton", command=self.on_resume)
        self.resume_button.pack(side="left", padx=8)
        self.stop_button = ttk.Button(controls, text="Detener", style="Primary.TButton", command=self.on_stop)
        self.stop_button.pack(side="left")

        status_bar = ttk.Frame(outer, style="Card.TFrame")
        status_bar.pack(fill="x", pady=(14, 16))

        self.interface_value = self._build_status_card(status_bar, "Interfaz seleccionada", "N/D")
        self.mikrotik_value = self._build_status_card(status_bar, "Estado de MikroTik", "Desconectado")
        self.capture_value = self._build_status_card(status_bar, "Estado de captura", "En ejecución")

        split = ttk.Panedwindow(outer, orient="vertical")
        split.pack(fill="both", expand=True)

        content_panel = ttk.Frame(split, style="Panel.TFrame", padding=12)
        logs_panel = ttk.Frame(split, style="Panel.TFrame", padding=12)
        split.add(content_panel, weight=4)
        split.add(logs_panel, weight=1)

        notebook = ttk.Notebook(content_panel)
        notebook.pack(fill="both", expand=True)

        packets_panel = ttk.Frame(notebook, style="Panel.TFrame", padding=12)
        alerts_panel = ttk.Frame(notebook, style="Panel.TFrame", padding=12)
        events_panel = ttk.Frame(notebook, style="Panel.TFrame", padding=12)
        hosts_panel = ttk.Frame(notebook, style="Panel.TFrame", padding=12)
        notebook.add(packets_panel, text="Tráfico")
        notebook.add(alerts_panel, text="Alertas activas")
        notebook.add(events_panel, text="Historial de eventos")
        notebook.add(hosts_panel, text="Equipos")

        ttk.Label(packets_panel, text="Tráfico en vivo", style="Body.TLabel").pack(anchor="w", pady=(0, 8))

        table_wrap = ttk.Frame(packets_panel, style="Panel.TFrame")
        table_wrap.pack(fill="both", expand=True)

        columns = ("number", "time", "source", "destination", "protocol", "length", "info")
        self.tree = ttk.Treeview(table_wrap, columns=columns, show="headings")
        headings = {
            "number": "No.",
            "time": "Hora",
            "source": "Origen",
            "destination": "Destino",
            "protocol": "Protocolo",
            "length": "Longitud",
            "info": "Información",
        }
        widths = {
            "number": 70,
            "time": 95,
            "source": 180,
            "destination": 180,
            "protocol": 90,
            "length": 80,
            "info": 540,
        }
        anchors = {
            "number": "center",
            "time": "center",
            "source": "w",
            "destination": "w",
            "protocol": "center",
            "length": "center",
            "info": "w",
        }
        for column in columns:
            self.tree.heading(column, text=headings[column])
            self.tree.column(column, width=widths[column], anchor=anchors[column], stretch=column == "info")

        self.tree.pack(side="left", fill="both", expand=True)
        yscroll = ttk.Scrollbar(table_wrap, orient="vertical", command=self.tree.yview)
        yscroll.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=yscroll.set)

        self.tree.tag_configure("TCP", background="#eff6ff", foreground="#172554")
        self.tree.tag_configure("UDP", background="#eef2ff", foreground="#312e81")
        self.tree.tag_configure("ARP", background="#f0fdf4", foreground="#14532d")
        self.tree.tag_configure("ICMP", background="#fefce8", foreground="#713f12")
        self.tree.tag_configure("OTHER", background="#ffffff", foreground="#0f172a")

        ttk.Label(alerts_panel, text="Alertas de seguridad activas", style="Body.TLabel").pack(anchor="w", pady=(0, 8))
        alerts_wrap = ttk.Frame(alerts_panel, style="Panel.TFrame")
        alerts_wrap.pack(fill="both", expand=True)

        alert_columns = ("time", "severity", "type", "attacker", "victim", "victim_mac", "status", "count")
        self.alerts_tree = ttk.Treeview(alerts_wrap, columns=alert_columns, show="headings")
        alert_headings = {
            "time": "Última actividad",
            "severity": "Severidad",
            "type": "Tipo de ataque",
            "attacker": "Atacante",
            "victim": "Víctima",
            "victim_mac": "MAC víctima",
            "status": "Estado",
            "count": "Eventos",
        }
        alert_widths = {
            "time": 100,
            "severity": 105,
            "type": 160,
            "attacker": 155,
            "victim": 155,
            "victim_mac": 180,
            "status": 120,
            "count": 80,
        }
        for column in alert_columns:
            self.alerts_tree.heading(column, text=alert_headings[column])
            self.alerts_tree.column(column, width=alert_widths[column], anchor="center")
        self.alerts_tree.pack(side="left", fill="both", expand=True)
        alerts_scroll = ttk.Scrollbar(alerts_wrap, orient="vertical", command=self.alerts_tree.yview)
        alerts_scroll.pack(side="right", fill="y")
        self.alerts_tree.configure(yscrollcommand=alerts_scroll.set)
        self.alerts_tree.tag_configure("critical", background="#fee2e2", foreground="#7f1d1d")
        self.alerts_tree.tag_configure("warning", background="#ffedd5", foreground="#7c2d12")
        self.alerts_tree.tag_configure("suspicious", background="#fef3c7", foreground="#713f12")
        self.alerts_tree.tag_configure("resolved", background="#dcfce7", foreground="#14532d")
        self.alerts_tree.tag_configure("failed", background="#fce7f3", foreground="#831843")

        ttk.Label(events_panel, text="Historial de eventos", style="Body.TLabel").pack(anchor="w", pady=(0, 8))
        events_wrap = ttk.Frame(events_panel, style="Panel.TFrame")
        events_wrap.pack(fill="both", expand=True)

        event_columns = ("timestamp", "type", "attacker", "victim", "status")
        self.events_tree = ttk.Treeview(events_wrap, columns=event_columns, show="headings")
        event_headings = {
            "timestamp": "Fecha y hora",
            "type": "Tipo",
            "attacker": "Atacante",
            "victim": "Víctima",
            "status": "Estado",
        }
        event_widths = {
            "timestamp": 190,
            "type": 180,
            "attacker": 180,
            "victim": 180,
            "status": 130,
        }
        for column in event_columns:
            self.events_tree.heading(column, text=event_headings[column])
            self.events_tree.column(column, width=event_widths[column], anchor="center")
        self.events_tree.pack(side="left", fill="both", expand=True)
        events_scroll = ttk.Scrollbar(events_wrap, orient="vertical", command=self.events_tree.yview)
        events_scroll.pack(side="right", fill="y")
        self.events_tree.configure(yscrollcommand=events_scroll.set)
        self.events_tree.tag_configure("blocked", background="#fee2e2", foreground="#7f1d1d")
        self.events_tree.tag_configure("detected", background="#fef3c7", foreground="#713f12")
        self.events_tree.tag_configure("resolved", background="#dcfce7", foreground="#14532d")
        self.events_tree.tag_configure("failed", background="#fce7f3", foreground="#831843")

        hosts_header = ttk.Frame(hosts_panel, style="Panel.TFrame")
        hosts_header.pack(fill="x", pady=(0, 8))
        ttk.Label(hosts_header, text="Equipos detectados", style="Body.TLabel").pack(side="left")
        self.block_button = ttk.Button(
            hosts_header,
            text="Bloquear seleccionado",
            style="Primary.TButton",
            command=self._request_block,
            state="disabled",
        )
        self.block_button.pack(side="right", padx=(0, 8))
        self.unblock_button = ttk.Button(
            hosts_header,
            text="Desbloquear seleccionado",
            style="Secondary.TButton",
            command=self._request_unblock,
            state="disabled",
        )
        self.unblock_button.pack(side="right")

        hosts_wrap = ttk.Frame(hosts_panel, style="Panel.TFrame")
        hosts_wrap.pack(fill="both", expand=True)

        host_columns = ("ip", "mac", "status", "attack_type", "last_seen")
        self.hosts_tree = ttk.Treeview(hosts_wrap, columns=host_columns, show="headings")
        host_headings = {
            "ip": "IP",
            "mac": "MAC",
            "status": "Estado",
            "attack_type": "Tipo de ataque",
            "last_seen": "Última actividad",
        }
        host_widths = {
            "ip": 180,
            "mac": 190,
            "status": 120,
            "attack_type": 140,
            "last_seen": 150,
        }
        for column in host_columns:
            self.hosts_tree.heading(column, text=host_headings[column])
            self.hosts_tree.column(column, width=host_widths[column], anchor="center")

        self.hosts_tree.pack(side="left", fill="both", expand=True)
        hosts_scroll = ttk.Scrollbar(hosts_wrap, orient="vertical", command=self.hosts_tree.yview)
        hosts_scroll.pack(side="right", fill="y")
        self.hosts_tree.configure(yscrollcommand=hosts_scroll.set)
        self.hosts_tree.tag_configure("active", background="#dcfce7", foreground="#14532d")
        self.hosts_tree.tag_configure("blocked", background="#fee2e2", foreground="#7f1d1d")
        self.hosts_tree.tag_configure("suspicious", background="#fef3c7", foreground="#713f12")
        self.hosts_tree.bind("<<TreeviewSelect>>", self._on_host_selected)

        ttk.Label(logs_panel, text="Registros del sistema", style="Body.TLabel").pack(anchor="w", pady=(0, 8))

        self.log_text = ScrolledText(
            logs_panel,
            height=8,
            bg="#ffffff",
            fg="#0f172a",
            insertbackground="#0f172a",
            relief="flat",
            font=("Consolas", 10),
        )
        self.log_text.pack(fill="both", expand=True)
        self.log_text.configure(state="disabled")
        self.log_text.tag_configure("info", foreground="#334155")
        self.log_text.tag_configure("warning", foreground="#b45309")
        self.log_text.tag_configure("alert", foreground="#dc2626")
        self.log_text.tag_configure("error", foreground="#be123c")

    def _build_status_card(self, parent, title, value):
        card = ttk.Frame(parent, style="Panel.TFrame", padding=12)
        card.pack(side="left", fill="x", expand=True, padx=(0, 10))
        ttk.Label(card, text=title, style="Muted.TLabel").pack(anchor="w")
        value_label = ttk.Label(card, text=value, style="StatusValue.TLabel")
        value_label.pack(anchor="w", pady=(4, 0))
        return value_label

    def set_interface(self, interface_name, ip_address):
        self.interface_value.configure(text=f"{interface_name} | {ip_address}")

    def set_mikrotik_status(self, text, connected):
        self.mikrotik_value.configure(text=text)
        self.mikrotik_value.configure(foreground="#15803d" if connected else "#dc2626")

    def set_capture_state(self, paused=False, stopped=False):
        if stopped:
            self.set_capture_status("Detenido")
            self.pause_button.configure(state="disabled")
            self.resume_button.configure(state="disabled")
            self.stop_button.configure(state="disabled")
            return

        if paused:
            self.set_capture_status("Pausado")
            self.pause_button.configure(state="disabled")
            self.resume_button.configure(state="normal")
        else:
            self.set_capture_status("En ejecución")
            self.pause_button.configure(state="normal")
            self.resume_button.configure(state="disabled")
        self.stop_button.configure(state="normal")

    def set_capture_status(self, text):
        self.capture_value.configure(text=text)

    def add_packet(self, packet_record):
        item_id = self.tree.insert(
            "",
            "end",
            values=(
                packet_record.number,
                packet_record.time,
                packet_record.source,
                packet_record.destination,
                packet_record.protocol,
                packet_record.length,
                packet_record.info,
            ),
            tags=(packet_record.protocol if packet_record.protocol in {"TCP", "UDP", "ARP", "ICMP"} else "OTHER",),
        )
        self.packet_rows.append(item_id)

        while len(self.packet_rows) > self.MAX_ROWS:
            oldest = self.packet_rows.popleft()
            self.tree.delete(oldest)

        self.tree.yview_moveto(1.0)

    def _on_host_selected(self, _event=None):
        if self.on_unblock_host is None and self.on_block_host is None:
            self.unblock_button.configure(state="disabled")
            self.block_button.configure(state="disabled")
            return

        if self.on_unblock_host is None:
            self.unblock_button.configure(state="disabled")
        if self.on_block_host is None:
            self.block_button.configure(state="disabled")

        selected_ip = self.get_selected_host_ip()
        if selected_ip is None:
            self.unblock_button.configure(state="disabled")
            self.block_button.configure(state="disabled")
            return

        selected_host = self.host_state_by_ip.get(selected_ip, {})
        is_blocked = bool(selected_host.get("is_blocked", False))
        if self.on_block_host is not None:
            self.block_button.configure(state="disabled" if is_blocked else "normal")
        self.unblock_button.configure(state="normal" if is_blocked else "disabled")

    def _request_block(self):
        selected_ip = self.get_selected_host_ip()
        if selected_ip and self.on_block_host is not None:
            self.on_block_host(selected_ip)

    def _request_unblock(self):
        selected_ip = self.get_selected_host_ip()
        if selected_ip and self.on_unblock_host is not None:
            self.on_unblock_host(selected_ip)

    def get_selected_host_ip(self):
        selection = self.hosts_tree.selection()
        if not selection:
            return None
        values = self.hosts_tree.item(selection[0], "values")
        return str(values[0]).strip() if values else None

    def update_hosts(self, hosts):
        selected_ip = self.get_selected_host_ip()
        self.host_state_by_ip = {}
        for item in self.hosts_tree.get_children():
            self.hosts_tree.delete(item)

        for host in hosts:
            status = str(host.get("status", "active")).strip().lower()
            ip_address = host.get("ip", "N/D")
            self.host_state_by_ip[str(ip_address).strip()] = dict(host)
            is_blocked = bool(host.get("is_blocked", False))
            display_status = self._translate_status(host.get("display_status") or status)
            attack_type = host.get("attack_type")
            if attack_type:
                attack_type = self._translate_attack_type(attack_type)
            self.hosts_tree.insert(
                "",
                "end",
                values=(
                    ip_address,
                    self._translate_placeholder(host.get("mac", "unknown")),
                    display_status,
                    attack_type or "-",
                    host.get("last_seen", "-"),
                ),
                tags=(("blocked" if is_blocked else status) if (is_blocked or status in {"active", "suspicious"}) else "active",),
            )

        if selected_ip:
            for item in self.hosts_tree.get_children():
                values = self.hosts_tree.item(item, "values")
                if values and str(values[0]).strip() == selected_ip:
                    self.hosts_tree.selection_set(item)
                    self.hosts_tree.focus(item)
                    break

        self._on_host_selected()

    def update_active_alerts(self, alerts):
        for item in self.alerts_tree.get_children():
            self.alerts_tree.delete(item)

        for alert in alerts:
            status = str(alert.get("status", "active")).strip().lower()
            severity = str(alert.get("severity", "suspicious")).strip().lower()
            tag = "resolved" if status in {"resolved", "unblocked", "mitigated"} else severity
            if "failed" in status:
                tag = "failed"
            self.alerts_tree.insert(
                "",
                "end",
                values=(
                    alert.get("timestamp", "-"),
                    self._translate_severity(severity).upper(),
                    self._translate_attack_type(alert.get("type", "Unknown")),
                    self._translate_placeholder(alert.get("attacker", "unknown")),
                    self._translate_placeholder(alert.get("victim", "unknown")),
                    self._translate_placeholder(alert.get("victim_mac", "unknown")),
                    self._translate_status(status).upper(),
                    alert.get("count", 1),
                ),
                tags=(tag,),
            )

    def update_event_history(self, events):
        for item in self.events_tree.get_children():
            self.events_tree.delete(item)

        for event in events:
            status = str(event.get("status", "unknown")).strip().lower()
            if "fail" in status:
                tag = "failed"
            elif "block" in status or "mitigat" in status:
                tag = "blocked"
            elif "resolv" in status or "unblock" in status:
                tag = "resolved"
            else:
                tag = "detected"
            self.events_tree.insert(
                "",
                "end",
                values=(
                    event.get("timestamp", "-"),
                    self._translate_attack_type(event.get("type", "Unknown")),
                    self._translate_placeholder(event.get("attacker", "unknown")),
                    self._translate_placeholder(event.get("victim", "unknown")),
                    self._translate_status(event.get("status", "unknown")),
                ),
                tags=(tag,),
            )

    def append_log(self, message, level="info"):
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{timestamp}] {message}\n", level)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")
