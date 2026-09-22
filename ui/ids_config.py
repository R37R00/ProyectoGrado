import tkinter as tk
from tkinter import ttk


class IDSConfigView(ttk.Frame):
    def __init__(self, parent, config, on_save, on_cancel):
        super().__init__(parent, style="App.TFrame")

        self.config = config
        self.on_save = on_save
        self.on_cancel = on_cancel

        self.message_var = tk.StringVar(value="")

        self.arp_window_var = tk.StringVar()
        self.arp_threshold_var = tk.StringVar()

        self.port_window_var = tk.StringVar()
        self.port_threshold_var = tk.StringVar()

        self.dos_window_var = tk.StringVar()
        self.dos_cooldown_var = tk.StringVar()
        self.dos_events_var = tk.StringVar()
        self.dos_reset_var = tk.StringVar()

        self.icmp_alert_pps_var = tk.StringVar()
        self.icmp_block_pps_var = tk.StringVar()
        self.icmp_block_bps_var = tk.StringVar()

        self.syn_alert_pps_var = tk.StringVar()
        self.syn_block_pps_var = tk.StringVar()
        self.syn_block_bps_var = tk.StringVar()

        self.mitigation_enabled_var = tk.BooleanVar()
        self.periodic_enabled_var = tk.BooleanVar()
        self.lock_gateway_enabled_var = tk.BooleanVar()
        self.aggressive_mode_var = tk.BooleanVar()

        self._load_config_values()
        self._build_layout()

    def _load_config_values(self):
        arp_config = self.config.get("arp", {})
        port_scan_config = self.config.get("port_scan", {})
        dos_config = self.config.get("dos", {})
        mitigation_config = self.config.get("arp_mitigation", {})

        icmp_config = dos_config.get("profiles", {}).get("icmp_flood", {})
        syn_config = dos_config.get("profiles", {}).get("syn_flood", {})

        self.arp_window_var.set(str(arp_config.get("suspicion_window_s", "")))
        self.arp_threshold_var.set(str(arp_config.get("suspicion_threshold", "")))

        self.port_window_var.set(str(port_scan_config.get("window_s", "")))
        self.port_threshold_var.set(str(port_scan_config.get("threshold", "")))

        self.dos_window_var.set(str(dos_config.get("window_s", "")))
        self.dos_cooldown_var.set(str(dos_config.get("alert_cooldown_s", "")))
        self.dos_events_var.set(str(dos_config.get("min_suspicious_events", "")))
        self.dos_reset_var.set(str(dos_config.get("event_reset_s", "")))

        self.icmp_alert_pps_var.set(str(icmp_config.get("alert_pps", "")))
        self.icmp_block_pps_var.set(str(icmp_config.get("block_pps", "")))
        self.icmp_block_bps_var.set(str(icmp_config.get("block_bps", "")))

        self.syn_alert_pps_var.set(str(syn_config.get("alert_pps", "")))
        self.syn_block_pps_var.set(str(syn_config.get("block_pps", "")))
        self.syn_block_bps_var.set(str(syn_config.get("block_bps", "")))

        self.mitigation_enabled_var.set(
            bool(mitigation_config.get("enabled", True))
        )
        self.periodic_enabled_var.set(
            bool(mitigation_config.get("periodic_enabled", False))
        )
        self.lock_gateway_enabled_var.set(
            bool(mitigation_config.get("lock_gateway_enabled", False))
        )
        self.aggressive_mode_var.set(
            bool(mitigation_config.get("aggressive_mode", False))
        )

    def _build_layout(self):
        outer = ttk.Frame(self, style="Card.TFrame", padding=18)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer, style="Card.TFrame")
        header.pack(fill="x")

        ttk.Label(
            header,
            text="Configuración del sistema de detección",
            style="SectionTitle.TLabel",
        ).pack(anchor="w")

        ttk.Label(
            header,
            text=(
                "Ajusta los criterios de detección y las opciones de "
                "mitigación sin modificar la lógica del sistema."
            ),
            style="Muted.TLabel",
            wraplength=1050,
            justify="left",
        ).pack(anchor="w", pady=(6, 12))

        # Área desplazable para las opciones de configuración.
        content_container = ttk.Frame(
            outer,
            style="Panel.TFrame",
        )
        content_container.pack(
            fill="both",
            expand=True,
        )

        canvas = tk.Canvas(
            content_container,
            highlightthickness=0,
            borderwidth=0,
        )
        scrollbar = ttk.Scrollbar(
            content_container,
            orient="vertical",
            command=canvas.yview,
        )

        content = ttk.Frame(
            canvas,
            style="Panel.TFrame",
            padding=14,
        )

        content_window = canvas.create_window(
            (0, 0),
            window=content,
            anchor="nw",
        )

        canvas.configure(
            yscrollcommand=scrollbar.set,
        )

        canvas.pack(
            side="left",
            fill="both",
            expand=True,
        )

        scrollbar.pack(
            side="right",
            fill="y",
        )

        def _update_scroll_region(_event=None):
            canvas.configure(
                scrollregion=canvas.bbox("all"),
            )

        def _resize_content(event):
            canvas.itemconfigure(
                content_window,
                width=event.width,
            )

        content.bind(
            "<Configure>",
            _update_scroll_region,
        )

        canvas.bind(
            "<Configure>",
            _resize_content,
        )

        self._build_detection_section(content)
        self._build_dos_section(content)
        self._build_mitigation_section(content)

        footer = ttk.Frame(
            outer,
            style="Card.TFrame",
        )
        footer.pack(
            fill="x",
            pady=(12, 0),
        )

        ttk.Label(
            footer,
            textvariable=self.message_var,
            style="Muted.TLabel",
        ).pack(side="left")

        ttk.Button(
            footer,
            text="Volver",
            style="Secondary.TButton",
            command=self.on_cancel,
        ).pack(side="right")

        ttk.Button(
            footer,
            text="Guardar y aplicar",
            style="Primary.TButton",
            command=self._submit,
        ).pack(side="right", padx=(0, 10))

    def _build_detection_section(self, parent):
        detection_frame = ttk.Frame(parent, style="Panel.TFrame")
        detection_frame.pack(fill="x", pady=(0, 12))

        arp_frame = ttk.LabelFrame(
            detection_frame,
            text="ARP",
            style="Card.TLabelframe",
            padding=12,
        )
        arp_frame.pack(side="left", fill="both", expand=True, padx=(0, 6))

        self._add_entry_field(
            arp_frame,
            0,
            "Ventana de sospecha (s)",
            self.arp_window_var,
        )
        self._add_entry_field(
            arp_frame,
            1,
            "Umbral de sospecha",
            self.arp_threshold_var,
        )

        port_frame = ttk.LabelFrame(
            detection_frame,
            text="Port Scan",
            style="Card.TLabelframe",
            padding=12,
        )
        port_frame.pack(side="left", fill="both", expand=True, padx=(6, 0))

        self._add_entry_field(
            port_frame,
            0,
            "Ventana (s)",
            self.port_window_var,
        )
        self._add_entry_field(
            port_frame,
            1,
            "Umbral de puertos",
            self.port_threshold_var,
        )

    def _build_dos_section(self, parent):
        dos_frame = ttk.LabelFrame(
            parent,
            text="DoS",
            style="Card.TLabelframe",
            padding=12,
        )
        dos_frame.pack(fill="x", pady=(0, 12))

        general_frame = ttk.Frame(dos_frame, style="Card.TLabelframe")
        general_frame.pack(fill="x")

        self._add_entry_field(
            general_frame,
            0,
            "Ventana (s)",
            self.dos_window_var,
        )
        self._add_entry_field(
            general_frame,
            1,
            "Cooldown de alerta (s)",
            self.dos_cooldown_var,
        )
        self._add_entry_field(
            general_frame,
            2,
            "Eventos sospechosos mínimos",
            self.dos_events_var,
        )
        self._add_entry_field(
            general_frame,
            3,
            "Reinicio del estado (s)",
            self.dos_reset_var,
        )

        profiles_frame = ttk.Frame(dos_frame, style="Card.TLabelframe")
        profiles_frame.pack(fill="x", pady=(12, 0))

        icmp_frame = ttk.LabelFrame(
            profiles_frame,
            text="ICMP Flood",
            style="Card.TLabelframe",
            padding=12,
        )
        icmp_frame.pack(side="left", fill="both", expand=True, padx=(0, 6))

        self._add_entry_field(
            icmp_frame,
            0,
            "Alert PPS",
            self.icmp_alert_pps_var,
        )
        self._add_entry_field(
            icmp_frame,
            1,
            "Block PPS",
            self.icmp_block_pps_var,
        )
        self._add_entry_field(
            icmp_frame,
            2,
            "Block BPS",
            self.icmp_block_bps_var,
        )

        syn_frame = ttk.LabelFrame(
            profiles_frame,
            text="SYN Flood",
            style="Card.TLabelframe",
            padding=12,
        )
        syn_frame.pack(side="left", fill="both", expand=True, padx=(6, 0))

        self._add_entry_field(
            syn_frame,
            0,
            "Alert PPS",
            self.syn_alert_pps_var,
        )
        self._add_entry_field(
            syn_frame,
            1,
            "Block PPS",
            self.syn_block_pps_var,
        )
        self._add_entry_field(
            syn_frame,
            2,
            "Block BPS",
            self.syn_block_bps_var,
        )

    def _build_mitigation_section(self, parent):
        mitigation_frame = ttk.LabelFrame(
            parent,
            text="Mitigación ARP",
            style="Card.TLabelframe",
            padding=12,
        )
        mitigation_frame.pack(fill="x")

        ttk.Checkbutton(
            mitigation_frame,
            text="Habilitada",
            variable=self.mitigation_enabled_var,
        ).pack(anchor="w", pady=3)

        ttk.Checkbutton(
            mitigation_frame,
            text="Mitigación periódica",
            variable=self.periodic_enabled_var,
        ).pack(anchor="w", pady=3)

        ttk.Checkbutton(
            mitigation_frame,
            text="Bloquear gateway",
            variable=self.lock_gateway_enabled_var,
        ).pack(anchor="w", pady=3)

        ttk.Checkbutton(
            mitigation_frame,
            text="Modo agresivo",
            variable=self.aggressive_mode_var,
        ).pack(anchor="w", pady=3)

    def _add_entry_field(self, parent, row, label_text, variable):
        parent.columnconfigure(1, weight=1)

        ttk.Label(
            parent,
            text=label_text,
            style="Body.TLabel",
        ).grid(
            row=row,
            column=0,
            sticky="w",
            padx=(0, 12),
            pady=6,
        )

        entry = ttk.Entry(
            parent,
            textvariable=variable,
            width=14,
        )
        entry.grid(
            row=row,
            column=1,
            sticky="ew",
            pady=6,
        )

    def _submit(self):
        try:
            config = self._build_config_from_fields()
        except ValueError as error:
            self.set_message(str(error), is_error=True)
            return

        self.on_save(config)

    def _build_config_from_fields(self):
        arp_window = self._positive_float(
            self.arp_window_var.get(),
            "La ventana de sospecha de ARP debe ser mayor que 0.",
        )
        arp_threshold = self._positive_int(
            self.arp_threshold_var.get(),
            "El umbral de sospecha de ARP debe ser un entero mayor que 0.",
        )

        port_window = self._positive_float(
            self.port_window_var.get(),
            "La ventana de Port Scan debe ser mayor que 0.",
        )
        port_threshold = self._positive_int(
            self.port_threshold_var.get(),
            "El umbral de Port Scan debe ser un entero mayor que 0.",
        )

        dos_window = self._positive_float(
            self.dos_window_var.get(),
            "La ventana de DoS debe ser mayor que 0.",
        )
        dos_cooldown = self._non_negative_float(
            self.dos_cooldown_var.get(),
            "El cooldown de alerta de DoS debe ser mayor o igual a 0.",
        )
        dos_events = self._positive_int(
            self.dos_events_var.get(),
            "Los eventos sospechosos mínimos deben ser un entero mayor que 0.",
        )
        dos_reset = self._positive_float(
            self.dos_reset_var.get(),
            "El reinicio del estado de DoS debe ser mayor que 0.",
        )

        icmp_alert_pps = self._non_negative_float(
            self.icmp_alert_pps_var.get(),
            "Alert PPS de ICMP debe ser mayor o igual a 0.",
        )
        icmp_block_pps = self._non_negative_float(
            self.icmp_block_pps_var.get(),
            "Block PPS de ICMP debe ser mayor o igual a 0.",
        )
        icmp_block_bps = self._non_negative_float(
            self.icmp_block_bps_var.get(),
            "Block BPS de ICMP debe ser mayor o igual a 0.",
        )

        syn_alert_pps = self._non_negative_float(
            self.syn_alert_pps_var.get(),
            "Alert PPS de SYN debe ser mayor o igual a 0.",
        )
        syn_block_pps = self._non_negative_float(
            self.syn_block_pps_var.get(),
            "Block PPS de SYN debe ser mayor o igual a 0.",
        )
        syn_block_bps = self._non_negative_float(
            self.syn_block_bps_var.get(),
            "Block BPS de SYN debe ser mayor o igual a 0.",
        )

        config = {
            "arp": {
                "suspicion_window_s": arp_window,
                "suspicion_threshold": arp_threshold,
            },
            "port_scan": {
                "window_s": port_window,
                "threshold": port_threshold,
            },
            "dos": {
                "window_s": dos_window,
                "alert_cooldown_s": dos_cooldown,
                "min_suspicious_events": dos_events,
                "event_reset_s": dos_reset,
                "profiles": {
                    "icmp_flood": {
                        "alert_pps": icmp_alert_pps,
                        "block_pps": icmp_block_pps,
                        "block_bps": icmp_block_bps,
                    },
                    "syn_flood": {
                        "alert_pps": syn_alert_pps,
                        "block_pps": syn_block_pps,
                        "block_bps": syn_block_bps,
                    },
                },
            },
            "arp_mitigation": {
                "enabled": self.mitigation_enabled_var.get(),
                "periodic_enabled": self.periodic_enabled_var.get(),
                "lock_gateway_enabled": self.lock_gateway_enabled_var.get(),
                "aggressive_mode": self.aggressive_mode_var.get(),
            },
        }

        return config

    @staticmethod
    def _positive_float(value, error_message):
        try:
            number = float(value)
        except (TypeError, ValueError):
            raise ValueError(error_message)

        if number <= 0:
            raise ValueError(error_message)

        return number

    @staticmethod
    def _positive_int(value, error_message):
        try:
            number = int(value)
        except (TypeError, ValueError):
            raise ValueError(error_message)

        if number <= 0:
            raise ValueError(error_message)

        return number

    @staticmethod
    def _non_negative_float(value, error_message):
        try:
            number = float(value)
        except (TypeError, ValueError):
            raise ValueError(error_message)

        if number < 0:
            raise ValueError(error_message)

        return number

    def set_message(self, message, is_error=False):
        prefix = "Error: " if is_error and message else ""
        self.message_var.set(f"{prefix}{message}" if message else "")