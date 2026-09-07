from tkinter import StringVar, ttk


class RouterConfigView(ttk.Frame):
    def __init__(self, parent, interface_info, defaults, on_accept, on_cancel):
        super().__init__(parent, style="App.TFrame")
        self.on_accept = on_accept
        self.on_cancel = on_cancel
        self.message_var = StringVar(value="")

        self.host_var = StringVar(value=getattr(defaults, "host", "") or "")
        self.username_var = StringVar(value=getattr(defaults, "username", "") or "")
        self.password_var = StringVar(value="" if getattr(defaults, "password", None) is None else str(defaults.password))
        self.port_var = StringVar(value=str(getattr(defaults, "port", 8728) or 8728))

        self._build_layout(interface_info)

    def _build_layout(self, interface_info):
        card = ttk.Frame(self, style="Card.TFrame", padding=24)
        card.pack(fill="both", expand=True)

        ttk.Label(card, text="Configuración del router", style="SectionTitle.TLabel").pack(anchor="w")
        ttk.Label(
            card,
            text=f"Interfaz seleccionada: {interface_info.name} | {interface_info.ip_address}",
            style="Muted.TLabel",
        ).pack(anchor="w", pady=(6, 20))

        form = ttk.Frame(card, style="Card.TFrame")
        form.pack(fill="x")
        form.columnconfigure(1, weight=1)

        fields = [
            ("IP de MikroTik", self.host_var, False),
            ("Usuario", self.username_var, False),
            ("Contraseña", self.password_var, True),
            ("Puerto API", self.port_var, False),
        ]

        for row_index, (label_text, variable, is_password) in enumerate(fields):
            ttk.Label(form, text=label_text, style="Body.TLabel").grid(row=row_index, column=0, sticky="w", pady=8, padx=(0, 14))
            entry = ttk.Entry(form, textvariable=variable, show="*" if is_password else "")
            entry.grid(row=row_index, column=1, sticky="ew", pady=8)

        ttk.Label(
            card,
            textvariable=self.message_var,
            style="Muted.TLabel",
            wraplength=900,
            justify="left",
        ).pack(anchor="w", pady=(18, 0))

        buttons = ttk.Frame(card, style="Card.TFrame")
        buttons.pack(fill="x", pady=(24, 0))

        self.cancel_button = ttk.Button(buttons, text="Cancelar", style="Secondary.TButton", command=self.on_cancel)
        self.cancel_button.pack(side="right")

        self.accept_button = ttk.Button(buttons, text="Aceptar", style="Primary.TButton", command=self._submit)
        self.accept_button.pack(side="right", padx=(0, 10))

    def _submit(self):
        self.on_accept(
            {
                "host": self.host_var.get(),
                "username": self.username_var.get(),
                "password": self.password_var.get(),
                "port": self.port_var.get(),
            }
        )

    def set_message(self, message, is_error=False):
        prefix = "Error: " if is_error and message else ""
        self.message_var.set(f"{prefix}{message}" if message else "")

    def set_busy(self, busy, message, keep_cancel_enabled=True):
        self.accept_button.configure(state="disabled" if busy else "normal")
        self.cancel_button.configure(state="normal" if keep_cancel_enabled else ("disabled" if busy else "normal"))
        self.set_message(message, is_error=False)
