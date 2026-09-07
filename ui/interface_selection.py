import tkinter as tk
from tkinter import ttk


class InterfaceSelectionView(ttk.Frame):
    def __init__(self, parent, on_continue, on_refresh):
        super().__init__(parent, style="App.TFrame")
        self.on_continue = on_continue
        self.on_refresh = on_refresh
        self.interface_index = {}

        self._build_layout()

    def _build_layout(self):
        hero = ttk.Frame(self, style="Card.TFrame", padding=22)
        hero.pack(fill="both", expand=True)

        ttk.Label(hero, text="Seleccionar interfaz de captura", style="SectionTitle.TLabel").pack(anchor="w")
        ttk.Label(
            hero,
            text="Elige el adaptador de red que deseas monitorear. La vista está optimizada para revisión rápida y selección con doble clic, similar a Wireshark.",
            style="Muted.TLabel",
            wraplength=1020,
            justify="left",
        ).pack(anchor="w", pady=(6, 18))

        table_frame = ttk.Frame(hero, style="Panel.TFrame", padding=14)
        table_frame.pack(fill="both", expand=True)

        columns = ("name", "description", "ip")
        self.tree = ttk.Treeview(table_frame, columns=columns, show="headings", height=18)
        self.tree.heading("name", text="Interfaz")
        self.tree.heading("description", text="Descripción")
        self.tree.heading("ip", text="Dirección IP")
        self.tree.column("name", width=300, anchor="w")
        self.tree.column("description", width=560, anchor="w")
        self.tree.column("ip", width=180, anchor="center")
        self.tree.pack(side="left", fill="both", expand=True)

        scrollbar = ttk.Scrollbar(table_frame, orient="vertical", command=self.tree.yview)
        scrollbar.pack(side="right", fill="y")
        self.tree.configure(yscrollcommand=scrollbar.set)

        self.tree.bind("<<TreeviewSelect>>", self._update_selection_state)
        self.tree.bind("<Double-1>", self._handle_double_click)

        footer = ttk.Frame(hero, style="Card.TFrame")
        footer.pack(fill="x", pady=(16, 0))

        self.selection_label = ttk.Label(footer, text="No hay ninguna interfaz seleccionada.", style="Muted.TLabel")
        self.selection_label.pack(side="left")

        ttk.Button(footer, text="Actualizar", style="Secondary.TButton", command=self.on_refresh).pack(side="right")
        self.continue_button = ttk.Button(
            footer,
            text="Continuar",
            style="Primary.TButton",
            command=self._submit_selection,
            state="disabled",
        )
        self.continue_button.pack(side="right", padx=(0, 10))

    def populate_interfaces(self, interfaces):
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.interface_index.clear()

        for index, interface in enumerate(interfaces):
            item_id = f"iface-{index}"
            self.interface_index[item_id] = interface
            self.tree.insert(
                "",
                "end",
                iid=item_id,
                values=(interface.name, interface.description, interface.ip_address),
            )

        if interfaces:
            first_id = next(iter(self.interface_index))
            self.tree.selection_set(first_id)
            self.tree.focus(first_id)
            self.tree.see(first_id)
            self._update_selection_state()
        else:
            self.selection_label.configure(text="No se detectaron interfaces en este sistema.")
            self.continue_button.configure(state="disabled")

    def _selected_interface(self):
        selection = self.tree.selection()
        if not selection:
            return None
        return self.interface_index.get(selection[0])

    def _update_selection_state(self, _event=None):
        interface = self._selected_interface()
        if interface is None:
            self.selection_label.configure(text="No hay ninguna interfaz seleccionada.")
            self.continue_button.configure(state="disabled")
            return

        self.selection_label.configure(
            text=f"Seleccionada: {interface.name} | IP {interface.ip_address}"
        )
        self.continue_button.configure(state="normal")

    def _handle_double_click(self, _event):
        self._submit_selection()

    def _submit_selection(self):
        interface = self._selected_interface()
        if interface is not None:
            self.on_continue(interface)
