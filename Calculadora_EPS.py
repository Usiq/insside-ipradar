from PyQt5.QtWidgets import (QApplication, QWidget, QLabel, QLineEdit, QPushButton,
                             QVBoxLayout, QHBoxLayout, QGridLayout, QMessageBox, QScrollArea, QGroupBox, QFileDialog)
from PyQt5.QtGui import QFont, QIcon, QPixmap, QPalette, QColor
from PyQt5.QtCore import Qt
import sys
import os
from datetime import datetime

class EPSCalculator(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Calculadora de EPS para QRadar")
        self.setWindowIcon(QIcon("icon.png"))
        self.setStyleSheet("""
            QWidget {
                font-family: Segoe UI, sans-serif;
                font-size: 12pt;
                background-color: #0d1b2a;
                color: #ffffff;
            }
            QLabel {
                font-size: 11pt;
            }
            QLineEdit {
                padding: 6px;
                border-radius: 6px;
                border: 1px solid #ccc;
                background-color: #ffffff;
                color: #000000;
            }
            QPushButton {
                background-color: #0078d7;
                color: white;
                padding: 8px 12px;
                border: none;
                border-radius: 6px;
            }
            QPushButton:hover {
                background-color: #005fa1;
            }
        """)

        self.resize(650, 750)

        self.categorias_config = {
            "High Volume Core Systems": {"type": "device_based", "eps_base": 300, "desc": "Core Firewalls, Ingress Proxies, Core UTM Firewalls, etc"},
            "Medium Volume Core Systems": {"type": "device_based", "eps_base": 75, "desc": "Outbound Proxies, Egress Web Filtering, Web/Mail Security Gateways, Edge/Small Firewalls/UTM"},
            "Typical Security Infrastructure": {"type": "device_based", "eps_base": 45, "desc": "IDS/IPS, VPN, Load Balancers, NAC, DLP, WAF, etc."},
            "Authentication Solutions": {"type": "device_based", "eps_base": 20, "desc": "AD, Authentication, IAM, PIM, PAM, MFA, etc"},
            "Network Service Solutions": {"type": "device_based", "eps_base": 50, "desc": "DHCP, DNS, Virtual/Cloud (i.e. ESX) Sources"},
            "IaaS/PaaS Solutions": {"type": "employee_based", "eps_base": 0.5, "desc": "IaaS Accounts/Hubs (Amazon, IBM Cloud, AWS, Google, Azure, etc.)"},
            "Core SaaS Solutions": {"type": "employee_based", "eps_base": 0.2, "desc": "Core SaaS (O365, Akami, GuardDuty, CloudTrail, etc.)"},
            "Anti-Malware Solutions": {"type": "employee_based", "eps_base": 0.05, "desc": "Anti-malware/Anti-Virus, Mail Gateway Solutions"},
            "Encryption Solutions": {"type": "device_based", "eps_base": 40, "desc": "Encryption Management, PKI, Certificate Management"},
            "Web/Mail Servers Logging": {"type": "device_based", "eps_base": 20, "desc": "IIS, Apache, Exchange, SendMail, etc"},
            "Inventory Management Solutions": {"type": "device_based", "eps_base": 20, "desc": "IPAM, Patch Management, Configuration Management, etc"},
            "HIPS & Deception Solutions": {"type": "device_based", "eps_base": 10, "desc": "Honeypots, Host Intrusion Detection/Prevention"},
            "Edge SaaS Solutions": {"type": "employee_based", "eps_base": 0.1, "desc": "Small/Edge SaaS Solutions (Salesforce, Box, etc.)"},
            "Database Servers Logging": {"type": "device_based", "eps_base": 10, "desc": "Oracle, IBM, iSeries, Microsoft, etc."},
            "Windows Servers Logging": {"type": "device_based", "eps_base": 4, "desc": "Windows OS General Purpose Servers"},
            "Linux Servers Logging": {"type": "device_based", "eps_base": 2, "desc": "Linux/Unix OS General Purpose Servers"},
            "Workstation Endpoints/Hosts Logging": {"type": "employee_based", "eps_base": 0.25, "desc": "EDR, Client host OS, Sysmon sources"},
            "Network IDS/IPS/NSM": {"type": "device_based", "eps_base": 750, "desc": "Inline Network Security Monitoring, IDS/IPS appliances"}
        }

        self.entries = {}
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout()

        logo = QLabel()
        pixmap = QPixmap("/mnt/data/insside_logo-header.webp")
        if not pixmap.isNull():
            logo.setPixmap(pixmap.scaled(120, 120, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        logo.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(logo)

        form_layout = QGridLayout()
        form_layout.addWidget(QLabel("Cantidad de empleados:"), 0, 0)
        self.empleados_entry = QLineEdit()
        form_layout.addWidget(self.empleados_entry, 0, 1)

        form_layout.addWidget(QLabel("Factor de endpoints por empleado (ej: 1.2):"), 1, 0)
        self.factor_entry = QLineEdit()
        form_layout.addWidget(self.factor_entry, 1, 1)

        main_layout.addLayout(form_layout)

        group_box = QGroupBox("Cantidad por categoría")
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        grid = QGridLayout()

        for i, (categoria, config) in enumerate(self.categorias_config.items()):
            label = QLabel(categoria)
            entry = QLineEdit()
            entry.setPlaceholderText(config.get("desc", ""))
            grid.addWidget(label, i, 0)
            grid.addWidget(entry, i, 1)
            self.entries[categoria] = entry

        scroll_content.setLayout(grid)
        scroll.setWidget(scroll_content)
        group_box_layout = QVBoxLayout()
        group_box_layout.addWidget(scroll)
        group_box.setLayout(group_box_layout)

        main_layout.addWidget(group_box)

        self.calc_button = QPushButton("Calcular EPS")
        self.calc_button.clicked.connect(self.calcular_eps)
        main_layout.addWidget(self.calc_button)

        self.resultado_label = QLabel("")
        self.resultado_label.setWordWrap(True)
        self.resultado_label.setAlignment(Qt.AlignTop)
        main_layout.addWidget(self.resultado_label)

        self.setLayout(main_layout)

    def calcular_eps(self):
        try:
            empleados = int(self.empleados_entry.text())
            factor = float(self.factor_entry.text())
            if empleados < 0 or factor <= 0:
                raise ValueError

            total_endpoints = empleados * factor
            total_eps = 0
            resultado = []

            resultado.append(f"Empleados: {empleados}\nEndpoints estimados: {int(total_endpoints)}\n")

            for categoria, config in self.categorias_config.items():
                entrada = self.entries[categoria].text().strip()

                if entrada != "":
                    cantidad = int(entrada)
                    if cantidad < 0:
                        raise ValueError
                elif config['type'] == 'employee_based':
                    cantidad = round(total_endpoints) if categoria in ["Anti-Malware Solutions", "Workstation Endpoints/Hosts Logging"] else empleados
                else:
                    cantidad = 0

                eps = cantidad * config['eps_base']
                total_eps += eps

                tipo_fuente = "Empleado/Endpoint" if config['type'] == 'employee_based' else "Dispositivo"
                resultado.append(f"{categoria}: {cantidad} x {config['eps_base']} EPS por {tipo_fuente} = {eps:.2f} EPS")

            recomendado = int(total_eps * 1.35)
            resultado.append(f"\nEPS estimado base: {total_eps:.2f}\nEPS recomendado (+35%): {recomendado} EPS")

            resultado_texto = "<br>".join([f"<b>{line}</b>" if i == 0 else line for i, line in enumerate(resultado)])
            self.resultado_label.setText(resultado_texto)

            # Guardar resultado en archivo con nombre basado en fecha y hora
            timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            filename = f"resultado_eps_{timestamp}.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write("\n".join(resultado))

        except ValueError:
            QMessageBox.critical(self, "Error", "Verifique que todos los valores ingresados sean correctos.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = EPSCalculator()
    window.show()
    sys.exit(app.exec_())
