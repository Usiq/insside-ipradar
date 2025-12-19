import math

def calcular_eps_qradar():
    print("=== Estimador de EPS para QRadar (Versión Mejorada y Ajustada por Empleados) ===\n")

    while True:
        try:
            empleados = int(input("Ingrese la cantidad de empleados: "))
            if empleados < 0:
                raise ValueError
            break
        except ValueError:
            print("Por favor, ingrese un número entero no negativo.")

    while True:
        try:
            factor_endpoint = float(input("Ingrese el factor estimado de endpoints (PCs/laptops) por empleado (ej: 1.2, si hay 1.2 equipos por persona): "))
            if factor_endpoint <= 0:
                raise ValueError
            break
        except ValueError:
            print("Por favor, ingrese un número decimal positivo.")

    total_endpoints = int(empleados * factor_endpoint)
    print(f"\nSe estiman {total_endpoints} endpoints en total basados en {empleados} empleados y un factor de {factor_endpoint}\n")

    categorias_config = {
        "High Volume Core Systems (ej: Firewall principal, WAFs)": {"type": "device_based", "eps_base": 300, "prompt_desc": "cantidad de dispositivos"},
        "Medium Volume Core Systems (ej: Firewall interno, balanceador de carga)": {"type": "device_based", "eps_base": 75, "prompt_desc": "cantidad de dispositivos"},
        "Typical Security Infrastructure (ej: IPS, Proxy)": {"type": "device_based", "eps_base": 45, "prompt_desc": "cantidad de dispositivos"},
        "Authentication Solutions (ej: Active Directory DCs)": {"type": "device_based", "eps_base": 20, "prompt_desc": "cantidad de dispositivos (DCs)"},
        "Network Service Solutions (ej: DNS, DHCP)": {"type": "device_based", "eps_base": 50, "prompt_desc": "cantidad de dispositivos"},
        "Networking & Storage Systems (ej: Routers, Switches, NAS)": {"type": "device_based", "eps_base": 4, "prompt_desc": "cantidad de dispositivos"},
        "IaaS/PaaS Solutions (ej: AWS CloudTrail, GCP Audit Logs)": {"type": "employee_based", "eps_base": 0.5, "prompt_desc": f"cantidad de empleados usando IaaS/PaaS (0 para usar el total de {empleados})"},
        "Core SaaS Solutions (ej: O365 Audit Logs, G-Suite Audit)": {"type": "employee_based", "eps_base": 0.2, "prompt_desc": f"cantidad de empleados usando Core SaaS (0 para usar el total de {empleados})"},
        "Anti-Malware Solutions (Endpoint Protection)": {"type": "employee_based", "eps_base": 0.05, "prompt_desc": f"cantidad de endpoints con AV (0 para usar el total de {total_endpoints})"},
        "Encryption Solutions (ej: BitLocker, EDR con logs de cifrado)": {"type": "device_based", "eps_base": 40, "prompt_desc": "cantidad de dispositivos"},
        "Web/Mail Servers Logging (ej: Apache, IIS, Exchange logs)": {"type": "device_based", "eps_base": 20, "prompt_desc": "cantidad de dispositivos"},
        "Inventory Management Solutions (ej: CMDB logs)": {"type": "device_based", "eps_base": 20, "prompt_desc": "cantidad de dispositivos"},
        "HIPS & Deception Solutions (Host IPS, honeypots)": {"type": "device_based", "eps_base": 10, "prompt_desc": "cantidad de dispositivos"},
        "Edge SaaS Solutions (ej: Zoom, Slack logs)": {"type": "employee_based", "eps_base": 0.1, "prompt_desc": f"cantidad de empleados usando Edge SaaS (0 para usar el total de {empleados})"},
        "Database Servers Logging (ej: SQL, Oracle, PostgreSQL)": {"type": "device_based", "eps_base": 10, "prompt_desc": "cantidad de dispositivos"},
        "Windows Servers Logging (general)": {"type": "device_based", "eps_base": 4, "prompt_desc": "cantidad de dispositivos"},
        "Linux Servers Logging (general)": {"type": "device_based", "eps_base": 2, "prompt_desc": "cantidad de dispositivos"},
        "Workstation Endpoints/Hosts Logging": {"type": "employee_based", "eps_base": 0.25, "prompt_desc": f"cantidad de workstations (0 para usar el total de {total_endpoints})"},
        "Network IDS/IPS/NSM (ej: Suricata)": {"type": "device_based", "eps_base": 0, "prompt_desc": "cantidad de sensores (Suricata)"}
    }

    dispositivos_calculados = {}
    for nombre, config in categorias_config.items():
        cantidad_final = 0
        eps_base_final = config["eps_base"]

        while True:
            try:
                if "cantidad de sensores (Suricata)" in config["prompt_desc"]:
                    cantidad = int(input(f"{nombre} ({config['prompt_desc']}): "))
                    if cantidad < 0: raise ValueError
                    cantidad_final = cantidad
                    if cantidad > 0:
                        print("  ¿Cuál es el nivel de logueo esperado para Suricata?")
                        print("    1. Solo alertas críticas/firmas (bajo volumen)")
                        print("    2. Alertas + metadatos de red (HTTP, DNS, TLS - volumen medio)")
                        print("    3. Todo (Detección de flujo, metadatos, extracción de archivos - alto volumen)")
                        nivel_logueo_suricata = int(input("  Seleccione una opción (1-3): "))
                        if nivel_logueo_suricata == 1: eps_base_final = 100
                        elif nivel_logueo_suricata == 2: eps_base_final = 750
                        elif nivel_logueo_suricata == 3: eps_base_final = 1500
                        else:
                            print("  Opción no válida. Se usará el nivel 2 por defecto para Suricata.")
                            eps_base_final = 750
                    break
                elif config["type"] == "employee_based":
                    cantidad_input = input(f"{nombre} ({config['prompt_desc']}): [Enter para NO contar, 0 para usar total] ")
                    if cantidad_input.strip().lower() in ["", "n/a"]:
                        cantidad_final = 0
                        print(f"  -> No se contará esta categoría.")
                    elif cantidad_input.strip() == "0":
                        if "empleados" in config["prompt_desc"]:
                            cantidad_final = empleados
                            print(f"  -> Usando el total de empleados ({empleados}) para esta categoría.")
                        elif "endpoints" in config["prompt_desc"]:
                            cantidad_final = total_endpoints
                            print(f"  -> Usando el total de endpoints ({total_endpoints}) para esta categoría.")
                    else:
                        cantidad_final = int(cantidad_input)
                        if cantidad_final < 0: raise ValueError
                    break
                else:
                    cantidad = int(input(f"{nombre} ({config['prompt_desc']}): "))
                    if cantidad < 0: raise ValueError
                    cantidad_final = cantidad
                    break
            except ValueError:
                print("Por favor, ingrese un número entero no negativo, o '0' para usar el valor por defecto si aplica.")

        dispositivos_calculados[nombre] = {"cantidad": cantidad_final, "eps_base": eps_base_final, "type": config["type"]}

    total_eps = 0
    print("\n--- Cálculo de EPS por categoría ---")
    print(f"{'Categoría':55} {'Cantidad':>8} {'EPS base':>12} {'Tipo Cálculo':>15} {'EPS Total':>12}")
    print("-" * 105)
    for nombre, datos in dispositivos_calculados.items():
        if datos["cantidad"] > 0:
            if datos["type"] == "employee_based":
                eps = datos["cantidad"] * datos["eps_base"]
                base_str = f"{datos['eps_base']:.3f}/ {'empleado' if 'empleados' in categorias_config[nombre]['prompt_desc'] else 'endpoint'}"
                tipo_calc_str = "Por Usuario/Endpoint"
            else:
                eps = datos["cantidad"] * datos["eps_base"]
                base_str = f"{datos['eps_base']:.2f}/dispositivo"
                tipo_calc_str = "Por Dispositivo"
            total_eps += eps
            print(f"{nombre:55} {datos['cantidad']:8} {base_str:12} {tipo_calc_str:15} {eps:12.2f}")
        # Si cantidad es 0, no mostrar ni sumar EPS

    margen_total = 1.35
    recomendado = int(total_eps * margen_total)

    print("\n=== Resultados del Estimador de EPS ===")
    print(f"EPS estimado base (suma de todos): {total_eps:.2f} EPS")
    print(f"Margen adicional aplicado ({int((margen_total - 1) * 100)}% para picos y crecimiento futuro).")
    print(f"EPS Total Recomendado para Dimensionamiento de QRadar: {recomendado:.2f} EPS")

    if total_eps < 100:
        print("\nADVERTENCIA: El EPS total parece bajo. Por favor, revise si ha incluido todas las fuentes de log relevantes o si la estimación es demasiado conservadora para su entorno.")
    if total_eps > 5000:
        print("\nADVERTENCIA: El EPS total es muy alto. Podría requerir una arquitectura QRadar distribuida compleja (varios Event Processors). Considere segmentar la ingesta de logs.")

    print("\n--- Recomendaciones Clave ---")
    print("1. **Validación:** Estas son ESTIMACIONES. Obtenga datos reales de sus logs actuales para la planificación final.")
    print("2. **Dimensionamiento:** Siempre dimensiona QRadar en base al EPS Total Recomendado o incluso un poco por encima.")
    print("3. **Flujos (FPM):** Recuerda que QRadar también consume licencias por Flujos Por Minuto (FPM). Estima también tu FPM.")
    print("4. **PoC:** Una Prueba de Concepto (PoC) o un periodo de recolección de logs en un entorno de prueba es invaluable.")
    print("5. **Monitoreo Continuo:** Monitorea el uso de licencia y el rendimiento de QRadar una vez implementado para reajustar si es necesario.")
    print("6. **Optimización:** Implementa filtros de eventos en la fuente o en QRadar para reducir el ruido no relevante.")


if __name__ == "__main__":
    calcular_eps_qradar()