#!/usr/bin/env python3

import argparse
import json
import os
from datetime import datetime
from typing import Dict, List, Any

def parse_json_safely(data: str) -> Dict[str, Any]:
    """Safely parse JSON data with error handling"""
    try:
        return json.loads(data)
    except json.JSONDecodeError:
        # Try to fix common JSON issues
        data = data.strip()
        if not data.startswith('{') and not data.startswith('['):
            data = '{' + data + '}'
        try:
            return json.loads(data)
        except json.JSONDecodeError:
            return {}

def extract_incidents(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Extract incidents from CORTEX XSOAR JSON structure"""
    incidents = []
    
    # Handle different possible JSON structures
    if isinstance(data, dict) and 'data_sources' in data:
        for source in data['data_sources']:
            if 'incidents' in source:
                incidents.extend(source['incidents'])
    elif isinstance(data, dict) and 'incidents' in data:
        incidents.extend(data['incidents'])
    elif isinstance(data, list):
        incidents.extend(data)
    else:
        # Single incident case
        if isinstance(data, dict) and ('incident_id' in data or 'id' in data):
            incidents.append(data)
    
    return incidents

def extract_alert_info(incident: Dict[str, Any]) -> Dict[str, Any]:
    """Extract key information from incident for dashboard"""
    alert_info = {
        'id': incident.get('incident_id', incident.get('id', 'Unknown')),
        'name': incident.get('name', incident.get('title', 'Sin nombre')),
        'severity': incident.get('severity', incident.get('Severity', 0)),
        'type': incident.get('type', incident.get('Type', 'Unknown')),
        'status': incident.get('status', incident.get('Status', 'Unknown')),
        'created': incident.get('created', incident.get('Created', '')),
        'owner': incident.get('owner', incident.get('Owner', 'Unassigned')),
        'description': incident.get('description', incident.get('Description', ''))
    }
    
    # Extract additional info from labels if present
    if 'labels' in incident and isinstance(incident['labels'], list):
        for label in incident['labels']:
            if label.get('type') == 'Instance':
                alert_info['instance'] = label.get('value', '')
            elif label.get('type') == 'Brand':
                alert_info['brand'] = label.get('value', '')
    
    # Parse custom fields
    if 'CustomFields' in incident and isinstance(incident['CustomFields'], dict):
        custom = incident['CustomFields']
        alert_info['source_ip'] = custom.get('sourceip', '')
        alert_info['dest_ip'] = custom.get('destinationip', '')
        alert_info['event_count'] = custom.get('eventcount', '')
    
    return alert_info

def get_severity_text(severity: int) -> str:
    """Convert numeric severity to text"""
    severity_map = {
        0: 'Informativo',
        1: 'Bajo',
        2: 'Medio',
        3: 'Alto',
        4: 'Crítico'
    }
    return severity_map.get(int(severity) if str(severity).isdigit() else 0, 'Desconocido')

def get_severity_color(severity: int) -> str:
    """Get color for severity level"""
    color_map = {
        0: '#17a2b8',  # info - blue
        1: '#28a745',  # low - green
        2: '#ffc107',  # medium - yellow
        3: '#fd7e14',  # high - orange
        4: '#dc3545'   # critical - red
    }
    return color_map.get(int(severity) if str(severity).isdigit() else 0, '#6c757d')

def generate_html_dashboard(alerts: List[Dict[str, Any]]) -> str:
    """Generate HTML dashboard for CORTEX XSOAR alerts"""
    
    # Sort alerts by severity (descending) and by name (ascending)
    alerts_by_severity = sorted(
        alerts,
        key=lambda x: int(x['severity']) if str(x['severity']).isdigit() else 0,
        reverse=True
    )
    alerts_by_name = sorted(alerts, key=lambda x: str(x['name']).lower())
    
    # Calculate statistics
    total_alerts = len(alerts)
    critical_high = sum(
        1 for a in alerts
        if str(a['severity']).isdigit() and int(a['severity']) >= 3
    )
    active_alerts = sum(
        1 for a in alerts
        if str(a['status']).lower() in ('active', 'open')
    )
    unique_analysts = len(
        set(a['owner'] for a in alerts if a['owner'] != 'Unassigned')
    )
    
    html = f"""
<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dashboard CORTEX XSOAR - Alertas</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background-color: #f8f9fa;
            color: #333;
            line-height: 1.6;
        }}
        
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 2rem 0;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .header h1 {{
            font-size: 2.5rem;
            margin-bottom: 0.5rem;
        }}
        
        .header p {{
            font-size: 1.1rem;
            opacity: 0.9;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
            padding: 2rem;
        }}
        
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-bottom: 2rem;
        }}
        
        .stat-card {{
            background: white;
            padding: 1.5rem;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 4px solid #667eea;
        }}
        
        .stat-number {{
            font-size: 2rem;
            font-weight: bold;
            color: #667eea;
        }}
        
        .stat-label {{
            color: #666;
            margin-top: 0.5rem;
        }}
        
        .dashboard-tabs {{
            display: flex;
            margin-bottom: 2rem;
            background: white;
            border-radius: 10px;
            overflow: hidden;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }}
        
        .tab {{
            flex: 1;
            padding: 1rem 2rem;
            background: white;
            border: none;
            cursor: pointer;
            font-size: 1rem;
            transition: all 0.3s ease;
        }}
        
        .tab.active {{
            background: #667eea;
            color: white;
        }}
        
        .tab:hover {{
            background: #f8f9fa;
        }}
        
        .tab.active:hover {{
            background: #5a6fd8;
        }}
        
        .tab-content {{
            display: none;
        }}
        
        .tab-content.active {{
            display: block;
        }}
        
        .alerts-grid {{
            display: grid;
            gap: 1rem;
        }}
        
        .alert-card {{
            background: white;
            border-radius: 10px;
            padding: 1.5rem;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            border-left: 4px solid #ddd;
        }}
        
        .alert-card:hover {{
            transform: translateY(-2px);
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
        }}
        
        .alert-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 1rem;
        }}
        
        .alert-title {{
            font-size: 1.2rem;
            font-weight: bold;
            color: #333;
            flex: 1;
        }}
        
        .severity-badge {{
            padding: 0.3rem 0.8rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
            color: white;
            text-transform: uppercase;
        }}
        
        .alert-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 1rem;
            margin-top: 1rem;
        }}
        
        .info-item {{
            display: flex;
            flex-direction: column;
        }}
        
        .info-label {{
            font-weight: bold;
            color: #666;
            font-size: 0.8rem;
            text-transform: uppercase;
            margin-bottom: 0.2rem;
        }}
        
        .info-value {{
            color: #333;
            font-size: 0.9rem;
        }}
        
        .no-alerts {{
            text-align: center;
            padding: 3rem;
            color: #666;
            font-size: 1.1rem;
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 1rem;
            }}
            
            .header h1 {{
                font-size: 2rem;
            }}
            
            .dashboard-tabs {{
                flex-direction: column;
            }}
            
            .alert-info {{
                grid-template-columns: 1fr;
            }}
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>Dashboard CORTEX XSOAR</h1>
        <p>Panel de Alertas y Incidentes de Seguridad</p>
        <p>Generado el: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}</p>
    </div>
    
    <div class="container">
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{total_alerts}</div>
                <div class="stat-label">Total Alertas</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{critical_high}</div>
                <div class="stat-label">Críticas/Altas</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{active_alerts}</div>
                <div class="stat-label">Activas</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{unique_analysts}</div>
                <div class="stat-label">Analistas</div>
            </div>
        </div>
        
        <div class="dashboard-tabs">
            <button class="tab active" onclick="showTab(event, 'severity')">Ordenado por Severidad</button>
            <button class="tab" onclick="showTab(event, 'name')">Ordenado por Nombre</button>
        </div>
        
        <div id="severity-tab" class="tab-content active">
            <div class="alerts-grid">
"""
    # Alerts by severity
    if alerts_by_severity:
        for alert in alerts_by_severity:
            severity_num = int(alert['severity']) if str(alert['severity']).isdigit() else 0
            severity_text = get_severity_text(severity_num)
            severity_color = get_severity_color(severity_num)
            
            html += f"""
                <div class="alert-card" style="border-left-color: {severity_color}">
                    <div class="alert-header">
                        <div class="alert-title">{alert['name'][:100]}{'...' if len(alert['name']) > 100 else ''}</div>
                        <span class="severity-badge" style="background-color: {severity_color}">{severity_text}</span>
                    </div>
                    <div class="alert-info">
                        <div class="info-item">
                            <div class="info-label">ID</div>
                            <div class="info-value">{alert['id']}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Tipo</div>
                            <div class="info-value">{alert['type']}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Estado</div>
                            <div class="info-value">{alert['status']}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Propietario</div>
                            <div class="info-value">{alert['owner']}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Creado</div>
                            <div class="info-value">{alert['created'][:19] if alert['created'] else 'N/A'}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Descripción</div>
                            <div class="info-value">{alert['description'][:100] if alert['description'] else 'N/A'}{'...' if alert['description'] and len(alert['description']) > 100 else ''}</div>
                        </div>
                    </div>
                </div>
"""
    else:
        html += '<div class="no-alerts">No se encontraron alertas</div>'
    
    html += """
            </div>
        </div>
        
        <div id="name-tab" class="tab-content">
            <div class="alerts-grid">
"""
    # Alerts by name
    if alerts_by_name:
        for alert in alerts_by_name:
            severity_num = int(alert['severity']) if str(alert['severity']).isdigit() else 0
            severity_text = get_severity_text(severity_num)
            severity_color = get_severity_color(severity_num)
            
            html += f"""
                <div class="alert-card" style="border-left-color: {severity_color}">
                    <div class="alert-header">
                        <div class="alert-title">{alert['name'][:100]}{'...' if len(alert['name']) > 100 else ''}</div>
                        <span class="severity-badge" style="background-color: {severity_color}">{severity_text}</span>
                    </div>
                    <div class="alert-info">
                        <div class="info-item">
                            <div class="info-label">ID</div>
                            <div class="info-value">{alert['id']}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Tipo</div>
                            <div class="info-value">{alert['type']}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Estado</div>
                            <div class="info-value">{alert['status']}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Propietario</div>
                            <div class="info-value">{alert['owner']}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Creado</div>
                            <div class="info-value">{alert['created'][:19] if alert['created'] else 'N/A'}</div>
                        </div>
                        <div class="info-item">
                            <div class="info-label">Descripción</div>
                            <div class="info-value">{alert['description'][:100] if alert['description'] else 'N/A'}{'...' if alert['description'] and len(alert['description']) > 100 else ''}</div>
                        </div>
                    </div>
                </div>
"""
    else:
        html += '<div class="no-alerts">No se encontraron alertas</div>'
    
    html += """
            </div>
        </div>
    </div>
    
    <script>
        function showTab(event, tabName) {
            const contents = document.querySelectorAll('.tab-content');
            contents.forEach(content => content.classList.remove('active'));
            
            const tabs = document.querySelectorAll('.tab');
            tabs.forEach(tab => tab.classList.remove('active'));
            
            document.getElementById(tabName + '-tab').classList.add('active');
            event.target.classList.add('active');
        }
    </script>
</body>
</html>
"""
    return html

def main():
    parser = argparse.ArgumentParser(description='Convert CORTEX XSOAR alerts to HTML dashboard')
    parser.add_argument('-i', help='Comma-separated input file paths')
    parser.add_argument('-o', required=True, help='Output file path')
    args = parser.parse_args()
    
    all_alerts = []
    
    if args.i:
        input_files = {path.split('/')[-1]: path for path in args.i.split(',')}
        
        for filename, filepath in input_files.items():
            try:
                print(f"Procesando archivo: {filepath}")
                
                if not os.path.exists(filepath):
                    print(f"Archivo no encontrado: {filepath}")
                    continue
                
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read().strip()
                
                if not content:
                    print(f"Archivo vacío: {filepath}")
                    continue
                
                data = parse_json_safely(content)
                if not data:
                    print(f"No se pudo parsear JSON en: {filepath}")
                    continue
                
                incidents = extract_incidents(data)
                print(f"Encontrados {len(incidents)} incidentes en {filepath}")
                
                for incident in incidents:
                    alert_info = extract_alert_info(incident)
                    all_alerts.append(alert_info)
                    
            except Exception as e:
                print(f"Error procesando {filepath}: {str(e)}")
                continue
    else:
        print("No se proporcionaron archivos de entrada")
    
    print(f"Total de alertas procesadas: {len(all_alerts)}")
    
    try:
        html_content = generate_html_dashboard(all_alerts)
        
        with open(args.o, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        print(f"Dashboard HTML generado exitosamente en: {args.o}")
        
    except Exception as e:
        print(f"Error generando dashboard: {str(e)}")
        with open(args.o, 'w', encoding='utf-8') as f:
            f.write(f"<html><body><h1>Error</h1><p>Error generando dashboard: {str(e)}</p></body></html>")

if __name__ == '__main__':
    main()