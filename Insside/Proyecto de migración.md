
**QRadar SIEM + Cortex XSOAR → Google SecOps (SIEM + SOAR)**

## 1. Principios rectores de la migración

Estos principios deben gobernar todo el plan:

- **Migración progresiva, no masiva**: nunca más de 1–2 clientes simultáneamente.
    
- **Coexistencia controlada**: QRadar / Cortex seguirán activos mientras Google SecOps valida cobertura y calidad.
    
- **Prioridad por retención y costo**: primero los clientes con mayor retención histórica de logs (impacto directo en TCO).
    
- **Enfoque MSSP**: reutilización de pipelines, detecciones y playbooks entre clientes.
    
- **Cero impacto en SLA/SOC**: el SOC sigue operando sin degradación de visibilidad ni respuesta.

---

## 2. Segmentación inicial de clientes (muy importante)

Antes de migrar, clasificar los ~30 clientes en 4 grupos:

### Grupo A – Clientes de prueba (piloto)

- 1–2 clientes chicos
    
- Bajo EPS
    
- Pocas integraciones críticas
    
- Idealmente con bajo ruido operativo  
    **Ejemplo:** ENARSA / Mitrani
    

 Objetivo: validar arquitectura, parsing, detecciones y SOAR end-to-end.

---

### Grupo B – Clientes con alta retención

- Alto volumen histórico
    
- Requerimientos regulatorios (PCI, SOX, etc.)
    
- Costos elevados en QRadar (/store, Data Nodes)
    

Objetivo: reducir costos de retención y validar capacidades de búsqueda histórica.

---

### Grupo C – Clientes QRadar + Cortex

- SIEM + SOAR separados
    
- Detecciones y automatizaciones maduras
    

Objetivo: validar reemplazo funcional completo.

---

### Grupo D – Clientes solo Cortex XSOAR

- Poco o nulo SIEM
    
- Automatización como valor principal
    

 Objetivo: validar Google SecOps SOAR como reemplazo directo.

---

## 3. Arquitectura objetivo (Target Architecture)

**Google SecOps como plataforma única:**

- Ingesta centralizada de logs
    
- Normalización + enrichment
    
- Correlación nativa
    
- SOAR integrado
    
- Multitenancy lógico (clientes separados por proyecto / namespace)
    

QRadar y Cortex quedan **en paralelo** durante la transición.

---

## 4. Fases de la migración

---

## FASE 0 – Preparación (Transversal)

**Objetivo:** dejar el terreno listo antes de tocar clientes productivos.

### Actividades

- Inventario por cliente:
    
    - Fuentes de log
        
    - EPS promedio / pico
        
    - Retención actual
        
    - Casos de uso activos
        
    - Playbooks SOAR
        
- Definir **naming convention MSSP** en Google SecOps
    
- Definir modelo de segregación por cliente
    
- Definir métricas de éxito:
    
    - Cobertura de fuentes (%)
        
    - Exactitud de parsing
        
    - Detecciones equivalentes
        
    - MTTR / MTTD
        

---

## FASE 1 – Piloto de Ingesta (Cliente Test)

**Clientes:** 1–2 chicos (ENARSA / Mitrani)

### Objetivo

Validar **solo ingesta + visibilidad**, sin apagar nada existente.

### Alcance

- Envío de logs en paralelo:
    
    - QRadar / Cortex → siguen activos
        
    - Google SecOps → nuevo destino
        
- Fuentes iniciales:
    
    - AD / Entra ID
        
    - Firewall principal
        
    - Endpoint
        
    - Cloud (si aplica)
        

### Entregables

- Validación de:
    
    - Parsing
        
    - Campos normalizados
        
    - Búsquedas
        
- Dashboard básico por cliente
    
- Documento de lecciones aprendidas
    

---

## FASE 2 – Migración de Ingesta por Oleadas

**Objetivo:** mover progresivamente la ingesta de logs.

### Orden recomendado

1. Clientes con **mayor retención**
    
2. Clientes medianos
    
3. Clientes pequeños restantes
    

### Estrategia

- Cliente por cliente
    
- Ventana de coexistencia:
    
    - 30–60 días con doble ingesta
        
- No se apaga QRadar hasta:
    
    - Confirmar cobertura ≥ 95%
        
    - Confirmar queries clave
        

### Resultado

- Google SecOps se convierte en **SIEM primario**
    
- QRadar queda en modo contingencia
    

---

## FASE 3 – Migración de Correlaciones (Custom Rules)

**Objetivo:** reemplazar reglas QRadar y detecciones Cortex.

### Enfoque recomendado

- No migrar 1:1
    
- Re-diseñar detecciones usando:
    
    - Modelo de datos de Google SecOps
        
    - MITRE ATT&CK
        
    - Reducción de falsos positivos
        

### Priorización

1. Casos críticos (Credential Access, Lateral Movement)
    
2. Casos regulatorios
    
3. Casos de alto ruido (optimización)
    

### Entregables

- Matriz de equivalencia:
    
    - QRadar Rule → Google SecOps Detection
        
- Validación SOC
    
- Runbooks actualizados
    

---

## FASE 4 – Migración SOAR (Playbooks)

**Objetivo:** reemplazar Cortex XSOAR.

### Estrategia

- Migrar solo playbooks:
    
    - De alto uso
        
    - De alto impacto
        
- Unificar automatizaciones MSSP reutilizables
    

### Ejemplos

- Phishing
    
- Brute force
    
- Impossible travel
    
- Malware endpoint
    

### Resultado

- Google SecOps como **plataforma única de respuesta**
    
- Cortex XSOAR en retiro progresivo
    

---

## FASE 5 – Decommissioning Controlado

**Objetivo:** apagar QRadar y Cortex sin riesgo.

### Requisitos

- 60–90 días sin incidentes críticos no detectados
    
- Aprobación SOC / cliente
    
- Export de evidencia histórica si aplica
    

### Resultado

- Reducción de costos
    
- Simplificación operativa
    
- Plataforma única
    

---

## 5. Roadmap sugerido (alto nivel)

|Mes|Actividad|
|---|---|
|1|Fase 0 + Piloto|
|2|Ingesta clientes grandes|
|3|Ingesta clientes medianos|
|4|Correlaciones críticas|
|5|SOAR|
|6|Decommissioning|


## **Métricas de Éxito - Migración de SIEM**

**Cobertura de Fuentes**

- % de fuentes migradas
- Volumetría: EPS recibidos vs. esperados
- **Meta**: 95% de fuentes críticas operativas

**Casos de Uso y Detecciones**

- Reglas/alertas migradas del SIEM anterior
- Casos de uso custom nuevos implementados
- **Meta**: 100% casos custom

**Reconocimiento de Fuentes (Parsing/Mapping)**

- % de eventos correctamente parseados
- % de properties normalizadas (usuario, IP, acción, timestamp)
- **Meta**: 90% parsing exitoso, 100% campos críticos mapeados

Métricas de éxito, tres pilares fundamentales: Primero, la **cobertura de fuentes**, que mide el porcentaje de dispositivos y aplicaciones que están enviando logs correctamente al nuevo SIEM, con el objetivo de alcanzar al menos un 90% de fuentes críticas operativas. Segundo, los **casos de uso y detecciones**, que evalúan cuántas reglas de correlación y alertas del SIEM anterior fueron migradas exitosamente, cuántos casos de uso nuevos se implementaron, garantizando que el 100% de las detecciones críticas estén funcionando. Y tercero, el **reconocimiento y normalización de fuentes (parsing/mapping)**, que verifica que los logs sean correctamente interpretados por el SIEM, En conjunto, estas métricas evalúan el porcentaje total por cliente de éxito de migración