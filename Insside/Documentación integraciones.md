
Requerimiento de integraciones 

IONIX:

- AWS SES: No cuenta con integraciones nativas, se evaluaran métodos para lograr la misma (Enviar los logs a un bucket o solicitar un security hub)

- FreeIPA: Se nos informo que el mismo pasa directamente por Linux, así que la configuración recomendada es la oficial por IBM en donde se modifica el archivo de configuración "Rsyslog.conf" y se coloca el facility correspondiente a donde apuntan los logs de la plataforma:

https://www.ibm.com/docs/en/security-qradar/log-insights/saas?topic=os-configuring-syslog-linux#t_dsm_guide_linux_os_syslog

- RDS AWS: Mismo caso que el primero, no cuenta con integraciones nativas por lo que se tratará de integrar por medio de Bucket AWS, Cloudwatch Logs.

- IAM: Misma situación
- PfSense: https://www.ibm.com/docs/en/dsm?topic=pfsense-configuring-netgate-communicate-qradar


FLENI:

Fortinet:

Nos dirigimos a "Log settings" y habilitamos la "Address". En este apartado verificamos las configuraciones de "Event Logging" y "Local traffic logging". Se pueden dejar ambos en 'ALL' pero se recomienda customizar por lo que crean optimo enviar a SIEM.

Finalmente habilitamos el "Syslog Logging" y colocamos en el apartado de IP, la misma del Event Processor 'ADDRESS':

![[Pasted image 20250605110904.png]]



Wincollect:

Junto con el instalador, damos click en 'Quick' para iniciar la instalación rápida.

![[Pasted image 20250605111847.png]]v
 
Luego nos pedirá el la IP o el Hostname de la máquina, es ==IMPORTANTE== colocar el hostname sobre la IP para evitar conflicto en futuros flujos del lado del SIEM:

![[Pasted image 20250605112100.png]]

Posterior a esto, finalizará la instalación del agente y comenzará a eventos al SIEM



Los documentos de Casos de Uso que mencionás provienen de gestiones previas a nuestra participación en el proyecto, por lo que no contamos con el detalle exacto de las fuentes originales utilizadas en ese momento para su elaboración.

Desde nuestra gestión actual, estamos trabajando en reordenar y estandarizar la documentación, y los documentos de casos de uso que les compartimos ahora son la base oficial con la que trabajamos y entregamos a los clientes.  
Cada caso de uso que hemos revisado y documentado es aquel del cual nos aseguramos que funcione con los logs disponibles en la plataforma.

Puede ocurrir que en ciertos casos se realicen ajustes menores en los umbrales de alerta o en la sensibilidad de algunas reglas con el fin de evitar falsos positivos, pero estas variaciones no cambian la esencia ni el objetivo de los casos de uso definidos.


[VULN] - Log4Shell Evasion Pattern
Busca en las URLs indicios de los patrones de ataque más comunes de Log4Shell, sin importar si el firewall los bloqueó o no. Sirve para detectar de forma temprana intentos de explotación.

[VULN] - Log4Shell Base Pattern
Revisa el tráfico que **sí fue permitido** por el firewall de aplicaciones (AWS WAF) y detecta cadenas que esconden la palabra “jndi”, típica del exploit. Si se activa, significa que un ataque logró atravesar el firewall.

[VULN] - Potential Log4Shell Activity
Utiliza la capacidad incorporada de QRadar para reconocer automáticamente distintas variantes conocidas de Log4Shell en varios campos de los registros. Es una protección más amplia y constantemente actualizada.