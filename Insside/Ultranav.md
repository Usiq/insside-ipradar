
Reglas detectadas de Entra ID:

Las **reglas de Entra ID en Microsoft** (antes Azure AD) se refieren a las **políticas y configuraciones de seguridad** que permiten controlar cómo, cuándo y desde dónde se autentican y usan las identidades dentro de la nube de Microsoft. No son “reglas” en el mismo sentido que un firewall, sino mecanismos que gestionan **acceso y protección de cuentas**.


- **Brute force attack against a Cloud PC**  
    Detecta múltiples intentos de autenticación fallidos contra un Cloud PC, indicando un posible ataque de fuerza bruta para adivinar credenciales.
    
- **Successful logon from IP and failure from a different IP**  
    Identifica cuando una misma cuenta logra iniciar sesión exitosamente desde una IP, pero poco antes o después se registran intentos fallidos desde otra IP distinta, lo que puede indicar uso indebido de credenciales comprometidas.
    
- **Distributed password cracking attempts in Microsoft Entra ID**  
    Señala intentos de adivinación de contraseñas distribuidos desde múltiples orígenes contra cuentas de Entra ID, un patrón típico de ataques coordinados para evadir bloqueos.
    
- **Failed login attempts to Azure Portal**  
    Registra múltiples intentos fallidos de autenticación en el portal de Azure, lo que puede reflejar ataques de fuerza bruta o credenciales inválidas en cuentas objetivo.


Las reglas **ASR (Attack Surface Reduction) de Microsoft Defender** son un conjunto de controles diseñados para **limitar la superficie de ataque en los equipos Windows**, bloqueando comportamientos comunes que los atacantes suelen aprovechar para ejecutar malware o moverse dentro de un entorno.

En términos simples, estas reglas actúan como **filtros de seguridad en el sistema operativo**, restringiendo acciones de aplicaciones legítimas que podrían ser usadas de manera maliciosa. Algunos ejemplos de bloqueos que realizan son:

- **Bloquear la ejecución de procesos sospechosos por parte de Office** (ej. impedir que Word o Excel lancen PowerShell o cmd.exe).
    
- **Evitar la ejecución de archivos desde ubicaciones típicamente usadas por malware**, como carpetas temporales o de correo electrónico.
    
- **Bloquear la inyección de código en procesos sensibles** para evitar técnicas de _process hollowing_ o _credential dumping_.
    
- **Prevenir que controladores inseguros o vulnerables se carguen** en el sistema.
    
- **Restringir macros maliciosas o scripts no firmados** que puedan descargar o ejecutar payloads.
    

En resumen, las reglas ASR están orientadas a **bloquear vectores de ataque conocidos y técnicas de ejecución utilizadas por malware**, actuando como una capa de defensa preventiva que reduce significativamente las oportunidades de explotación.


Reglas, bloqueo:

- **AsrLsassCredentialTheftBlocked** → Bloquea al **proceso atacante** cuando intenta leer credenciales de LSASS en el equipo. Protege al usuario porque evita el robo de contraseñas.
    
- **AsrAbusedSystemToolBlocked** → Bloquea la **ejecución de herramientas del sistema** usadas de manera maliciosa (ej. PowerShell con parámetros sospechosos). No bloquea al usuario, sino la acción peligrosa.
    
- **AsrUntrustedUsbProcessBlocked** → Bloquea **procesos ejecutados desde un USB no confiable**, evitando que un malware se ejecute al conectar un dispositivo externo en el equipo.
    
- **AsrOfficeChildProcessBlocked** → Bloquea que un documento de **Office genere un proceso secundario** (ej. Word intentando abrir PowerShell). Aquí no se bloquea al usuario, sino la acción del archivo.
    
- **AsrOfficeCommAppChildProcessBlocked** → Bloquea que **Outlook u otra app de comunicación de Office** creen procesos secundarios, protegiendo al equipo de malware adjunto en correos.
    
- **AsrVulnerableSignedDriverBlocked** → Bloquea la **carga de un driver firmado pero vulnerable** en el sistema. No bloquea al usuario, sino que impide que el driver malicioso se ejecute en el kernel del equipo.




No se migran los 15 clientes de golpe, cliente por cliente

- Migrar los clientes con mayor tiempo de retención de logs
- Un/dos cliente chico de Test (Posiblemente ENARSA o Mitrani)

Primera etapa de la migración: Migrar la ingesta | segunda etapa: Migrar correlaciones custom

