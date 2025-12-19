Revisión técnica de visualización de logs en Qradar - PORQUE NO LLEGARON LOS EVENTOS
Si hubiesen llegado los eventos - ¿Tenemos Reglas para creación de nuevas ofensas? Y cual seria la severidad de estos eventos.

En relación al incidente sucedido, se revisó la integración correspondiente a AWS tanto en la cuenta de IONIX como en la cuenta de Pinapp. En conjunto se llegó a al hallazgo de que existían WAFs que no estaban enviando sus logs hacia el bucket (Nuestra integración esta realizada en base a una SQS que consulta un bucket S3). Y los encontrados estaban apuntando hacia "Cloudwatch" o directamente se encontraban con el envió de sus logs deshabilitado, por lo que en ninguna de las dos maneras estarían llegando hacia nuestra plataforma SIEM.

Continuando con la teoría de si los eventos hubiesen sido parte de nuestra infra, las reglas que se hubieran correlacionado serian:

[WAF][AWS] - Exceso de bloqueos de IP por rate-limit
[CLD][WAF] Detection of Suspicious User-Agents Allowed

Adicional a esto, se crearon estas reglas:

[AWS] Suspicious File Access with Malicious/Empty User-Agent -> (Esta regla en QRadar busca identificar accesos sospechosos a aplicaciones expuestas en AWS, detectando intentos de explorar o descargar archivos sensibles (como `.php`, `.env` o `.bak`) cuando provienen de herramientas de escaneo, bots o navegadores obsoletos.)


[WAF] Multiple Suspicious Web Paths from Same Source IP  -> (Esta regla detecta posibles **intentos de exploración o fuerza bruta web** al identificar que una misma dirección IP origina, en un lapso de cinco minutos, al menos 30 solicitudes hacia rutas de URL comúnmente asociadas a ataques o configuraciones sensibles)






Respecto a los CU que están en esta carpeta que tanta importancia se le dio a estos documentos? Entiendo que hay muchos casos en esa carpeta que no se implementaron, y otros que no se pueden implementar porque no existen los logs de origen. Pero no tenemos la información de cuales fueron los origenes de esos CU. O sea de donde se sacó la información para hacer esos documentos Hay varias diferencias de lo que dicen esos documentos comparado a los detalles que pasamos nosotros y también son diferentes los detalles de los casos que teniamos nosotros en elastic




