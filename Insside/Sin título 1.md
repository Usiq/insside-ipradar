Cola SQS VPC PinApp: [https://sqs.us-east-1.amazonaws.com/689641733403/Logs-VPC-FlowLogs-PROD-Pinapp](https://sqs.us-east-1.amazonaws.com/689641733403/Logs-VPC-FlowLogs-PROD-Pinapp)

Cola SQS VPC Ionix: [https://sqs.us-east-1.amazonaws.com/726663883567/Logs-VPC-FlowLogs-PROD-Ionix](https://sqs.us-east-1.amazonaws.com/726663883567/Logs-VPC-FlowLogs-PROD-Ionix)

Diego Molina

11:49 a.m.

Cuenta Ionix, IP Event Collector: 10.215.2.45

Diego Molina

11:56 a.m.

Cuenta Pinapp, IP Event Collector: 10.216.2.35


Log Group: FlowLogs-VPC_Marketing

Diego Molina

12:25 p.m.

Log Group: FlowLogs-VPC-PBX-vpc

Root: c9U511Bjm$we23df
ec2-user: tkjVr1268x46=1%4

IP Collector Ionix: 10.215.2.6 (Nueva a agregar)
IP Collector PinApp: 10.216.2.61 (Nueva a agregar)
root:0fU&x6fgNQ4S82

Event Collector: c9U511Bjm1we23df (Nueva contraseña actualizado)

_send_

0fU&x6fgNQ4S82
Enviar mensaje

12:06p.m.
_send_

Enviar mensaje

4:37p.m.

252bd428-644c-4969-b565-2b41ba2ca575 QDI UP12

-------------------------------

NUEVO APARTADO: UP11

iONIX --> 10.215.2.40

![[Pasted image 20250702131113.png]]![[Pasted image 20250702131217.png]]

LogGroup:


FlowLogs-MACH-PRD-VPC
FlowLogs-PRD-VPC
FlowLogs-PinApp-Admin-VPC
FlowLogs-PinApp-HSM-VPC
FlowLogs-PinApp-SOC-VPC
FlowLogs-Wallet-Cali-Admin-VPC
FlowLogs-Wallet-Cali-VPC




`sudo umount /store
sudo umount /transient`


`sudo lvchange -an /dev/storerhel/store
sudo lvchange -an /dev/storerhel/transient`


`sudo vgchange -an storerhel`


Log groups de ZELERI: 

Log Group Zeleri 
/aws/rds/instance/zeleri-production/upgrade
/aws/rds/instance/zeleri-production/postgresql

gcloud pubsub topics add-iam-policy-binding qradar-topic \
  --member="serviceAccount:service-org-709022431819@gcp-sa-logging.iam.gserviceaccount.com" \
  --role="roles/pubsub.publisher"

Error Detail The specified topic does not allow the service account associated with the log sink to publish to it. Grant publish permission for the service account specified in the sink's writerIdentity field on the topic.

Aaron Olivera Garcia

2:56 p.m.

[https://cloud.google.com/logging/docs/export/troubleshoot?hl=es-419](https://cloud.google.com/logging/docs/export/troubleshoot?hl=es-419)

Tú

2:57 p.m.

gcloud asset feeds describe <NAME SINK>

_keep_

Fijar mensaje

Tú

3:10 p.m.

gcloud logging sinks list --organization=<ORGANIZATION_ID>

_keep_

Fijar mensaje

JUAN DANIEL CONTRERAS SOTOMAYOR

3:13 p.m.

gcloud logging sinks list --organization=709022431819

Aaron Olivera Garcia

3:15 p.m.

aolivera@cloudshell:~ (findep-produccion)$ gcloud logging sinks list --organization=709022431819 NAME: log_soc_insside DESTINATION: pubsub.googleapis.com/projects/findep-produccion/topics/qradar-topic FILTER: logName:activity NAME: _Required DESTINATION: logging.googleapis.com/organizations/709022431819/locations/global/buckets/_Required FILTER: LOG_ID("cloudaudit.googleapis.com/activity") OR LOG_ID("externalaudit.googleapis.com/activity") OR LOG_ID("cloudaudit.googleapis.com/system_event") OR

Aaron Olivera Garcia

3:16 p.m.

.

serviceAccount:service-org-709022431819@gcp-sa-logging.iam.gserviceaccount.com

pubsub.googleapis.com/projects/findep-produccion/topics/qradar-topic

Tú

3:17 p.m.

gcloud pubsub topics add-iam-policy-binding qradar-topic \ --member="serviceAccount:service-org-709022431819@gcp-sa-logging.iam.gserviceaccount.com" \ --role="roles/pubsub.publisher"