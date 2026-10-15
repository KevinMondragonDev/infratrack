# InfraTrack

[![CI y nightly build](https://github.com/KevinMondragonDev/infratrack/actions/workflows/ci.yml/badge.svg)](https://github.com/KevinMondragonDev/infratrack/actions/workflows/ci.yml)

Herramienta web interna para diseñar y dar seguimiento a infraestructura AWS: lienzo drag & drop,
notas y configuración por componente, palomita de **terraformado**, preguntas para el arquitecto
y un **Copilot** que revisa el diseño con reglas de AWS (red, IAM, firewall, alta disponibilidad,
datos y costo).

- Python 3.9+ **sólo con la librería estándar** (no hay que instalar nada).
- Sin base de datos: todo vive en archivos JSON dentro de `data/`.
- No es un .exe: es un servidor local que abres en el navegador.

## Descargar

- **Nightly** (último `main`, se publica cada noche y en cada push): [Releases → nightly](https://github.com/KevinMondragonDev/infratrack/releases/tag/nightly)
- O clona el repositorio: `git clone https://github.com/KevinMondragonDev/infratrack.git`

## Iniciar

```bash
python3 app.py --open
```

Abre http://127.0.0.1:8765. La primera vez se crea un proyecto de ejemplo (app de pedidos + data lake).

Opciones: `--port 9000`, `--data /ruta/a/mis-datos`, `--host 0.0.0.0` (para que tu arquitecto lo abra
desde la red local; **no tiene autenticación**, úsalo sólo en redes de confianza).

## Cómo se usa

| Acción | Cómo |
|---|---|
| Agregar componente | Arrástralo desde la paleta (o clic para soltarlo al centro) |
| Ubicar en red | Suéltalo dentro de una VPC y luego dentro de una Subnet (pública/privada/aislada) |
| Conectar | Arrastra desde el punto azul del borde derecho hacia el destino. La flecha va de **quien llama** a **quien es llamado** |
| Terraformado | Clic en el círculo ✓ de la esquina del componente (o en el panel derecho) |
| Configuración | Pestaña *Configuración*: formulario específico por servicio (S3: Iceberg/Hive/Delta, retención, lifecycle, cifrado…; EMR: Serverless/EC2/EKS, capacidad, Spot, catálogo…) |
| Notas | Pestaña *Notas*: bitácora con autor y fecha |
| Arquitecto | Pestaña *Arquitecto*: preguntas, respuestas/decisiones y estado (abierta, respondida, cerrada) |
| Permisos de una conexión | Selecciona la flecha: política IAM, políticas de recurso, reglas de Security Group, ruta (NAT/endpoints/VPC Link) y Terraform |
| Copilot | Botón **Copilot**: hallazgos, roles IAM consolidados, Security Groups, preguntas, pendientes de terraform |
| Reporte | Menú *Proyecto → Exportar reporte Markdown* para llevar a la revisión con el arquitecto |

Atajos: `Supr` eliminar · `Ctrl/Cmd+Z` deshacer · `Ctrl/Cmd+Shift+Z` rehacer · `Ctrl/Cmd+D` duplicar ·
`Esc` deseleccionar · `Ctrl/Cmd + rueda` (o pinch) zoom · arrastrar el fondo para moverte.

## Qué revisa el Copilot

Las reglas viven en `copilot.py` y se ejecutan localmente cada vez que cambias algo (no se conecta a AWS):

- **Red**: CIDR válidos y sin traslapes (VPC y subnets), subnets dentro del rango de la VPC, IGW para
  subnets públicas, NAT en subnet pública, salida a internet desde privadas/aisladas, VPC endpoints
  necesarios (Gateway gratis para S3/DynamoDB vs NAT), servicios que requieren 2 AZ (ALB, RDS, EKS, MWAA…),
  balanceadores internet-facing en subnets públicas, conexiones entre VPCs sin Peering/TGW,
  API Gateway hacia backends privados sin VPC Link, Lambda/Glue/EMR fuera de VPC hablando con bases privadas,
  conectividad híbrida con on-premise.
- **¿Necesito balanceador?**: usuarios entrando directo a EC2/ECS, varias instancias/tareas recibiendo
  tráfico sin ALB/NLB, ASG con health check ELB sin target group.
- **IAM**: por cada conexión genera la política de mínimo privilegio en el rol correcto (rol de ejecución
  de Lambda, task role de ECS, runtime role de EMR Serverless, instance profile…), incluyendo KMS cuando
  el destino está cifrado, Glue Data Catalog/S3 Tables para Iceberg, `iam:PassRole` para lanzar jobs,
  políticas de recurso (permiso de Lambda, queue/topic policy, bucket policy OAC) y trust policies.
- **Firewall / Security Groups**: reglas de entrada y salida referenciando SG, prefix lists (S3, CloudFront)
  o CIDR; WAF en entradas públicas; filtrado de egress. Si dibujas un **Security Group** y lo conectas a sus
  recursos, compara sus reglas con las que exigen las conexiones (botón *Agregar reglas sugeridas*) y marca
  reglas peligrosas (SSH/RDP o puertos de base de datos abiertos a internet, todo el tráfico abierto).
- **Network ACL** (dentro de una subnet): evalúa las reglas en orden como lo hace AWS, incluido el *deny*
  implícito, y avisa cuando bloquean una conexión o sus respuestas (puertos efímeros 1024-65535).
- **Tablas de rutas** (dentro de una subnet, o en la VPC como tabla principal): subnet pública sin
  0.0.0.0/0 → IGW, privada con ruta al IGW, rutas a NAT/TGW/peering que no existen, Gateway endpoints no
  asociados a la tabla y rutas faltantes entre VPCs. Cuando hay tabla de rutas, la salida a internet o a
  servicios se calcula con sus rutas reales.
- **Otros servicios**: AWS Batch (Spot sin reintentos, timeouts), App Runner (VPC connector), Elastic
  Beanstalk (política de despliegue, single instance), Amazon MQ (público, single-instance, modo inválido),
  Global Accelerator (endpoints soportados), Shield, Direct Connect (redundancia y VPN de respaldo) y VPN.
- **Datos**: retención y lifecycle, versionado, Iceberg sin catálogo/compactación/expiración de snapshots,
  EMR leyendo Iceberg sin habilitarlo, formatos columnares, PITR, backups.
- **Costo y operación**: EMR sin auto-terminación o sin límite de capacidad, Spot en task nodes,
  Athena sin límite de escaneo, DLQ, visibility timeout vs timeout de Lambda, logs.
- **Seguimiento**: configuración requerida incompleta, componentes sin conexiones, terraformado sin aprobar.

Puedes marcar un hallazgo como **“Aceptar riesgo / no aplica”** con un motivo; queda registrado en el reporte.

## Copilot IA (opcional)

Además de las reglas, puedes hacer preguntas libres o pedir una revisión completa con Claude:

```bash
pip install anthropic
export ANTHROPIC_API_KEY=...
python3 app.py
```

Usa `claude-opus-5-5` por defecto (cámbialo con `INFRATRACK_MODEL`) y tiene activado el *fallback*
del lado del servidor por si el modelo declina una solicitud. El diagrama completo se envía a la API de
Anthropic cuando usas esta pestaña; si eso no está permitido para tu información, no configures la llave.

## Datos y respaldos

```
data/projects/<id>.json      un archivo por proyecto (escritura atómica)
data/backups/<id>/*.json     respaldo automático cada 5 min de edición (últimos 50)
data/trash/                  proyectos eliminados
```

Los archivos son JSON legibles: puedes versionarlos en git. Si dos personas editan el mismo proyecto a la
vez, la app detecta el conflicto y te deja recargar o sobrescribir.

## Pruebas

```bash
python3 -m unittest discover -s tests -v
```

GitHub Actions las corre en Linux (Python 3.9, 3.11, 3.13), Windows y macOS en cada push, en cada PR y cada noche.

## Extender

- Nuevos servicios o campos: `catalog.py` (`C(...)` con su formulario).
- Nuevas reglas: `copilot.py` (`check_network`, `check_services`, `statements_for` para IAM).
