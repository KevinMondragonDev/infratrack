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

### Iconos oficiales de AWS

El repositorio incluye los iconos oficiales de [AWS Architecture Icons](https://aws.amazon.com/architecture/icons/)
que usa la app (`static/icons/aws/`, paquete del 31-jul-2026). AWS permite usarlos para crear diagramas de
arquitectura. Para actualizarlos cuando AWS publique un paquete nuevo:

```bash
python3 app.py --setup-icons
```

Sin conexión o detrás de un proxy, descarga el ZIP a mano y usa `python3 app.py --icons-zip Icon-package.zip`.

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

### Diagramas de proyectos reales

- **Zona / Workspace** (contenedor): agrupa visualmente (orquestación, datos, seguridad corporativa, pipeline IaC…)
  con nombre, color y descripción, y arrastra sus componentes. No cambia la evaluación de seguridad.
- **Sistemas externos con comportamiento propio**: identidad corporativa (Azure AD / Entra ID), proxy y firewall
  corporativos, seguridad externa (Wiz, Sysdig), observabilidad (Dynatrace, Alma), CI/CD e IaC (Terraform Enterprise,
  GitHub), almacenamiento externo (Azure Blob), plataformas de datos (Snowflake, Adobe AEP), sistemas origen y un
  **Externo personalizado** con nombre, abreviatura y color. El Copilot distingue red corporativa de internet, genera
  el rol con ExternalId/OIDC para terceros y avisa de llaves de larga duración.
- **Salida corporativa**: una ruta 0.0.0.0/0 → TGW con inspección declarada, o pasar por el proxy/firewall corporativo,
  cuenta como salida filtrada.
- **Flujos**: define FL-01 Ingesta, FL-02 Egresión… en el panel del proyecto, asígnalos a cada conexión (una conexión
  puede pertenecer a varios) y resalta un flujo con el selector del lienzo.
- **Nombres legibles**: el nombre se parte en dos líneas, los nodos se pueden redimensionar y el nombre completo aparece
  al pasar el mouse.
- **Endpoint en varias subnets**: conecta el VPC endpoint con cada subnet adicional (se dibuja como "desplegado en").
- **Glue Data Catalog**: componente con pestaña *Catálogo* para subir la salida de `aws glue get-databases` y
  `aws glue get-tables --database-name <base>` (varios archivos a la vez) o un CSV
  (`database, table, column, type, partition, comment, format, location, pii, description, owner`). Muestra y permite
  editar bases, tablas, columnas, particiones, formato (Iceberg/Delta/Hudi/Hive), ubicación, dueño, sensibilidad,
  retención y columnas con datos personales (se detectan por nombre: RFC, CURP, email, teléfono…). Genera el Terraform
  (`aws_glue_catalog_database` / `aws_glue_catalog_table`), los permisos IAM por base de datos y reglas: catálogo sin
  cifrar, datos personales sin Lake Formation o sin clasificar, tablas sin dueño/descripción, tablas de texto sin
  particiones y buckets que no están en el diagrama.
- **Tags de gobierno**: tags obligatorios y tags por defecto en el proyecto, en la cuenta o en cada componente; el
  Copilot avisa qué falta y genera el bloque `default_tags` de Terraform (pestaña *Tags y Terraform*).
- **Ambientes**: *Proyecto → Duplicar como otro ambiente* cambia los IDs de cuenta (p. ej. PRE/PRO) y deja la línea base
  "Sin confirmar"; *Comparar con otro proyecto* muestra componentes, configuración y conexiones que difieren.
- **Menos ruido**: la línea base de la cuenta acepta *Sí / No / Sin confirmar* (sólo "No" es falla), una NACL
  "Pendiente de definición" no genera hallazgos de bloqueo, y un endpoint de interfaz de S3 no exige ruta de Gateway.

> Al actualizar desde una versión anterior, los datos de cuenta guardados como `false` pasan a "Sin confirmar"
> (antes no se distinguía "no" de "sin confirmar"). Si tienes iconos instalados, la paleta te ofrecerá actualizarlos
> para los componentes nuevos.

### Seguridad, cuentas y ambientes

La pestaña **Copilot → Seguridad** muestra la postura por dominios del pilar de seguridad de Well-Architected
(identidad, detección, infraestructura, datos, aplicaciones, usuario final, gobierno multi-cuenta y respuesta a
incidentes). Cada control dice si cumple, falla, está aceptado o sin evaluar, con referencias a AWS Foundational
Security Best Practices (FSBP) y CIS cuando aplica, y sus hallazgos.

- **Cuenta AWS** (contenedor): arrastra dentro sus VPCs y servicios y marca su línea base (root con MFA, Identity
  Center, GuardDuty, Security Hub, Config, Access Analyzer, CloudTrail, cifrado EBS por defecto, S3 BPA de cuenta,
  alertas, logs centralizados…). Con varias cuentas revisa AWS Organizations, guardrails SCP/RCP, administradores
  delegados, cuentas security-tooling/log-archive y conexiones que mezclan producción con no-producción.
- **Accesos entre cuentas**: al conectar componentes de cuentas distintas genera la política de recurso del destino
  (o el rol a asumir con su trust policy) y avisa sobre key policies de KMS.
- **Políticas escritas a mano**: pega JSON en la política inline de un IAM Role, la bucket policy de S3, la key policy
  de KMS o la policy de un VPC endpoint y el Copilot detecta `*:*`, comodines de servicio, `iam:PassRole` abierto,
  `NotAction`, Principal `*` sin condiciones y cuentas que no están en el proyecto.
- **Usuario final**: Amazon WorkSpaces, AppStream 2.0, WorkSpaces Secure Browser y Directory Service (cifrado de
  volúmenes, MFA, restricción por IP/dispositivo, fuga de datos por portapapeles/unidades/descargas, IP pública,
  directorio y 2 AZ).
- El selector de **ambiente** en la barra del lienzo resalta sólo las cuentas de ese ambiente.

### Estado y plan de Terraform

*Proyecto → Importar estado o plan de Terraform*:

```bash
terraform show -json > estado.json                      # o sube terraform.tfstate directamente
terraform plan -out plan.tfplan && terraform show -json plan.tfplan > plan.json
```

- **Estado**: empareja cada recurso con su componente (primero por la dirección de Terraform del componente, luego por
  nombre/tag `Name` y tipo), marca la palomita de terraformado y guarda dirección y ARN. Lista lo que existe en Terraform
  y no en el diagrama (puedes agregarlo con un clic) y lo que está en el diagrama pero no en el estado.
- **Plan**: dibuja en cada componente lo que va a pasar (+ crear, ~ modificar, − destruir, ± reemplazar) y el Copilot
  marca como **alto** cualquier destrucción o reemplazo de un recurso con datos (RDS, Aurora, S3, DynamoDB, KMS, EFS…).
- Sólo se guardan nombres, direcciones, ARNs, CIDRs y tags: nunca contraseñas ni valores marcados como sensibles.

### Reglas configurables por proyecto

En **Copilot → Reglas** están las ~250 reglas (el registro se genera leyendo el código, así que siempre está al día).
Puedes desactivar las que no apliquen, cambiar su severidad y dejar un comentario; los ajustes se guardan con el
proyecto y aparecen en el reporte. Para revisarlas con tu arquitecto: **Exportar lista para revisión (CSV)**, que la
editen en Excel (columnas `activa`, `severidad_proyecto`, `comentario`) e **Importar CSV revisado**. También puedes
exportar/importar la configuración en JSON para reutilizarla en otros proyectos.

Los escenarios reales viven en `tests/cases/*.json` (proyecto + reglas que deben y no deben aparecer): agregar un caso
es la forma de evitar que una regla nueva rompa otra.

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

GitHub Actions las corre en Linux (Python 3.9, 3.11, 3.13), Windows y macOS en cada push, en cada PR y cada noche,
junto con las pruebas de interfaz (Playwright) y SonarCloud.

**Demo pública**: https://infratrack-brown.vercel.app (los proyectos se guardan sólo en tu navegador).

## Desarrollo

- Backend: Python sólo con librería estándar (`app.py`, `copilot.py`, `security.py`, `extensions.py`, `catalog.py`…).
- Frontend: módulos ES nativos en `static/js/` (sin build): `main.js` arranca la app; `canvas.js`, `interaction.js`,
  `inspector-*.js`, `copilot-modal.js`, `glue-catalog.js`, `storage.js` (servidor o navegador), etc.
- `node scripts/check-modules.mjs` verifica que todos los módulos enlacen.
- Pruebas de interfaz con Playwright:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements-ui.txt && .venv/bin/python -m playwright install chromium
.venv/bin/python -m unittest tests.ui.test_ui -v
```

## Licencia

Código bajo licencia [MIT](LICENSE). Los iconos de `static/icons/aws/` son de AWS y se rigen por sus términos
(ver [static/icons/aws/NOTICE.md](static/icons/aws/NOTICE.md)).

## Extender

- Nuevos servicios o campos: `catalog.py` (`C(...)` con su formulario).
- Nuevas reglas: `copilot.py` (`check_network`, `check_services`, `statements_for` para IAM).
