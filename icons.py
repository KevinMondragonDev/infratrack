"""Iconos oficiales de AWS (AWS Architecture Icons).

Los iconos no se incluyen en el repositorio: se descargan del paquete oficial de AWS
(https://aws.amazon.com/architecture/icons/) con `python3 app.py --setup-icons`
o desde el botón de la paleta. AWS permite usarlos para crear diagramas de arquitectura.

Sólo se extraen los SVG que usa la app y se guardan como static/icons/aws/<componente>.svg.
"""
import json
import os
import re
import tempfile
import urllib.request
import zipfile

ICON_PACKAGE_URL = ("https://d1.awsstatic.com/onedam/marketing-channels/website/public/shared/architecture-icon-release/"
                    "Icon-package_07312026.5846e92413caa21490223536cc97f1269e44fa92.zip")
ICON_PACKAGE_VERSION = "2026-07-31"
MAX_ZIP_BYTES = 100 * 1024 * 1024
MAX_SVG_BYTES = 512 * 1024

# componente → nombre de archivo dentro del paquete (sin carpeta)
ICON_MAP = {
    # contenedores (Architecture-Group-Icons)
    "account": "AWS-Account_32.svg",
    "vpc": "Virtual-private-cloud-VPC_32.svg",
    "subnet-public": "Public-subnet_32.svg",
    "subnet-private": "Private-subnet_32.svg",
    "onprem": "Corporate-data-center_32.svg",
    # red
    "igw": "Res_Amazon-VPC_Internet-Gateway_48.svg",
    "nat": "Res_Amazon-VPC_NAT-Gateway_48.svg",
    "vpce": "Res_Amazon-VPC_Endpoints_48.svg",
    "tgw": "Arch_AWS-Transit-Gateway_64.svg",
    "peering": "Res_Amazon-VPC_Peering-Connection_48.svg",
    "alb": "Res_Elastic-Load-Balancing_Application-Load-Balancer_48.svg",
    "nlb": "Res_Elastic-Load-Balancing_Network-Load-Balancer_48.svg",
    "apigw": "Arch_Amazon-API-Gateway_64.svg",
    "cloudfront": "Arch_Amazon-CloudFront_64.svg",
    "route53": "Arch_Amazon-Route-53_64.svg",
    "waf": "Arch_AWS-WAF_64.svg",
    "netfw": "Arch_AWS-Network-Firewall_64.svg",
    "dnsfw": "Res_Amazon-Route-53_Resolver-DNS-Firewall_48.svg",
    "vpn": "Arch_AWS-Site-to-Site-VPN_64.svg",
    "dx": "Arch_AWS-Direct-Connect_64.svg",
    "globalaccel": "Arch_AWS-Global-Accelerator_64.svg",
    "shield": "Arch_AWS-Shield_64.svg",
    "sg": "Res_Firewall_48_Light.svg",
    "nacl": "Res_Amazon-VPC_Network-Access-Control-List_48.svg",
    "rtb": "Res_Amazon-VPC_Router_48.svg",
    # cómputo
    "ec2": "Arch_Amazon-EC2_64.svg",
    "asg": "Arch_Amazon-EC2-Auto-Scaling_64.svg",
    "lambda": "Arch_AWS-Lambda_64.svg",
    "ecs": "Arch_Amazon-Elastic-Container-Service_64.svg",
    "eks": "Arch_Amazon-Elastic-Kubernetes-Service_64.svg",
    "stepfn": "Arch_AWS-Step-Functions_64.svg",
    "batch": "Arch_AWS-Batch_64.svg",
    "apprunner": "Arch_AWS-App-Runner_64.svg",
    "beanstalk": "Arch_AWS-Elastic-Beanstalk_64.svg",
    "ecr": "Arch_Amazon-Elastic-Container-Registry_64.svg",
    # almacenamiento y datos
    "s3": "Arch_Amazon-Simple-Storage-Service_64.svg",
    "efs": "Arch_Amazon-EFS_64.svg",
    "backup": "Arch_AWS-Backup_64.svg",
    "rds": "Arch_Amazon-RDS_64.svg",
    "aurora": "Arch_Amazon-Aurora_64.svg",
    "dynamodb": "Arch_Amazon-DynamoDB_64.svg",
    "elasticache": "Arch_Amazon-ElastiCache_64.svg",
    "redshift": "Arch_Amazon-Redshift_64.svg",
    "opensearch": "Arch_Amazon-OpenSearch-Service_64.svg",
    "documentdb": "Arch_Amazon-DocumentDB_64.svg",
    # analítica
    "emr": "Arch_Amazon-EMR_64.svg",
    "glue": "Arch_AWS-Glue_64.svg",
    "athena": "Arch_Amazon-Athena_64.svg",
    "kinesis": "Arch_Amazon-Kinesis-Data-Streams_64.svg",
    "firehose": "Arch_Amazon-Data-Firehose_64.svg",
    "msk": "Arch_Amazon-Managed-Streaming-for-Apache-Kafka_64.svg",
    "lakeformation": "Arch_AWS-Lake-Formation_64.svg",
    "mwaa": "Arch_Amazon-Managed-Workflows-for-Apache-Airflow_64.svg",
    "quicksight": "Arch_Amazon-Quick_64.svg",
    # integración
    "sqs": "Arch_Amazon-Simple-Queue-Service_64.svg",
    "sns": "Arch_Amazon-Simple-Notification-Service_64.svg",
    "eventbridge": "Arch_Amazon-EventBridge_64.svg",
    "appflow": "Arch_Amazon-AppFlow_64.svg",
    "mq": "Arch_Amazon-MQ_64.svg",
    # seguridad, operación y gobierno
    "iam_role": "Res_AWS-Identity-Access-Management_Role_48.svg",
    "kms": "Arch_AWS-Key-Management-Service_64.svg",
    "secrets": "Arch_AWS-Secrets-Manager_64.svg",
    "cognito": "Arch_Amazon-Cognito_64.svg",
    "acm": "Arch_AWS-Certificate-Manager_64.svg",
    "guardduty": "Arch_Amazon-GuardDuty_64.svg",
    "cloudwatch": "Arch_Amazon-CloudWatch_64.svg",
    "cloudtrail": "Arch_AWS-CloudTrail_64.svg",
    "ssm": "Arch_AWS-Systems-Manager_64.svg",
    "organization": "Arch_AWS-Organizations_64.svg",
    # usuario final (AppStream y Secure Browser son parte de la familia WorkSpaces)
    "directory": "Arch_AWS-Directory-Service_64.svg",
    "workspaces": "Arch_Amazon-WorkSpaces_64.svg",
    "appstream": "Arch_Amazon-WorkSpaces_64.svg",
    "securebrowser": "Arch_Amazon-WorkSpaces_64.svg",
    # externos
    "users": "Res_Users_48_Light.svg",
    "saas": "Res_Internet_48_Light.svg",
}

UNSAFE_SVG = re.compile(rb"<script|<foreignObject|\son[a-z]+\s*=|javascript:", re.IGNORECASE)


def icons_dir(base):
    return os.path.join(base, "static", "icons", "aws")


def available(base):
    d = icons_dir(base)
    if not os.path.isdir(d):
        return {"available": [], "version": None}
    ids = sorted(f[:-4] for f in os.listdir(d) if f.endswith(".svg"))
    version = None
    try:
        with open(os.path.join(d, "manifest.json"), encoding="utf-8") as fh:
            version = json.load(fh).get("version")
    except (OSError, ValueError):
        pass
    return {"available": ids, "version": version}


def _download(url, dest, log):
    log(f"Descargando iconos oficiales de AWS desde {url} …")
    req = urllib.request.Request(url, headers={"User-Agent": "InfraTrack/1.0"})
    total = 0
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as fh:
        while True:
            chunk = r.read(1024 * 256)
            if not chunk:
                break
            total += len(chunk)
            if total > MAX_ZIP_BYTES:
                raise ValueError("El paquete de iconos es más grande de lo esperado; descarga cancelada.")
            fh.write(chunk)
    log(f"Descargados {total / 1024 / 1024:.1f} MB")


def setup_icons(base, zip_path=None, url=ICON_PACKAGE_URL, log=print):
    """Extrae los iconos que usa la app. Devuelve {'installed': n, 'missing': [...]}."""
    out_dir = icons_dir(base)
    os.makedirs(out_dir, exist_ok=True)
    tmp = None
    try:
        if not zip_path:
            fd, tmp = tempfile.mkstemp(suffix=".zip")
            os.close(fd)
            _download(url, tmp, log)
            zip_path = tmp
        if not zipfile.is_zipfile(zip_path):
            raise ValueError("El archivo descargado no es un ZIP válido.")
        with zipfile.ZipFile(zip_path) as z:
            index = {}
            for name in z.namelist():
                if name.startswith("__MACOSX/") or not name.lower().endswith(".svg"):
                    continue
                index.setdefault(name.rsplit("/", 1)[-1], name)
            installed, missing = 0, []
            for comp_id, filename in ICON_MAP.items():
                member = index.get(filename)
                if not member:
                    missing.append(comp_id)
                    continue
                info = z.getinfo(member)
                if info.file_size > MAX_SVG_BYTES:
                    missing.append(comp_id)
                    continue
                data = z.read(member)
                if UNSAFE_SVG.search(data) or b"<svg" not in data[:2000]:
                    missing.append(comp_id)
                    continue
                target = os.path.join(out_dir, f"{comp_id}.svg")  # nombre fijo: nunca se usa la ruta del ZIP
                with open(target + ".tmp", "wb") as fh:
                    fh.write(data)
                os.replace(target + ".tmp", target)
                installed += 1
        with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8") as fh:
            json.dump({"source": url if tmp is not None else os.path.basename(zip_path),
                       "version": ICON_PACKAGE_VERSION, "installed": installed, "missing": missing}, fh, indent=2)
        log(f"Iconos instalados: {installed}" + (f" · sin icono: {', '.join(missing)}" if missing else ""))
        return {"installed": installed, "missing": missing, "version": ICON_PACKAGE_VERSION}
    finally:
        if tmp and os.path.exists(tmp):
            os.remove(tmp)
