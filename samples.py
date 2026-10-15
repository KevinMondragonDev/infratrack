"""Proyecto de ejemplo: app web + data lake (con algunos detalles por corregir a propósito)."""
from storage import now_iso


def N(id, type, label, x, y, w=150, h=56, **kw):
    d = {"id": id, "type": type, "label": label, "x": x, "y": y, "w": w, "h": h, "config": {},
         "terraformed": False, "status": "Borrador", "notes": [], "questions": []}
    d.update(kw)
    return d


def E(id, s, t, access=None, port=None, **kw):
    d = {"id": id, "source": s, "target": t, "access": access, "port": port, "notes": "", "terraformed": False}
    d.update(kw)
    return d


def sample_project():
    ts = now_iso()
    nodes = [
        N("acct", "account", "pedidos-prod", 290, -30, 1240, 820, terraformed=True, status="Aprobado",
          config={"account_id": "123456789012", "environment": "prod", "ou": "Workloads/Prod", "regions": "us-east-1",
                  "root_mfa": True, "root_no_keys": True, "identity_center": True, "iam_users_keys": 1,
                  "guardduty": True, "securityhub": False, "config": True, "access_analyzer": False, "cloudtrail": True,
                  "ebs_default_encryption": True, "s3_account_bpa": True, "findings_alerts": False}),
        N("vpc1", "vpc", "VPC principal", 320, 40, 760, 700, terraformed=True, status="Aprobado",
          config={"cidr": "10.20.0.0/16", "region": "us-east-1", "flow_logs": False}),
        N("pubA", "subnet", "Pública A", 340, 130, 340, 150, terraformed=True, status="Aprobado",
          config={"tier": "public", "cidr": "10.20.0.0/24", "az": "a"}),
        N("pubB", "subnet", "Pública B", 710, 130, 340, 150, terraformed=True, status="Aprobado",
          config={"tier": "public", "cidr": "10.20.1.0/24", "az": "b"}),
        N("privA", "subnet", "Privada A", 340, 310, 340, 310, terraformed=True, status="Aprobado",
          config={"tier": "private", "cidr": "10.20.10.0/23", "az": "a"}),
        N("privB", "subnet", "Privada B", 710, 310, 340, 310, terraformed=False, status="En revisión",
          config={"tier": "private", "cidr": "10.20.12.0/23", "az": "b"}),
        N("igw", "igw", "IGW", 625, 60, 110, 50, terraformed=True, status="Aprobado"),
        N("nat", "nat", "NAT A", 518, 190, terraformed=True, status="Aprobado", config={"connectivity": "public", "ha": "Uno compartido (ahorro)"}),
        N("alb", "alb", "ALB público", 352, 190, status="Aprobado",
          config={"scheme": "internet-facing", "listeners": ["HTTP:80", "HTTPS:443"], "target_type": "ip",
                  "health_check": "/health"}),
        N("ecs", "ecs", "API pedidos", 352, 370, status="En revisión",
          config={"launch_type": "Fargate", "cpu": 512, "memory": 1024, "desired": 2, "port": 8080, "image_source": "ECR"},
          description="Microservicio de pedidos expuesto vía ALB.",
          notes=[{"id": "n1", "text": "Imagen base python:3.13-slim, healthcheck en /health.", "author": "equipo",
                  "at": ts}]),
        N("lambda", "lambda", "Procesa pedidos", 518, 370,
          config={"runtime": "python3.13", "memory": 512, "timeout": 60, "trigger": "SQS"}),
        N("rds", "rds", "BD pedidos", 352, 520,
          config={"engine": "PostgreSQL", "instance_class": "db.r7g.large", "multi_az": True, "backup_days": 7}),
        N("emr", "emr", "EMR curación", 518, 520, status="Borrador",
          config={"deployment": "EMR Serverless", "release": "emr-7.9.0", "app_type": "Spark",
                  "catalog": "AWS Glue Data Catalog"},
          questions=[{"id": "q1", "text": "¿EMR Serverless o EMR on EC2 con Spot para los jobs nocturnos de 3 h?",
                      "author": "equipo", "at": ts, "status": "open", "answer": ""}]),
        N("sgdb", "sg", "SG base de datos", 352, 650, status="En revisión",
          config={"group_name": "sg-pedidos-bd", "description": "Acceso a PostgreSQL de pedidos", "allow_all_egress": True,
                  "rules": [{"direction": "ingress", "protocol": "tcp", "from_port": 5432, "to_port": 5432,
                             "peer": "sg-pedidos-api-pedidos", "description": "API pedidos"}]}),
        N("users", "users", "Clientes", 60, 200),
        N("sqs", "sqs", "Cola pedidos", 1140, 360, config={"type": "Standard", "visibility": 30, "dlq": True}),
        N("raw", "s3", "Data lake raw", 1140, 120,
          config={"purpose": "Data lake - raw/landing", "table_format": "Hive (tablas Glue clásicas)",
                  "file_format": "JSON", "catalog": "AWS Glue Data Catalog", "encryption": "SSE-KMS",
                  "retention_days": 90, "partitioning": "dt=YYYY-MM-DD"}),
        N("curated", "s3", "Data lake curated", 1140, 230,
          config={"purpose": "Data lake - curated/silver", "table_format": "Apache Iceberg", "file_format": "Parquet",
                  "catalog": "AWS Glue Data Catalog", "encryption": "SSE-S3"}),
        N("athena", "athena", "Athena analytics", 1340, 230,
          config={"workgroup": "analytics", "results_location": "s3://empresa-athena-results/"}),
        N("secret", "secrets", "Credenciales BD", 1340, 470, config={"secret_type": "Credenciales de BD"}),
        N("kms", "kms", "CMK data lake", 1340, 120, config={"key_spec": "Simétrica (SYMMETRIC_DEFAULT)", "alias": "alias/datalake"}),
    ]
    edges = [
        E("e1", "users", "alb", "network", 443),
        E("e2", "alb", "ecs", "invoke", 8080),
        E("e3", "ecs", "rds", "network"),
        E("e4", "ecs", "sqs", "write"),
        E("e5", "sqs", "lambda", "invoke"),
        E("e6", "lambda", "raw", "write"),
        E("e7", "emr", "raw", "read"),
        E("e8", "emr", "curated", "readwrite"),
        E("e9", "athena", "curated", "read"),
        E("e10", "ecs", "secret", "read"),
        E("e11", "raw", "kms", None),
        E("e12", "lambda", "rds", "network", notes="Actualiza el estado del pedido"),
        E("e13", "sgdb", "rds"),
    ]
    return {"name": "Ejemplo: app de pedidos + data lake", "description": "Proyecto de ejemplo. Bórralo cuando quieras.",
            "settings": {"region": "us-east-1", "account_id": "123456789012", "environment": "prod", "prefix": "pedidos"},
            "nodes": nodes, "edges": edges, "dismissed": {}}
