"""Reglas de seguridad: cuentas y ambientes, políticas IAM, paquete por servicio,
usuario final (WorkSpaces/AppStream) y postura por dominios del pilar de seguridad.

`SecurityChecks` es un mixin del Analyzer de copilot.py (usa sus helpers: nodes,
cfg, label, add, of_type, neighbors, ancestor, etc.).

Las referencias "FSBP" son controles de AWS Foundational Security Best Practices
de Security Hub; "CIS" indica que el tema forma parte de CIS AWS Foundations.
Verifica la numeración contra la versión del estándar que uses.
"""
import json
import re

from extensions import TRI_NO, TRI_UNKNOWN, TRI_YES, tri_state

PROD = {"prod"}
NON_PROD = {"staging", "qa", "dev", "sandbox"}
RESOURCE_POLICY_TARGETS = {"s3", "sqs", "sns", "kms", "lambda", "secrets", "ecr", "dynamodb", "kinesis", "eventbridge",
                           "apigw", "opensearch", "glue"}
SECRET_RE = re.compile(r"(password|passwd|pwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key)\s*[=:]\s*\S+",
                       re.IGNORECASE)
HIGH_RISK_SERVICES = {"iam", "sts", "kms", "organizations", "s3", "ec2", "lambda", "secretsmanager"}

DOMAINS = [
    ("identity", "Identidad y accesos"),
    ("detection", "Detección y registro"),
    ("infrastructure", "Protección de infraestructura"),
    ("data", "Protección de datos"),
    ("app", "Aplicaciones y cargas"),
    ("enduser", "Usuario final (WorkSpaces / AppStream)"),
    ("governance", "Gobierno multi-cuenta"),
    ("ir", "Respuesta a incidentes"),
]

# (id, dominio, título, referencias, aplica_a, reglas)
#   aplica_a: tupla de tipos de componente, "account" (línea base de cuenta) o "always".
CONTROLS = [
    ("IAM-ROOT-MFA", "identity", "Root con MFA", ["CIS", "FSBP IAM.9"], "account", ["ACC-ROOT-MFA"]),
    ("IAM-ROOT-KEYS", "identity", "Root sin access keys", ["CIS", "FSBP IAM.4"], "account", ["ACC-ROOT-KEYS"]),
    ("IAM-SSO", "identity", "Acceso humano federado (Identity Center), sin llaves de larga duración", ["CIS"], "account",
     ["ACC-SSO", "ACC-IAM-KEYS", "ACC-PASSWORD", "IDP-MFA"]),
    ("IAM-ANALYZER", "identity", "IAM Access Analyzer activo", ["CIS"], "account", ["ACC-ACCESS-ANALYZER"]),
    ("IAM-ADMIN", "identity", "Sin políticas de administrador completo (*:*)", ["CIS", "FSBP IAM.1"],
     ("iam_role",), ["POL-ADMIN"]),
    ("IAM-WILDCARD", "identity", "Sin comodines en acciones sensibles ni PassRole abierto", [],
     ("iam_role",), ["POL-SERVICE-WILDCARD", "POL-PASSROLE", "POL-NOTACTION", "POL-INVALID"]),
    ("IAM-RESOURCE-POL", "identity", "Políticas de recurso sin Principal '*' ni cuentas desconocidas", [],
     ("s3", "kms", "vpce", "glue_catalog"), ["POL-PUBLIC-PRINCIPAL", "POL-EXTERNAL-ACCOUNT"]),
    ("IAM-WORKLOAD", "identity", "Cada carga con su propio rol y trust policy correcta", [],
     ("lambda", "ecs", "eks", "emr", "glue", "batch", "iam_role"), ["EKS-NODE-ROLE", "IAM-TRUST-MISMATCH"]),
    ("IAM-EXTERNAL", "identity", "Terceros y pipelines entran con roles (ExternalId / OIDC), sin llaves", [],
     ("secops", "observability", "cicd", "ext_dataplatform"), ["EXT-NO-EXTERNALID", "EXT-CICD-KEYS"]),
    ("IAM-XACCT", "identity", "Accesos entre cuentas acotados y sin mezclar ambientes", [], "always",
     ["XACCT-ENV-MIX"]),

    ("DET-GUARDDUTY", "detection", "GuardDuty habilitado", ["FSBP GuardDuty.1"], "account", ["ACC-GUARDDUTY", "DET-NONE"]),
    ("DET-SECHUB", "detection", "Security Hub con estándares activos", [], "account", ["ACC-SECURITYHUB"]),
    ("DET-CONFIG", "detection", "AWS Config grabando recursos", ["CIS", "FSBP Config.1"], "account", ["ACC-CONFIG"]),
    ("DET-CLOUDTRAIL", "detection", "CloudTrail multi-región", ["CIS", "FSBP CloudTrail.1"], "always",
     ["GOV-CLOUDTRAIL", "CT-MULTIREGION", "ACC-CLOUDTRAIL"]),
    ("DET-CT-INTEGRITY", "detection", "Validación de integridad de logs de CloudTrail", ["CIS", "FSBP CloudTrail.4"],
     ("cloudtrail",), ["CT-VALIDATION", "CT-DATA-EVENTS"]),
    ("DET-FLOWLOGS", "detection", "VPC Flow Logs", ["CIS", "FSBP EC2.6"], ("vpc",), ["NET-FLOWLOGS"]),
    ("DET-ACCESS-LOGS", "detection", "Logs de acceso (S3, ALB, CloudFront, API Gateway)", ["FSBP S3.9"],
     ("s3", "alb", "cloudfront", "apigw"), ["S3-ACCESS-LOGS", "ALB-LOGS", "CF-LOGS", "APIGW-LOGS"]),
    ("DET-LOG-RETENTION", "detection", "Retención de logs suficiente para investigaciones", [], ("cloudwatch",),
     ["CW-RETENTION", "OPS-CW"]),
    ("DET-EKS-LOGS", "detection", "Logs del control plane de EKS", [], ("eks",), ["EKS-LOGS"]),

    ("INF-ADMIN-PORTS", "infrastructure", "Sin SSH/RDP abiertos a internet", ["CIS", "FSBP EC2.13", "FSBP EC2.14"],
     ("sg", "nacl", "ec2", "asg"), ["SG-OPEN-ADMIN", "EC2-SSH-PUBLIC", "NACL-ADMIN-OPEN"]),
    ("INF-OPEN-PORTS", "infrastructure", "Sin puertos de alto riesgo abiertos a internet", ["FSBP EC2.19"], ("sg",),
     ["SG-OPEN-ALL", "SG-OPEN-DB", "SG-OPEN-WIDE"]),
    ("INF-PUBLIC-DATA", "infrastructure", "Bases de datos y brokers no públicos", ["FSBP RDS.2", "FSBP Redshift.1"],
     ("rds", "aurora", "redshift", "opensearch", "mq", "elasticache", "documentdb", "msk"),
     ["SEC-DATA-PUBLIC", "SEC-DATA-PUBLIC-SUBNET", "OS-PUBLIC"]),
    ("INF-EXPOSURE", "infrastructure", "Backends privados detrás de balanceador", [],
     ("ec2", "asg", "ecs", "eks", "emr", "subnet"), ["NET-DIRECT-EXPOSE", "ECS-PUBLIC-IP", "EMR-PUBLIC", "RTB-PRIVATE-IGW"]),
    ("INF-WAF", "infrastructure", "WAF en entradas públicas", [], ("alb", "apigw", "cloudfront", "apprunner"),
     ["SEC-WAF"]),
    ("INF-DDOS", "infrastructure", "Protección DDoS acorde al riesgo", [], ("alb", "cloudfront", "globalaccel", "shield"),
     ["SEC-SHIELD", "SHIELD-NONE", "SHIELD-L7"]),
    ("INF-IMDS", "infrastructure", "IMDSv2 obligatorio", ["CIS", "FSBP EC2.8"], ("ec2", "asg", "beanstalk"), ["EC2-IMDS"]),
    ("INF-SSM", "infrastructure", "Administración sin SSH (Session Manager)", [], ("ec2", "asg"), ["EC2-SSH"]),
    ("INF-EGRESS", "infrastructure", "Salida a internet filtrada", [], "always", ["SEC-EGRESS-FILTER", "PROXY-CA"]),
    ("INF-EKS-ENDPOINT", "infrastructure", "API de EKS no pública", ["FSBP EKS.1"], ("eks",), ["EKS-ENDPOINT"]),
    ("INF-PATCHING", "infrastructure", "Parches administrados", [], ("beanstalk",), ["EB-UPDATES"]),

    ("DAT-S3-PUBLIC", "data", "S3 Block Public Access (bucket y cuenta)", ["CIS", "FSBP S3.8", "FSBP S3.1"],
     ("s3",), ["S3-PUBLIC", "SEC-S3-DIRECT", "ACC-S3-BPA"]),
    ("DAT-S3-TLS", "data", "S3 rechaza peticiones sin TLS", ["CIS", "FSBP S3.5"], ("s3",), ["S3-TLS"]),
    ("DAT-ENC-REST", "data", "Cifrado en reposo", ["CIS", "FSBP RDS.3", "FSBP EC2.7"], "always",
     ["DB-ENC", "EC2-EBS", "ENC-REST", "ACC-EBS-DEFAULT"]),
    ("DAT-ENC-TRANSIT", "data", "Cifrado en tránsito y políticas TLS vigentes", [],
     ("alb", "cloudfront", "msk", "elasticache", "documentdb"),
     ["ALB-HTTPS", "CF-HTTP", "CF-TLS", "ALB-TLS-POLICY", "MSK-TLS", "EC-TLS", "DOC-TLS"]),
    ("DAT-KMS", "data", "Rotación de llaves KMS", ["CIS", "FSBP KMS.4"], ("kms",), ["KMS-ROT"]),
    ("DAT-SECRETS", "data", "Secretos administrados y rotados (nunca en variables)", ["FSBP SecretsManager.1"],
     ("secrets", "rds", "aurora", "lambda", "ext_storage"), ["SM-ROT", "DB-SECRET", "LAMBDA-SECRET-ENV", "EXT-STORAGE-SECRET"]),
    ("DAT-BACKUP", "data", "Backups y recuperación", ["FSBP DynamoDB.2"],
     ("rds", "aurora", "dynamodb", "s3", "backup"), ["DB-BACKUP", "DDB-PITR", "S3-VERSIONING", "BKP-NONE"]),
    ("DAT-CATALOG", "data", "Catálogo de datos cifrado, clasificado y con datos personales gobernados", [],
     ("glue_catalog",), ["GLUE-CAT-ENC", "GLUE-PII-NO-LF", "GLUE-SENSITIVITY"]),
    ("DAT-DISCOVERY", "data", "Descubrimiento de datos sensibles (Macie)", [], "account", ["ACC-MACIE"]),

    ("APP-AUTH", "app", "APIs y usuarios autenticados (con MFA)", [], ("apigw", "cognito"), ["APIGW-AUTH", "COG-MFA"]),
    ("APP-IMAGES", "app", "Imágenes escaneadas e inmutables", ["FSBP ECR.1", "FSBP ECR.2"], ("ecr",),
     ["ECR-SCAN", "ECR-MUTABLE"]),
    ("APP-VULN", "app", "Escaneo de vulnerabilidades (Inspector)", [], "account", ["ACC-INSPECTOR"]),
    ("APP-EKS-SECRETS", "app", "Secrets de Kubernetes cifrados con KMS", ["FSBP EKS.3"], ("eks",), ["EKS-SECRETS"]),
    ("APP-BROKER-AUTH", "app", "Brokers y cachés con autenticación", [], ("msk", "elasticache"), ["MSK-AUTH", "EC-AUTH"]),

    ("EUC-ENC", "enduser", "Volúmenes de escritorios cifrados", [], ("workspaces",), ["WS-ENC"]),
    ("EUC-MFA", "enduser", "MFA para usuarios de escritorios", [], ("workspaces", "directory", "appstream"),
     ["WS-MFA", "AS-AUTH"]),
    ("EUC-ACCESS", "enduser", "Acceso restringido por IP / dispositivo", [], ("workspaces", "securebrowser"),
     ["WS-IP", "WSB-IP"]),
    ("EUC-DLP", "enduser", "Controles contra fuga de datos (portapapeles, unidades, descargas)", [],
     ("workspaces", "appstream", "securebrowser"), ["WS-DLP", "AS-DLP", "WSB-DLP"]),
    ("EUC-NETWORK", "enduser", "Escritorios en subnets privadas, salida controlada", [],
     ("workspaces", "appstream"), ["WS-PUBLIC", "AS-INTERNET"]),
    ("EUC-DIRECTORY", "enduser", "Directorio resiliente y conectado", [], ("workspaces", "directory"),
     ["WS-NO-DIR", "DIR-CONNECTOR", "DIR-SIMPLE"]),

    ("GOV-ORG", "governance", "Cuentas bajo AWS Organizations", [], "multiaccount", ["ORG-MISSING"]),
    ("GOV-SCP", "governance", "Guardrails preventivos (SCP/RCP)", [], ("organization",), ["ORG-NO-SCP", "ORG-SCP-CORE"]),
    ("GOV-SEGREGATION", "governance", "Producción separada de no-producción", [], "multiaccount",
     ["XACCT-ENV-MIX", "ACC-MIXED"]),
    ("GOV-LZ", "governance", "Cuentas dedicadas de seguridad y log archive", [], "multiaccount", ["ORG-LZ"]),
    ("GOV-DELEGATED", "governance", "Servicios de seguridad con administrador delegado", [], ("organization",),
     ["ORG-DELEGATED"]),
    ("GOV-TAGS", "governance", "Tags de gobierno completos (default_tags)", [], "tags", ["TAG-MISSING"]),
    ("APP-PIPELINE", "governance", "Pipeline IaC con aprobación de planes", [], ("cicd",), ["EXT-CICD-APPROVAL"]),
    ("GOV-COST", "governance", "Alertas de presupuesto y anomalías", [], "account", ["ACC-BUDGET"]),

    ("IR-ALERTS", "ir", "Hallazgos enrutados a alertas", [], "account", ["ACC-ALERTS"]),
    ("IR-CENTRAL-LOGS", "ir", "Logs centralizados en cuenta log-archive", [], "account", ["ACC-CENTRAL-LOGS"]),
    ("IR-CONTACT", "ir", "Contacto de seguridad configurado", ["CIS"], "account", ["ACC-SEC-CONTACT"]),
    ("IR-IMMUTABLE-BACKUP", "ir", "Backups inmutables (Vault Lock)", [], ("backup",), ["BKP-VAULT-LOCK"]),
]

# Línea base por cuenta: (campo, regla, severidad, título, recomendación)
ACCOUNT_BASELINE = [
    ("root_mfa", "ACC-ROOT-MFA", "critical", "root sin MFA confirmado",
     "Activa MFA de hardware o passkey en el usuario root y guárdalo en custodia."),
    ("root_no_keys", "ACC-ROOT-KEYS", "critical", "root podría tener access keys",
     "Elimina las access keys del root; usa roles para todo."),
    ("identity_center", "ACC-SSO", "medium", "sin IAM Identity Center confirmado",
     "Centraliza el acceso humano con IAM Identity Center y permission sets."),
    ("guardduty", "ACC-GUARDDUTY", "high", "sin GuardDuty", "Habilita GuardDuty (idealmente en toda la organización)."),
    ("securityhub", "ACC-SECURITYHUB", "medium", "sin Security Hub",
     "Habilita Security Hub con AWS Foundational Security Best Practices y CIS."),
    ("config", "ACC-CONFIG", "medium", "sin AWS Config", "Graba todos los recursos con AWS Config (requisito de Security Hub)."),
    ("access_analyzer", "ACC-ACCESS-ANALYZER", "medium", "sin IAM Access Analyzer",
     "Crea un analyzer de organización para detectar accesos externos y permisos sin uso."),
    ("cloudtrail", "ACC-CLOUDTRAIL", "high", "sin cobertura de CloudTrail confirmada",
     "Usa un trail de organización multi-región hacia la cuenta log-archive."),
    ("ebs_default_encryption", "ACC-EBS-DEFAULT", "medium", "sin cifrado EBS por defecto",
     "Activa EBS encryption by default en cada región usada."),
    ("s3_account_bpa", "ACC-S3-BPA", "high", "sin S3 Block Public Access de cuenta",
     "Activa Block Public Access a nivel cuenta (y bloquéalo con SCP)."),
    ("macie", "ACC-MACIE", "low", "sin Macie", "Habilita Macie si la cuenta guarda datos personales o sensibles."),
    ("inspector", "ACC-INSPECTOR", "low", "sin Inspector", "Habilita Inspector para EC2, ECR y Lambda."),
    ("findings_alerts", "ACC-ALERTS", "medium", "hallazgos sin alertas",
     "Enruta hallazgos de GuardDuty/Security Hub con EventBridge a SNS, Chat o tu SIEM."),
    ("central_logs", "ACC-CENTRAL-LOGS", "low", "logs no centralizados",
     "Envía CloudTrail, Config y Flow Logs a la cuenta log-archive con retención inmutable."),
    ("security_contact", "ACC-SEC-CONTACT", "low", "sin contacto de seguridad", "Configura el contacto alterno de seguridad."),
    ("budget_alerts", "ACC-BUDGET", "low", "sin alertas de presupuesto",
     "Configura AWS Budgets y Cost Anomaly Detection (un gasto anómalo suele ser señal de compromiso)."),
]
EXEMPT_BASELINE = {"sandbox": {"ACC-MACIE", "ACC-INSPECTOR", "ACC-CENTRAL-LOGS"}}


def parse_policy(text):
    """Devuelve (statements, error). Acepta un documento, una lista de statements o un statement."""
    if not text or not str(text).strip():
        return None, None
    t = str(text).strip()
    if t[0] not in "{[":
        return None, None
    try:
        doc = json.loads(t)
    except json.JSONDecodeError as exc:
        return None, f"JSON inválido: {exc.msg} (línea {exc.lineno})"
    if isinstance(doc, dict) and "Statement" in doc:
        st = doc["Statement"]
    else:
        st = doc
    if isinstance(st, dict):
        st = [st]
    if not isinstance(st, list) or not all(isinstance(x, dict) for x in st):
        return None, "No se encontró una lista de statements"
    return st, None


def _as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


RULE_FIELD = {rule: field for field, rule, *_ in ACCOUNT_BASELINE}


class SecurityChecks:
    def field_label(self, comp_id, key):
        from catalog import COMPONENTS_BY_ID
        return next((f["label"] for f in COMPONENTS_BY_ID[comp_id]["fields"] if f["key"] == key), key)

    # ───────────── helpers de cuentas ─────────────
    def account_of(self, n):
        return n if n["type"] == "account" else self.ancestor(n, "account")

    def env_of(self, n):
        a = self.account_of(n)
        if a:
            return self.cfg(a).get("environment") or ""
        return self.env

    def acct_id(self, n):
        a = self.account_of(n) if n else None
        return (self.cfg(a).get("account_id") if a else None) or self.account

    def known_accounts(self):
        ids = {str(self.cfg(a).get("account_id")) for a in self.of_type("account") if self.cfg(a).get("account_id")}
        if self.settings.get("account_id"):
            ids.add(str(self.settings["account_id"]))
        for o in self.of_type("organization"):
            if self.cfg(o).get("management_account"):
                ids.add(str(self.cfg(o)["management_account"]))
        return ids

    # ───────────── cuentas y organización ─────────────
    def check_accounts(self):
        accounts = self.of_type("account")
        for a in accounts:
            c, L = self.cfg(a), self.label(a)
            env = c.get("environment") or ""
            exempt = EXEMPT_BASELINE.get(env, set())
            unconfirmed = []
            for field, rule, sev, title, rec in ACCOUNT_BASELINE:
                st = tri_state(c.get(field))
                if rule in exempt or st == TRI_YES:
                    continue
                if st == TRI_UNKNOWN:
                    unconfirmed.append(self.field_label("account", field))
                    continue
                if env not in PROD and sev == "critical":
                    sev = "high"
                self.add(sev, "Seguridad", rule, f"Cuenta '{L}': {title}", f"Línea base de seguridad de la cuenta ({env or 'sin ambiente'}).",
                         rec, [a])
            if unconfirmed:
                self.add("info", "Seguimiento", "ACC-UNCONFIRMED", f"Cuenta '{L}': {len(unconfirmed)} controles sin confirmar",
                         "Sin confirmar: " + "; ".join(unconfirmed) + ". No cuentan como falla hasta que se respondan.",
                         "Confirma cada dato con el equipo de plataforma y márcalo como Sí o No.", [a])
            keys = c.get("iam_users_keys") or 0
            if keys:
                self.add("high" if env in PROD else "medium", "Seguridad", "ACC-IAM-KEYS",
                         f"Cuenta '{L}': {keys} usuarios IAM con access keys",
                         "Las llaves de larga duración son la causa más común de compromisos.",
                         "Migra a IAM Identity Center y roles; si son para máquinas, usa roles (OIDC/IRSA/instance profile).", [a])
                if tri_state(c.get("identity_center")) != TRI_YES and tri_state(c.get("password_policy")) == TRI_NO:
                    self.add("medium", "Seguridad", "ACC-PASSWORD", f"Cuenta '{L}': sin política de contraseñas",
                             "Hay usuarios IAM y no se confirmó política de contraseñas.",
                             "Exige longitud ≥14, sin reutilización, y MFA para usuarios de consola.", [a])
            if tri_state(c.get("securityhub")) == TRI_YES and not c.get("sh_standards"):
                self.add("low", "Seguridad", "ACC-SECURITYHUB", f"Cuenta '{L}': Security Hub sin estándares",
                         "Security Hub está habilitado pero no se indicaron estándares.",
                         "Activa al menos AWS Foundational Security Best Practices y CIS.", [a])
            # Workloads de varios ambientes en una misma cuenta
            for v in [n for n in self.nodes.values() if n["type"] == "vpc" and self.account_of(n) is a]:
                name = (self.label(v) + " " + str(self.cfg(v).get("cidr") or "")).lower()
                other = [e for e in ("prod", "dev", "qa", "staging") if re.search(rf"\b{e}\b", name) and e != env]
                if other and env in PROD | NON_PROD:
                    self.add("medium", "Gobierno", "ACC-MIXED", f"'{self.label(v)}' parece de {other[0]} dentro de '{L}' ({env})",
                             "Mezclar ambientes en una cuenta comparte límites, permisos y radio de impacto.",
                             "Separa cada ambiente en su propia cuenta.", [v, a])
        # Organización
        orgs = self.of_type("organization")
        if len(accounts) >= 2 and not orgs:
            self.add("medium", "Gobierno", "ORG-MISSING", "Varias cuentas sin AWS Organizations",
                     f"Hay {len(accounts)} cuentas y no se dibujó la organización.",
                     "Agrupa las cuentas en AWS Organizations (o Control Tower) para aplicar guardrails y servicios centralizados.",
                     accounts)
        if len(accounts) >= 2:
            envs = {self.cfg(a).get("environment") for a in accounts}
            missing = [e for e in ("security-tooling", "log-archive") if e not in envs]
            if missing:
                self.add("low", "Gobierno", "ORG-LZ", "Faltan cuentas de la landing zone",
                         f"No hay cuenta(s): {', '.join(missing)}.",
                         "Usa una cuenta security-tooling (administrador delegado) y otra log-archive (logs inmutables).",
                         accounts)
        core = ["Denegar salir de la organización", "Denegar desactivar CloudTrail",
                "Denegar desactivar GuardDuty / Security Hub / Config"]
        for o in orgs:
            c, L = self.cfg(o), self.label(o)
            scps = c.get("scps") or []
            if not scps:
                self.add("medium", "Gobierno", "ORG-NO-SCP", f"'{L}' sin guardrails", "No hay SCP/RCP declaradas.",
                         "Empieza por: no salir de la organización, no desactivar CloudTrail/GuardDuty/Config, restringir regiones.",
                         [o])
            else:
                miss = [x for x in core if x not in scps]
                if miss:
                    self.add("low", "Gobierno", "ORG-SCP-CORE", f"'{L}': faltan guardrails básicos", "Faltan: " + "; ".join(miss) + ".",
                             "Agrega esas SCP: protegen la detección aunque se comprometa una cuenta.", [o])
            deleg = c.get("delegated") or []
            miss = [x for x in ("GuardDuty", "Security Hub", "IAM Access Analyzer") if x not in deleg]
            if accounts and miss:
                self.add("low", "Gobierno", "ORG-DELEGATED", f"'{L}': sin administrador delegado para {', '.join(miss)}",
                         "Sin administrador delegado los hallazgos quedan dispersos por cuenta.",
                         "Delega su administración a la cuenta security-tooling.", [o])

    def cross_account(self, plan, e, src, tgt):
        sa, ta = self.account_of(src), self.account_of(tgt)
        if not sa or not ta or sa["id"] == ta["id"]:
            return
        sid, tid = self.acct_id(src), self.acct_id(tgt)
        senv, tenv = self.env_of(src), self.env_of(tgt)
        plan["notes"].insert(0, f"Acceso entre cuentas: {self.label(sa)} ({sid}, {senv or '—'}) → {self.label(ta)} ({tid}, {tenv or '—'}).")
        if (senv in PROD and tenv in NON_PROD) or (senv in NON_PROD and tenv in PROD):
            self.add("high", "Gobierno", "XACCT-ENV-MIX", f"Conexión entre ambientes: {self.label(src)} ({senv}) → {self.label(tgt)} ({tenv})",
                     "Un ambiente no productivo conectado con producción rompe el aislamiento (datos reales en dev o "
                     "cambios de dev afectando prod).",
                     "Elimina la dependencia o pasa los datos por un mecanismo controlado (réplica anonimizada, API pública).",
                     [src, tgt], [e])
        pr = plan.get("principal")
        if not pr:
            return
        role_arn = f"arn:aws:iam::{sid}:role/{pr['role']}"
        if tgt["type"] in RESOURCE_POLICY_TARGETS:
            acts = sorted({a for s in plan["identity"] for a in _as_list(s.get("Action"))
                           if not a.startswith(("kms:", "glue:", "lakeformation:", "iam:"))})
            if acts:
                plan["resource_policies"].append({
                    "type": "Política de recurso (cross-account)", "on": self.label(tgt),
                    "statement": {"Sid": "CrossAccount" + re.sub(r"[^A-Za-z0-9]", "", self.label(src)),
                                  "Effect": "Allow", "Principal": {"AWS": role_arn}, "Action": acts,
                                  "Resource": [s for st in plan["identity"] for s in _as_list(st.get("Resource"))
                                               if not str(s).startswith(("arn:aws:kms", "arn:aws:glue"))] or "*"}})
                plan["notes"].append("Entre cuentas se necesitan ambos lados: la política de identidad en el rol origen "
                                     "y la política de recurso en el destino.")
            if any(a.startswith("kms:") for s in plan["identity"] for a in _as_list(s.get("Action"))):
                plan["notes"].append(f"La key policy de la CMK en {tid} debe permitir a {role_arn}; las llaves administradas "
                                     "por AWS (aws/s3, aws/sqs…) no se pueden compartir entre cuentas.")
        else:
            target_role = f"arn:aws:iam::{tid}:role/{self.name(src)}-access"
            plan["identity"].append({"Sid": "AssumeCrossAccountRole", "Effect": "Allow", "Action": ["sts:AssumeRole"],
                                     "Resource": [target_role]})
            plan["resource_policies"].append({
                "type": f"Trust policy del rol en la cuenta {tid}", "on": target_role,
                "statement": {"Effect": "Allow", "Principal": {"AWS": role_arn}, "Action": "sts:AssumeRole",
                              "Condition": {"StringEquals": {"aws:PrincipalOrgID": "<o-xxxxxxxx>"}}}})
            plan["notes"].append(f"{self.comp(tgt)['name']} no admite políticas de recurso: crea un rol en la cuenta "
                                 f"{tid} con los permisos y deja que el origen lo asuma.")

    # ───────────── políticas escritas a mano ─────────────
    def check_policies(self):
        known = self.known_accounts()
        sources = [("iam_role", "inline", "identity"), ("s3", "bucket_policy", "resource"), ("glue_catalog", "resource_policy", "resource"),
                   ("kms", "key_policy", "resource"), ("vpce", "policy", "resource")]
        for typ, field, kind in sources:
            for n in self.of_type(typ):
                st, err = parse_policy(self.cfg(n).get(field))
                L = self.label(n)
                if err:
                    self.add("low", "IAM", "POL-INVALID", f"Política de '{L}' no se puede leer", err,
                             "Corrige el JSON para que el Copilot pueda revisarla.", [n])
                    continue
                for s in st or []:
                    self._check_statement(n, L, s, kind, known)
        for n in self.of_type("iam_role"):
            txt = str(self.cfg(n).get("managed_policies") or "")
            L = self.label(n)
            if re.search(r"\bAdministratorAccess\b", txt):
                self.add("critical", "IAM", "POL-ADMIN", f"Rol '{L}' con AdministratorAccess",
                         "Privilegios completos sobre la cuenta.", "Reemplázala por una política de mínimo privilegio.", [n])
            elif re.search(r"\b(PowerUserAccess|IAMFullAccess)\b", txt):
                self.add("high", "IAM", "POL-ADMIN", f"Rol '{L}' con PowerUserAccess/IAMFullAccess",
                         "Permisos casi de administrador.", "Acota a las acciones y recursos que usa el componente.", [n])
            elif re.search(r"FullAccess\b", txt):
                self.add("medium", "IAM", "POL-SERVICE-WILDCARD", f"Rol '{L}' con políticas *FullAccess",
                         "Las políticas administradas FullAccess conceden todo el servicio sobre todos los recursos.",
                         "Usa las políticas que genera el Copilot por conexión.", [n])

    def _check_statement(self, n, L, s, kind, known):
        if s.get("Effect", "Allow") != "Allow":
            return
        actions = [str(a) for a in _as_list(s.get("Action"))]
        resources = [str(r) for r in _as_list(s.get("Resource"))]
        sid = s.get("Sid") or "sin Sid"
        if s.get("NotAction") is not None or s.get("NotResource") is not None:
            self.add("medium", "IAM", "POL-NOTACTION", f"'{L}' usa NotAction/NotResource con Allow",
                     f"Statement {sid}: concede todo lo no listado, incluidas acciones futuras.",
                     "Reescríbelo con Action/Resource explícitos.", [n])
        if "*" in actions and (kind == "identity" and ("*" in resources or not resources)):
            self.add("critical", "IAM", "POL-ADMIN", f"'{L}' concede *:* (administrador)",
                     f"Statement {sid}: Action '*' sobre Resource '*'.", "Limita acciones y recursos al mínimo necesario.", [n])
        elif "*" in actions:
            self.add("high", "IAM", "POL-ADMIN", f"'{L}' concede todas las acciones",
                     f"Statement {sid}: Action '*'.", "Lista sólo las acciones necesarias.", [n])
        else:
            wild = [a for a in actions if a.endswith(":*")]
            if wild:
                risky = [a for a in wild if a.split(":")[0].lower() in HIGH_RISK_SERVICES]
                self.add("high" if risky else "medium", "IAM", "POL-SERVICE-WILDCARD",
                         f"'{L}' usa comodines de servicio: {', '.join(wild[:4])}",
                         f"Statement {sid}." + (" Incluye servicios sensibles." if risky else ""),
                         "Reemplaza el comodín por las acciones concretas.", [n])
        if kind == "identity" and any(a.lower() in ("iam:passrole", "iam:*") for a in actions) and \
                any(r == "*" or r.endswith(":role/*") for r in resources):
            self.add("high", "IAM", "POL-PASSROLE", f"'{L}' permite iam:PassRole sobre cualquier rol",
                     f"Statement {sid}: permite escalar privilegios pasando roles más poderosos a servicios.",
                     "Limita PassRole a ARNs concretos y agrega la condición iam:PassedToService.", [n])
        if kind == "resource":
            principals = s.get("Principal")
            values = []
            if principals == "*":
                values = ["*"]
            elif isinstance(principals, dict):
                for v in principals.values():
                    values += [str(x) for x in _as_list(v)]
            cond = s.get("Condition") or {}
            if "*" in values and not cond:
                self.add("critical", "Seguridad", "POL-PUBLIC-PRINCIPAL", f"'{L}' permite a cualquiera (Principal '*')",
                         f"Statement {sid} sin condiciones: el recurso queda público.",
                         "Restringe el Principal o agrega condiciones (aws:PrincipalOrgID, aws:SourceVpce, aws:SourceArn).", [n])
            for v in values:
                m = re.search(r"(?:arn:aws:iam::)?(\d{12})", v)
                if m and known and m.group(1) not in known:
                    self.add("medium", "IAM", "POL-EXTERNAL-ACCOUNT", f"'{L}' concede acceso a la cuenta {m.group(1)}",
                             f"Statement {sid}: la cuenta no aparece en el proyecto.",
                             "Confirma que es un tercero esperado y agrega condiciones (sts:ExternalId, aws:PrincipalOrgID).", [n])

    # ───────────── paquete por servicio ─────────────
    def check_security_pack(self):
        prod = self.is_prod()
        for n in list(self.nodes.values()):
            t, c, L = n["type"], self.cfg(n), self.label(n)
            node_prod = self.env_of(n) in PROD if self.account_of(n) else prod

            def enc(field, sev, what):
                if c.get(field) is False:
                    self.add(sev, "Seguridad", "ENC-REST", f"{what} sin cifrado en reposo: '{L}'", "",
                             "Habilita el cifrado con KMS (no se puede activar después en varios servicios).", [n])

            if t == "s3":
                if not c.get("tls_only", True):
                    self.add("medium", "Seguridad", "S3-TLS", f"Bucket '{L}' acepta peticiones sin TLS",
                             "Falta el deny con aws:SecureTransport = false.", "Agrega ese statement a la bucket policy.", [n])
                if not c.get("access_logs") and c.get("purpose") != "Logs" and str(c.get("purpose", "")).startswith(("Data lake", "Intercambio")):
                    self.add("low", "Seguridad", "S3-ACCESS-LOGS", f"Bucket '{L}' sin logs de acceso",
                             "Sin server access logs o data events no hay trazabilidad de quién leyó qué.",
                             "Activa CloudTrail data events (o server access logs) para buckets con datos.", [n])
            elif t == "alb":
                if not c.get("access_logs"):
                    self.add("low", "Seguridad", "ALB-LOGS", f"ALB '{L}' sin access logs", "", "Activa access logs hacia S3.", [n])
                if "legado" in str(c.get("tls_policy") or ""):
                    self.add("medium", "Seguridad", "ALB-TLS-POLICY", f"ALB '{L}' con política TLS antigua",
                             "Permite TLS 1.0/1.1.", "Usa ELBSecurityPolicy-TLS13-1-2-2021-06.", [n])
            elif t == "cloudfront":
                if c.get("min_tls") == "TLSv1":
                    self.add("medium", "Seguridad", "CF-TLS", f"CloudFront '{L}' permite TLS 1.0", "", "Usa TLSv1.2_2021.", [n])
                if not c.get("logging"):
                    self.add("low", "Seguridad", "CF-LOGS", f"CloudFront '{L}' sin logs", "", "Activa logs estándar o en tiempo real.", [n])
            elif t == "apigw" and not c.get("access_logs", True):
                self.add("low", "Seguridad", "APIGW-LOGS", f"API '{L}' sin access logs", "", "Activa access logging.", [n])
            elif t == "cognito" and c.get("mfa") == "OFF":
                self.add("high" if node_prod else "medium", "Seguridad", "COG-MFA", f"Cognito '{L}' sin MFA", "",
                         "Configura MFA opcional u obligatorio (TOTP o passkeys).", [n])
            elif t == "eks":
                if not c.get("secrets_kms", True):
                    self.add("medium", "Seguridad", "EKS-SECRETS", f"EKS '{L}' sin cifrado KMS de secrets", "",
                             "Habilita envelope encryption de secrets con una CMK.", [n])
                if not c.get("control_plane_logs"):
                    self.add("low", "Seguridad", "EKS-LOGS", f"EKS '{L}' sin logs del control plane",
                             "Sin audit logs no sabrás quién cambió qué en el cluster.", "Activa al menos audit y authenticator.", [n])
            elif t == "ecr":
                if not c.get("scan_on_push", True):
                    self.add("medium", "Seguridad", "ECR-SCAN", f"ECR '{L}' sin escaneo de imágenes", "",
                             "Activa scan on push (o Inspector enhanced scanning).", [n])
                if not c.get("immutable", True):
                    self.add("low", "Seguridad", "ECR-MUTABLE", f"ECR '{L}' con tags mutables",
                             "Un tag puede sobrescribirse con otra imagen.", "Activa tag immutability.", [n])
            elif t == "lambda":
                for line in str(c.get("env_vars") or "").splitlines():
                    if SECRET_RE.search(line) and "arn:aws" not in line and "{{resolve" not in line:
                        self.add("high", "Seguridad", "LAMBDA-SECRET-ENV", f"Posible secreto en variables de '{L}'",
                                 f"Línea: {line.split('=')[0].split(':')[0].strip()}=…",
                                 "Guarda el valor en Secrets Manager/Parameter Store y léelo en ejecución.", [n])
                        break
            elif t == "cloudtrail":
                if not c.get("multi_region", True):
                    self.add("high", "Seguridad", "CT-MULTIREGION", f"CloudTrail '{L}' no es multi-región", "",
                             "Usa un trail multi-región (de organización).", [n])
                if not c.get("validation", True):
                    self.add("medium", "Seguridad", "CT-VALIDATION", f"CloudTrail '{L}' sin validación de integridad", "",
                             "Activa log file validation.", [n])
                if not c.get("data_events"):
                    self.add("low", "Seguridad", "CT-DATA-EVENTS", f"CloudTrail '{L}' sin data events",
                             "No registra lecturas/escrituras de objetos S3 ni invocaciones Lambda.",
                             "Activa data events al menos para buckets con datos sensibles.", [n])
            elif t == "cloudwatch" and (c.get("log_retention") or 0) < (365 if node_prod else 30):
                self.add("low", "Seguridad", "CW-RETENTION", f"Retención de logs corta en '{L}'",
                         f"{c.get('log_retention') or 0} días.", "Para investigaciones en producción conserva ≥ 1 año "
                         "(o exporta a S3/log-archive).", [n])
            elif t == "backup" and node_prod and not c.get("vault_lock"):
                self.add("low", "Seguridad", "BKP-VAULT-LOCK", f"Backups de '{L}' sin Vault Lock",
                         "Un atacante con permisos podría borrar los respaldos (ransomware).", "Activa Vault Lock en modo compliance.", [n])
            elif t == "elasticache" and c.get("auth") == "Ninguna":
                self.add("medium", "Seguridad", "EC-AUTH", f"ElastiCache '{L}' sin autenticación", "",
                         "Usa IAM auth o RBAC con usuarios.", [n])
            elif t == "documentdb" and not c.get("tls", True):
                self.add("medium", "Seguridad", "DOC-TLS", f"DocumentDB '{L}' sin TLS obligatorio", "", "Activa tls=enabled.", [n])
            if t in ("efs", "redshift", "documentdb", "opensearch"):
                enc("encrypted", "high", self.comp(n)["name"])
            elif t == "elasticache":
                enc("rest_encryption", "medium", "ElastiCache")
            elif t == "kinesis":
                enc("encrypted", "medium", "Kinesis")
            elif t == "sns":
                enc("encrypted", "low", "SNS")
            elif t == "athena":
                enc("results_encrypted", "medium", "Resultados de Athena")
            elif t == "emr":
                enc("encryption", "medium", "EMR")
            if t == "opensearch" and not c.get("fgac", True):
                self.add("medium", "Seguridad", "OS-FGAC", f"OpenSearch '{L}' sin fine-grained access control", "",
                         "Activa FGAC para permisos por índice/documento.", [n])
        datastores = self.of_type("rds", "aurora", "dynamodb", "efs", "documentdb", "ec2")
        if datastores and (prod or any(self.env_of(d) in PROD for d in datastores)) and not self.of_type("backup"):
            self.add("low", "Seguridad", "BKP-NONE", "Sin AWS Backup en el diagrama",
                     "Hay almacenes de datos en producción y no se documentó una política de respaldo centralizada.",
                     "Usa AWS Backup con planes por etiqueta y copia a otra cuenta/región.", datastores[:6])
        if len(self.nodes) >= 3 and not self.of_type("account"):
            gd = [g for g in self.of_type("guardduty") if "GuardDuty" in (self.cfg(g).get("services") or [])]
            if not gd:
                self.add("medium", "Seguridad", "DET-NONE", "No se documentó la detección de amenazas",
                         "No hay GuardDuty (ni una Cuenta AWS con su línea base) en el diagrama.",
                         "Agrega un componente 'Cuenta AWS' y marca sus controles, o el componente GuardDuty / Security Hub.", [])

    # ───────────── usuario final ─────────────
    def check_enduser(self):
        for n in self.of_type("workspaces"):
            c, L = self.cfg(n), self.label(n)
            if not c.get("root_encryption") or not c.get("user_encryption"):
                self.add("high", "Seguridad", "WS-ENC", f"WorkSpaces '{L}' sin cifrado de volúmenes",
                         "Los volúmenes raíz y de usuario guardan datos de la empresa.",
                         "Activa el cifrado con KMS al crear los WorkSpaces (no se puede activar después).", [n])
            dirs = self.neighbors(n, "directory")
            if not c.get("mfa") and not any(self.cfg(d).get("mfa") for d in dirs):
                self.add("high", "Seguridad", "WS-MFA", f"WorkSpaces '{L}' sin MFA",
                         "Un escritorio con acceso a la red interna sólo protegido por contraseña.",
                         "Habilita MFA vía RADIUS en el directorio o usa autenticación con certificados + IdP.", [n])
            if not str(c.get("ip_groups") or "").strip() and not c.get("trusted_devices"):
                self.add("medium", "Seguridad", "WS-IP", f"WorkSpaces '{L}' accesible desde cualquier IP/dispositivo",
                         "Sin IP access control groups ni dispositivos de confianza.",
                         "Restringe por IP (oficinas/VPN) o exige certificados de dispositivo.", [n])
            leaks = [x for x, k in (("portapapeles", "clipboard"), ("unidades locales", "local_drives"), ("impresión", "printing"))
                     if c.get(k)]
            if leaks:
                self.add("medium", "Seguridad", "WS-DLP", f"WorkSpaces '{L}' permite {', '.join(leaks)}",
                         "Permite sacar datos del escritorio al equipo personal.", "Desactívalos por política de grupo salvo necesidad.", [n])
            if self.tier(n) == "public" or c.get("public_ip"):
                self.add("medium", "Seguridad", "WS-PUBLIC", f"WorkSpaces '{L}' con IP pública",
                         "Cada escritorio queda expuesto con su propia IP.", "Usa subnets privadas con NAT (y filtrado de salida).", [n])
            if not dirs:
                self.add("high", "Seguimiento", "WS-NO-DIR", f"WorkSpaces '{L}' sin directorio",
                         "WorkSpaces Personal/Pools requiere un directorio (AD o SAML para Pools).",
                         "Conecta WorkSpaces → Directory Service.", [n])
            if c.get("internet"):
                self._needs_internet(n, "los escritorios tienen acceso a internet")
            if c.get("running_mode") == "AlwaysOn":
                self.add("info", "Costo", "WS-ALWAYSON", f"WorkSpaces '{L}' en AlwaysOn",
                         "AlwaysOn cobra mensual aunque no se use.", "Usa AutoStop para usuarios de uso parcial (< ~80 h/mes).", [n])
            s = self.subnet_of(n)
            if s and len(self.azs(self.subnets_in_vpc(self.vpc_of(n), self.cfg(s).get("tier", "private")))) < 2:
                self.add("high", "Alta disponibilidad", "HA-MULTI-AZ-REQ", f"WorkSpaces '{L}' sin subnets en 2 AZ",
                         "WorkSpaces requiere dos subnets en AZ distintas.", "Crea otra subnet privada en otra AZ.", [n])
        for n in self.of_type("directory"):
            c, L = self.cfg(n), self.label(n)
            if c.get("type") == "AD Connector":
                linked = [x for x in self.neighbors(n) if x["type"] in ("onprem", "vpn", "dx")] or self.of_type("vpn", "dx")
                if not linked:
                    self.add("high", "Red", "DIR-CONNECTOR", f"AD Connector '{L}' sin conectividad a on-premise",
                             "AD Connector reenvía autenticaciones a tus controladores de dominio.",
                             "Agrega VPN/Direct Connect y conecta el directorio con on-premise.", [n])
            if c.get("type") == "Simple AD" and self.env_of(n) in PROD:
                self.add("low", "Seguridad", "DIR-SIMPLE", f"Simple AD '{L}' en producción",
                         "Simple AD no soporta MFA, trusts ni todas las funciones de AD.", "Usa AWS Managed Microsoft AD.", [n])
            s = self.subnet_of(n)
            if s and len(self.azs(self.subnets_in_vpc(self.vpc_of(n), self.cfg(s).get("tier", "private")))) < 2:
                self.add("high", "Alta disponibilidad", "HA-MULTI-AZ-REQ", f"Directorio '{L}' sin subnets en 2 AZ",
                         "Directory Service crea controladores en dos AZ.", "Crea otra subnet en otra AZ.", [n])
        for n in self.of_type("appstream"):
            c, L = self.cfg(n), self.label(n)
            if c.get("default_internet"):
                self.add("medium", "Seguridad", "AS-INTERNET", f"AppStream '{L}' con internet por defecto",
                         "Las instancias reciben IP pública.", "Desactívalo y sal por NAT con filtrado.", [n])
            leaks = [x for x, k in (("portapapeles", "clipboard"), ("transferencia de archivos", "file_transfer"),
                                    ("impresión", "printing")) if c.get(k)]
            if leaks:
                self.add("medium", "Seguridad", "AS-DLP", f"AppStream '{L}' permite {', '.join(leaks)}", "",
                         "Restringe en la configuración del stack.", [n])
            if c.get("auth") == "User pool de AppStream" and self.env_of(n) in PROD:
                self.add("medium", "Seguridad", "AS-AUTH", f"AppStream '{L}' usa user pool propio",
                         "Sin MFA ni ciclo de vida corporativo de identidades.", "Federa con SAML 2.0 a tu IdP.", [n])
        for n in self.of_type("securebrowser"):
            c, L = self.cfg(n), self.label(n)
            leaks = [x for x, k in (("copiar", "clipboard"), ("descargas", "download"), ("impresión", "printing")) if c.get(k)]
            if leaks:
                self.add("medium", "Seguridad", "WSB-DLP", f"Secure Browser '{L}' permite {', '.join(leaks)}", "",
                         "Desactívalo para que los datos no salgan del navegador administrado.", [n])
            if not str(c.get("ip_access") or "").strip():
                self.add("low", "Seguridad", "WSB-IP", f"Secure Browser '{L}' sin restricción de IP", "",
                         "Define IP access settings si el acceso debe ser sólo desde oficinas/VPN.", [n])

    # ───────────── postura ─────────────
    def posture(self, findings):
        by_rule = {}
        for f in findings:
            by_rule.setdefault(f["rule"], []).append(f)
        has_accounts = bool(self.of_type("account"))
        multi = len(self.of_type("account")) >= 2
        types = {n["type"] for n in self.nodes.values()}
        domains = {d: {"id": d, "name": name, "controls": [], "pass": 0, "fail": 0, "accepted": 0, "unknown": 0}
                   for d, name in DOMAINS}
        for cid, dom, title, refs, applies, rules in CONTROLS:
            fs = [f for r in rules for f in by_rule.get(r, [])]
            active = [f for f in fs if not f.get("dismissed")]
            hint = ""
            if applies == "account":
                status = None if has_accounts else ("fail" if active else "unknown")
                if has_accounts and not active:
                    fields = [RULE_FIELD[r] for r in rules if r in RULE_FIELD]
                    pending = [self.label(a) for a in self.of_type("account")
                               if any(tri_state(self.cfg(a).get(f)) == TRI_UNKNOWN for f in fields)]
                    if pending:
                        status, hint = "unknown", "Sin confirmar en: " + ", ".join(pending)
            elif applies == "multiaccount":
                status = "na" if not multi else None
            elif applies == "tags":
                status = None if self.required_tags() else "na"
            elif applies == "always":
                status = None
            else:
                status = None if types & set(applies) else "na"
            if status is None:
                status = "fail" if active else ("accepted" if fs else "pass")
            ctrl = {"id": cid, "title": title, "refs": refs, "status": status,
                    "finding_ids": [f["id"] for f in fs],
                    "worst": min((f["severity"] for f in active), key=["critical", "high", "medium", "low", "info"].index,
                                 default=None),
                    "hint": hint or ("Agrega un componente 'Cuenta AWS' y marca su línea base." if status == "unknown" else "")}
            d = domains[dom]
            d["controls"].append(ctrl)
            if status in ("pass", "fail", "accepted", "unknown"):
                d[status] += 1
        out = []
        tot_ok = tot = 0
        for d, _ in DOMAINS:
            x = domains[d]
            evaluated = x["pass"] + x["fail"] + x["accepted"]
            x["score"] = round(100 * (x["pass"] + x["accepted"]) / evaluated) if evaluated else None
            tot_ok += x["pass"] + x["accepted"]
            tot += evaluated
            out.append(x)
        return {"domains": out, "score": round(100 * tot_ok / tot) if tot else None,
                "evaluated": tot, "unknown": sum(x["unknown"] for x in out)}
