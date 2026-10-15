"""Copilot de arquitectura: revisa el diagrama contra reglas de AWS.

Produce:
  - findings: hallazgos (red, seguridad, IAM, HA, datos, costo, seguimiento).
  - plans: por cada conexión, qué permisos IAM, políticas de recurso, reglas de
    Security Group y requisitos de ruta (NAT / endpoints / VPC Link) necesita.
  - roles: políticas IAM consolidadas por componente (con Terraform).
  - security_groups: reglas de SG consolidadas (con Terraform).
  - summary: avance de terraform, completitud de configuración, preguntas.

Todo es determinista y local: no llama a AWS ni a internet.
"""
import hashlib
import ipaddress
import json
import re
import unicodedata

from catalog import COMPONENTS_BY_ID, effective_config, missing_required

SEVERITIES = ["critical", "high", "medium", "low", "info"]

# Servicios regionales a los que se llega por endpoint público (o VPC endpoint)
VPCE_SERVICES = {
    "s3": ["s3"], "dynamodb": ["dynamodb"], "sqs": ["sqs"], "sns": ["sns"], "eventbridge": ["events"],
    "kinesis": ["kinesis-streams"], "firehose": ["firehose"], "secrets": ["secretsmanager"], "kms": ["kms"],
    "cloudwatch": ["logs", "monitoring"], "stepfn": ["states"], "glue": ["glue"], "athena": ["athena"],
    "ecr": ["ecr.api", "ecr.dkr", "s3"], "lambda": ["lambda"], "apigw": ["execute-api"],
    "lakeformation": ["lakeformation"], "ssm": ["ssm"], "cloudtrail": [], "cognito": [],
}
GATEWAY_ENDPOINT_SERVICES = {"s3", "dynamodb"}
INTERNET_ENTRY = {"alb", "nlb", "apigw", "cloudfront", "cognito", "route53", "waf", "s3"}
COMPUTE = {"ec2", "asg", "ecs", "eks", "lambda"}
DATASTORES_IN_VPC = {"rds", "aurora", "elasticache", "redshift", "opensearch", "msk", "documentdb", "efs"}
EXTERNAL = {"users", "onprem", "saas"}
POLLERS = {"sqs", "kinesis", "dynamodb", "msk"}  # fuentes que Lambda "lee" vía event source mapping
ACCESS_LABEL = {"read": "lee de", "write": "escribe en", "readwrite": "lee y escribe en",
                "invoke": "invoca a", "network": "envía tráfico a"}


def slugify(text):
    text = unicodedata.normalize("NFKD", text or "").encode("ascii", "ignore").decode()
    s = re.sub(r"[^a-zA-Z0-9]+", "-", (text or "").strip().lower()).strip("-")
    return s or "recurso"


def fid(*parts):
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()[:12]


class Analyzer:
    def __init__(self, project):
        self.p = project
        self.settings = project.get("settings") or {}
        self.region = self.settings.get("region") or "<region>"
        self.account = self.settings.get("account_id") or "<account-id>"
        self.prefix = self.settings.get("prefix") or ""
        self.env = (self.settings.get("environment") or "").lower()
        self.nodes = {n["id"]: n for n in project.get("nodes", []) if n.get("type") in COMPONENTS_BY_ID}
        self.edges = [e for e in project.get("edges", [])
                      if e.get("source") in self.nodes and e.get("target") in self.nodes]
        self.cfgs = {nid: effective_config(self.comp(n), n.get("config") or {}) for nid, n in self.nodes.items()}
        self.findings = []
        self._gw_hints = {}
        self._compute_parents()

    # ───────────── helpers de grafo ─────────────
    def comp(self, n):
        return COMPONENTS_BY_ID[n["type"]]

    def cfg(self, n):
        return self.cfgs[n["id"]]

    def label(self, n):
        return n.get("label") or self.comp(n)["name"]

    def name(self, n):
        c = self.cfg(n)
        for k in ("bucket_name", "table_name", "role_name", "workgroup"):
            if c.get(k):
                return c[k]
        base = slugify(self.label(n))
        return f"{self.prefix}-{base}" if self.prefix else base

    def is_prod(self):
        return self.env in ("prod", "produccion", "producción", "production", "prd")

    def _compute_parents(self):
        containers = [n for n in self.nodes.values() if self.comp(n)["container"]]

        def rect(n):
            return n.get("x", 0), n.get("y", 0), n.get("w", 170), n.get("h", 60)

        self.parent = {}
        for n in self.nodes.values():
            x, y, w, h = rect(n)
            cx, cy = x + w / 2, y + h / 2
            best, best_area = None, None
            for c in containers:
                if c["id"] == n["id"]:
                    continue
                X, Y, W, H = rect(c)
                if not (X <= cx <= X + W and Y <= cy <= Y + H):
                    continue
                area = W * H
                if self.comp(n)["container"] and area <= w * h:
                    continue
                if n["type"] == "vpc" and c["type"] == "subnet":
                    continue
                if best_area is None or area < best_area:
                    best, best_area = c, area
            self.parent[n["id"]] = best["id"] if best else None

    def ancestor(self, n, typ):
        pid = self.parent.get(n["id"])
        while pid:
            p = self.nodes[pid]
            if p["type"] == typ:
                return p
            pid = self.parent.get(pid)
        return None

    def vpc_of(self, n):
        return n if n["type"] == "vpc" else self.ancestor(n, "vpc")

    def subnet_of(self, n):
        return self.ancestor(n, "subnet")

    def tier(self, n):
        s = self.subnet_of(n)
        return self.cfg(s).get("tier", "private") if s else None

    def in_vpc(self, n):
        return self.subnet_of(n) is not None

    def children(self, container, typ=None):
        out = []
        for n in self.nodes.values():
            if n["id"] == container["id"]:
                continue
            anc = self.vpc_of(n) if container["type"] == "vpc" else self.subnet_of(n)
            if anc and anc["id"] == container["id"] and (typ is None or n["type"] == typ):
                out.append(n)
        return out

    def subnets_in_vpc(self, vpc, tier=None):
        return [s for s in self.children(vpc, "subnet") if tier is None or self.cfg(s).get("tier", "private") == tier]

    def azs(self, subnets):
        return {self.cfg(s).get("az") for s in subnets if self.cfg(s).get("az")}

    def out_edges(self, n):
        return [e for e in self.edges if e["source"] == n["id"]]

    def in_edges(self, n):
        return [e for e in self.edges if e["target"] == n["id"]]

    def neighbors(self, n, typ=None):
        ids = {e["target"] for e in self.out_edges(n)} | {e["source"] for e in self.in_edges(n)}
        return [self.nodes[i] for i in ids if typ is None or self.nodes[i]["type"] == typ]

    def of_type(self, *types):
        return [n for n in self.nodes.values() if n["type"] in types]

    def access(self, e):
        if e.get("access"):
            return e["access"]
        t = self.nodes[e["target"]]["type"]
        if t in ("lambda", "stepfn", "glue", "emr", "athena", "apigw", "alb", "nlb", "ec2", "asg", "ecs", "eks",
                 "cloudfront", "mwaa"):
            return "invoke"
        if t in DATASTORES_IN_VPC:
            return "network"
        return "readwrite"

    # ───────────── hallazgos ─────────────
    def add(self, sev, cat, rule, title, detail, rec, nodes=(), edges=(), ref=None):
        ids = sorted({n["id"] if isinstance(n, dict) else n for n in nodes})
        eids = sorted({e["id"] if isinstance(e, dict) else e for e in edges})
        self.findings.append({
            "id": fid(rule, *ids, *eids), "severity": sev, "category": cat, "rule": rule,
            "title": title, "detail": detail, "recommendation": rec,
            "node_ids": ids, "edge_ids": eids, "ref": ref,
        })

    # ───────────── red ─────────────
    def check_network(self):
        vpcs = self.of_type("vpc")
        nets = {}
        for v in vpcs:
            c = self.cfg(v)
            cidr = c.get("cidr")
            if not cidr:
                self.add("medium", "Red", "NET-VPC-CIDR", f"VPC '{self.label(v)}' sin CIDR",
                         "No se definió el bloque CIDR de la VPC.",
                         "Define un CIDR privado RFC1918 (ej. 10.20.0.0/16) que no se traslape con otras VPC u on-premise.", [v])
                continue
            try:
                net = ipaddress.ip_network(cidr, strict=True)
            except ValueError:
                self.add("high", "Red", "NET-VPC-CIDR-INV", f"CIDR inválido en VPC '{self.label(v)}'",
                         f"'{cidr}' no es un CIDR válido (¿bits de host encendidos?).", "Corrige el CIDR, ej. 10.0.0.0/16.", [v])
                continue
            if not (16 <= net.prefixlen <= 28):
                self.add("high", "Red", "NET-VPC-SIZE", f"Tamaño de VPC no permitido en '{self.label(v)}'",
                         f"AWS sólo permite VPC entre /16 y /28; tienes /{net.prefixlen}.", "Ajusta la máscara.", [v])
            if not net.is_private:
                self.add("medium", "Red", "NET-VPC-PUBLIC-RANGE", f"VPC '{self.label(v)}' usa rango no privado",
                         f"{cidr} no es RFC1918.", "Usa 10.0.0.0/8, 172.16.0.0/12 o 192.168.0.0/16.", [v])
            nets[v["id"]] = net
            if not c.get("flow_logs"):
                self.add("low", "Seguridad", "NET-FLOWLOGS", f"VPC '{self.label(v)}' sin Flow Logs",
                         "Sin Flow Logs no hay trazabilidad de tráfico para investigaciones o troubleshooting.",
                         "Habilita VPC Flow Logs (CloudWatch o S3, idealmente formato Parquet en S3).", [v],
                         ref="Well-Architected SEC04")

        # Traslapes entre VPCs
        ids = list(nets)
        for i in range(len(ids)):
            for j in range(i + 1, len(ids)):
                a, b_ = nets[ids[i]], nets[ids[j]]
                if a.overlaps(b_):
                    va, vb = self.nodes[ids[i]], self.nodes[ids[j]]
                    connected = self._vpcs_linked(va, vb)
                    self.add("critical" if connected else "medium", "Red", "NET-VPC-OVERLAP",
                             f"CIDR traslapados: '{self.label(va)}' y '{self.label(vb)}'",
                             f"{a} se traslapa con {b_}. "
                             + ("Están conectadas: el ruteo no funcionará." if connected else
                                "No podrás conectarlas por Peering/TGW en el futuro."),
                             "Re-planea el direccionamiento (IPAM) para que cada VPC tenga un rango único.", [va, vb])

        # Subnets
        for s in self.of_type("subnet"):
            c = self.cfg(s)
            v = self.vpc_of(s)
            if not v:
                self.add("high", "Red", "NET-SUBNET-ORPHAN", f"Subnet '{self.label(s)}' fuera de una VPC",
                         "Toda subnet pertenece a una VPC.", "Arrastra la subnet dentro de su VPC.", [s])
                continue
            if not c.get("az"):
                self.add("medium", "Red", "NET-SUBNET-AZ", f"Subnet '{self.label(s)}' sin zona de disponibilidad",
                         "La AZ determina la alta disponibilidad de lo que vive en ella.", "Asigna la AZ (a, b, c...).", [s])
            cidr = c.get("cidr")
            if not cidr:
                continue
            try:
                sn = ipaddress.ip_network(cidr, strict=True)
            except ValueError:
                self.add("high", "Red", "NET-SUBNET-CIDR-INV", f"CIDR inválido en subnet '{self.label(s)}'",
                         f"'{cidr}' no es válido.", "Corrige el CIDR.", [s])
                continue
            vn = nets.get(v["id"])
            if vn and not sn.subnet_of(vn):
                self.add("critical", "Red", "NET-SUBNET-OUT", f"Subnet '{self.label(s)}' fuera del rango de la VPC",
                         f"{sn} no está contenido en {vn}.", "Usa un CIDR dentro del rango de la VPC (o agrega un CIDR secundario).",
                         [s, v])
            if sn.prefixlen > 28:
                self.add("high", "Red", "NET-SUBNET-SIZE", f"Subnet '{self.label(s)}' demasiado pequeña",
                         "AWS permite subnets entre /16 y /28.", "Usa al menos /28 (recomendado /24 o mayor para EKS/Lambda).", [s])
            if sn.prefixlen >= 26 and self.children(s) and any(n["type"] in ("eks", "lambda", "ecs", "emr") for n in self.children(s)):
                self.add("medium", "Red", "NET-SUBNET-IPS", f"Subnet '{self.label(s)}' con pocas IPs para cargas elásticas",
                         f"{sn} tiene {sn.num_addresses - 5} IPs utilizables; EKS/Lambda/ECS/EMR consumen una ENI/IP por pod/tarea.",
                         "Usa /22 o más grande (o un CIDR secundario 100.64.0.0/10 para pods).", [s])
        for v in vpcs:
            subs = self.subnets_in_vpc(v)
            parsed = []
            for s in subs:
                try:
                    parsed.append((s, ipaddress.ip_network(self.cfg(s).get("cidr") or "", strict=True)))
                except ValueError:
                    pass
            for i in range(len(parsed)):
                for j in range(i + 1, len(parsed)):
                    if parsed[i][1].overlaps(parsed[j][1]):
                        self.add("critical", "Red", "NET-SUBNET-OVERLAP",
                                 f"Subnets traslapadas en '{self.label(v)}'",
                                 f"{parsed[i][1]} ({self.label(parsed[i][0])}) y {parsed[j][1]} ({self.label(parsed[j][0])}).",
                                 "Cada subnet debe tener un rango único.", [parsed[i][0], parsed[j][0]])

            igws = self.children(v, "igw")
            pub = self.subnets_in_vpc(v, "public")
            priv = self.subnets_in_vpc(v, "private")
            if pub and not igws:
                self.add("high", "Red", "NET-NO-IGW", f"Subnets públicas sin Internet Gateway en '{self.label(v)}'",
                         "Una subnet sólo es pública si su tabla de rutas tiene 0.0.0.0/0 → IGW.",
                         "Agrega un Internet Gateway a la VPC y la ruta 0.0.0.0/0 en la tabla de rutas pública.", [v] + pub)
            if igws and not pub:
                self.add("low", "Red", "NET-IGW-UNUSED", f"IGW sin subnets públicas en '{self.label(v)}'",
                         "Hay un Internet Gateway pero ninguna subnet pública que lo use.",
                         "Elimínalo o agrega subnets públicas (necesarias para NAT y ALB internet-facing).", [v] + igws)
            workloads = [n for n in self.children(v) if n["type"] not in ("subnet", "igw", "vpce", "nat")]
            if workloads and len(self.azs(subs)) < 2:
                self.add("medium", "Alta disponibilidad", "HA-SINGLE-AZ", f"VPC '{self.label(v)}' en una sola AZ",
                         "Todas las subnets están en la misma zona: una falla de AZ tumba la carga.",
                         "Crea al menos 2 subnets por capa (pública/privada) en AZ distintas.", [v],
                         ref="Well-Architected REL10")
            nats = self.children(v, "nat")
            for nat in nats:
                if self.tier(nat) != "public" and self.cfg(nat).get("connectivity", "public") == "public":
                    self.add("high", "Red", "NET-NAT-PRIVATE", f"NAT Gateway '{self.label(nat)}' en subnet no pública",
                             "Un NAT público debe vivir en una subnet pública (con ruta al IGW).",
                             "Mueve el NAT a una subnet pública; las privadas apuntan 0.0.0.0/0 al NAT.", [nat])
            if nats and priv and len(self.azs(priv)) > 1 and len(nats) == 1 and "Regional" not in str(self.cfg(nats[0]).get("ha", "")):
                self.add("medium" if self.is_prod() else "low", "Alta disponibilidad", "HA-SINGLE-NAT",
                         f"Un solo NAT Gateway para varias AZ en '{self.label(v)}'",
                         "Si la AZ del NAT falla, todas las subnets privadas pierden salida; además pagas transferencia cross-AZ.",
                         "En producción usa un NAT por AZ (o Regional NAT Gateway).", [v] + nats)

        # Componentes que deben vivir dentro de una subnet
        for n in self.nodes.values():
            comp = self.comp(n)
            if comp["vpc"] == "required" and n["type"] != "subnet" and not self.in_vpc(n):
                self.add("high", "Red", "NET-NEEDS-SUBNET", f"'{self.label(n)}' debe estar dentro de una subnet",
                         f"{comp['name']} se despliega en subnets de una VPC (ENIs con Security Groups).",
                         "Arrástralo dentro de la subnet correspondiente (privada para backends y datos).", [n])
            if comp["vpc"] == "vpc" and not self.vpc_of(n):
                self.add("high", "Red", "NET-NEEDS-VPC", f"'{self.label(n)}' debe estar dentro de una VPC",
                         f"{comp['name']} se adjunta a una VPC.", "Colócalo dentro de la VPC.", [n])
            if comp["vpc"] == "never" and not comp["container"] and self.vpc_of(n) and n["type"] not in ("note", "iam_role", "kms", "secrets"):
                self.add("info", "Red", "NET-REGIONAL-IN-VPC", f"'{self.label(n)}' no vive dentro de la VPC",
                         f"{comp['name']} es un servicio regional/global; se accede vía endpoint público o VPC endpoint.",
                         "Sácalo de la VPC en el diagrama y, si se accede desde subnets privadas, agrega un VPC endpoint.", [n])

        # Requisitos multi-AZ por servicio
        multi_az = {
            "alb": ("ALB", "un ALB requiere subnets en al menos 2 AZ", "high"),
            "rds": ("RDS", "el DB subnet group requiere subnets en al menos 2 AZ", "high"),
            "aurora": ("Aurora", "el DB subnet group requiere subnets en al menos 2 AZ", "high"),
            "documentdb": ("DocumentDB", "el subnet group requiere al menos 2 AZ", "high"),
            "mwaa": ("MWAA", "MWAA requiere exactamente 2 subnets privadas en AZ distintas", "high"),
            "eks": ("EKS", "el control plane de EKS requiere subnets en al menos 2 AZ", "high"),
            "msk": ("MSK", "los brokers se distribuyen en 2 o 3 AZ", "high"),
            "elasticache": ("ElastiCache", "Multi-AZ requiere subnets en varias AZ", "medium"),
            "nlb": ("NLB", "para alta disponibilidad usa subnets en varias AZ", "medium"),
            "asg": ("Auto Scaling Group", "distribuye instancias en varias AZ", "medium"),
            "ecs": ("ECS", "distribuye tareas en varias AZ", "medium"),
        }
        for n in self.of_type(*multi_az):
            s = self.subnet_of(n)
            v = self.vpc_of(n)
            if not s or not v:
                continue
            tier = self.cfg(s).get("tier", "private")
            same = self.subnets_in_vpc(v, tier)
            if len(self.azs(same)) < 2:
                name, why, sev = multi_az[n["type"]]
                self.add(sev, "Alta disponibilidad", "HA-MULTI-AZ-REQ", f"{name} '{self.label(n)}' sin subnets en 2 AZ",
                         f"Sólo hay subnets '{tier}' en {len(self.azs(same)) or 'una'} AZ: {why}.",
                         f"Crea otra subnet '{tier}' en una AZ distinta dentro de '{self.label(v)}'.", [n, v])

        # Balanceadores en la capa correcta
        for lb in self.of_type("alb", "nlb"):
            c = self.cfg(lb)
            t = self.tier(lb)
            if not t:
                continue
            if c.get("scheme") == "internet-facing" and t != "public":
                self.add("high", "Red", "NET-LB-SCHEME", f"Balanceador internet-facing '{self.label(lb)}' en subnet {t}",
                         "Un balanceador internet-facing necesita subnets públicas (ruta al IGW).",
                         "Muévelo a subnets públicas o cámbialo a 'internal'.", [lb])
            if c.get("scheme") == "internal" and t == "public":
                self.add("low", "Red", "NET-LB-INTERNAL-PUBLIC", f"Balanceador interno '{self.label(lb)}' en subnet pública",
                         "Funciona, pero los balanceadores internos suelen ir en subnets privadas.",
                         "Ubícalo en subnets privadas.", [lb])

        # Datos en subnets públicas
        for n in self.of_type(*DATASTORES_IN_VPC):
            c = self.cfg(n)
            if self.tier(n) == "public":
                self.add("high", "Seguridad", "SEC-DATA-PUBLIC-SUBNET", f"'{self.label(n)}' en subnet pública",
                         "Las bases de datos y almacenes de datos deben vivir en subnets privadas o aisladas.",
                         "Muévelo a una subnet privada/aislada; accede vía SG desde la capa de aplicación.", [n])
            if c.get("public"):
                self.add("critical", "Seguridad", "SEC-DATA-PUBLIC", f"'{self.label(n)}' publicly accessible",
                         "La base de datos tiene endpoint público.", "Desactiva 'publicly accessible'; usa bastion/SSM o VPN.", [n])

    def _vpcs_linked(self, va, vb):
        for link in self.of_type("tgw", "peering"):
            touched = set()
            for nb in self.neighbors(link):
                v = self.vpc_of(nb)
                if v:
                    touched.add(v["id"])
            if va["id"] in touched and vb["id"] in touched:
                return True
        return False

    # ───────────── rutas de cada conexión ─────────────
    def egress_requirements(self, src, tgt_services, why, e=None):
        """Revisa que un recurso en subnet tenga ruta hacia servicios regionales/internet."""
        v = self.vpc_of(src)
        tier = self.tier(src)
        if not v or tier is None:
            return []
        reqs = []
        endpoints = set()
        for ep in self.children(v, "vpce"):
            endpoints.update(self.cfg(ep).get("services") or [])
        nats = [nn for nn in self.children(v, "nat") if self.tier(nn) == "public"]
        igw = bool(self.children(v, "igw"))
        internet = tgt_services is None
        needed = [] if internet else [s for s in tgt_services if s not in endpoints]
        if not internet and not needed:
            reqs.append(f"✔ Ruta privada vía VPC endpoint ({', '.join(tgt_services)}).")
            return reqs
        if tier == "isolated":
            if internet:
                self.add("critical", "Red", "NET-ISOLATED-INTERNET", f"'{self.label(src)}' no tiene salida a internet",
                         f"Está en subnet aislada y {why}.",
                         "Muévelo a una subnet privada con NAT, o elimina la dependencia de internet.", [src], [e] if e else [])
                reqs.append("✖ Subnet aislada: no hay salida a internet.")
            else:
                self.add("high", "Red", "NET-ISOLATED-ENDPOINT", f"'{self.label(src)}' necesita VPC endpoint",
                         f"Está en subnet aislada y {why}; faltan endpoints: {', '.join(needed)}.",
                         f"Agrega VPC endpoints para: {', '.join(needed)}.", [src], [e] if e else [])
                reqs.append(f"✖ Faltan VPC endpoints: {', '.join(needed)}.")
            return reqs
        if tier == "public":
            if not igw:
                reqs.append("✖ Subnet pública sin IGW.")
            elif src["type"] in ("lambda", "ecs", "emr", "glue", "mwaa") and not self.cfg(src).get("public_ip"):
                self.add("high", "Red", "NET-PUBLIC-NO-IP", f"'{self.label(src)}' en subnet pública sin IP pública",
                         f"{self.comp(src)['name']} no recibe IP pública en subnets públicas, así que no puede salir por el IGW ({why}).",
                         "Colócalo en una subnet privada con NAT Gateway o VPC endpoints.", [src], [e] if e else [])
                reqs.append("✖ Sin IP pública: no puede usar el IGW. Usa subnet privada + NAT.")
            else:
                reqs.append("✔ Sale por Internet Gateway (requiere IP pública).")
            return reqs
        # private
        if nats:
            reqs.append(f"✔ Sale por NAT Gateway '{self.label(nats[0])}'.")
            if not internet:
                gw = [s for s in needed if s in GATEWAY_ENDPOINT_SERVICES]
                if gw:
                    for svc in gw:
                        self._gw_hint(v, svc, src)
                    reqs.append(f"💡 Recomendado: Gateway endpoint para {', '.join(gw)} (gratis, sin NAT).")
        else:
            if internet:
                self.add("high", "Red", "NET-NEEDS-NAT", f"'{self.label(src)}' necesita NAT Gateway",
                         f"Está en subnet privada y {why}, pero la VPC no tiene NAT en subnet pública.",
                         "Agrega un NAT Gateway en subnet pública (+IGW) y la ruta 0.0.0.0/0 → NAT en la tabla privada.",
                         [src, v], [e] if e else [])
                reqs.append("✖ Falta NAT Gateway para salir a internet.")
            else:
                gw = [s for s in needed if s in GATEWAY_ENDPOINT_SERVICES]
                itf = [s for s in needed if s not in GATEWAY_ENDPOINT_SERVICES]
                rec = []
                if gw:
                    rec.append(f"Gateway endpoint (gratis) para {', '.join(gw)}")
                if itf:
                    rec.append(f"Interface endpoints para {', '.join(itf)}")
                self.add("high", "Red", "NET-NEEDS-ENDPOINT", f"'{self.label(src)}' no tiene ruta a {', '.join(needed)}",
                         f"Está en subnet privada sin NAT y {why}.",
                         "Agrega " + " y ".join(rec) + ", o un NAT Gateway.", [src, v], [e] if e else [])
                reqs.append("✖ Sin ruta: agrega " + " y ".join(rec) + " (o NAT).")
        return reqs

    # ───────────── IAM ─────────────
    def arn(self, n, kind="main"):
        r, a, nm = self.region, self.account, self.name(n)
        t = n["type"]
        c = self.cfg(n)
        if t == "s3":
            return f"arn:aws:s3:::{nm}" if kind == "bucket" else f"arn:aws:s3:::{nm}/*"
        if t == "dynamodb":
            if kind == "index":
                return f"arn:aws:dynamodb:{r}:{a}:table/{nm}/index/*"
            if kind == "stream":
                return f"arn:aws:dynamodb:{r}:{a}:table/{nm}/stream/*"
            return f"arn:aws:dynamodb:{r}:{a}:table/{nm}"
        m = {
            "sqs": f"arn:aws:sqs:{r}:{a}:{nm}" + (".fifo" if c.get("type") == "FIFO" else ""),
            "sns": f"arn:aws:sns:{r}:{a}:{nm}",
            "eventbridge": f"arn:aws:events:{r}:{a}:event-bus/{'default' if c.get('bus') == 'default' else nm}",
            "kinesis": f"arn:aws:kinesis:{r}:{a}:stream/{nm}",
            "firehose": f"arn:aws:firehose:{r}:{a}:deliverystream/{nm}",
            "lambda": f"arn:aws:lambda:{r}:{a}:function:{nm}",
            "stepfn": f"arn:aws:states:{r}:{a}:stateMachine:{nm}",
            "secrets": f"arn:aws:secretsmanager:{r}:{a}:secret:{nm}-*",
            "kms": f"arn:aws:kms:{r}:{a}:key/<{nm}-key-id>",
            "glue": f"arn:aws:glue:{r}:{a}:job/{nm}",
            "athena": f"arn:aws:athena:{r}:{a}:workgroup/{c.get('workgroup') or nm}",
            "ecr": f"arn:aws:ecr:{r}:{a}:repository/{nm}",
            "apigw": f"arn:aws:execute-api:{r}:{a}:<{nm}-api-id>/*/*/*",
            "opensearch": f"arn:aws:es:{r}:{a}:domain/{nm}/*",
            "cloudwatch": f"arn:aws:logs:{r}:{a}:log-group:*:*",
            "msk": f"arn:aws:kafka:{r}:{a}:cluster/{nm}/*",
            "ecs": f"arn:aws:ecs:{r}:{a}:task-definition/{nm}:*",
            "redshift": f"arn:aws:redshift-serverless:{r}:{a}:workgroup/*",
            "rds": f"arn:aws:rds-db:{r}:{a}:dbuser:<DbiResourceId>/<db_user>",
            "aurora": f"arn:aws:rds-db:{r}:{a}:dbuser:<ClusterResourceId>/<db_user>",
            "elasticache": f"arn:aws:elasticache:{r}:{a}:replicationgroup:{nm}",
        }
        return m.get(t, "*")

    def kms_for(self, n):
        keys = self.neighbors(n, "kms")
        return [self.arn(k) for k in keys] or [f"arn:aws:kms:{self.region}:{self.account}:key/<cmk-de-{self.name(n)}>"]

    def glue_catalog_arns(self, db="*"):
        r, a = self.region, self.account
        return [f"arn:aws:glue:{r}:{a}:catalog", f"arn:aws:glue:{r}:{a}:database/{db}",
                f"arn:aws:glue:{r}:{a}:table/{db}/*"]

    def principal_of(self, n):
        """(servicio, rol, descripción) del rol que usa el componente para llamar a otros."""
        t = n["type"]
        c = self.cfg(n)
        role_nodes = self.neighbors(n, "iam_role")
        role_name = None
        if role_nodes:
            role_name = self.cfg(role_nodes[0]).get("role_name") or self.name(role_nodes[0])
        base = self.name(n)
        desc = {
            "lambda": ("lambda.amazonaws.com", "rol de ejecución de la Lambda"),
            "ec2": ("ec2.amazonaws.com", "instance profile de EC2"),
            "asg": ("ec2.amazonaws.com", "instance profile del launch template"),
            "ecs": ("ecs-tasks.amazonaws.com", "task role de ECS (no el execution role)"),
            "eks": ("pods.eks.amazonaws.com", "rol de Pod Identity / IRSA del service account"),
            "glue": ("glue.amazonaws.com", "rol del job de Glue"),
            "stepfn": ("states.amazonaws.com", "rol de la state machine"),
            "mwaa": ("airflow-env.amazonaws.com", "execution role de MWAA"),
            "firehose": ("firehose.amazonaws.com", "rol de entrega de Firehose"),
            "redshift": ("redshift.amazonaws.com", "rol IAM asociado a Redshift (COPY/UNLOAD/Spectrum)"),
            "apigw": ("apigateway.amazonaws.com", "credentials role de la integración de API Gateway"),
            "eventbridge": ("events.amazonaws.com", "rol del target de EventBridge"),
            "athena": ("<usuarios/roles que consultan>", "identidad que ejecuta las consultas de Athena"),
            "quicksight": ("quicksight.amazonaws.com", "rol de servicio de QuickSight"),
            "sns": ("sns.amazonaws.com", "rol de suscripción de SNS"),
            "kinesis": ("<consumidor>", "consumidor del stream"),
            "appflow": ("appflow.amazonaws.com", "rol del servicio de ingesta"),
        }
        if t == "emr":
            dep = c.get("deployment", "EMR Serverless")
            if dep == "EMR Serverless":
                svc, d = "emr-serverless.amazonaws.com", "job runtime role de EMR Serverless"
            elif dep == "EMR on EKS":
                svc, d = "<OIDC del cluster EKS>", "job execution role de EMR on EKS"
            else:
                svc, d = "ec2.amazonaws.com", "instance profile de EMR (EMR_EC2_DefaultRole) o runtime role"
            role_name = role_name or c.get("runtime_role") or None
        elif t in desc:
            svc, d = desc[t]
        else:
            return None
        return {"service": svc, "role": role_name or f"{base}-role", "desc": d, "explicit": bool(role_nodes)}

    def statements_for(self, src, tgt, access):
        """Permisos de identidad que necesita el principal de `src` para `access` sobre `tgt`."""
        t = tgt["type"]
        c = self.cfg(tgt)
        st, notes = [], []
        rd = access in ("read", "readwrite")
        wr = access in ("write", "readwrite")

        def S(sid, actions, resources, cond=None):
            s = {"Sid": sid, "Effect": "Allow", "Action": sorted(set(actions)), "Resource": resources}
            if cond:
                s["Condition"] = cond
            st.append(s)

        if t == "s3":
            fmt = c.get("table_format", "Ninguno (archivos)")
            if fmt == "S3 Tables (Iceberg administrado)":
                acts = ["s3tables:GetTableBucket", "s3tables:GetNamespace", "s3tables:GetTable", "s3tables:ListTables",
                        "s3tables:GetTableMetadataLocation", "s3tables:GetTableData"]
                if wr:
                    acts += ["s3tables:PutTableData", "s3tables:UpdateTableMetadataLocation", "s3tables:CreateTable",
                             "s3tables:CreateNamespace"]
                S("S3Tables", acts, [f"arn:aws:s3tables:{self.region}:{self.account}:bucket/{self.name(tgt)}",
                                     f"arn:aws:s3tables:{self.region}:{self.account}:bucket/{self.name(tgt)}/table/*"])
            else:
                S("ListBucket", ["s3:ListBucket", "s3:GetBucketLocation"], [self.arn(tgt, "bucket")])
                acts = []
                if rd:
                    acts += ["s3:GetObject", "s3:GetObjectVersion"]
                if wr:
                    acts += ["s3:PutObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"]
                    if fmt in OPEN_FORMATS or src["type"] in ("emr", "glue", "athena", "firehose"):
                        acts += ["s3:DeleteObject"]
                        notes.append("s3:DeleteObject es necesario para commits/compactación/expire_snapshots de tablas "
                                     "abiertas y para archivos temporales de Spark/Glue.")
                S("Objects", acts or ["s3:GetObject"], [self.arn(tgt)])
            if fmt in ("Apache Iceberg", "Hive (tablas Glue clásicas)", "Delta Lake", "Apache Hudi") \
                    and c.get("catalog", "AWS Glue Data Catalog") == "AWS Glue Data Catalog":
                acts = ["glue:GetDatabase", "glue:GetDatabases", "glue:GetTable", "glue:GetTables",
                        "glue:GetPartition", "glue:GetPartitions", "glue:BatchGetPartition"]
                if wr:
                    acts += ["glue:CreateTable", "glue:UpdateTable", "glue:CreatePartition", "glue:BatchCreatePartition",
                             "glue:UpdatePartition", "glue:BatchUpdatePartition", "glue:DeletePartition"]
                S("GlueCatalog", acts, self.glue_catalog_arns())
            if c.get("encryption") in ("SSE-KMS", "DSSE-KMS"):
                acts = ["kms:Decrypt"] + (["kms:GenerateDataKey", "kms:Encrypt"] if wr else [])
                S("KmsForS3", acts, self.kms_for(tgt),
                  {"StringEquals": {"kms:ViaService": f"s3.{self.region}.amazonaws.com"}})
                notes.append("La key policy de la CMK debe permitir al rol (o delegar a IAM con la raíz de la cuenta).")
            if c.get("lake_formation"):
                S("LakeFormation", ["lakeformation:GetDataAccess"], ["*"])
                notes.append("Lake Formation: otorga al rol permisos LF (SELECT/INSERT/DESCRIBE o LF-Tags) sobre la "
                             "base/tablas; IAM por sí solo no basta si la ubicación está registrada en LF.")
        elif t == "dynamodb":
            acts = []
            if rd:
                acts += ["dynamodb:GetItem", "dynamodb:BatchGetItem", "dynamodb:Query", "dynamodb:Scan",
                         "dynamodb:DescribeTable", "dynamodb:ConditionCheckItem"]
            if wr:
                acts += ["dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem", "dynamodb:BatchWriteItem"]
            if src["type"] == "lambda" and access == "invoke":
                acts = ["dynamodb:GetRecords", "dynamodb:GetShardIterator", "dynamodb:DescribeStream", "dynamodb:ListStreams"]
                S("DynamoStreams", acts, [self.arn(tgt, "stream")])
            else:
                S("DynamoDB", acts or ["dynamodb:GetItem"], [self.arn(tgt), self.arn(tgt, "index")])
            if c.get("encryption") == "Customer managed key (KMS)":
                S("KmsForDynamo", ["kms:Decrypt"] + (["kms:GenerateDataKey", "kms:Encrypt"] if wr else []), self.kms_for(tgt))
        elif t == "sqs":
            acts = []
            if wr or access == "invoke":
                acts += ["sqs:SendMessage", "sqs:GetQueueUrl", "sqs:GetQueueAttributes"]
            if rd:
                acts += ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:ChangeMessageVisibility", "sqs:GetQueueAttributes"]
            S("SQS", acts, [self.arn(tgt)])
            if c.get("encryption") == "SSE-KMS":
                S("KmsForSQS", ["kms:Decrypt"] + (["kms:GenerateDataKey"] if wr else []), self.kms_for(tgt))
        elif t == "sns":
            S("SNSPublish", ["sns:Publish"], [self.arn(tgt)])
            if c.get("encrypted"):
                S("KmsForSNS", ["kms:GenerateDataKey", "kms:Decrypt"], self.kms_for(tgt))
        elif t == "eventbridge":
            S("PutEvents", ["events:PutEvents"], [self.arn(tgt)])
        elif t == "kinesis":
            acts = []
            if wr or access == "invoke":
                acts += ["kinesis:PutRecord", "kinesis:PutRecords", "kinesis:DescribeStreamSummary"]
            if rd:
                acts += ["kinesis:GetRecords", "kinesis:GetShardIterator", "kinesis:DescribeStream",
                         "kinesis:DescribeStreamSummary", "kinesis:ListShards", "kinesis:SubscribeToShard",
                         "kinesis:DescribeStreamConsumer"]
            S("Kinesis", acts, [self.arn(tgt), self.arn(tgt) + "/consumer/*"])
            if c.get("encrypted", True):
                S("KmsForKinesis", ["kms:Decrypt"] + (["kms:GenerateDataKey"] if wr else []), self.kms_for(tgt))
        elif t == "firehose":
            S("Firehose", ["firehose:PutRecord", "firehose:PutRecordBatch"], [self.arn(tgt)])
        elif t == "lambda":
            S("InvokeLambda", ["lambda:InvokeFunction"], [self.arn(tgt), self.arn(tgt) + ":*"])
        elif t == "stepfn":
            acts = ["states:StartExecution", "states:DescribeExecution"]
            if c.get("type") == "Express":
                acts.append("states:StartSyncExecution")
            S("StepFunctions", acts, [self.arn(tgt)])
        elif t == "secrets":
            S("ReadSecret", ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"], [self.arn(tgt)])
            if c.get("cmk"):
                S("KmsForSecret", ["kms:Decrypt"], self.kms_for(tgt),
                  {"StringEquals": {"kms:ViaService": f"secretsmanager.{self.region}.amazonaws.com"}})
        elif t == "kms":
            acts = ["kms:Decrypt", "kms:DescribeKey"] + (["kms:Encrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*"] if wr else [])
            S("UseKey", acts, [self.arn(tgt)])
            notes.append("Verifica que la key policy permita a este rol (o tenga el statement 'Enable IAM User Permissions').")
        elif t == "glue":
            if access in ("invoke", "write"):
                S("RunGlueJob", ["glue:StartJobRun", "glue:GetJobRun", "glue:GetJobRuns", "glue:BatchStopJobRun"], [self.arn(tgt)])
            S("GlueCatalogRead", ["glue:GetDatabase", "glue:GetDatabases", "glue:GetTable", "glue:GetTables",
                                  "glue:GetPartitions"], self.glue_catalog_arns(c.get("database") or "*"))
        elif t == "athena":
            S("AthenaQuery", ["athena:StartQueryExecution", "athena:GetQueryExecution", "athena:GetQueryResults",
                              "athena:StopQueryExecution", "athena:GetWorkGroup"], [self.arn(tgt)])
            S("GlueCatalogForAthena", ["glue:GetDatabase", "glue:GetDatabases", "glue:GetTable", "glue:GetTables",
                                       "glue:GetPartition", "glue:GetPartitions", "glue:BatchGetPartition"], self.glue_catalog_arns())
            res = c.get("results_location") or "s3://<bucket-resultados-athena>/"
            bucket = res.replace("s3://", "").split("/")[0]
            S("AthenaResults", ["s3:GetBucketLocation", "s3:GetObject", "s3:ListBucket", "s3:PutObject",
                                "s3:AbortMultipartUpload"], [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"])
            notes.append("Además necesita s3:GetObject/ListBucket sobre los buckets de datos que consulta (conecta Athena → S3).")
        elif t == "emr":
            dep = c.get("deployment", "EMR Serverless")
            role = c.get("runtime_role") or f"{self.name(tgt)}-role"
            if dep == "EMR Serverless":
                S("EmrServerlessJobs", ["emr-serverless:StartJobRun", "emr-serverless:GetJobRun", "emr-serverless:CancelJobRun",
                                        "emr-serverless:GetApplication", "emr-serverless:StartApplication",
                                        "emr-serverless:GetDashboardForJobRun"],
                  [f"arn:aws:emr-serverless:{self.region}:{self.account}:/applications/*"])
            elif dep == "EMR on EKS":
                S("EmrOnEksJobs", ["emr-containers:StartJobRun", "emr-containers:DescribeJobRun", "emr-containers:CancelJobRun"],
                  [f"arn:aws:emr-containers:{self.region}:{self.account}:/virtualclusters/*"])
            else:
                acts = ["elasticmapreduce:AddJobFlowSteps", "elasticmapreduce:DescribeStep", "elasticmapreduce:DescribeCluster",
                        "elasticmapreduce:ListSteps", "elasticmapreduce:CancelSteps"]
                if self.cfg(tgt).get("cluster_lifecycle") == "Transitorio (por job)":
                    acts += ["elasticmapreduce:RunJobFlow", "elasticmapreduce:TerminateJobFlows"]
                S("EmrOnEc2", acts, ["*"])
            S("PassRuntimeRole", ["iam:PassRole"], [f"arn:aws:iam::{self.account}:role/{role}"],
              {"StringLike": {"iam:PassedToService": ["emr-serverless.amazonaws.com", "elasticmapreduce.amazonaws.com",
                                                      "ec2.amazonaws.com"]}})
        elif t == "ecs":
            S("RunTask", ["ecs:RunTask", "ecs:DescribeTasks", "ecs:StopTask"], [self.arn(tgt)])
            S("PassTaskRoles", ["iam:PassRole"], [f"arn:aws:iam::{self.account}:role/{self.name(tgt)}-*"],
              {"StringLike": {"iam:PassedToService": "ecs-tasks.amazonaws.com"}})
        elif t == "ecr":
            S("EcrAuth", ["ecr:GetAuthorizationToken"], ["*"])
            S("EcrPull", ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"], [self.arn(tgt)])
            if src["type"] == "ecs":
                notes.append("En ECS estos permisos van en el *execution role* (lo usa el agente para descargar la imagen).")
        elif t == "cloudwatch":
            S("Logs", ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"], [self.arn(tgt)])
            S("Metrics", ["cloudwatch:PutMetricData"], ["*"])
        elif t == "apigw":
            if self.cfg(tgt).get("auth") == "IAM (SigV4)":
                S("InvokeApi", ["execute-api:Invoke"], [self.arn(tgt)])
        elif t in ("rds", "aurora"):
            if c.get("iam_auth"):
                S("RdsIamAuth", ["rds-db:connect"], [self.arn(tgt)])
            if c.get("data_api"):
                S("DataApi", ["rds-data:ExecuteStatement", "rds-data:BatchExecuteStatement"], ["*"])
            if c.get("managed_secret", True) and not c.get("iam_auth"):
                S("DbSecret", ["secretsmanager:GetSecretValue"],
                  [f"arn:aws:secretsmanager:{self.region}:{self.account}:secret:rds!*"])
                notes.append("La credencial administrada por RDS vive en Secrets Manager (prefijo rds!).")
        elif t == "redshift":
            if c.get("deployment") == "Serverless":
                S("RedshiftServerless", ["redshift-serverless:GetCredentials"], [self.arn(tgt)])
            S("RedshiftDataApi", ["redshift-data:ExecuteStatement", "redshift-data:DescribeStatement",
                                  "redshift-data:GetStatementResult"], ["*"])
        elif t == "opensearch":
            acts = ["es:ESHttpGet", "es:ESHttpHead"] + (["es:ESHttpPost", "es:ESHttpPut", "es:ESHttpDelete"] if wr else [])
            if c.get("deployment") == "Serverless":
                S("Aoss", ["aoss:APIAccessAll"], [f"arn:aws:aoss:{self.region}:{self.account}:collection/*"])
                notes.append("OpenSearch Serverless además requiere una data access policy de la colección.")
            else:
                S("OpenSearchHttp", acts, [self.arn(tgt)])
                if c.get("fgac", True):
                    notes.append("Con fine-grained access control mapea el rol a un backend role de OpenSearch.")
        elif t == "msk" and c.get("auth") == "IAM":
            acts = ["kafka-cluster:Connect", "kafka-cluster:DescribeCluster", "kafka-cluster:DescribeTopic"]
            if rd:
                acts += ["kafka-cluster:ReadData", "kafka-cluster:AlterGroup", "kafka-cluster:DescribeGroup"]
            if wr or access == "invoke":
                acts += ["kafka-cluster:WriteData", "kafka-cluster:CreateTopic"]
            nm = self.name(tgt)
            S("MskIam", acts, [f"arn:aws:kafka:{self.region}:{self.account}:cluster/{nm}/*",
                               f"arn:aws:kafka:{self.region}:{self.account}:topic/{nm}/*",
                               f"arn:aws:kafka:{self.region}:{self.account}:group/{nm}/*"])
        elif t == "elasticache" and c.get("auth") == "IAM":
            S("ElastiCacheIam", ["elasticache:Connect"], [self.arn(tgt)])
        elif t == "lakeformation":
            S("LakeFormation", ["lakeformation:GetDataAccess"], ["*"])
            notes.append("Otorga grants de Lake Formation al rol (SELECT/INSERT/DESCRIBE) o asócialo a LF-Tags.")
        elif t == "mwaa":
            S("MwaaApi", ["airflow:CreateCliToken", "airflow:CreateWebLoginToken", "airflow:InvokeRestApi"],
              [f"arn:aws:airflow:{self.region}:{self.account}:environment/{self.name(tgt)}"])
        return st, notes

    def connection_plan(self, e):
        src, tgt = self.nodes[e["source"]], self.nodes[e["target"]]
        st_, tt = src["type"], tgt["type"]
        acc = self.access(e)
        plan = {"edge_id": e["id"], "source": src["id"], "target": tgt["id"], "access": acc,
                "summary": f"{self.label(src)} {ACCESS_LABEL.get(acc, '→')} {self.label(tgt)}",
                "principal": None, "identity": [], "resource_policies": [], "network": [], "path": [], "notes": [],
                "terraform": ""}

        if "note" in (st_, tt):
            return plan
        if "iam_role" in (st_, tt):
            role = src if st_ == "iam_role" else tgt
            other = tgt if role is src else src
            pr = self.principal_of(other)
            trusted = self.cfg(role).get("trusted")
            plan["summary"] = f"Rol '{self.label(role)}' asignado a '{self.label(other)}'"
            if pr and trusted and pr["service"].endswith("amazonaws.com") and trusted != pr["service"]:
                plan["notes"].append(f"✖ La trust policy confía en {trusted} pero {self.comp(other)['name']} necesita {pr['service']}.")
                self.add("high", "IAM", "IAM-TRUST-MISMATCH", f"Trust policy incorrecta en '{self.label(role)}'",
                         f"El rol confía en {trusted}, pero lo usa {self.label(other)} ({pr['service']}).",
                         f"Cambia el principal de la trust policy a {pr['service']}.", [role, other], [e])
            elif pr:
                plan["notes"].append(f"✔ Se usará como {pr['desc']}.")
            return plan

        if tt == "kms" and st_ in ("s3", "dynamodb", "sqs", "sns", "kinesis", "rds", "aurora", "secrets", "redshift",
                                   "ebs", "efs", "ec2", "msk", "opensearch", "cloudwatch", "elasticache", "emr", "documentdb"):
            plan["summary"] = f"{self.label(src)} se cifra con la llave '{self.label(tgt)}'"
            plan["notes"].append("Quien lea/escriba datos de este recurso necesita kms:Decrypt / kms:GenerateDataKey "
                                 "sobre esta llave (se agrega automáticamente en las otras conexiones).")
            plan["notes"].append("La key policy debe permitir el uso vía el servicio (kms:ViaService) a esos roles.")
            return plan

        # ¿Quién es el principal? (patrón push vs pull)
        principal_node, perm_target, perm_access = src, tgt, acc
        resource_policy = None
        if tt == "lambda" and st_ in POLLERS:
            principal_node, perm_target, perm_access = tgt, src, "read"
            if st_ == "dynamodb":
                perm_access = "invoke"
            plan["notes"].append(f"Lambda lee de {self.comp(src)['name']} mediante un event source mapping: "
                                 "los permisos van en el rol de la Lambda, no en el origen.")
        elif st_ in ("s3", "sns", "eventbridge", "apigw", "alb", "cognito", "cloudfront") and tt == "lambda":
            principal_node = None
            svc = {"s3": "s3.amazonaws.com", "sns": "sns.amazonaws.com", "eventbridge": "events.amazonaws.com",
                   "apigw": "apigateway.amazonaws.com", "alb": "elasticloadbalancing.amazonaws.com",
                   "cognito": "cognito-idp.amazonaws.com", "cloudfront": "edgelambda.amazonaws.com"}[st_]
            resource_policy = {"type": "Permiso de Lambda (aws_lambda_permission)", "on": self.label(tgt),
                               "statement": {"Effect": "Allow", "Principal": {"Service": svc}, "Action": "lambda:InvokeFunction",
                                             "Resource": self.arn(tgt),
                                             "Condition": {"ArnLike": {"AWS:SourceArn": f"<arn de {self.label(src)}>"}}},
                               "terraform": self._tf_lambda_permission(src, tgt, svc)}
        elif st_ in ("s3", "sns", "eventbridge") and tt in ("sqs", "sns"):
            principal_node = None
            svc = {"s3": "s3.amazonaws.com", "sns": "sns.amazonaws.com", "eventbridge": "events.amazonaws.com"}[st_]
            action = "sqs:SendMessage" if tt == "sqs" else "sns:Publish"
            kind = "Queue policy (aws_sqs_queue_policy)" if tt == "sqs" else "Topic policy (aws_sns_topic_policy)"
            resource_policy = {"type": kind, "on": self.label(tgt),
                               "statement": {"Effect": "Allow", "Principal": {"Service": svc}, "Action": action,
                                             "Resource": self.arn(tgt),
                                             "Condition": {"ArnEquals": {"aws:SourceArn": f"<arn de {self.label(src)}>"}}}}
            if tt == "sqs" and self.cfg(tgt).get("encryption") == "SSE-KMS":
                plan["notes"].append(f"✖ La cola usa SSE-KMS: la key policy de la CMK debe permitir a {svc} "
                                     "kms:GenerateDataKey y kms:Decrypt (no funciona con la llave aws/sqs administrada).")
                self.add("medium", "IAM", "IAM-KMS-SERVICE", f"{self.label(src)} → {self.label(tgt)}: revisa la key policy",
                         f"{self.comp(src)['name']} publicará en una cola cifrada con KMS.",
                         f"Usa una CMK cuya key policy permita a {svc} kms:GenerateDataKey/Decrypt, o SSE-SQS.", [src, tgt], [e])
        elif st_ == "s3" and tt == "eventbridge":
            principal_node = None
            plan["notes"].append("Habilita 'Amazon EventBridge' en las notificaciones del bucket (no requiere política adicional).")
        elif st_ == "cloudfront" and tt == "s3":
            principal_node = None
            resource_policy = {"type": "Bucket policy (OAC)", "on": self.label(tgt),
                               "statement": {"Effect": "Allow", "Principal": {"Service": "cloudfront.amazonaws.com"},
                                             "Action": "s3:GetObject", "Resource": self.arn(tgt),
                                             "Condition": {"StringEquals": {
                                                 "AWS:SourceArn": f"arn:aws:cloudfront::{self.account}:distribution/<id>"}}}}
            if self.cfg(tgt).get("encryption") in ("SSE-KMS", "DSSE-KMS"):
                plan["notes"].append("Con SSE-KMS la key policy debe permitir a cloudfront.amazonaws.com kms:Decrypt.")
        elif st_ == "eventbridge" and tt not in ("lambda", "sqs", "sns"):
            plan["notes"].append("EventBridge necesita un rol (events.amazonaws.com) para este tipo de target.")
        elif st_ == "sns" and tt == "firehose":
            plan["notes"].append("La suscripción SNS → Firehose requiere un subscription role con firehose:PutRecord*.")
        elif st_ in EXTERNAL or st_ == "users":
            principal_node = None
        elif st_ in ("alb", "nlb", "cloudfront", "route53", "waf", "vpce", "igw", "nat", "tgw", "peering", "vpn",
                     "netfw", "dnsfw", "acm", "cognito", "s3", "dynamodb", "sqs", "sns", "kinesis", "msk", "rds", "aurora",
                     "elasticache", "efs", "documentdb", "kms", "secrets", "lakeformation", "vpc", "subnet",
                     "cloudwatch", "cloudtrail", "ecr", "backup", "guardduty", "ssm", "opensearch"):
            # Componentes que no son "principal" de una llamada a la API
            principal_node = None if tt not in ("lambda",) else principal_node
            if st_ in ("s3", "dynamodb", "sqs", "sns", "kinesis") and tt not in ("lambda",):
                plan["notes"].append(f"{self.comp(src)['name']} no inicia conexiones: ¿la flecha debería ir al revés "
                                     f"({self.label(tgt)} → {self.label(src)})? La dirección indica quién llama a quién.")
                self.add("low", "Seguimiento", "EDGE-DIRECTION", f"Dirección dudosa: {self.label(src)} → {self.label(tgt)}",
                         f"{self.comp(src)['name']} es pasivo; normalmente el consumidor es quien inicia.",
                         "Invierte la conexión si el componente destino es quien lee/escribe.", [src, tgt], [e])

        if principal_node is not None:
            pr = self.principal_of(principal_node)
            if pr:
                stmts, notes = self.statements_for(principal_node, perm_target, perm_access)
                plan["principal"] = {"node_id": principal_node["id"], **pr}
                plan["identity"] = stmts
                plan["notes"] += notes
                if stmts:
                    plan["terraform"] = self._tf_inline_policy(principal_node, pr, perm_target, stmts)
        if resource_policy:
            plan["resource_policies"].append(resource_policy)

        # Red: Security Groups
        self._network_for_edge(e, src, tgt, plan)
        return plan

    def default_port(self, n):
        t, c = n["type"], self.cfg(n)
        if c.get("port"):
            return c["port"]
        if t == "rds":
            return {"PostgreSQL": 5432, "MySQL": 3306, "MariaDB": 3306, "Oracle": 1521, "SQL Server": 1433}.get(c.get("engine"), 5432)
        if t == "aurora":
            return 5432 if "PostgreSQL" in str(c.get("engine")) else 3306
        if t == "msk":
            return {"IAM": 9098, "SASL/SCRAM": 9096, "mTLS": 9094}.get(c.get("auth"), 9092)
        if t == "alb":
            return 443 if "HTTPS:443" in (c.get("listeners") or []) else 80
        return {"redshift": 5439, "documentdb": 27017, "elasticache": 11211 if c.get("engine") == "Memcached" else 6379,
                "opensearch": 443, "efs": 2049, "eks": 443, "mwaa": 443, "vpce": 443, "nlb": c.get("port")}.get(t)

    def sg(self, n):
        return f"sg-{self.name(n)}"

    def _network_for_edge(self, e, src, tgt, plan):
        st_, tt = src["type"], tgt["type"]
        port = e.get("port") or self.default_port(tgt)
        proto = (e.get("protocol") or "tcp").lower()
        port_s = str(port) if port else "<puerto-app>"
        src_in, tgt_in = self.in_vpc(src), self.in_vpc(tgt)
        sv, tv = self.vpc_of(src), self.vpc_of(tgt)

        def rule(desc, peer, kind="sg"):
            plan["network"].append({"sg": self.sg(tgt), "direction": "ingress", "protocol": proto, "port": port_s,
                                    "peer": peer, "peer_kind": kind, "description": desc})

        # Tráfico desde internet / usuarios
        if st_ == "users":
            if tt in ("alb", "nlb"):
                if self.cfg(tgt).get("scheme") == "internal":
                    self.add("high", "Red", "NET-USERS-INTERNAL-LB", f"Usuarios de internet → balanceador interno '{self.label(tgt)}'",
                             "Un balanceador 'internal' no es alcanzable desde internet.",
                             "Cambia el esquema a internet-facing (en subnets públicas) o pon CloudFront/API GW delante.", [tgt], [e])
                rule("Desde internet", "0.0.0.0/0", "cidr")
            elif tt in COMPUTE or tt in DATASTORES_IN_VPC:
                if self.tier(tgt) == "public":
                    self.add("high", "Red", "NET-DIRECT-EXPOSE", f"Usuarios acceden directo a '{self.label(tgt)}'",
                             "Exponer instancias/servicios directamente a internet amplía la superficie de ataque y no escala.",
                             "Pon un ALB (o NLB) internet-facing en subnets públicas y mueve el backend a subnets privadas.",
                             [tgt], [e])
                    rule("Desde internet (no recomendado)", "0.0.0.0/0", "cidr")
                elif tt == "lambda" and not tgt_in:
                    self.add("medium", "Red", "NET-LAMBDA-PUBLIC", f"Usuarios invocan '{self.label(tgt)}' directamente",
                             "Sólo es posible con Function URL; sin throttling ni WAF.",
                             "Expón la Lambda detrás de API Gateway o ALB.", [tgt], [e])
                else:
                    self.add("critical", "Red", "NET-UNREACHABLE", f"'{self.label(tgt)}' no es alcanzable desde internet",
                             "Está en una subnet privada/aislada; los usuarios no pueden llegar directamente.",
                             "Agrega un ALB/NLB internet-facing en subnets públicas, API Gateway con VPC Link o CloudFront.",
                             [tgt], [e])
            elif tt == "s3":
                self.add("medium", "Seguridad", "SEC-S3-DIRECT", f"Usuarios acceden directo al bucket '{self.label(tgt)}'",
                         "Servir contenido directamente desde S3 requiere hacerlo público.",
                         "Usa CloudFront con Origin Access Control (OAC) y mantén Block Public Access activo, "
                         "o URLs prefirmadas.", [tgt], [e])
            return

        if st_ == "onprem":
            conn = self.cfg(src).get("connectivity", "Por definir")
            if tgt_in:
                has_link = bool(self.of_type("vpn")) or conn in ("Site-to-Site VPN", "Direct Connect")
                if not has_link:
                    self.add("high", "Red", "NET-HYBRID", f"On-premise → '{self.label(tgt)}' sin conectividad híbrida",
                             "El recurso está en subnet privada y no hay VPN/Direct Connect definidos.",
                             "Agrega Site-to-Site VPN o Direct Connect (con TGW o VGW) y rutas hacia el CIDR on-prem.", [src, tgt], [e])
                rule("Desde on-premise", self.cfg(src).get("cidr") or "<cidr-on-prem>", "cidr")
                plan["path"].append("Ruta: on-prem → VPN/DX → TGW/VGW → subnet de destino (propaga rutas BGP).")
            return

        if st_ == "cloudfront" and tt in ("alb", "nlb"):
            rule("Sólo CloudFront", "com.amazonaws.global.cloudfront.origin-facing", "prefix-list")
            plan["notes"].append("Restringe el SG del ALB al managed prefix list de CloudFront y valida un header secreto.")
            return

        if st_ == "apigw" and tgt_in:
            if tt in ("alb", "nlb"):
                plan["path"].append("Requiere VPC Link (HTTP API: ALB/NLB/Cloud Map; REST API: NLB).")
                if not self.cfg(src).get("vpc_link"):
                    self.add("high", "Red", "NET-VPC-LINK", f"API Gateway → '{self.label(tgt)}' privado sin VPC Link",
                             "API Gateway no vive en tu VPC; para llegar a un balanceador privado necesita VPC Link.",
                             "Habilita VPC Link. Para REST API el target debe ser un NLB.", [src, tgt], [e])
                if self.cfg(src).get("api_type") == "REST API" and tt == "alb":
                    plan["notes"].append("REST API sólo soporta VPC Link hacia NLB (o integración privada vía NLB→ALB).")
                rule("Desde VPC Link de API Gateway", f"sg-vpclink-{self.name(src)}")
            elif tt in COMPUTE:
                self.add("medium", "Red", "NET-APIGW-NEEDS-LB", f"API Gateway → '{self.label(tgt)}' sin balanceador",
                         "Para integrar API Gateway con servicios en VPC necesitas VPC Link + ALB/NLB (o Cloud Map).",
                         "Pon un ALB/NLB interno delante del servicio.", [src, tgt], [e])
            return

        # Recurso en VPC hablando con servicios regionales
        if src_in and (self.comp(tgt)["vpc"] == "never" or (self.comp(tgt)["vpc"] == "optional" and not tgt_in)):
            if tt in EXTERNAL:
                why = f"se conecta a '{self.label(tgt)}' (internet)"
                plan["path"] += self.egress_requirements(src, None, why, e)
                if tt == "saas" and self.cfg(tgt).get("ip_allowlist"):
                    plan["notes"].append("El tercero exige IP fija: la IP de salida es la Elastic IP del NAT Gateway.")
                plan["network"].append({"sg": self.sg(src), "direction": "egress", "protocol": "tcp", "port": port_s or "443",
                                        "peer": "0.0.0.0/0", "peer_kind": "cidr",
                                        "description": f"Salida a {self.label(tgt)} (restringe con Network Firewall si aplica)"})
                return
            services = VPCE_SERVICES.get(tt)
            if tt == "emr":
                services = ["emr-serverless"] if self.cfg(tgt).get("deployment", "EMR Serverless") == "EMR Serverless" \
                    else ["elasticmapreduce"]
            if tt == "apigw" and self.cfg(tgt).get("endpoint_type") == "Private":
                services = ["execute-api"]
            if services:
                why = f"llama a {self.comp(tgt)['name']} '{self.label(tgt)}'"
                plan["path"] += self.egress_requirements(src, services, why, e)
                plan["network"].append({"sg": self.sg(src), "direction": "egress", "protocol": "tcp", "port": "443",
                                        "peer": "pl-" + services[0] if services[0] in GATEWAY_ENDPOINT_SERVICES else "sg-vpce / 0.0.0.0/0",
                                        "peer_kind": "prefix-list" if services[0] in GATEWAY_ENDPOINT_SERVICES else "cidr",
                                        "description": f"HTTPS hacia {self.comp(tgt)['name']}"})
            return

        # Origen fuera de VPC → destino dentro de VPC
        if tgt_in and not src_in:
            if st_ in ("lambda", "glue", "emr", "opensearch") and tt not in ("alb", "nlb") or \
                    (st_ in ("lambda", "glue", "emr") and tt in ("alb", "nlb") and self.cfg(tgt).get("scheme") == "internal"):
                fixes = {"lambda": "Configura la Lambda en subnets privadas de la VPC (VpcConfig) con su propio SG.",
                         "glue": "Crea una Glue connection (tipo NETWORK/JDBC) en una subnet privada con SG self-referencing "
                                 "y un Gateway Endpoint de S3.",
                         "emr": "Configura la red de EMR Serverless (subnets privadas + SG) o despliega EMR en la VPC.",
                         "opensearch": "Coloca el dominio en la VPC."}
                self.add("high", "Red", "NET-OUTSIDE-TO-PRIVATE", f"'{self.label(src)}' no puede llegar a '{self.label(tgt)}'",
                         f"{self.comp(src)['name']} está fuera de la VPC y {self.comp(tgt)['name']} vive en una subnet privada.",
                         fixes.get(st_, "Coloca el origen dentro de la VPC."), [src, tgt], [e])
            elif st_ in ("stepfn", "eventbridge") and tt in DATASTORES_IN_VPC:
                self.add("medium", "Red", "NET-SERVICE-TO-DB", f"{self.comp(src)['name']} no se conecta por red a '{self.label(tgt)}'",
                         "Estos servicios usan APIs; no abren conexiones de red a recursos en tu VPC.",
                         "Intercala una Lambda/ECS en la VPC o usa Data API (Aurora/Redshift).", [src, tgt], [e])
            return

        # Ambos en VPC
        if src_in and tgt_in:
            if sv and tv and sv["id"] != tv["id"]:
                linked = self._vpcs_linked(sv, tv)
                plan["path"].append(("✔" if linked else "✖") + f" Tráfico entre VPCs ({self.label(sv)} → {self.label(tv)}): "
                                    "requiere Peering, Transit Gateway o PrivateLink, con rutas en ambas tablas.")
                if not linked:
                    self.add("high", "Red", "NET-CROSS-VPC", f"Conexión entre VPCs sin enlace: {self.label(src)} → {self.label(tgt)}",
                             f"'{self.label(sv)}' y '{self.label(tv)}' no están conectadas.",
                             "Agrega un Transit Gateway o VPC Peering conectado a ambas VPC (o expón el servicio con PrivateLink). "
                             "En SG usa el CIDR de la otra VPC (SG referencing sólo funciona con peering en la misma región).",
                             [src, tgt, sv, tv], [e])
                rule(f"Desde {self.label(src)} (otra VPC)", self.cfg(sv).get("cidr") or "<cidr-vpc-origen>", "cidr")
            else:
                rule(f"Desde {self.label(src)}", self.sg(src))
                plan["network"].append({"sg": self.sg(src), "direction": "egress", "protocol": proto, "port": port_s,
                                        "peer": self.sg(tgt), "peer_kind": "sg", "description": f"Hacia {self.label(tgt)}"})
            if tt in ("alb", "nlb") and st_ not in ("alb", "nlb") and self.cfg(tgt).get("scheme") == "internet-facing":
                plan["notes"].append("Tráfico interno hacia un balanceador internet-facing sale por internet; usa uno interno.")
            if tt in COMPUTE and not port:
                plan["notes"].append("Define el puerto de la aplicación en la conexión o en la configuración del destino.")

    # ───────────── reglas por servicio ─────────────
    def check_services(self):
        for n in self.nodes.values():
            t, c, L = n["type"], self.cfg(n), self.label(n)
            if t == "s3":
                if not c.get("block_public", True) and c.get("purpose") != "Sitio estático":
                    self.add("high", "Seguridad", "S3-PUBLIC", f"Bucket '{L}' sin Block Public Access",
                             "El bucket podría exponerse públicamente por una política/ACL.",
                             "Activa Block Public Access (a nivel cuenta y bucket).", [n])
                if c.get("purpose") == "Sitio estático" and not self.neighbors(n, "cloudfront"):
                    self.add("medium", "Seguridad", "S3-STATIC-CF", f"Sitio estático '{L}' sin CloudFront",
                             "S3 website endpoint no soporta HTTPS y requiere bucket público.",
                             "Sirve el sitio vía CloudFront + OAC con el bucket privado.", [n])
                fmt = c.get("table_format")
                if c.get("retention_days") in (None, "") and c.get("purpose") != "Sitio estático":
                    self.add("medium", "Datos", "S3-RETENTION", f"Sin política de retención en '{L}'",
                             "No está definido cuánto tiempo vive la data.",
                             "Define expiración y transiciones (lifecycle). Para raw típicamente 30-90 días; para gold según negocio/regulación.",
                             [n])
                if not c.get("versioning", True) and str(c.get("purpose", "")).startswith("Data lake"):
                    self.add("medium", "Datos", "S3-VERSIONING", f"Bucket de data lake '{L}' sin versionado",
                             "Sin versionado no hay recuperación ante borrados/escrituras accidentales.",
                             "Habilita versionado con expiración de versiones no actuales (ej. 7-30 días).", [n])
                if c.get("versioning", True) and c.get("noncurrent_days") in (None, "") and fmt in OPEN_FORMATS:
                    self.add("low", "Costo", "S3-NONCURRENT", f"Versiones no actuales sin expirar en '{L}'",
                             "Con versionado + tablas abiertas (muchos rewrites) las versiones viejas se acumulan.",
                             "Agrega NoncurrentVersionExpiration (ej. 7 días).", [n])
                if fmt in ICEBERG_FORMATS:
                    if c.get("catalog") in (None, "", "Ninguno") and fmt == "Apache Iceberg":
                        self.add("high", "Datos", "ICE-CATALOG", f"Tablas Iceberg en '{L}' sin catálogo",
                                 "Iceberg requiere un catálogo para el puntero de metadata y commits atómicos.",
                                 "Usa AWS Glue Data Catalog (o S3 Tables).", [n])
                    if c.get("compaction") in (None, "", "Ninguna") and fmt == "Apache Iceberg":
                        self.add("medium", "Datos", "ICE-COMPACTION", f"Iceberg sin compactación en '{L}'",
                                 "Escrituras frecuentes generan archivos pequeños que degradan lecturas y elevan costos.",
                                 "Habilita Glue automatic compaction o programa rewrite_data_files.", [n])
                    if c.get("snapshot_retention_days") in (None, "") and fmt == "Apache Iceberg":
                        self.add("medium", "Datos", "ICE-SNAPSHOTS", f"Iceberg sin expiración de snapshots en '{L}'",
                                 "Los snapshots retienen archivos borrados indefinidamente (costo y time travel ilimitado).",
                                 "Define retención (ej. 7 días) con expire_snapshots / optimización de Glue.", [n])
                    if c.get("file_format") in ("CSV", "JSON"):
                        self.add("low", "Datos", "ICE-FORMAT", f"Iceberg con {c.get('file_format')} en '{L}'",
                                 "Iceberg funciona mejor con formatos columnares.", "Usa Parquet.", [n])
                if fmt == "Hive (tablas Glue clásicas)" and str(c.get("purpose", "")).startswith("Data lake - curated"):
                    self.add("info", "Datos", "HIVE-TO-ICEBERG", f"Evalúa Iceberg para '{L}'",
                             "Las tablas Hive no soportan updates/deletes ACID, schema evolution segura ni time travel.",
                             "Si haces upserts/CDC o GDPR deletes, considera Apache Iceberg.", [n])
                if c.get("file_format") in ("CSV", "JSON") and str(c.get("purpose", "")).startswith("Data lake - a"):
                    self.add("low", "Costo", "S3-COLUMNAR", f"Capa analítica '{L}' en {c.get('file_format')}",
                             "Formatos de texto aumentan el escaneo en Athena/EMR.", "Usa Parquet/ORC con compresión.", [n])
                for svc in c.get("notifications") or []:
                    match = {"Lambda": "lambda", "SQS": "sqs", "SNS": "sns", "EventBridge": "eventbridge"}[svc]
                    if not any(nb["type"] == match for nb in self.neighbors(n)):
                        self.add("low", "Seguimiento", "S3-NOTIF-EDGE", f"'{L}' notifica a {svc} pero no hay conexión",
                                 "La configuración menciona notificaciones que no aparecen en el diagrama.",
                                 f"Conecta '{L}' → {svc} para que el Copilot genere las políticas.", [n])
            elif t == "rds" or t == "aurora":
                if not c.get("encrypted", True):
                    self.add("high", "Seguridad", "DB-ENC", f"'{L}' sin cifrado en reposo",
                             "No se puede habilitar después de crear la instancia.", "Habilita storage_encrypted con KMS.", [n])
                if t == "rds" and not c.get("multi_az", True):
                    self.add("medium" if self.is_prod() else "low", "Alta disponibilidad", "DB-MULTIAZ", f"'{L}' sin Multi-AZ",
                             "Una falla de AZ o mantenimiento genera indisponibilidad.", "Habilita Multi-AZ en producción.", [n])
                if t == "aurora" and (c.get("instances") or 1) < 2:
                    self.add("medium" if self.is_prod() else "low", "Alta disponibilidad", "DB-AURORA-READER",
                             f"Aurora '{L}' con una sola instancia", "Sin reader no hay failover rápido.",
                             "Agrega al menos un reader en otra AZ.", [n])
                if (c.get("backup_days") or 0) < 7:
                    self.add("medium", "Datos", "DB-BACKUP", f"Retención de backups corta en '{L}'",
                             f"{c.get('backup_days') or 0} días.", "Usa ≥7 días (prod: 14-35) o AWS Backup.", [n])
                if not c.get("deletion_protection", True):
                    self.add("low", "Operación", "DB-DELPROT", f"'{L}' sin protección contra borrado",
                             "Un terraform destroy accidental elimina la base.", "Activa deletion_protection.", [n])
                if not c.get("managed_secret", True) and not c.get("iam_auth"):
                    self.add("medium", "Seguridad", "DB-SECRET", f"Credenciales de '{L}' no administradas",
                             "La contraseña maestra podría terminar en tfstate o variables.",
                             "Usa manage_master_user_password (Secrets Manager) o autenticación IAM.", [n])
            elif t == "dynamodb":
                if not c.get("pitr", True):
                    self.add("medium", "Datos", "DDB-PITR", f"'{L}' sin Point-in-time recovery",
                             "Sin PITR no puedes restaurar a un momento específico.", "Habilita PITR.", [n])
                if c.get("streams") not in (None, "", "Deshabilitado") and not self.out_edges(n):
                    self.add("low", "Seguimiento", "DDB-STREAM-UNUSED", f"Streams habilitado en '{L}' sin consumidor",
                             "No hay conexiones salientes que consuman el stream.", "Conecta el consumidor o deshabilítalo.", [n])
            elif t in ("ec2", "asg"):
                if not c.get("imdsv2", True):
                    self.add("medium", "Seguridad", "EC2-IMDS", f"'{L}' sin IMDSv2 obligatorio",
                             "IMDSv1 es vulnerable a SSRF para robo de credenciales.", "Configura http_tokens = required.", [n])
                if not c.get("ebs_encrypted", True):
                    self.add("high", "Seguridad", "EC2-EBS", f"EBS sin cifrar en '{L}'", "Datos en reposo sin cifrado.",
                             "Habilita EBS encryption by default en la cuenta.", [n])
                if c.get("access") in ("SSH directo", "SSH vía bastion"):
                    self.add("low", "Seguridad", "EC2-SSH", f"'{L}' administrado por SSH",
                             "Requiere puerto 22 abierto y gestión de llaves.",
                             "Usa SSM Session Manager (sin puertos abiertos, auditado en CloudTrail).", [n])
                    if c.get("access") == "SSH directo" and self.tier(n) == "public":
                        self.add("high", "Seguridad", "EC2-SSH-PUBLIC", f"SSH expuesto en '{L}'",
                                 "Instancia en subnet pública con SSH directo.", "Cierra el 22 y usa SSM Session Manager.", [n])
                if c.get("access") == "SSM Session Manager" and self.tier(n) in ("private", "isolated"):
                    self._needs_services(n, ["ssm", "ssmmessages", "ec2messages"], "usa SSM Session Manager")
            elif t == "lambda":
                if (c.get("timeout") or 0) > 900:
                    self.add("high", "Operación", "LAMBDA-TIMEOUT", f"Timeout de '{L}' > 900 s",
                             "Lambda tiene un máximo de 15 minutos.", "Usa Step Functions, ECS o Glue/EMR para procesos largos.", [n])
                for e in self.in_edges(n):
                    s = self.nodes[e["source"]]
                    if s["type"] == "sqs":
                        vis = self.cfg(s).get("visibility") or 30
                        if vis < 6 * (c.get("timeout") or 3):
                            self.add("medium", "Operación", "SQS-VISIBILITY",
                                     f"Visibility timeout de '{self.label(s)}' corto para '{L}'",
                                     f"Visibility {vis}s < 6 × timeout de la Lambda ({c.get('timeout')}s): mensajes duplicados.",
                                     f"Sube el visibility timeout a ≥ {6 * (c.get('timeout') or 3)} s.", [s, n], [e])
                if c.get("trigger") in ("S3", "SNS", "EventBridge") and not c.get("dlq"):
                    self.add("low", "Operación", "LAMBDA-DLQ", f"'{L}' asíncrona sin DLQ/on-failure destination",
                             "Los eventos que fallen tras los reintentos se pierden.", "Configura un destino on-failure (SQS/SNS).", [n])
            elif t == "ecs":
                if self.tier(n) in ("private", "isolated"):
                    svcs = ["logs"]
                    if c.get("image_source", "ECR") == "ECR":
                        svcs = ["ecr.api", "ecr.dkr", "s3", "logs"]
                        self._needs_services(n, svcs, "descarga imágenes de ECR y envía logs")
                    elif c.get("image_source"):
                        self._needs_internet(n, "descarga imágenes de un registry público")
                if c.get("public_ip") and self.tier(n) == "public":
                    self.add("low", "Seguridad", "ECS-PUBLIC-IP", f"Tareas de '{L}' con IP pública",
                             "Funciona, pero expone las tareas.", "Usa subnets privadas + NAT/endpoints y un ALB delante.", [n])
            elif t == "eks":
                if c.get("endpoint_access") == "Público":
                    self.add("medium", "Seguridad", "EKS-ENDPOINT", f"API server de '{L}' sólo público",
                             "El plano de control queda expuesto a internet.",
                             "Usa acceso privado (o público restringido por CIDR + privado).", [n])
                if c.get("pod_iam") == "Rol del nodo (no recomendado)":
                    self.add("high", "IAM", "EKS-NODE-ROLE", f"Pods de '{L}' usan el rol del nodo",
                             "Todos los pods heredan los mismos permisos (sin mínimo privilegio).", "Usa EKS Pod Identity o IRSA.", [n])
                if self.tier(n) in ("private", "isolated"):
                    self._needs_services(n, ["ecr.api", "ecr.dkr", "s3", "sts", "logs", "ec2"], "los nodos descargan imágenes y se registran")
                if "aws-load-balancer-controller" not in (c.get("addons") or []) and any(
                        nb["type"] in ("alb", "nlb") for nb in self.neighbors(n)):
                    self.add("low", "Operación", "EKS-LBC", f"'{L}' usa balanceador sin AWS Load Balancer Controller",
                             "El controller crea y registra targets del ALB/NLB desde Ingress/Service.",
                             "Agrega el add-on aws-load-balancer-controller (o EKS Auto Mode).", [n])
            elif t == "emr":
                dep = c.get("deployment", "EMR Serverless")
                if dep == "EMR on EC2":
                    if c.get("cluster_lifecycle") == "Persistente" and not c.get("auto_terminate"):
                        self.add("medium", "Costo", "EMR-AUTOTERM", f"Cluster EMR '{L}' persistente sin auto-terminación",
                                 "Un cluster ocioso sigue cobrando EC2 + EMR.", "Configura auto-termination por inactividad o usa clusters transitorios.", [n])
                    if (c.get("task_count") or 0) > 0 and not c.get("task_spot"):
                        self.add("low", "Costo", "EMR-SPOT", f"Task nodes On-Demand en '{L}'",
                                 "Los task nodes no guardan HDFS y toleran interrupciones.", "Usa Spot (instance fleets diversificadas).", [n])
                    if self.tier(n) == "public":
                        self.add("medium", "Seguridad", "EMR-PUBLIC", f"EMR '{L}' en subnet pública",
                                 "Los nodos quedan con IP pública.", "Usa subnet privada + Gateway endpoint S3 + NAT/endpoints.", [n])
                    if (c.get("primary_count") or 1) == 1 and c.get("cluster_lifecycle") == "Persistente" and self.is_prod():
                        self.add("low", "Alta disponibilidad", "EMR-PRIMARY", f"EMR persistente '{L}' con 1 nodo primary",
                                 "El primary es punto único de falla.", "Usa 3 nodos primary para clusters de larga duración.", [n])
                if dep == "EMR Serverless" and not c.get("max_vcpu"):
                    self.add("medium", "Costo", "EMR-SLS-MAX", f"EMR Serverless '{L}' sin capacidad máxima",
                             "Sin límite, un job mal dimensionado puede escalar sin control.", "Define maximumCapacity (vCPU/memoria).", [n])
                if not c.get("log_uri"):
                    self.add("low", "Operación", "EMR-LOGS", f"EMR '{L}' sin Log URI", "Sin logs persistentes es difícil depurar.",
                             "Configura log URI en S3 (o logging administrado).", [n])
                reads_iceberg = [nb for nb in self.neighbors(n, "s3")
                                 if self.cfg(nb).get("table_format") in ICEBERG_FORMATS]
                apps = c.get("applications") or []
                if reads_iceberg and not c.get("iceberg") and "Iceberg" not in apps:
                    self.add("high", "Datos", "EMR-ICEBERG", f"EMR '{L}' usa tablas Iceberg sin habilitarlo",
                             f"Se conecta a {', '.join(self.label(x) for x in reads_iceberg)} (Iceberg).",
                             "Habilita Iceberg (classification iceberg-defaults o spark.sql.extensions + SparkCatalog con GlueCatalog).",
                             [n] + reads_iceberg)
                if self.in_vpc(n) and self.tier(n) in ("private", "isolated"):
                    self._needs_services(n, ["s3"], "lee/escribe datos y logs en S3")
            elif t == "glue":
                if self.in_vpc(n) and not c.get("vpc_connection"):
                    self.add("low", "Red", "GLUE-CONN", f"Glue '{L}' dibujado en VPC sin Glue connection",
                             "Glue corre fuera de tu VPC salvo que uses una connection.", "Marca 'Glue connection a VPC' o sácalo de la VPC.", [n])
                if c.get("vpc_connection") and self.in_vpc(n):
                    self._needs_services(n, ["s3"], "usa una Glue connection (requiere Gateway endpoint de S3)")
                    self.add("info", "Red", "GLUE-SG-SELF", f"SG self-referencing para Glue '{L}'",
                             "Los workers de Glue se comunican entre sí.", "Agrega en su SG una regla de ingreso de todo TCP desde el mismo SG.", [n])
            elif t == "athena":
                if not c.get("scan_limit_gb"):
                    self.add("low", "Costo", "ATHENA-LIMIT", f"Workgroup '{L}' sin límite de escaneo",
                             "Una query sin filtros de partición puede escanear TB.", "Define BytesScannedCutoffPerQuery.", [n])
            elif t == "sqs":
                if not c.get("dlq", True):
                    self.add("medium", "Operación", "SQS-DLQ", f"Cola '{L}' sin DLQ", "Mensajes envenenados se reintentan indefinidamente.",
                             "Configura una DLQ con maxReceiveCount (3-5) y alarma sobre su profundidad.", [n])
            elif t == "kms":
                if not c.get("rotation", True) and str(c.get("key_spec", "")).startswith("Simétrica"):
                    self.add("low", "Seguridad", "KMS-ROT", f"Llave '{L}' sin rotación", "Buenas prácticas/compliance piden rotación.",
                             "Habilita enable_key_rotation.", [n])
            elif t == "secrets":
                if not c.get("rotation"):
                    self.add("low", "Seguridad", "SM-ROT", f"Secreto '{L}' sin rotación", "Credenciales estáticas de larga vida.",
                             "Habilita rotación automática (RDS administrado la trae nativa).", [n])
            elif t == "alb":
                if "HTTPS:443" not in (c.get("listeners") or []) and c.get("scheme") == "internet-facing":
                    self.add("high", "Seguridad", "ALB-HTTPS", f"ALB público '{L}' sin HTTPS",
                             "Tráfico en texto plano desde internet.", "Agrega listener HTTPS:443 con certificado ACM y redirige HTTP→HTTPS.", [n])
                if not self.out_edges(n):
                    self.add("low", "Seguimiento", "ALB-NO-TARGET", f"ALB '{L}' sin targets", "No hay conexiones hacia backends.",
                             "Conecta el ALB a sus target groups (EC2/ASG/ECS/EKS/Lambda).", [n])
            elif t == "apigw":
                if c.get("auth") == "Ninguna":
                    self.add("medium", "Seguridad", "APIGW-AUTH", f"API '{L}' sin autorización", "Cualquiera puede invocarla.",
                             "Usa Cognito/JWT, IAM o Lambda authorizer; como mínimo throttling + WAF.", [n])
                if c.get("endpoint_type") == "Private":
                    v_ok = any("execute-api" in (self.cfg(ep).get("services") or []) for ep in self.of_type("vpce"))
                    if not v_ok:
                        self.add("high", "Red", "APIGW-PRIVATE-VPCE", f"API privada '{L}' sin endpoint execute-api",
                                 "Las APIs privadas sólo son accesibles vía Interface endpoint execute-api.",
                                 "Agrega un VPC endpoint de interfaz 'execute-api' y una resource policy con aws:SourceVpce.", [n])
            elif t == "cloudfront":
                if "S3" in (c.get("origins") or []) and not c.get("oac", True):
                    self.add("medium", "Seguridad", "CF-OAC", f"CloudFront '{L}' sin OAC", "El bucket origen debe estar público o usar OAI legado.",
                             "Usa Origin Access Control y bucket policy restringida a la distribución.", [n])
                if c.get("viewer_protocol") == "allow-all":
                    self.add("medium", "Seguridad", "CF-HTTP", f"CloudFront '{L}' permite HTTP", "Tráfico sin cifrar.",
                             "Usa redirect-to-https.", [n])
            elif t == "msk":
                if c.get("auth") == "Sin autenticación":
                    self.add("high", "Seguridad", "MSK-AUTH", f"MSK '{L}' sin autenticación", "Cualquier cliente con red puede producir/consumir.",
                             "Usa IAM access control o SASL/SCRAM.", [n])
                if c.get("transit") == "PLAINTEXT":
                    self.add("medium", "Seguridad", "MSK-TLS", f"MSK '{L}' sin TLS", "Datos en tránsito sin cifrar.", "Usa TLS.", [n])
            elif t == "elasticache":
                if not c.get("transit_encryption", True):
                    self.add("medium", "Seguridad", "EC-TLS", f"ElastiCache '{L}' sin cifrado en tránsito", "", "Habilita TLS.", [n])
            elif t == "opensearch":
                if c.get("network") == "Público":
                    self.add("high", "Seguridad", "OS-PUBLIC", f"OpenSearch '{L}' con acceso público",
                             "El dominio es alcanzable desde internet.", "Despliégalo en VPC o restringe con políticas + FGAC.", [n])
            elif t == "mwaa":
                if c.get("webserver") == "Público":
                    self.add("low", "Seguridad", "MWAA-PUBLIC", f"Webserver de MWAA '{L}' público", "", "Usa acceso privado + VPN/SSO.", [n])
                if self.tier(n) in ("private", "isolated"):
                    self._needs_services(n, ["s3", "logs", "monitoring", "sqs", "airflow.api", "airflow.env"],
                                         "MWAA necesita S3, CloudWatch, SQS y endpoints de Airflow")
            elif t == "nat":
                if not self.in_edges(n) and not self.out_edges(n):
                    pass
            elif t == "onprem":
                if c.get("connectivity") in (None, "", "Por definir") and self.edges_of(n):
                    self.add("medium", "Red", "ONPREM-CONN", f"Conectividad con '{L}' por definir",
                             "Hay integraciones con on-premise sin definir el enlace.",
                             "Define Site-to-Site VPN (rápido) o Direct Connect (latencia/ancho de banda estables).", [n])
            elif t == "iam_role":
                if not self.edges_of(n):
                    self.add("low", "IAM", "IAM-ROLE-ORPHAN", f"Rol '{L}' sin asignar", "No está conectado a ningún componente.",
                             "Conéctalo al componente que lo asume.", [n])

        # Componentes con mucho tráfico entrante sin balanceador
        for n in self.of_type("ec2", "asg", "ecs"):
            c = self.cfg(n)
            many = (n["type"] == "ec2" and (c.get("count") or 1) > 1) or n["type"] == "asg" or \
                   (n["type"] == "ecs" and (c.get("desired") or 1) > 1)
            ins = [self.nodes[e["source"]] for e in self.in_edges(n)]
            callers = [s for s in ins if s["type"] not in ("iam_role", "note", "kms", "secrets")]
            has_lb = any(s["type"] in ("alb", "nlb") for s in callers)
            if many and callers and not has_lb:
                self.add("medium", "Alta disponibilidad", "LB-NEEDED", f"'{self.label(n)}' necesita un balanceador",
                         f"Recibe tráfico de {', '.join(self.label(s) for s in callers)} y corre en varias instancias/tareas.",
                         "Agrega un ALB (HTTP/gRPC) o NLB (TCP/UDP, IP fija) con health checks delante del servicio.", [n] + callers)
            if n["type"] == "asg" and not has_lb and self.cfg(n).get("health_check") == "ELB":
                self.add("low", "Operación", "ASG-ELB-HC", f"ASG '{self.label(n)}' con health check ELB sin balanceador",
                         "Health check tipo ELB requiere target group.", "Conecta un ALB/NLB o usa health check EC2.", [n])

        # CloudTrail / CloudWatch / detección
        if self.nodes and not self.of_type("cloudtrail"):
            self.add("info", "Seguridad", "GOV-CLOUDTRAIL", "No hay CloudTrail en el diagrama",
                     "Auditoría de API (quién hizo qué).", "Confirma que existe un trail organizacional (o agrégalo).", [])
        if self.of_type(*COMPUTE, "emr", "glue") and not self.of_type("cloudwatch"):
            self.add("info", "Operación", "OPS-CW", "No hay CloudWatch en el diagrama",
                     "Define retención de logs, alarmas y dashboards.", "Agrega CloudWatch y documenta alarmas clave.", [])
        public_entries = [n for n in self.of_type("alb", "apigw", "cloudfront")
                          if any(self.nodes[e["source"]]["type"] == "users" for e in self.in_edges(n))
                          and not self.cfg(n).get("waf") and not self.neighbors(n, "waf")]
        if public_entries:
            self.add("medium", "Seguridad", "SEC-WAF", "Entradas públicas sin WAF",
                     f"{', '.join(self.label(n) for n in public_entries)} reciben tráfico de internet sin protección L7 "
                     "(SQLi, XSS, bots, rate limiting).",
                     "Asocia AWS WAF con las reglas administradas Common, KnownBadInputs e IpReputationList y una regla "
                     "de rate limiting (o marca 'WAF asociado' si ya existe).", public_entries)
        egress_internet = [e for e in self.edges if self.nodes[e["target"]]["type"] in ("saas", "users")
                           and self.in_vpc(self.nodes[e["source"]])]
        if egress_internet and not self.of_type("netfw", "dnsfw"):
            self.add("low", "Seguridad", "SEC-EGRESS-FILTER", "Salida a internet sin filtrado",
                     "Hay componentes en VPC que salen a internet sin control de dominios.",
                     "Considera AWS Network Firewall (allowlist de dominios) o Route 53 DNS Firewall.",
                     [self.nodes[e["source"]] for e in egress_internet])

    def edges_of(self, n):
        return self.in_edges(n) + self.out_edges(n)

    def _needs_services(self, n, services, why):
        v = self.vpc_of(n)
        if not v:
            return
        eps = set()
        for ep in self.children(v, "vpce"):
            eps.update(self.cfg(ep).get("services") or [])
        missing = [s for s in services if s not in eps]
        nat = [x for x in self.children(v, "nat") if self.tier(x) == "public"]
        if not missing:
            return
        if self.tier(n) == "isolated" or not nat:
            self.add("high", "Red", "NET-SVC-ENDPOINTS", f"'{self.label(n)}' sin ruta a servicios AWS",
                     f"{self.comp(n)['name']} {why}; en subnet {self.tier(n)} sin NAT faltan endpoints: {', '.join(missing)}.",
                     f"Agrega VPC endpoints ({', '.join(missing)}) o un NAT Gateway.", [n, v])
        elif "s3" in missing:
            self._gw_hint(v, "s3", n)

    def _gw_hint(self, vpc, svc, node):
        self._gw_hints.setdefault((vpc["id"], svc), set()).add(node["id"])

    def emit_gw_hints(self):
        for (vid, svc), ids in self._gw_hints.items():
            v = self.nodes[vid]
            names = ", ".join(sorted(self.label(self.nodes[i]) for i in ids))
            self.add("low", "Costo", "COST-GW-ENDPOINT", f"Agrega Gateway Endpoint de {svc} en '{self.label(v)}'",
                     f"{names} acceden a {svc} a través del NAT Gateway (cobro por GB procesado).",
                     f"El Gateway Endpoint de {svc} es gratuito, mantiene el tráfico en la red de AWS y "
                     "se asocia a las tablas de rutas privadas.", [v] + [self.nodes[i] for i in ids])

    def _needs_internet(self, n, why):
        v = self.vpc_of(n)
        if not v:
            return
        nat = [x for x in self.children(v, "nat") if self.tier(x) == "public"]
        if self.tier(n) == "isolated" or (self.tier(n) == "private" and not nat):
            self.add("high", "Red", "NET-NEEDS-NAT", f"'{self.label(n)}' necesita salida a internet",
                     f"{self.comp(n)['name']} {why}.", "Agrega un NAT Gateway (o replica la imagen en ECR con endpoints).", [n, v])

    # ───────────── seguimiento ─────────────
    def check_tracking(self):
        pending = [n for n in self.nodes.values() if self.comp(n)["terraformable"] and not n.get("terraformed")]
        for n in self.nodes.values():
            comp = self.comp(n)
            if n["type"] == "note":
                continue
            miss = missing_required(comp, n.get("config") or {})
            if miss:
                self.add("low", "Seguimiento", "TRK-CONFIG", f"Configuración incompleta: '{self.label(n)}'",
                         "Faltan: " + ", ".join(miss[:8]) + ("…" if len(miss) > 8 else ""),
                         "Completa la pestaña Configuración (o pregúntale al arquitecto).", [n])
            if not self.edges_of(n) and not comp["container"] and n["type"] not in ("igw", "nat", "vpce", "cloudtrail",
                                                                                     "guardduty", "backup", "acm", "route53"):
                self.add("low", "Seguimiento", "TRK-ORPHAN", f"'{self.label(n)}' sin conexiones",
                         "El componente no se relaciona con nada en el diagrama.", "Conéctalo o elimínalo si ya no aplica.", [n])
            if n.get("terraformed") and n.get("status") in ("Requiere cambios", "Borrador"):
                self.add("medium", "Seguimiento", "TRK-TF-STATUS", f"'{self.label(n)}' terraformado pero en estado '{n.get('status')}'",
                         "Está marcado como terraformado aunque el diseño no está aprobado.", "Revisa con el arquitecto.", [n])
        for e in self.edges:
            if not e.get("access"):
                s, t = self.nodes[e["source"]], self.nodes[e["target"]]
                if "note" in (s["type"], t["type"]) or "iam_role" in (s["type"], t["type"]) or t["type"] == "kms":
                    continue
                self.add("info", "Seguimiento", "TRK-EDGE-ACCESS", f"Conexión sin tipo de acceso: {self.label(s)} → {self.label(t)}",
                         f"Se asumió '{self.access(e)}'.", "Define lectura/escritura/invocación para generar permisos de mínimo privilegio.",
                         [s, t], [e])
        return pending

    # ───────────── consolidación ─────────────
    def consolidate_roles(self, plans):
        roles = {}
        for p in plans.values():
            pr = p.get("principal")
            if not pr or not p["identity"]:
                continue
            node = self.nodes[pr["node_id"]]
            r = roles.setdefault(pr["node_id"], {
                "node_id": pr["node_id"], "component": self.label(node), "role": pr["role"], "service": pr["service"],
                "desc": pr["desc"], "explicit": pr["explicit"], "statements": [], "edges": []})
            r["edges"].append(p["edge_id"])
            target = self.label(self.nodes[p["target"] if p["source"] == pr["node_id"] else p["source"]])
            for s in p["identity"]:
                s2 = dict(s)
                s2["Sid"] = re.sub(r"[^A-Za-z0-9]", "", f"{s['Sid']}{slugify(target).title()}")[:120]
                r["statements"].append(s2)
        for r in roles.values():
            node = self.nodes[r["node_id"]]
            if node["type"] == "lambda":
                r["statements"].insert(0, {"Sid": "BasicLogs", "Effect": "Allow",
                                           "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                                           "Resource": [f"arn:aws:logs:{self.region}:{self.account}:log-group:/aws/lambda/{self.name(node)}:*"]})
                if self.in_vpc(node):
                    r["managed"] = ["arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"]
            if node["type"] in ("ec2", "asg") and self.cfg(node).get("access") == "SSM Session Manager":
                r["managed"] = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
            if node["type"] == "glue":
                r["managed"] = ["arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"]
            r["policy"] = {"Version": "2012-10-17", "Statement": r["statements"]}
            svc = r["service"]
            if svc.endswith("amazonaws.com"):
                actions = ["sts:AssumeRole", "sts:TagSession"] if svc == "pods.eks.amazonaws.com" else "sts:AssumeRole"
                r["trust"] = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Principal": {"Service": svc},
                                                                      "Action": actions}]}
            else:
                r["trust"] = None
            r["terraform"] = self._tf_role(r)
        # Componentes que ejecutan código sin ningún permiso definido
        for n in self.of_type("lambda", "ecs", "glue", "emr", "stepfn"):
            if n["id"] not in roles and self.edges_of(n):
                pass
        return list(roles.values())

    def consolidate_sgs(self, plans):
        sgs = {}
        for p in plans.values():
            for r in p["network"]:
                g = sgs.setdefault(r["sg"], {"sg": r["sg"], "ingress": [], "egress": []})
                key = (r["protocol"], r["port"], r["peer"])
                lst = g[r["direction"]]
                if key not in {(x["protocol"], x["port"], x["peer"]) for x in lst}:
                    lst.append(r)
        for g in sgs.values():
            g["terraform"] = self._tf_sg(g)
        return sorted(sgs.values(), key=lambda g: g["sg"])

    # ───────────── Terraform ─────────────
    def _tf_id(self, s):
        return re.sub(r"[^a-z0-9_]", "_", s.lower()).strip("_") or "x"

    def _tf_inline_policy(self, node, pr, target, stmts):
        rid = self._tf_id(f"{self.name(node)}_to_{self.name(target)}")
        role = self._tf_id(pr["role"])
        return (f'resource "aws_iam_role_policy" "{rid}" {{\n'
                f'  name   = "{self.name(node)}-to-{self.name(target)}"\n'
                f'  role   = aws_iam_role.{role}.id\n'
                f'  policy = jsonencode({_hcl(dict(Version="2012-10-17", Statement=stmts), 2)})\n}}\n')

    def _tf_role(self, r):
        rid = self._tf_id(r["role"])
        out = []
        if r.get("trust"):
            out.append(f'resource "aws_iam_role" "{rid}" {{\n  name = "{r["role"]}"\n'
                       f'  assume_role_policy = jsonencode({_hcl(r["trust"], 2)})\n}}\n')
        else:
            out.append(f'# Rol "{r["role"]}": define la trust policy para {r["service"]}\n')
        out.append(f'resource "aws_iam_role_policy" "{rid}_inline" {{\n  name   = "{r["role"]}-inline"\n'
                   f'  role   = aws_iam_role.{rid}.id\n  policy = jsonencode({_hcl(r["policy"], 2)})\n}}\n')
        for i, m in enumerate(r.get("managed") or []):
            out.append(f'resource "aws_iam_role_policy_attachment" "{rid}_managed_{i}" {{\n'
                       f'  role       = aws_iam_role.{rid}.name\n  policy_arn = "{m}"\n}}\n')
        return "\n".join(out)

    def _tf_lambda_permission(self, src, tgt, svc):
        rid = self._tf_id(f"allow_{self.name(src)}_{self.name(tgt)}")
        return (f'resource "aws_lambda_permission" "{rid}" {{\n'
                f'  statement_id  = "Allow-{self.name(src)}"\n'
                f'  action        = "lambda:InvokeFunction"\n'
                f'  function_name = aws_lambda_function.{self._tf_id(self.name(tgt))}.function_name\n'
                f'  principal     = "{svc}"\n'
                f'  source_arn    = "<arn de {self.label(src)}>"\n}}\n')

    def _tf_sg(self, g):
        sg = self._tf_id(g["sg"])
        out = []
        for d in ("ingress", "egress"):
            for i, r in enumerate(g[d]):
                port = r["port"]
                ports = f'  from_port   = {port}\n  to_port     = {port}\n' if str(port).isdigit() else \
                    f'  from_port   = 0 # TODO {port}\n  to_port     = 0\n'
                if r["peer_kind"] == "sg":
                    peer = f'  referenced_security_group_id = aws_security_group.{self._tf_id(r["peer"])}.id\n'
                elif r["peer_kind"] == "prefix-list":
                    peer = f'  prefix_list_id = "<{r["peer"]}>"\n'
                else:
                    peer = f'  cidr_ipv4   = "{r["peer"]}"\n'
                out.append(f'resource "aws_vpc_security_group_{d}_rule" "{sg}_{d}_{i}" {{\n'
                           f'  security_group_id = aws_security_group.{sg}.id\n'
                           f'  description = "{r["description"][:200]}"\n  ip_protocol = "{r["protocol"]}"\n{ports}{peer}}}\n')
        return "\n".join(out)

    # ───────────── resumen ─────────────
    def summary(self, pending):
        tf_nodes = [n for n in self.nodes.values() if self.comp(n)["terraformable"]]
        done = [n for n in tf_nodes if n.get("terraformed")]
        open_q = sum(1 for n in self.nodes.values() for q in n.get("questions") or [] if q.get("status") != "closed"
                     and not q.get("answer"))
        answered = sum(1 for n in self.nodes.values() for q in n.get("questions") or [] if q.get("answer") and q.get("status") != "closed")
        cfg_total = cfg_done = 0
        for n in self.nodes.values():
            comp = self.comp(n)
            req = [f for f in comp["fields"] if f.get("required")]
            if not req:
                continue
            from catalog import visible_fields
            vis = [f for f in visible_fields(comp, self.cfg(n)) if f.get("required")]
            cfg_total += len(vis)
            cfg_done += len(vis) - len(missing_required(comp, n.get("config") or {}))
        by_sev = {s: 0 for s in SEVERITIES}
        for f in self.findings:
            if not f.get("dismissed"):
                by_sev[f["severity"]] += 1
        by_status = {}
        for n in tf_nodes:
            st = n.get("status") or "Borrador"
            by_status[st] = by_status.get(st, 0) + 1
        return {
            "components": len(tf_nodes), "terraformed": len(done),
            "terraform_pct": round(100 * len(done) / len(tf_nodes)) if tf_nodes else 0,
            "edges": len(self.edges), "edges_terraformed": sum(1 for e in self.edges if e.get("terraformed")),
            "config_pct": round(100 * cfg_done / cfg_total) if cfg_total else 100,
            "open_questions": open_q, "answered_questions": answered,
            "findings": by_sev, "by_status": by_status,
            "pending_terraform": [n["id"] for n in pending],
        }

    def run(self):
        self.check_network()
        plans = {e["id"]: self.connection_plan(e) for e in self.edges}
        self.check_services()
        self.emit_gw_hints()
        pending = self.check_tracking()
        # de-duplicar por id
        seen, uniq = set(), []
        for f in self.findings:
            if f["id"] in seen:
                continue
            seen.add(f["id"])
            uniq.append(f)
        dismissed = self.p.get("dismissed") or {}
        for f in uniq:
            if f["id"] in dismissed:
                f["dismissed"] = dismissed[f["id"]]
        uniq.sort(key=lambda f: (SEVERITIES.index(f["severity"]), f["category"], f["title"]))
        self.findings = uniq
        node_sev = {}
        for f in uniq:
            if f.get("dismissed"):
                continue
            for nid in f["node_ids"]:
                cur = node_sev.get(nid)
                if cur is None or SEVERITIES.index(f["severity"]) < SEVERITIES.index(cur):
                    node_sev[nid] = f["severity"]
        return {
            "findings": uniq, "plans": plans, "roles": self.consolidate_roles(plans),
            "security_groups": self.consolidate_sgs(plans), "summary": self.summary(pending),
            "node_severity": node_sev, "parents": self.parent,
        }


OPEN_FORMATS = {"Apache Iceberg", "S3 Tables (Iceberg administrado)", "Delta Lake", "Apache Hudi"}
ICEBERG_FORMATS = {"Apache Iceberg", "S3 Tables (Iceberg administrado)"}


def _hcl(obj, indent=0):
    """JSON con indentación para incrustar en jsonencode() (HCL acepta la sintaxis de objetos JSON)."""
    txt = json.dumps(obj, indent=2, ensure_ascii=False)
    pad = " " * indent
    return txt.replace("\n", "\n" + pad)


def analyze(project):
    return Analyzer(project).run()
