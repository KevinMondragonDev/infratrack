"""Sistemas externos (red corporativa, SaaS, terceros que asumen roles), salida
corporativa filtrada, endpoints en varias subnets y tags de gobierno.

Mixin del Analyzer de copilot.py.
"""
import re

import glue_catalog as gc

TRI_YES, TRI_NO, TRI_UNKNOWN = "yes", "no", "unknown"
EXTERNAL_TYPES = {"users", "onprem", "saas", "idp", "corp_proxy", "corp_firewall", "secops", "observability", "cicd",
                  "ext_storage", "ext_dataplatform", "ext_source", "custom_ext"}
CORP_EGRESS = {"corp_proxy", "corp_firewall"}
TAGGABLE_EXCLUDE = EXTERNAL_TYPES | {"note", "zone", "organization", "iam_role", "account"}
DEFAULT_REQUIRED_TAGS_HINT = ["ProductOwner", "CostCenter", "CIA", "APMCode", "APMFunctional", "MegaId", "SharedCost",
                              "Environment", "Project", "managed_by", "assignment_group", "support_group"]


def tri_state(v):
    """Sí/True → yes · No → no · Sin confirmar/False/None → unknown (False de versiones previas = no confirmado)."""
    if v is True or v == "Sí":
        return TRI_YES
    if v == "No":
        return TRI_NO
    return TRI_UNKNOWN


def parse_tags(value):
    """Acepta dict, lista de {key, value} o texto 'clave=valor' por línea."""
    if not value:
        return {}
    if isinstance(value, dict):
        return {str(k).strip(): str(v).strip() for k, v in value.items() if str(k).strip()}
    if isinstance(value, list):
        return {str(r.get("key", "")).strip(): str(r.get("value", "") or "").strip()
                for r in value if isinstance(r, dict) and str(r.get("key", "")).strip()}
    out = {}
    for line in str(value).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        k, _, v = line.partition("=") if "=" in line else line.partition(":")
        if k.strip():
            out[k.strip()] = v.strip()
    return out


class ExtensionChecks:
    # ───────────── clasificación de externos ─────────────
    def ext_kind(self, n):
        """corp (red corporativa) · internet · none · aws (otra cuenta AWS) · None si no es externo."""
        t, c = n["type"], self.cfg(n)
        if t not in EXTERNAL_TYPES:
            return None
        if t in ("onprem", "corp_proxy", "corp_firewall"):
            return "corp" if not str(c.get("location", "")).startswith(("Inspection", "Nube")) else "internet"
        if t == "ext_source":
            return {"On-premise": "corp", "Otra cuenta AWS": "aws"}.get(c.get("location"), "internet")
        if t == "custom_ext":
            return {"Sistema on-premise / red corporativa": "corp", "Sin red (sólo documentación)": "none"}.get(
                c.get("behaves_as"), "internet")
        return "internet"

    def is_association(self, a, b):
        types = {a["type"], b["type"]}
        return bool(types & {"sg", "iam_role"}) or types == {"vpce", "subnet"}

    def external_principal(self, n):
        """Rol que asume un tercero (CSPM, observabilidad, CI/CD, plataforma de datos) para entrar a AWS."""
        t, c = n["type"], self.cfg(n)
        product = c.get("product") or self.label(n)
        role = f"{self.name(n)}-access"
        vendor = c.get("vendor_account") or c.get("vendor_principal") or "<cuenta-o-ARN-del-proveedor>"
        if re.fullmatch(r"\d{12}", str(vendor)):
            vendor = f"arn:aws:iam::{vendor}:root"
        if t == "cicd":
            auth = c.get("aws_auth") or ""
            if auth.startswith("Usuario IAM"):
                return {"service": "external", "role": f"{self.name(n)}-deployer (usuario IAM)", "explicit": False,
                        "desc": f"usuario IAM con llaves usado por {product} (no recomendado)", "trust_override": None}
            if auth.startswith("Agente"):
                return {"service": "ec2.amazonaws.com", "role": role, "explicit": False,
                        "desc": f"rol del agente de {product} dentro de AWS", "trust_override": None}
            return {"service": "external", "role": role, "explicit": False,
                    "desc": f"rol que asume {product} por OIDC (sin llaves)",
                    "trust_override": {"Version": "2012-10-17", "Statement": [{
                        "Effect": "Allow", "Principal": {"Federated": f"arn:aws:iam::{self.account}:oidc-provider/<host-oidc>"},
                        "Action": "sts:AssumeRoleWithWebIdentity",
                        "Condition": {"StringLike": {"<host-oidc>:sub": "<organización/repo o workspace>"}}}]}}
        if t == "ext_dataplatform" and not str(c.get("access", "")).startswith("Rol"):
            return None
        if t in ("secops", "observability") and "Rol" not in str(c.get("integration", "")) and c.get("integration") != "Mixta":
            return None
        return {"service": "external", "role": role, "explicit": False,
                "desc": f"rol cross-account que asume {product} desde su cuenta",
                "trust_override": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"AWS": vendor}, "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"sts:ExternalId": "<external-id-del-proveedor>"}}}]}}

    # ───────────── salida filtrada ─────────────
    def egress_filtered(self, src):
        """¿La salida a internet de `src` pasa por inspección (NFW, DNS FW, TGW con inspección, proxy/firewall corporativo)?"""
        if self.of_type("netfw", "dnsfw"):
            return True
        if any(nb["type"] in CORP_EGRESS for nb in self.neighbors(src)):
            return True
        inspected_tgw = [t for t in self.of_type("tgw") if str(self.cfg(t).get("egress_inspection", "")).startswith(
            ("Inspection", "Proxy"))]
        corp = self.of_type(*CORP_EGRESS)
        if not inspected_tgw and not corp:
            return False
        rtb = self.rtb_for(self.subnet_of(src)) if self.subnet_of(src) else None
        if rtb is None:
            return bool(inspected_tgw)  # sin tabla dibujada: se asume la salida centralizada declarada en el TGW
        import ipaddress
        r = self.route_for(rtb, ipaddress.ip_network("0.0.0.0/0"))
        return bool(r and r.get("target_type") in ("tgw", "nfw"))

    def has_private_path(self):
        """¿Hay conectividad privada hacia la red corporativa (TGW / VPN / Direct Connect)?"""
        return bool(self.of_type("tgw", "vpn", "dx"))

    # ───────────── reglas de externos ─────────────
    def check_externals(self):
        checks = {"secops": self._check_vendor_role, "observability": self._check_vendor_role, "cicd": self._check_cicd,
                  "ext_storage": self._check_ext_storage, "idp": self._check_idp, "corp_proxy": self._check_proxy,
                  "eventbridge": self._check_scheduler, "nacl": self._check_nacl_pending}
        for n in list(self.nodes.values()):
            fn = checks.get(n["type"])
            if fn:
                fn(n, self.cfg(n), self.label(n))
        self._check_vpce_azs()

    def _check_vendor_role(self, n, c, L):
        roleish = "Rol" in str(c.get("integration", "")) or c.get("integration") == "Mixta"
        if roleish and tri_state(c.get("external_id")) == TRI_NO:
            self.add("medium", "IAM", "EXT-NO-EXTERNALID", f"'{L}' asume un rol sin ExternalId",
                     "Sin ExternalId otro cliente del proveedor podría usar tu rol (confused deputy).",
                     "Exige sts:ExternalId en la trust policy del rol del proveedor.", [n])

    def _check_cicd(self, n, c, L):
        if str(c.get("aws_auth", "")).startswith("Usuario IAM"):
            self.add("high", "IAM", "EXT-CICD-KEYS", f"'{L}' despliega con access keys de un usuario IAM",
                     "Llaves de larga duración con permisos de despliegue: objetivo prioritario de ataque.",
                     "Usa OIDC (Terraform Enterprise/GitHub soportan dynamic credentials) o un agente con rol.", [n])
        if not c.get("approvers"):
            self.add("low", "Gobierno", "EXT-CICD-APPROVAL", f"'{L}' sin aprobadores de planes definidos",
                     "No está documentado quién aprueba los planes de Terraform.", "Define aprobadores por ambiente.", [n])

    def _check_ext_storage(self, n, c, L):
        if str(c.get("auth", "")).startswith(("SAS", "Usuario")) and not c.get("secret_in_sm"):
            self.add("medium", "Seguridad", "EXT-STORAGE-SECRET", f"Credencial de '{L}' sin Secrets Manager",
                     "La llave/SAS de larga duración debe guardarse y rotarse en Secrets Manager.",
                     "Guárdala en Secrets Manager con rotación y dale sólo GetSecretValue al rol que la usa.", [n])

    def _check_idp(self, n, c, L):
        if tri_state(c.get("mfa")) == TRI_NO:
            self.add("high", "Seguridad", "IDP-MFA", f"El IdP '{L}' no exige MFA", "",
                     "Exige MFA (o passkeys) en el IdP para el acceso a AWS.", [n])

    def _check_proxy(self, n, c, L):
        if not c.get("tls_inspection"):
            return
        st = tri_state(c.get("ca_distributed"))
        if st != TRI_YES:
            self.add("medium" if st == TRI_NO else "low", "Operación", "PROXY-CA",
                     f"Proxy '{L}' inspecciona TLS: distribuye su certificado raíz",
                     "Lambdas, contenedores y AMIs fallarán con errores de certificado si no confían en la CA del proxy.",
                     "Incluye la CA en las imágenes base, layers de Lambda y AWS_CA_BUNDLE / REQUESTS_CA_BUNDLE.", [n])

    def _check_scheduler(self, n, c, L):
        if c.get("scheduler") and not c.get("scheduler_dlq"):
            self.add("low", "Operación", "SCHED-DLQ", f"Schedules de '{L}' sin DLQ",
                     "Si el target falla tras los reintentos, la ejecución programada se pierde sin aviso.",
                     "Configura una DLQ (SQS) en cada schedule y una alarma sobre su profundidad.", [n])

    def _check_nacl_pending(self, n, c, L):
        if self._nacl_pending(n):
            self.add("info", "Seguimiento", "NACL-PENDING", f"NACL '{L}' pendiente de definición",
                     "No se evalúa hasta que se definan sus reglas.", "Define las reglas cuando se cierre el requerimiento.", [n])

    def _check_vpce_azs(self):
        for ep in self.of_type("vpce"):
            if self.cfg(ep).get("endpoint_type") != "Interface":
                continue
            subs = self.vpce_subnets(ep)
            if subs and len(self.azs(subs)) < 2:
                self.add("medium", "Alta disponibilidad", "VPCE-SINGLE-AZ", f"Endpoint '{self.label(ep)}' en una sola AZ",
                         "Si la AZ falla, las cargas de otras AZ pierden el endpoint (y pagan tráfico cross-AZ).",
                         "Despliégalo en una subnet por AZ: conéctalo a las subnets adicionales.", [ep] + subs)

    # ───────────── Glue Data Catalog ─────────────
    def check_glue_catalogs(self):
        buckets = {str(self.cfg(b).get("bucket_name") or self.name(b)).lower() for b in self.of_type("s3")}
        for n in self.of_type("glue_catalog"):
            c, L = self.cfg(n), self.label(n)
            tables = [(d["name"], t) for d in (c.get("catalog") or {}).get("databases", []) for t in d.get("tables", [])]
            if tri_state(c.get("encryption")) == TRI_NO:
                self.add("medium", "Seguridad", "GLUE-CAT-ENC", f"Metadatos del catálogo '{L}' sin cifrar", "",
                         "Activa el cifrado de metadatos del Data Catalog con una CMK (y el de contraseñas de conexiones).", [n])
            pii = [f"{db}.{t['name']}" for db, t in tables if any(x.get("pii") for x in t.get("columns", []) + t.get("partition_keys", []))]
            if pii and c.get("governance", "Sólo IAM") == "Sólo IAM":
                self.add("medium", "Seguridad", "GLUE-PII-NO-LF", f"{len(pii)} tabla(s) con datos personales sin Lake Formation",
                         "Tablas: " + ", ".join(pii[:6]) + ("…" if len(pii) > 6 else "") + ". Con sólo IAM no hay permisos por columna.",
                         "Gobierna el catálogo con Lake Formation (LF-Tags) para filtrar columnas sensibles.", [n])
            unclassified = [f"{db}.{t['name']}" for db, t in tables if f"{db}.{t['name']}" in pii and not t.get("sensitivity")]
            if unclassified:
                self.add("low", "Datos", "GLUE-SENSITIVITY", f"{len(unclassified)} tabla(s) con datos personales sin clasificar",
                         "Tablas: " + ", ".join(unclassified[:6]) + ("…" if len(unclassified) > 6 else ""),
                         "Asigna la sensibilidad (Confidencial / Restringida) en la pestaña Catálogo.", [n])
            undocumented = [f"{db}.{t['name']}" for db, t in tables if not t.get("description") or not t.get("owner")]
            if undocumented:
                self.add("low", "Seguimiento", "GLUE-DOC", f"{len(undocumented)} tabla(s) sin descripción o dueño en '{L}'",
                         "Tablas: " + ", ".join(undocumented[:6]) + ("…" if len(undocumented) > 6 else ""),
                         "Documenta propósito y dueño de cada tabla para la revisión con el arquitecto.", [n])
            no_part = [f"{db}.{t['name']}" for db, t in tables
                       if t.get("format") in ("Hive - CSV", "Hive - JSON") and not t.get("partition_keys")]
            if no_part:
                self.add("low", "Costo", "GLUE-NO-PARTITION", f"{len(no_part)} tabla(s) de texto sin particiones",
                         "Tablas: " + ", ".join(no_part[:6]), "Particiona (fecha) y usa Parquet/Iceberg para reducir el escaneo.", [n])
            unknown = sorted({m.group(1) for _, t in tables for m in [re.match(r"s3a?://([^/]+)", t.get("location") or "")]
                              if m and m.group(1).lower() not in buckets})
            if unknown and self.of_type("s3"):
                self.add("info", "Seguimiento", "GLUE-LOCATION", f"Buckets del catálogo que no están en el diagrama",
                         ", ".join(unknown[:8]), "Agrega esos buckets (o pon su nombre real en el campo 'Nombre del bucket').", [n])

    def glue_catalog_outputs(self):
        out = {}
        for n in self.of_type("glue_catalog"):
            cat = self.cfg(n).get("catalog") or {}
            a = self.account_of(n)
            out[n["id"]] = {"stats": gc.stats(cat),
                            "terraform": gc.terraform(cat, self.cfg(a).get("account_id") if a else None)}
        return out

    def _nacl_pending(self, n):
        return str(self.cfg(n).get("kind", "")).startswith("Pendiente") or n.get("status") == "Pendiente de definición"

    def vpce_subnets(self, ep):
        subs = [self.subnet_of(ep)] if self.subnet_of(ep) else []
        subs += [nb for nb in self.neighbors(ep, "subnet") if nb not in subs]
        return subs

    # ───────────── tags ─────────────
    def required_tags(self):
        raw = self.settings.get("required_tags") or []
        if isinstance(raw, str):
            raw = raw.replace(",", "\n").splitlines()
        return [t.strip() for t in raw if str(t).strip()]

    def effective_tags(self, n):
        tags = dict(parse_tags(self.settings.get("tags")))
        a = self.account_of(n)
        if a:
            tags.update(parse_tags(self.cfg(a).get("tags")))
        tags.update(parse_tags(n.get("tags")))
        return tags

    def check_tags(self):
        req = self.required_tags()
        if not req:
            return
        groups = {}
        for n in self.nodes.values():
            if n["type"] in TAGGABLE_EXCLUDE or not self.comp(n)["terraformable"]:
                continue
            tags = self.effective_tags(n)
            missing = tuple(k for k in req if not tags.get(k))
            if missing:
                groups.setdefault(missing, []).append(n)
        for missing, nodes in groups.items():
            names = ", ".join(self.label(x) for x in nodes[:6]) + ("…" if len(nodes) > 6 else "")
            self.add("low", "Gobierno", "TAG-MISSING", f"{len(nodes)} componente(s) sin tags: {', '.join(missing[:5])}"
                     + ("…" if len(missing) > 5 else ""),
                     f"Faltan {len(missing)} tags obligatorios en: {names}.",
                     "Defínelos en los tags por defecto del proyecto (default_tags), en la cuenta o en el componente.", nodes)

    def tags_terraform(self):
        req = self.required_tags()
        project = parse_tags(self.settings.get("tags"))
        blocks = []
        accounts = self.of_type("account") or [None]
        for a in accounts:
            tags = dict(project)
            if a:
                tags.update(parse_tags(self.cfg(a).get("tags")))
            for k in req:
                tags.setdefault(k, "")
            if not tags:
                continue
            width = max(len(k) for k in tags)
            body = "\n".join(f'      {k.ljust(width)} = "{v or "<definir>"}"' for k, v in tags.items())
            alias = f'\n  alias  = "{self.name(a)}"' if a and len(accounts) > 1 else ""
            region = self.region if self.region != "<region>" else "us-east-1"
            header = f"# Cuenta {self.label(a)} ({self.cfg(a).get('account_id') or '—'})\n" if a else ""
            blocks.append(f'{header}provider "aws" {{{alias}\n  region = "{region}"\n  default_tags {{\n    tags = {{\n{body}\n    }}\n  }}\n}}\n')
        extra = []
        for n in self.nodes.values():
            own = parse_tags(n.get("tags"))
            if own and n["type"] not in TAGGABLE_EXCLUDE:
                extra.append({"node_id": n["id"], "label": self.label(n), "tags": own})
        missing_cover = [k for k in req if not project.get(k)]
        return {"required": req, "project": project, "providers": "\n".join(blocks), "node_tags": extra,
                "missing_in_default": missing_cover, "template": DEFAULT_REQUIRED_TAGS_HINT}
