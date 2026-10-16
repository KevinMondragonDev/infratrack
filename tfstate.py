"""Importa el estado y el plan de Terraform y los compara con el diagrama.

Formatos aceptados:
  - `terraform show -json`               (estado: values.root_module + child_modules)
  - `terraform.tfstate` v4               (resources[].instances[].attributes)
  - `terraform show -json plan.tfplan`   (plan: resource_changes[].change.actions)

Sólo se conservan atributos de una lista blanca (arn, id, nombre, CIDR, motor, tags…):
nunca se guardan contraseñas, llaves ni valores marcados como sensibles.
"""
import json
import re

KEEP_ATTRS = ("arn", "id", "name", "bucket", "function_name", "cidr_block", "vpc_id", "subnet_id", "availability_zone",
              "engine", "instance_class", "load_balancer_type", "internal", "type", "runtime", "tags")
SECRET_HINT = re.compile(r"(password|secret|private_key|token|key_material|credential)", re.IGNORECASE)
MAX_RESOURCES = 20000

TYPE_MAP = {
    "aws_vpc": "vpc", "aws_subnet": "subnet", "aws_internet_gateway": "igw", "aws_nat_gateway": "nat",
    "aws_vpc_endpoint": "vpce", "aws_ec2_transit_gateway": "tgw", "aws_vpc_peering_connection": "peering",
    "aws_api_gateway_rest_api": "apigw", "aws_apigatewayv2_api": "apigw", "aws_cloudfront_distribution": "cloudfront",
    "aws_route53_zone": "route53", "aws_wafv2_web_acl": "waf", "aws_networkfirewall_firewall": "netfw",
    "aws_route53_resolver_firewall_rule_group": "dnsfw", "aws_vpn_connection": "vpn", "aws_dx_connection": "dx",
    "aws_globalaccelerator_accelerator": "globalaccel", "aws_shield_protection": "shield",
    "aws_security_group": "sg", "aws_network_acl": "nacl", "aws_route_table": "rtb",
    "aws_instance": "ec2", "aws_autoscaling_group": "asg", "aws_lambda_function": "lambda", "aws_ecs_service": "ecs",
    "aws_eks_cluster": "eks", "aws_sfn_state_machine": "stepfn", "aws_batch_compute_environment": "batch",
    "aws_apprunner_service": "apprunner", "aws_elastic_beanstalk_environment": "beanstalk", "aws_ecr_repository": "ecr",
    "aws_s3_bucket": "s3", "aws_efs_file_system": "efs", "aws_backup_plan": "backup", "aws_db_instance": "rds",
    "aws_rds_cluster": "aurora", "aws_dynamodb_table": "dynamodb", "aws_elasticache_replication_group": "elasticache",
    "aws_elasticache_serverless_cache": "elasticache", "aws_redshift_cluster": "redshift",
    "aws_redshiftserverless_workgroup": "redshift", "aws_opensearch_domain": "opensearch", "aws_docdb_cluster": "documentdb",
    "aws_emr_cluster": "emr", "aws_emrserverless_application": "emr", "aws_glue_job": "glue",
    "aws_glue_catalog_database": "glue_catalog", "aws_athena_workgroup": "athena", "aws_kinesis_stream": "kinesis",
    "aws_kinesis_firehose_delivery_stream": "firehose", "aws_msk_cluster": "msk", "aws_mwaa_environment": "mwaa",
    "aws_sqs_queue": "sqs", "aws_sns_topic": "sns", "aws_cloudwatch_event_bus": "eventbridge",
    "aws_scheduler_schedule_group": "eventbridge", "aws_mq_broker": "mq", "aws_iam_role": "iam_role", "aws_kms_key": "kms",
    "aws_secretsmanager_secret": "secrets", "aws_cognito_user_pool": "cognito", "aws_acm_certificate": "acm",
    "aws_guardduty_detector": "guardduty", "aws_cloudtrail": "cloudtrail", "aws_directory_service_directory": "directory",
    "aws_workspaces_directory": "workspaces", "aws_organizations_organization": "organization",
    "aws_lakeformation_data_lake_settings": "lakeformation", "aws_quicksight_data_source": "quicksight",
}
STATEFUL = {"rds", "aurora", "dynamodb", "s3", "efs", "kms", "documentdb", "redshift", "opensearch", "elasticache",
            "msk", "glue_catalog", "secrets", "backup"}
ACTION_LABEL = {"create": "crear", "update": "modificar", "delete": "destruir", "replace": "reemplazar"}


def _keep(attrs, sensitive=None):
    sensitive = sensitive if isinstance(sensitive, dict) else {}
    out = {}
    for k in KEEP_ATTRS:
        v = (attrs or {}).get(k)
        if v in (None, "", [], {}) or sensitive.get(k) is True or SECRET_HINT.search(k):
            continue
        if k == "tags" and isinstance(v, dict):
            out[k] = {str(tk): str(tv)[:200] for tk, tv in v.items() if not SECRET_HINT.search(str(tk))}
        elif not isinstance(v, (dict, list)):
            out[k] = v if isinstance(v, (bool, int, float)) else str(v)[:500]
    return out


def _resource(address, rtype, name, attrs, sensitive=None, action=None):
    if rtype == "aws_lb":
        comp = "nlb" if (attrs or {}).get("load_balancer_type") == "network" else "alb"
    else:
        comp = TYPE_MAP.get(rtype)
    r = {"address": address, "type": rtype, "name": name, "component": comp, "attributes": _keep(attrs, sensitive)}
    if action:
        r["action"] = action
    return r


def _walk_module(mod, out):
    for r in mod.get("resources") or []:
        if r.get("mode", "managed") == "managed":
            out.append(_resource(r.get("address", ""), r.get("type", ""), r.get("name", ""), r.get("values"),
                                 r.get("sensitive_values")))
    for child in mod.get("child_modules") or []:
        _walk_module(child, out)


def _from_v4(doc, out):
    for r in doc.get("resources") or []:
        if r.get("mode", "managed") != "managed":
            continue
        prefix = (r["module"] + ".") if r.get("module") else ""
        for inst in r.get("instances") or [{}]:
            key = inst.get("index_key")
            idx = "" if key is None else (f'["{key}"]' if isinstance(key, str) else f"[{key}]")
            out.append(_resource(f'{prefix}{r.get("type")}.{r.get("name")}{idx}', r.get("type", ""), r.get("name", ""),
                                 inst.get("attributes")))


def _plan_action(actions):
    actions = list(actions or [])
    if actions in (["delete", "create"], ["create", "delete"]):
        return "replace"
    for a in ("create", "update", "delete"):
        if a in actions:
            return a
    return None


def _from_plan(doc, out):
    for rc in doc.get("resource_changes") or []:
        if rc.get("mode", "managed") != "managed":
            continue
        ch = rc.get("change") or {}
        action = _plan_action(ch.get("actions"))
        if not action:
            continue
        attrs = ch.get("after") if action != "delete" else ch.get("before")
        out.append(_resource(rc.get("address", ""), rc.get("type", ""), rc.get("name", ""), attrs,
                             ch.get("after_sensitive") or ch.get("before_sensitive"), action))


def parse(text):
    """Devuelve {"kind": "state"|"plan", "resources": [...]}."""
    try:
        doc = json.loads(text or "")
    except json.JSONDecodeError as exc:
        raise ValueError(f"No es JSON válido ({exc.msg}). Usa `terraform show -json` o el archivo terraform.tfstate.") from exc
    if not isinstance(doc, dict):
        raise ValueError("Formato de Terraform no reconocido.")
    out = []
    if "resource_changes" in doc:
        kind = "plan"
        _from_plan(doc, out)
    elif "values" in doc and isinstance(doc.get("values"), dict):
        kind = "state"
        _walk_module(doc["values"].get("root_module") or {}, out)
    elif "resources" in doc and doc.get("version", 4) >= 3:
        kind = "state"
        _from_v4(doc, out)
    else:
        raise ValueError("Formato de Terraform no reconocido: usa `terraform show -json`, terraform.tfstate o un plan en JSON.")
    if len(out) > MAX_RESOURCES:
        raise ValueError(f"Demasiados recursos ({len(out)}).")
    return {"kind": kind, "resources": out}


def _norm(s):
    return re.sub(r"[^a-z0-9]", "", str(s or "").lower())


def _resource_names(r):
    a = r["attributes"]
    return {x for x in (_norm(a.get("bucket")), _norm(a.get("function_name")), _norm(a.get("name")),
                        _norm((a.get("tags") or {}).get("Name") if isinstance(a.get("tags"), dict) else ""),
                        _norm(r["name"])) if x}


def _node_names(n, prefix=""):
    c = n.get("config") or {}
    names = {_norm(c.get(k)) for k in ("bucket_name", "table_name", "role_name", "group_name", "workgroup")}
    label = n.get("label") or ""
    names |= {_norm(label), _norm(f"{prefix}-{label}") if prefix else ""}
    return {x for x in names if x}


def match(project, parsed):
    """Empareja recursos con nodos: primero por tf_address, luego por nombre y tipo (uno a uno)."""
    prefix = ((project.get("settings") or {}).get("prefix") or "")
    nodes = [n for n in project.get("nodes", []) if n.get("type") not in ("note", "zone", "users", "onprem", "saas")]
    by_addr = {n.get("tf_address"): n for n in nodes if n.get("tf_address")}
    used, matched, rest = set(), [], []
    for r in parsed["resources"]:
        n = by_addr.get(r["address"])
        if n and n["id"] not in used:
            used.add(n["id"])
            matched.append({"node_id": n["id"], "label": n.get("label"), **_brief(r)})
        else:
            rest.append(r)
    leftover = []
    for r in rest:
        names = _resource_names(r)
        cand = next((n for n in nodes if n["id"] not in used and n.get("type") == r["component"]
                     and names & _node_names(n, prefix)), None)
        if cand:
            used.add(cand["id"])
            matched.append({"node_id": cand["id"], "label": cand.get("label"), **_brief(r)})
        else:
            leftover.append(r)
    only_tf = [_brief(r) for r in leftover if r["component"]]
    unmapped = sorted({r["type"] for r in leftover if not r["component"]})
    from catalog import COMPONENTS_BY_ID
    only_diagram = [{"node_id": n["id"], "label": n.get("label"), "type": n["type"]} for n in nodes
                    if n["id"] not in used and COMPONENTS_BY_ID.get(n["type"], {}).get("terraformable")]
    return {"kind": parsed["kind"], "matched": matched, "only_tf": only_tf, "only_diagram": only_diagram,
            "unmapped_types": unmapped, "total": len(parsed["resources"])}


def _brief(r):
    a = r["attributes"]
    name = a.get("bucket") or a.get("function_name") or a.get("name") or \
        ((a.get("tags") or {}).get("Name") if isinstance(a.get("tags"), dict) else None) or r["name"]
    out = {"address": r["address"], "tf_type": r["type"], "component": r["component"], "name": str(name),
           "arn": a.get("arn") or ""}
    if r.get("action"):
        out["action"] = r["action"]
    if a.get("cidr_block"):
        out["cidr"] = a["cidr_block"]
    return out


def analyze_text(project, text):
    return match(project, parse(text))


def plan_findings(plan):
    """(severidad, regla, título, detalle, recomendación, node_ids) a partir del plan guardado en el proyecto."""
    changes = (plan or {}).get("changes") or {}
    created = (plan or {}).get("unmatched") or []
    counts = {}
    for c in list(changes.values()) + [x.get("action") for x in created]:
        if c:
            counts[c] = counts.get(c, 0) + 1
    out = []
    if counts:
        txt = ", ".join(f"{v} por {ACTION_LABEL.get(k, k)}" for k, v in sorted(counts.items()))
        out.append(("info", "TF-PLAN", f"Plan de Terraform: {sum(counts.values())} cambios", txt,
                    "Revisa el plan con el arquitecto antes de aplicarlo.", list(changes)))
    return out, counts
