"""Detalle del AWS Glue Data Catalog: importación, combinación y Terraform.

Formatos que se pueden subir:
  - JSON de la AWS CLI: `aws glue get-tables --database-name X`, `aws glue get-table`,
    `aws glue get-databases`, `aws glue search-tables` (o varios pegados en una lista).
  - CSV con encabezados: database, table, column, type, partition, comment, format, location, pii, description, owner.

Estructura normalizada (se guarda en node.config["catalog"]):
  {"databases": [{"name", "description", "location", "tables": [
      {"name", "description", "owner", "format", "table_type", "location", "classification", "sensitivity",
       "retention_days", "partition_keys": [{"name", "type", "comment"}],
       "columns": [{"name", "type", "comment", "pii"}], "parameters": {...}}]}]}
"""
import csv
import io
import json
import re

ICEBERG = "Apache Iceberg"
FORMATS = [ICEBERG, "Delta Lake", "Apache Hudi", "Hive - Parquet", "Hive - ORC", "Hive - Avro", "Hive - JSON",
           "Hive - CSV", "Hive - otro", "Vista"]
SENSITIVITY = ["Pública", "Interna", "Confidencial", "Restringida (PII / financiera)"]
PII_HINT = re.compile(r"(rfc|curp|email|correo|phone|telefono|tel[eé]fono|celular|nombre|name|apellido|address|direcci[oó]n|"
                      r"birth|nacimiento|ssn|passport|pasaporte|card|tarjeta|clabe|cuenta|account_number|ip_address)",
                      re.IGNORECASE)
MAX_TABLES = 5000
MAX_COLUMNS = 2000


def _s(v, limit=500):
    return str(v if v is not None else "").strip()[:limit]


def detect_format(t):
    params = {str(k).lower(): str(v).lower() for k, v in (t.get("Parameters") or {}).items()}
    sd = t.get("StorageDescriptor") or {}
    sd_params = {str(k).lower(): str(v).lower() for k, v in (sd.get("Parameters") or {}).items()}
    if t.get("TableType") == "VIRTUAL_VIEW":
        return "Vista"
    if params.get("table_type") == "iceberg" or "metadata_location" in params:
        return ICEBERG
    if params.get("spark.sql.sources.provider") == "delta" or params.get("table_type") == "delta":
        return "Delta Lake"
    if "hudi" in str(sd.get("InputFormat", "")).lower():
        return "Apache Hudi"
    cls = params.get("classification") or sd_params.get("classification") or ""
    if not cls:
        fmt = str(sd.get("InputFormat", "")).lower()
        cls = next((k for k in ("parquet", "orc", "avro") if k in fmt), "")
        if not cls and "text" in fmt:
            serde = str((sd.get("SerdeInfo") or {}).get("SerializationLibrary", "")).lower()
            cls = "json" if "json" in serde else "csv"
    return {"parquet": "Hive - Parquet", "orc": "Hive - ORC", "avro": "Hive - Avro", "json": "Hive - JSON",
            "csv": "Hive - CSV"}.get(cls, "Hive - otro")


def _column(c):
    name = _s(c.get("Name") or c.get("name"), 255)
    return {"name": name, "type": _s(c.get("Type") or c.get("type"), 2000), "comment": _s(c.get("Comment") or c.get("comment")),
            "pii": bool(PII_HINT.search(name))}


def table_from_aws(t):
    sd = t.get("StorageDescriptor") or {}
    params = t.get("Parameters") or {}
    return {
        "name": _s(t.get("Name"), 255),
        "description": _s(t.get("Description"), 2000),
        "owner": _s(t.get("Owner"), 255),
        "format": detect_format(t),
        "table_type": _s(t.get("TableType"), 50),
        "location": _s(sd.get("Location"), 2000),
        "classification": _s(params.get("classification") or (sd.get("Parameters") or {}).get("classification"), 50),
        "sensitivity": "",
        "retention_days": t.get("Retention") or None,
        "partition_keys": [_column(c) for c in (t.get("PartitionKeys") or [])][:200],
        "columns": [_column(c) for c in (sd.get("Columns") or [])][:MAX_COLUMNS],
        "parameters": {_s(k, 255): _s(v, 1000) for k, v in list(params.items())[:100]},
    }


def _collect(doc, dbs):
    """Recorre cualquier combinación de respuestas de la CLI."""
    if isinstance(doc, list):
        for x in doc:
            _collect(x, dbs)
        return
    if not isinstance(doc, dict):
        return
    for d in doc.get("DatabaseList") or ([doc["Database"]] if isinstance(doc.get("Database"), dict) else []):
        db = dbs.setdefault(_s(d.get("Name"), 255), {"tables": {}})
        db["description"] = _s(d.get("Description"), 2000) or db.get("description", "")
        db["location"] = _s(d.get("LocationUri"), 2000) or db.get("location", "")
    tables = list(doc.get("TableList") or [])
    if isinstance(doc.get("Table"), dict):
        tables.append(doc["Table"])
    if "StorageDescriptor" in doc and "Name" in doc:
        tables.append(doc)
    for t in tables:
        dbname = _s(t.get("DatabaseName"), 255) or "default"
        dbs.setdefault(dbname, {"tables": {}})["tables"][_s(t.get("Name"), 255)] = table_from_aws(t)


def _truthy(v):
    return str(v).strip().lower() in ("1", "true", "yes", "si", "sí", "x", "y")


def parse_csv(text):
    reader = csv.DictReader(io.StringIO(text))
    fields = {f.strip().lower(): f for f in reader.fieldnames or []}
    if "table" not in fields or "column" not in fields:
        raise ValueError("El CSV necesita al menos las columnas 'table' y 'column' (y opcionalmente database, type, "
                         "partition, comment, format, location, pii, description, owner).")
    dbs = {}
    get = lambda row, k: _s(row.get(fields.get(k, ""), ""), 2000)  # noqa: E731
    for row in reader:
        db = dbs.setdefault(get(row, "database") or "default", {"tables": {}})
        tname = get(row, "table")
        if not tname:
            continue
        t = db["tables"].setdefault(tname, {"name": tname, "description": "", "owner": "", "format": "", "table_type": "",
                                            "location": "", "classification": "", "sensitivity": "", "retention_days": None,
                                            "partition_keys": [], "columns": [], "parameters": {}})
        for k in ("description", "owner", "location"):
            t[k] = t[k] or get(row, k)
        fmt = get(row, "format")
        if fmt and not t["format"]:
            t["format"] = next((f for f in FORMATS if fmt.lower() in f.lower()), fmt)
        col = {"name": get(row, "column")[:255], "type": get(row, "type"), "comment": get(row, "comment"),
               "pii": _truthy(get(row, "pii")) if get(row, "pii") else bool(PII_HINT.search(get(row, "column")))}
        if col["name"]:
            (t["partition_keys"] if _truthy(get(row, "partition")) else t["columns"]).append(col)
    return dbs


def parse_import(text, filename=""):
    text = (text or "").strip()
    if not text:
        raise ValueError("El archivo está vacío.")
    if filename.lower().endswith(".csv") or (not text.startswith(("{", "[")) and "," in text.splitlines()[0]):
        dbs = parse_csv(text)
    else:
        try:
            doc = json.loads(text)
        except json.JSONDecodeError:
            # Varias respuestas JSON concatenadas (una por base de datos)
            doc, dec, pos = [], json.JSONDecoder(), 0
            while pos < len(text):
                obj, end = dec.raw_decode(text, pos)
                doc.append(obj)
                pos = end
                while pos < len(text) and text[pos] in " \r\n\t,":
                    pos += 1
        dbs = {}
        _collect(doc, dbs)
    if not dbs:
        raise ValueError("No se encontraron bases ni tablas. Usa la salida de `aws glue get-tables` / `get-databases` o un CSV.")
    total = sum(len(d["tables"]) for d in dbs.values())
    if total > MAX_TABLES:
        raise ValueError(f"Demasiadas tablas ({total}); el máximo por importación es {MAX_TABLES}.")
    return {"databases": [{"name": name, "description": d.get("description", ""), "location": d.get("location", ""),
                           "tables": sorted(d["tables"].values(), key=lambda t: t["name"])}
                          for name, d in sorted(dbs.items())]}


def merge(existing, incoming):
    """Combina por base y tabla. Lo importado actualiza el esquema; se conservan los datos capturados a mano
    (descripción, dueño, sensibilidad, retención y marcas de datos personales) cuando la importación no los trae."""
    out = {d["name"]: d for d in (existing or {}).get("databases", [])}
    for d in incoming.get("databases", []):
        cur = out.setdefault(d["name"], {"name": d["name"], "description": "", "location": "", "tables": []})
        cur["description"] = d.get("description") or cur.get("description", "")
        cur["location"] = d.get("location") or cur.get("location", "")
        tables = {t["name"]: t for t in cur.get("tables", [])}
        for t in d.get("tables", []):
            old = tables.get(t["name"])
            if old:
                for k in ("description", "owner", "sensitivity", "retention_days"):
                    t[k] = t.get(k) or old.get(k)
                old_pii = {c["name"]: c.get("pii") for c in old.get("columns", []) + old.get("partition_keys", [])}
                for c in t.get("columns", []) + t.get("partition_keys", []):
                    if c["name"] in old_pii:
                        c["pii"] = old_pii[c["name"]]
            tables[t["name"]] = t
        cur["tables"] = sorted(tables.values(), key=lambda t: t["name"])
    return {"databases": sorted(out.values(), key=lambda d: d["name"])}


def stats(cat):
    dbs = (cat or {}).get("databases", [])
    tables = [t for d in dbs for t in d.get("tables", [])]
    return {"databases": len(dbs), "tables": len(tables),
            "columns": sum(len(t.get("columns", [])) for t in tables),
            "pii_tables": sum(1 for t in tables if any(c.get("pii") for c in t.get("columns", []) + t.get("partition_keys", []))),
            "formats": sorted({t.get("format") or "—" for t in tables})}


def _tf_id(s):
    return re.sub(r"[^a-z0-9_]", "_", str(s).lower()).strip("_") or "x"


def _hcl_str(s):
    return json.dumps(str(s or ""), ensure_ascii=False)


PARQUET_SERDE = [
    '    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"',
    '    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"',
    "    ser_de_info {",
    '      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"',
    "    }",
]


def _tf_database(d, did, catalog_id):
    lines = [f'resource "aws_glue_catalog_database" "{did}" {{', f'  name        = {_hcl_str(d["name"])}']
    if d.get("description"):
        lines.append(f'  description = {_hcl_str(d["description"])}')
    if d.get("location"):
        lines.append(f'  location_uri = {_hcl_str(d["location"])}')
    if catalog_id:
        lines.append(f'  catalog_id  = {_hcl_str(catalog_id)}')
    return "\n".join(lines + ["}"]) + "\n"


def _tf_column_block(block, c, indent):
    pad = " " * indent
    lines = [f"{pad}{block} {{", f"{pad}  name = {_hcl_str(c['name'])}", f"{pad}  type = {_hcl_str(c['type'])}"]
    if c.get("comment"):
        lines.append(f"{pad}  comment = {_hcl_str(c['comment'])}")
    return lines + [f"{pad}}}"]


def _tf_parameters(t):
    params = {k: v for k, v in (t.get("parameters") or {}).items()
              if k not in ("metadata_location", "previous_metadata_location")}
    if t.get("classification"):
        params.setdefault("classification", t["classification"])
    if t.get("sensitivity"):
        params["data_sensitivity"] = t["sensitivity"]
    if not params:
        return []
    return ["  parameters = {"] + [f"    {_hcl_str(k)} = {_hcl_str(v)}" for k, v in sorted(params.items())] + ["  }"]


def _tf_table(t, db_name, did):
    iceberg = t.get("format") == ICEBERG
    tid = _tf_id(db_name + "_" + t["name"])
    lines = [f'resource "aws_glue_catalog_table" "{tid}" {{',
             f'  name          = {_hcl_str(t["name"])}',
             f'  database_name = aws_glue_catalog_database.{did}.name']
    for key in ("description", "owner"):
        if t.get(key):
            lines.append(f"  {key.ljust(13)} = {_hcl_str(t[key])}")
    lines.append(f'  table_type    = {_hcl_str(t.get("table_type") or "EXTERNAL_TABLE")}')
    if iceberg:
        lines += ["  open_table_format_input {", "    iceberg_input {", '      metadata_operation = "CREATE"', "    }", "  }"]
    else:
        lines += _tf_parameters(t)
    for pk in t.get("partition_keys", []):
        lines += _tf_column_block("partition_keys", pk, 2)
    lines.append("  storage_descriptor {")
    if t.get("location"):
        lines.append(f'    location = {_hcl_str(t["location"])}')
    if "Parquet" in (t.get("format") or ""):
        lines += PARQUET_SERDE
    for c in t.get("columns", []):
        lines += _tf_column_block("columns", c, 4)
    return "\n".join(lines + ["  }", "}"]) + "\n"


def terraform(cat, catalog_id=None):
    out = []
    for d in (cat or {}).get("databases", []):
        did = _tf_id(d["name"])
        out.append(_tf_database(d, did, catalog_id))
        out += [_tf_table(t, d["name"], did) for t in d.get("tables", [])]
    return "\n".join(out)
