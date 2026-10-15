"""Almacenamiento en archivos JSON (sin base de datos).

data/
  projects/<id>.json      proyecto actual (escritura atómica)
  backups/<id>/<ts>.json  copias automáticas (máx. MAX_BACKUPS por proyecto)
  trash/<id>-<ts>.json    proyectos eliminados (recuperables a mano)
"""
import json
import os
import re
import shutil
import threading
import time
import uuid
from datetime import datetime, timezone

MAX_BACKUPS = 50
BACKUP_EVERY_S = 300
ID_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")


def now_iso():
    return datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds")


class Conflict(Exception):
    pass


class Store:
    def __init__(self, root):
        self.root = os.path.abspath(root)
        self.projects = os.path.join(self.root, "projects")
        self.backups = os.path.join(self.root, "backups")
        self.trash = os.path.join(self.root, "trash")
        for d in (self.projects, self.backups, self.trash):
            os.makedirs(d, exist_ok=True)
        self.lock = threading.Lock()

    def _path(self, pid):
        if not ID_RE.match(pid or ""):
            raise KeyError(pid)
        return os.path.join(self.projects, f"{pid}.json")

    def _write(self, path, data):
        tmp = f"{path}.{uuid.uuid4().hex}.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)

    def list(self):
        out = []
        for fn in os.listdir(self.projects):
            if not fn.endswith(".json"):
                continue
            try:
                with open(os.path.join(self.projects, fn), encoding="utf-8") as fh:
                    p = json.load(fh)
            except (OSError, json.JSONDecodeError):
                continue
            nodes = p.get("nodes", [])
            out.append({"id": p["id"], "name": p.get("name", p["id"]), "updated": p.get("updated"),
                        "nodes": len(nodes), "terraformed": sum(1 for n in nodes if n.get("terraformed"))})
        return sorted(out, key=lambda x: x.get("updated") or "", reverse=True)

    def get(self, pid):
        path = self._path(pid)
        if not os.path.exists(path):
            raise KeyError(pid)
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    def create(self, name, template=None):
        pid = uuid.uuid4().hex[:10]
        p = template or {}
        p.update({
            "id": pid, "name": name or p.get("name") or "Nuevo proyecto", "created": now_iso(), "updated": now_iso(), "rev": 1,
        })
        p.setdefault("description", "")
        p.setdefault("settings", {"region": "us-east-1", "account_id": "", "environment": "dev", "prefix": ""})
        p.setdefault("nodes", [])
        p.setdefault("edges", [])
        p.setdefault("dismissed", {})
        with self.lock:
            self._write(self._path(pid), p)
        return p

    def save(self, pid, data, force=False):
        path = self._path(pid)
        with self.lock:
            current = None
            if os.path.exists(path):
                with open(path, encoding="utf-8") as fh:
                    current = json.load(fh)
            if current and not force and data.get("rev") is not None and data["rev"] != current.get("rev"):
                raise Conflict(current.get("rev"))
            if current:
                self._maybe_backup(pid, current)
            data["id"] = pid
            data["rev"] = (current or {}).get("rev", 0) + 1
            data["updated"] = now_iso()
            data.setdefault("created", (current or {}).get("created", now_iso()))
            self._write(path, data)
            return data

    def _maybe_backup(self, pid, current):
        d = os.path.join(self.backups, pid)
        os.makedirs(d, exist_ok=True)
        files = sorted(f for f in os.listdir(d) if f.endswith(".json"))
        if files:
            last = os.path.getmtime(os.path.join(d, files[-1]))
            if time.time() - last < BACKUP_EVERY_S:
                return
        ts = datetime.now().strftime("%Y%m%d-%H%M%S")
        self._write(os.path.join(d, f"{ts}.json"), current)
        files = sorted(f for f in os.listdir(d) if f.endswith(".json"))
        for old in files[:-MAX_BACKUPS]:
            os.remove(os.path.join(d, old))

    def list_backups(self, pid):
        self._path(pid)
        d = os.path.join(self.backups, pid)
        if not os.path.isdir(d):
            return []
        out = []
        for f in sorted(os.listdir(d), reverse=True):
            if f.endswith(".json"):
                out.append({"id": f[:-5], "size": os.path.getsize(os.path.join(d, f))})
        return out

    def restore_backup(self, pid, bid):
        if not re.match(r"^\d{8}-\d{6}$", bid or ""):
            raise KeyError(bid)
        path = os.path.join(self.backups, pid, f"{bid}.json")
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return self.save(pid, data, force=True)

    def delete(self, pid):
        path = self._path(pid)
        with self.lock:
            if not os.path.exists(path):
                raise KeyError(pid)
            ts = datetime.now().strftime("%Y%m%d-%H%M%S")
            shutil.move(path, os.path.join(self.trash, f"{pid}-{ts}.json"))
