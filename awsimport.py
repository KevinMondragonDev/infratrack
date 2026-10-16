"""Arma un diagrama a partir de la salida de la AWS CLI (sólo lectura, sin credenciales en la app).

Comandos (ver scripts/export-aws-network.sh):
  aws ec2 describe-vpcs / describe-subnets / describe-route-tables / describe-internet-gateways /
  describe-nat-gateways / describe-vpc-endpoints / describe-security-groups / describe-network-acls /
  describe-transit-gateways

Se pueden subir los archivos por separado o concatenados. El resultado son nodos con posiciones:
cada VPC es un contenedor con sus subnets en columnas por AZ y filas por tipo (pública/privada/aislada,
deducido de las tablas de rutas), con NAT, endpoints, tablas de rutas, NACL y Security Groups.
"""
import json
import re
import uuid

KEYS = ("Vpcs", "Subnets", "RouteTables", "InternetGateways", "NatGateways", "VpcEndpoints", "SecurityGroups",
        "NetworkAcls", "TransitGateways")
TIERS = ("public", "private", "isolated")
NODE_W, NODE_H, COL_W, GAP = 150, 56, 360, 20
PROTO = {"-1": "all", "6": "tcp", "17": "udp", "1": "icmp", "tcp": "tcp", "udp": "udp", "icmp": "icmp", "all": "all"}


def _id(prefix="n"):
    return prefix + uuid.uuid4().hex[:10]


def _name(obj, fallback):
    for t in obj.get("Tags") or []:
        if t.get("Key") == "Name" and t.get("Value"):
            return str(t["Value"])[:120]
    return fallback


def collect(texts):
    """Junta varias respuestas JSON (archivos separados, concatenados o en lista)."""
    data = {k: [] for k in KEYS}
    dec = json.JSONDecoder()
    for text in texts:
        text = (text or "").strip()
        pos = 0
        while pos < len(text):
            try:
                obj, pos = dec.raw_decode(text, pos)
            except json.JSONDecodeError as exc:
                raise ValueError(f"JSON inválido cerca de la posición {exc.pos}.") from exc
            for item in obj if isinstance(obj, list) else [obj]:
                if isinstance(item, dict):
                    for k in KEYS:
                        data[k] += [x for x in item.get(k) or [] if isinstance(x, dict)]
            while pos < len(text) and text[pos] in " \r\n\t,":
                pos += 1
    if not data["Vpcs"] and not data["Subnets"]:
        raise ValueError("No se encontraron VPCs ni subnets. Sube la salida de `aws ec2 describe-vpcs` y `describe-subnets`.")
    return data


def _route_target(r):
    if r.get("State") == "blackhole":
        return "blackhole", ""
    for key, kind in (("NatGatewayId", "nat"), ("TransitGatewayId", "tgw"), ("VpcPeeringConnectionId", "pcx"),
                      ("NetworkInterfaceId", "eni")):
        if r.get(key):
            return kind, r[key]
    gw = str(r.get("GatewayId") or "")
    if gw == "local":
        return None, ""
    return {"igw": "igw", "vpc": "vpce", "vgw": "vgw"}.get(gw.split("-")[0], "eni" if gw else None), gw


def _routes(rt, pl_names):
    rows = []
    for r in rt.get("Routes") or []:
        kind, target = _route_target(r)
        if not kind:
            continue
        dest = r.get("DestinationCidrBlock") or r.get("DestinationIpv6CidrBlock") or pl_names.get(r.get("DestinationPrefixListId"), r.get("DestinationPrefixListId")) or ""
        rows.append({"destination": dest, "target_type": kind, "target": target})
    return rows


def _tier(rt_rows):
    default = next((r for r in rt_rows if r["destination"] in ("0.0.0.0/0",)), None)
    if not default:
        return "isolated"
    return "public" if default["target_type"] == "igw" else "private"


def _sg_rules(sg, names):
    rows = []
    for direction, key in (("ingress", "IpPermissions"), ("egress", "IpPermissionsEgress")):
        for p in sg.get(key) or []:
            proto = PROTO.get(str(p.get("IpProtocol")), str(p.get("IpProtocol")))
            base = {"direction": direction, "protocol": proto,
                    "from_port": p.get("FromPort") if proto in ("tcp", "udp") else None,
                    "to_port": p.get("ToPort") if proto in ("tcp", "udp") else None}
            peers = [(x.get("CidrIp"), x.get("Description")) for x in p.get("IpRanges") or []]
            peers += [(x.get("CidrIpv6"), x.get("Description")) for x in p.get("Ipv6Ranges") or []]
            peers += [(names.get(x.get("GroupId"), x.get("GroupId")), x.get("Description")) for x in p.get("UserIdGroupPairs") or []]
            peers += [(x.get("PrefixListId"), x.get("Description")) for x in p.get("PrefixListIds") or []]
            rows += [{**base, "peer": peer, "description": (desc or "")[:120]} for peer, desc in peers if peer]
    return rows


def _nacl_rules(acl):
    rows = []
    for e in acl.get("Entries") or []:
        if e.get("RuleNumber") == 32767:
            continue  # deny implícito: InfraTrack ya lo aplica
        pr = e.get("PortRange") or {}
        rows.append({"rule_no": e.get("RuleNumber"), "direction": "egress" if e.get("Egress") else "ingress",
                     "action": e.get("RuleAction", "allow"), "protocol": PROTO.get(str(e.get("Protocol")), "all"),
                     "from_port": pr.get("From"), "to_port": pr.get("To"),
                     "cidr": e.get("CidrBlock") or e.get("Ipv6CidrBlock") or ""})
    return rows


def _node(type_, label, x, y, config=None, w=NODE_W, h=NODE_H, aws_id=None):
    n = {"id": _id(), "type": type_, "label": label, "x": x, "y": y, "w": w, "h": h, "config": config or {},
         "terraformed": False, "status": "Borrador", "notes": [], "questions": []}
    if aws_id:
        n["aws_id"] = aws_id
    return n


class _Builder:
    def __init__(self, data, region):
        self.d, self.region = data, region
        self.nodes, self.edges = [], []
        self.sg_names = {g["GroupId"]: g.get("GroupName") or g["GroupId"] for g in data["SecurityGroups"] if g.get("GroupId")}
        self.pl_names = {}
        for ep in data["VpcEndpoints"]:
            if ep.get("VpcEndpointType") == "Gateway":
                svc = str(ep.get("ServiceName", "")).split(".")[-1]
                for rt in data["RouteTables"]:
                    for r in rt.get("Routes") or []:
                        if r.get("GatewayId") == ep.get("VpcEndpointId") and r.get("DestinationPrefixListId"):
                            self.pl_names[r["DestinationPrefixListId"]] = f"pl-{svc}"

    def rt_for_subnet(self, vpc_id, subnet_id):
        rts = [rt for rt in self.d["RouteTables"] if rt.get("VpcId") == vpc_id]
        for rt in rts:
            if any(a.get("SubnetId") == subnet_id for a in rt.get("Associations") or []):
                return rt, True
        main = next((rt for rt in rts if any(a.get("Main") for a in rt.get("Associations") or [])), None)
        return main, False

    def nacl_for_subnet(self, subnet_id):
        return next((a for a in self.d["NetworkAcls"] if any(x.get("SubnetId") == subnet_id for x in a.get("Associations") or [])), None)

    def build(self, ox, oy):
        y = oy
        vpcs = self.d["Vpcs"] or [{"VpcId": vid} for vid in sorted({s.get("VpcId") for s in self.d["Subnets"]})]
        for vpc in vpcs:
            y += self.build_vpc(vpc, ox, y) + 80
        for i, tgw in enumerate(self.d["TransitGateways"]):
            self.nodes.append(_node("tgw", _name(tgw, tgw.get("TransitGatewayId", "TGW")), ox - 220, oy + i * 90,
                                    aws_id=tgw.get("TransitGatewayId")))
        return {"nodes": self.nodes, "edges": self.edges}

    def subnet_contents(self, vpc_id, sn):
        sid = sn.get("SubnetId")
        items = []
        for nat in self.d["NatGateways"]:
            if nat.get("SubnetId") == sid and nat.get("State", "available") != "deleted":
                items.append(("nat", _name(nat, nat.get("NatGatewayId", "NAT")),
                              {"connectivity": nat.get("ConnectivityType", "public")}, nat.get("NatGatewayId")))
        rt, explicit = self.rt_for_subnet(vpc_id, sid)
        rows = _routes(rt, self.pl_names) if rt else []
        if rt and explicit:
            items.append(("rtb", _name(rt, rt.get("RouteTableId", "Rutas")), {"routes": rows}, rt.get("RouteTableId")))
        acl = self.nacl_for_subnet(sid)
        if acl and not acl.get("IsDefault"):
            items.append(("nacl", _name(acl, acl.get("NetworkAclId", "NACL")),
                          {"kind": "Personalizada (deniega todo lo no permitido)", "rules": _nacl_rules(acl)}, acl.get("NetworkAclId")))
        return items, _tier(rows) if rt else "private"

    def endpoint_homes(self, endpoints, subnet_ids):
        """Subnets de cada endpoint: la primera es donde se dibuja, las demás se conectan como 'desplegado en'."""
        homes = []
        for ep in endpoints:
            targets = [s for s in ep.get("SubnetIds") or [] if s in subnet_ids]
            if not targets and ep.get("VpcEndpointType") == "Gateway":  # el Gateway no vive en subnets
                rts = set(ep.get("RouteTableIds") or [])
                targets = [s for s in subnet_ids if any(a.get("SubnetId") == s and rt.get("RouteTableId") in rts
                                                        for rt in self.d["RouteTables"] for a in rt.get("Associations") or [])]
                targets = targets[:1] or subnet_ids[:1]
            if targets:
                homes.append((ep, targets))
        return homes

    def build_vpc(self, vpc, ox, oy):
        vid = vpc.get("VpcId")
        subnets = [s for s in self.d["Subnets"] if s.get("VpcId") == vid]
        endpoints = [e for e in self.d["VpcEndpoints"] if e.get("VpcId") == vid]
        homes = self.endpoint_homes(endpoints, [s.get("SubnetId") for s in subnets])
        info = []
        for sn in subnets:
            items, tier = self.subnet_contents(vid, sn)
            for ep, targets in homes:
                if targets[0] == sn.get("SubnetId"):
                    svc = str(ep.get("ServiceName", "")).split(".")[-1]
                    items.append(("vpce", f"Endpoint {svc}", {"endpoint_type": ep.get("VpcEndpointType", "Interface"),
                                  "services": [svc], "private_dns": bool(ep.get("PrivateDnsEnabled"))}, ep.get("VpcEndpointId")))
            info.append((sn, items, tier))
        azs = sorted({s.get("AvailabilityZone", "?") for s in subnets}) or ["?"]
        tiers = [t for t in TIERS if any(t == x[2] for x in info)]
        # alto de cada fila: el máximo de nodos de sus subnets
        def sub_h(items):
            return max(150, 60 + ((len(items) + 1) // 2) * (NODE_H + 16) + 20)
        rows = {t: max([sub_h(i) for s, i, tt in info if tt == t] + [150]) for t in tiers}
        positions = {}
        cur_y = oy + 70
        for t in tiers:
            for c, az in enumerate(azs):
                for k, (sn, items, tt) in enumerate([x for x in info if x[2] == t and x[0].get("AvailabilityZone", "?") == az]):
                    positions[sn["SubnetId"]] = (ox + GAP + c * COL_W, cur_y + k * (rows[t] + GAP), rows[t])
            per_cell = max([len([x for x in info if x[2] == t and x[0].get("AvailabilityZone", "?") == az]) for az in azs] + [1])
            cur_y += per_cell * (rows[t] + GAP)
        sgs = [g for g in self.d["SecurityGroups"] if g.get("VpcId") == vid]
        sg_rows = (len(sgs) + 3) // 4
        width = max(len(azs) * COL_W + GAP, 4 * (NODE_W + 20) + 40)
        height = cur_y - oy + (sg_rows * (NODE_H + 16) + 20 if sgs else 0) + 10
        vpc_node = _node("vpc", _name(vpc, vid or "VPC"), ox, oy, {"cidr": vpc.get("CidrBlock", ""), "region": self.region},
                         w=width, h=height, aws_id=vid)
        self.nodes.append(vpc_node)
        for igw in self.d["InternetGateways"]:
            if any(a.get("VpcId") == vid for a in igw.get("Attachments") or []):
                self.nodes.append(_node("igw", _name(igw, "IGW"), ox + width - 140, oy + 8, w=110, h=50,
                                        aws_id=igw.get("InternetGatewayId")))
        main_rt = next((rt for rt in self.d["RouteTables"] if rt.get("VpcId") == vid
                        and any(a.get("Main") for a in rt.get("Associations") or [])), None)
        if main_rt:
            self.nodes.append(_node("rtb", _name(main_rt, "Tabla principal"), ox + width - 320, oy + 8,
                                    {"main": True, "routes": _routes(main_rt, self.pl_names)}, aws_id=main_rt.get("RouteTableId")))
        default_acl = next((a for a in self.d["NetworkAcls"] if a.get("VpcId") == vid and a.get("IsDefault")), None)
        if default_acl:
            self.nodes.append(_node("nacl", _name(default_acl, "NACL por defecto"), ox + width - 500, oy + 8,
                                    {"kind": "Personalizada (deniega todo lo no permitido)", "rules": _nacl_rules(default_acl)},
                                    aws_id=default_acl.get("NetworkAclId")))
        subnet_nodes = {}
        for sn, items, tier in info:
            x, y, h = positions[sn["SubnetId"]]
            node = _node("subnet", _name(sn, sn.get("SubnetId", "Subnet")), x, y,
                         {"tier": tier, "cidr": sn.get("CidrBlock", ""), "az": str(sn.get("AvailabilityZone", ""))[-1:],
                          "map_public_ip": bool(sn.get("MapPublicIpOnLaunch"))}, w=COL_W - GAP, h=h, aws_id=sn.get("SubnetId"))
            self.nodes.append(node)
            subnet_nodes[sn["SubnetId"]] = node
            for i, (typ, label, cfg, aws_id) in enumerate(items):
                self.nodes.append(_node(typ, label, x + 12 + (i % 2) * (NODE_W + 14), y + 50 + (i // 2) * (NODE_H + 16), cfg, aws_id=aws_id))
        self.link_endpoints(homes, subnet_nodes)
        sg_y = cur_y + 10
        for i, g in enumerate(sgs):
            self.nodes.append(_node("sg", g.get("GroupName") or g.get("GroupId"), ox + 20 + (i % 4) * (NODE_W + 20),
                                    sg_y + (i // 4) * (NODE_H + 16),
                                    {"group_name": g.get("GroupName", ""), "description": (g.get("Description") or "")[:200],
                                     "allow_all_egress": False, "rules": _sg_rules(g, self.sg_names)}, aws_id=g.get("GroupId")))
        return height

    def link_endpoints(self, homes, subnet_nodes):
        by_aws = {n.get("aws_id"): n for n in self.nodes if n.get("aws_id")}
        for ep, targets in homes:
            node = by_aws.get(ep.get("VpcEndpointId"))
            for other in targets[1:]:
                if node and other in subnet_nodes:
                    self.edges.append({"id": _id("e"), "source": node["id"], "target": subnet_nodes[other]["id"], "access": None,
                                       "notes": "", "terraformed": False})


def build(texts, region="", origin=(0, 0)):
    data = collect(texts)
    region = region or next((str(s.get("AvailabilityZone", ""))[:-1] for s in data["Subnets"] if s.get("AvailabilityZone")), "")
    result = _Builder(data, region).build(*origin)
    counts = {k: len(v) for k, v in data.items() if v}
    return {**result, "counts": counts, "region": region}


def safe_region(value):
    return value if re.fullmatch(r"[a-z]{2}-[a-z]+-\d", value or "") else ""
