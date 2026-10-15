"""Catálogo de componentes AWS y los formularios de configuración de cada uno.

Cada componente define:
  - category / abbr / color: cómo se dibuja en el lienzo.
  - container: True para VPC y Subnet (pueden contener otros componentes).
  - vpc: "required" (debe vivir en una subnet), "optional" (puede o no) o "never"
    (servicio regional/global que no vive dentro de la VPC).
  - principal: servicio que asume el rol IAM del componente (si ejecuta código/llamadas).
  - fields: formulario de configuración. Tipos: text, number, select, multiselect,
    bool, textarea, cidr. `show_if` muestra el campo sólo si otro campo tiene
    alguno de los valores indicados. `required` lo cuenta para el % de completitud.
"""

CATEGORIES = [
    {"id": "network", "name": "Redes y entrega", "color": "#8C4FFF"},
    {"id": "compute", "name": "Cómputo y contenedores", "color": "#ED7100"},
    {"id": "storage", "name": "Almacenamiento", "color": "#3F8624"},
    {"id": "database", "name": "Bases de datos", "color": "#C925D1"},
    {"id": "analytics", "name": "Analítica y datos", "color": "#01A88D"},
    {"id": "integration", "name": "Integración y mensajería", "color": "#E7157B"},
    {"id": "security", "name": "Seguridad e identidad", "color": "#DD344C"},
    {"id": "management", "name": "Operación y monitoreo", "color": "#B0084D"},
    {"id": "governance", "name": "Cuentas y gobierno", "color": "#D45B07"},
    {"id": "enduser", "name": "Escritorios y usuario final", "color": "#7D8998"},
    {"id": "external", "name": "Externos", "color": "#5F6B7A"},
]


def F(key, label, type="text", **kw):
    d = {"key": key, "label": label, "type": type}
    d.update(kw)
    return d


def sel(key, label, options, **kw):
    return F(key, label, "select", options=options, **kw)


def ms(key, label, options, **kw):
    return F(key, label, "multiselect", options=options, **kw)


def b(key, label, default=False, **kw):
    return F(key, label, "bool", default=default, **kw)


def num(key, label, **kw):
    return F(key, label, "number", **kw)


def ta(key, label, **kw):
    return F(key, label, "textarea", **kw)


AZS = ["a", "b", "c", "d", "e", "f"]
TABLE_FORMATS = ["Ninguno (archivos)", "Apache Iceberg", "S3 Tables (Iceberg administrado)",
                 "Hive (tablas Glue clásicas)", "Delta Lake", "Apache Hudi"]
OPEN_TABLE_FORMATS = ["Apache Iceberg", "S3 Tables (Iceberg administrado)", "Delta Lake", "Apache Hudi"]
ICEBERG = ["Apache Iceberg", "S3 Tables (Iceberg administrado)"]

COMPONENTS = []


def C(id, name, category, abbr, fields=None, **kw):
    comp = {
        "id": id, "name": name, "category": category, "abbr": abbr,
        "container": False, "vpc": "never", "principal": None,
        "terraformable": True, "fields": fields or [],
    }
    comp.update(kw)
    COMPONENTS.append(comp)
    return comp


# ───────────────────────────── Redes ─────────────────────────────
C("vpc", "VPC", "network", "VPC", container=True, desc="Red virtual aislada. Arrastra subnets dentro.", fields=[
    F("cidr", "CIDR IPv4", "cidr", required=True, placeholder="10.0.0.0/16",
      help="Entre /16 y /28. No debe traslaparse con otras VPC ni con on-premise si vas a conectarlas."),
    F("region", "Región", placeholder="us-east-1"),
    b("dns_hostnames", "DNS hostnames habilitado", True, help="Necesario para endpoints de interfaz con DNS privado."),
    b("dns_support", "DNS support habilitado", True),
    b("ipv6", "IPv6 habilitado"),
    b("flow_logs", "VPC Flow Logs", False, required=True),
    sel("flow_logs_dest", "Destino de Flow Logs", ["CloudWatch Logs", "S3", "Firehose"], show_if={"flow_logs": [True]}),
    sel("tenancy", "Tenancy", ["default", "dedicated"], default="default"),
])
C("subnet", "Subnet", "network", "SN", container=True, vpc="required",
  desc="Subnet pública, privada o aislada. Debe ir dentro de una VPC.", fields=[
    sel("tier", "Tipo de subnet", ["public", "private", "isolated"], default="private", required=True,
        help="public: ruta 0.0.0.0/0 al IGW. private: salida por NAT. isolated: sin salida a internet."),
    F("cidr", "CIDR", "cidr", required=True, placeholder="10.0.1.0/24"),
    sel("az", "Zona de disponibilidad", AZS, required=True),
    b("map_public_ip", "Asignar IP pública automáticamente", show_if={"tier": ["public"]}),
    b("custom_nacl", "NACL personalizada"),
    ta("routes", "Tabla de rutas (notas)", placeholder="0.0.0.0/0 -> nat-gw-a\npl-s3 -> vpce-s3"),
])
C("igw", "Internet Gateway", "network", "IGW", vpc="vpc",
  desc="Salida/entrada a internet para subnets públicas. Colócalo dentro de la VPC (fuera de subnets).", fields=[
    b("egress_only_ipv6", "Egress-only IGW para IPv6"),
])
C("nat", "NAT Gateway", "network", "NAT", vpc="required",
  desc="Salida a internet para subnets privadas. Debe estar en una subnet pública.", fields=[
    sel("connectivity", "Conectividad", ["public", "private"], default="public", required=True),
    sel("ha", "Estrategia HA", ["Uno por AZ (recomendado prod)", "Uno compartido (ahorro)", "Regional NAT"], required=True),
    b("eip", "Elastic IP asignada", True, show_if={"connectivity": ["public"]}),
])
C("vpce", "VPC Endpoint", "network", "VPCE", vpc="required",
  desc="Acceso privado a servicios AWS sin NAT. Gateway (S3/DynamoDB, gratis) o Interface (PrivateLink).", fields=[
    sel("endpoint_type", "Tipo", ["Gateway", "Interface"], required=True),
    ms("services", "Servicios", ["s3", "dynamodb", "ecr.api", "ecr.dkr", "logs", "monitoring", "secretsmanager",
                                 "ssm", "ssmmessages", "ec2messages", "sts", "kms", "sqs", "sns", "events",
                                 "glue", "athena", "execute-api", "kinesis-streams", "firehose", "lambda",
                                 "states", "emr-serverless", "elasticmapreduce", "rds", "redshift-data",
                                 "airflow.api", "airflow.env", "s3tables", "lakeformation"], required=True),
    b("private_dns", "DNS privado habilitado", True, show_if={"endpoint_type": ["Interface"]}),
    ta("policy", "Endpoint policy (notas)"),
])
C("tgw", "Transit Gateway", "network", "TGW", desc="Hub para conectar VPCs y on-premise.", fields=[
    F("asn", "ASN de Amazon", placeholder="64512"),
    b("default_rt_assoc", "Asociación a tabla de rutas por defecto", True),
    b("ram_share", "Compartido por RAM con otras cuentas"),
    ta("route_tables", "Tablas de rutas / segmentación"),
])
C("peering", "VPC Peering", "network", "PCX", desc="Conexión 1:1 entre dos VPC (sin transitividad).", fields=[
    b("cross_account", "Entre cuentas"),
    b("cross_region", "Entre regiones"),
    b("dns_resolution", "Resolución DNS remota", True),
])
C("alb", "Application Load Balancer", "network", "ALB", vpc="required",
  desc="Balanceador L7 (HTTP/HTTPS). Requiere subnets en al menos 2 AZ.", fields=[
    sel("scheme", "Esquema", ["internet-facing", "internal"], required=True),
    ms("listeners", "Listeners", ["HTTP:80", "HTTPS:443", "HTTP:8080"], required=True),
    b("https_redirect", "Redirigir HTTP a HTTPS", True),
    F("certificate", "Certificado ACM", placeholder="arn:aws:acm:...", show_if={"listeners": ["HTTPS:443"]}),
    sel("target_type", "Tipo de target", ["instance", "ip", "lambda"], required=True),
    F("health_check", "Health check path", placeholder="/health"),
    b("waf", "WAF asociado"),
    b("access_logs", "Access logs a S3"),
    b("deletion_protection", "Protección contra borrado", True),
    num("idle_timeout", "Idle timeout (s)", default=60),
    sel("tls_policy", "Política TLS", ["ELBSecurityPolicy-TLS13-1-2-2021-06", "ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
                                       "ELBSecurityPolicy-2016-08 (legado)"]),
])
C("nlb", "Network Load Balancer", "network", "NLB", vpc="required",
  desc="Balanceador L4 (TCP/UDP/TLS), IP estática, PrivateLink.", fields=[
    sel("scheme", "Esquema", ["internet-facing", "internal"], required=True),
    sel("protocol", "Protocolo", ["TCP", "TLS", "UDP", "TCP_UDP"], required=True),
    num("port", "Puerto del listener", required=True),
    sel("target_type", "Tipo de target", ["instance", "ip", "alb"]),
    b("cross_zone", "Cross-zone load balancing"),
    b("static_eip", "Elastic IPs estáticas", show_if={"scheme": ["internet-facing"]}),
    b("security_groups", "Con Security Groups", True),
    b("privatelink", "Expuesto como servicio PrivateLink"),
])
C("apigw", "API Gateway", "network", "APIGW", principal="apigateway.amazonaws.com",
  desc="API administrada (REST, HTTP o WebSocket).", fields=[
    sel("api_type", "Tipo de API", ["HTTP API", "REST API", "WebSocket"], required=True),
    sel("endpoint_type", "Endpoint", ["Regional", "Edge-optimized", "Private"], required=True,
        show_if={"api_type": ["REST API"]}),
    sel("auth", "Autorización", ["IAM (SigV4)", "Cognito", "Lambda authorizer", "JWT authorizer", "API Key + Usage plan", "Ninguna"],
        required=True),
    num("throttle_rps", "Throttling (req/s)"),
    num("throttle_burst", "Burst"),
    b("waf", "WAF asociado", show_if={"api_type": ["REST API"]}),
    b("vpc_link", "VPC Link a backend privado"),
    F("custom_domain", "Dominio personalizado"),
    b("access_logs", "Access logs", True),
    b("cache", "Caché de API", show_if={"api_type": ["REST API"]}),
])
C("cloudfront", "CloudFront", "network", "CF", desc="CDN global.", fields=[
    ms("origins", "Orígenes", ["S3", "ALB", "API Gateway", "Lambda URL", "Custom/HTTP"], required=True),
    b("oac", "Origin Access Control (OAC) para S3", True, show_if={"origins": ["S3"]}),
    sel("viewer_protocol", "Viewer protocol", ["redirect-to-https", "https-only", "allow-all"], default="redirect-to-https"),
    sel("price_class", "Price class", ["PriceClass_100", "PriceClass_200", "PriceClass_All"]),
    b("waf", "WAF (scope CLOUDFRONT)"),
    F("certificate", "Certificado ACM (us-east-1)"),
    sel("min_tls", "TLS mínimo", ["TLSv1.2_2021", "TLSv1.2_2019", "TLSv1"]),
    b("geo_restriction", "Restricción geográfica"),
    b("logging", "Logs estándar/tiempo real"),
])
C("route53", "Route 53", "network", "R53", desc="DNS administrado.", fields=[
    sel("zone_type", "Tipo de zona", ["public", "private"], required=True),
    F("domain", "Dominio", required=True, placeholder="ejemplo.com"),
    sel("routing", "Política de ruteo", ["simple", "weighted", "latency", "failover", "geolocation", "multivalue"]),
    b("health_checks", "Health checks"),
    b("dnssec", "DNSSEC"),
    b("resolver_endpoints", "Resolver endpoints (híbrido)"),
])
C("waf", "AWS WAF", "network", "WAF", desc="Firewall de aplicaciones web (L7).", fields=[
    sel("scope", "Scope", ["REGIONAL", "CLOUDFRONT"], required=True),
    ms("managed_rules", "Reglas administradas", ["AWSManagedRulesCommonRuleSet", "AWSManagedRulesKnownBadInputsRuleSet",
                                                "AWSManagedRulesSQLiRuleSet", "AWSManagedRulesAmazonIpReputationList",
                                                "AWSManagedRulesBotControlRuleSet", "AWSManagedRulesATPRuleSet"]),
    num("rate_limit", "Rate limit (req / 5 min por IP)"),
    b("logging", "Logging habilitado", True),
    sel("default_action", "Acción por defecto", ["Allow", "Block"]),
])
C("netfw", "Network Firewall", "network", "NFW", vpc="required",
  desc="Firewall administrado stateful para inspección de tráfico (egress/ingress/east-west).", fields=[
    sel("mode", "Uso", ["Egress filtering", "Ingress inspection", "East-west", "Centralizado (inspection VPC)"], required=True),
    ta("domain_allowlist", "Allowlist de dominios (egress)", placeholder=".amazonaws.com\n.github.com"),
    ta("stateful_rules", "Reglas stateful (Suricata / notas)"),
    b("tls_inspection", "Inspección TLS"),
    b("logging", "Alert/flow logs", True),
])
C("dnsfw", "Route 53 DNS Firewall", "network", "DNSFW",
  desc="Filtra resoluciones DNS salientes desde la VPC.", fields=[
    ta("blocked_domains", "Dominios bloqueados"),
    ta("allowed_domains", "Dominios permitidos"),
    b("managed_lists", "Listas administradas AWS (malware, botnets)", True),
])
C("vpn", "VPN (Site-to-Site / Client)", "network", "VPN",
  desc="Túnel IPsec hacia on-premise o acceso de usuarios por Client VPN.", fields=[
    sel("conn_type", "Tipo", ["Site-to-Site VPN", "Accelerated Site-to-Site VPN", "Client VPN"], required=True),
    sel("attach", "Terminación", ["Virtual Private Gateway", "Transit Gateway", "Cloud WAN"], required=True),
    F("onprem_cidrs", "CIDR on-premise / clientes", "cidr", placeholder="192.168.0.0/16"),
    sel("routing", "Ruteo", ["BGP dinámico", "Estático"]),
    b("two_tunnels", "Dos túneles activos (HA)", True),
    F("bandwidth", "Ancho de banda", placeholder="1.25 Gbps por túnel"),
    sel("client_auth", "Autenticación Client VPN", ["Mutual TLS (certificados)", "SAML / IAM Identity Center", "Active Directory"],
        show_if={"conn_type": ["Client VPN"]}),
])
C("dx", "Direct Connect", "network", "DX",
  desc="Enlace dedicado a AWS desde tu centro de datos (latencia y ancho de banda estables).", fields=[
    sel("conn_type", "Tipo de conexión", ["Dedicada", "Hosted (vía partner)"], required=True),
    sel("speed", "Velocidad", ["50 Mbps", "100 Mbps", "500 Mbps", "1 Gbps", "10 Gbps", "100 Gbps", "400 Gbps"], required=True),
    F("location", "Ubicación DX", placeholder="Equinix DA2"),
    ms("vif", "Virtual interfaces", ["Private VIF", "Transit VIF", "Public VIF"], required=True),
    sel("gateway", "Gateway", ["Direct Connect Gateway", "Virtual Private Gateway"], required=True),
    sel("redundancy", "Resiliencia", ["Una conexión (sin SLA)", "Alta (2 conexiones, 2 dispositivos, 1 ubicación)",
                                     "Máxima (2 ubicaciones x 2 conexiones)"], required=True),
    b("vpn_backup", "VPN como respaldo"),
    b("macsec", "Cifrado MACsec", help="Disponible en conexiones dedicadas de 10/100/400 Gbps."),
    F("asn", "ASN BGP on-premise", placeholder="65000"),
    F("onprem_cidrs", "CIDR on-premise", "cidr", placeholder="192.168.0.0/16"),
])
C("globalaccel", "Global Accelerator", "network", "GA",
  desc="IPs anycast estáticas y enrutamiento por la red global de AWS hacia ALB/NLB/EC2 en una o varias regiones.", fields=[
    sel("type", "Tipo", ["Standard", "Custom routing"], required=True),
    sel("ip_type", "Direcciones IP", ["IPv4", "Dual-stack"], default="IPv4"),
    ms("listeners", "Listeners", ["TCP:80", "TCP:443", "UDP:53", "UDP:443", "Otro"], required=True),
    F("regions", "Regiones de los endpoint groups", required=True, placeholder="us-east-1, eu-west-1"),
    num("traffic_dial", "Traffic dial (%)", default=100),
    sel("affinity", "Afinidad de cliente", ["NONE", "SOURCE_IP"], default="NONE"),
    b("client_ip_preservation", "Preservar IP del cliente", True),
    b("byoip", "IPs propias (BYOIP)"),
])
C("shield", "AWS Shield", "network", "SHLD", desc="Protección DDoS (Standard es automático; Advanced es de pago).", fields=[
    sel("tier", "Nivel", ["Standard (automático)", "Advanced"], required=True),
    ms("protected", "Recursos protegidos", ["CloudFront", "Route 53", "ALB", "NLB / EIP", "Global Accelerator"],
       show_if={"tier": ["Advanced"]}),
    b("auto_l7", "Mitigación automática de capa 7 (con WAF)", show_if={"tier": ["Advanced"]}),
    b("srt_access", "Acceso del Shield Response Team (SRT)", show_if={"tier": ["Advanced"]}),
    b("proactive", "Proactive engagement", show_if={"tier": ["Advanced"]}),
    b("health_checks", "Health checks de Route 53 para detección", show_if={"tier": ["Advanced"]}),
])
C("sg", "Security Group", "network", "SG", vpc="vpc",
  desc="Firewall stateful por recurso. Colócalo dentro de la VPC y conéctalo a los componentes que lo usan.", fields=[
    F("group_name", "Nombre del SG", required=True, placeholder="sg-app"),
    F("description", "Descripción", placeholder="Tráfico de la capa de aplicación"),
    b("allow_all_egress", "Permitir toda la salida (0.0.0.0/0)", True,
      help="Comportamiento por defecto de AWS. Desmárcalo para declarar cada regla de salida."),
    F("rules", "Reglas", "rules", columns=[
        {"key": "direction", "label": "Dir.", "type": "select", "options": ["ingress", "egress"]},
        {"key": "protocol", "label": "Proto", "type": "select", "options": ["tcp", "udp", "icmp", "all"]},
        {"key": "from_port", "label": "Desde", "type": "number"},
        {"key": "to_port", "label": "Hasta", "type": "number"},
        {"key": "peer", "label": "Origen / destino", "type": "text", "placeholder": "sg-app · 10.0.0.0/16 · pl-s3"},
        {"key": "description", "label": "Descripción", "type": "text"},
    ], help="Origen/destino: nombre de otro SG, un CIDR o un prefix list. Puertos vacíos = todos."),
])
C("nacl", "Network ACL", "network", "NACL", vpc="vpc",
  desc="Firewall stateless por subnet. Colócala dentro de la subnet que protege (fuera de subnets = NACL por defecto de la VPC).",
  fields=[
    sel("kind", "Tipo", ["Personalizada (deniega todo lo no permitido)", "Default (permite todo)"], required=True,
        default="Personalizada (deniega todo lo no permitido)"),
    F("rules", "Reglas (se evalúan por número, la primera que coincide gana)", "rules", columns=[
        {"key": "rule_no", "label": "#", "type": "number"},
        {"key": "direction", "label": "Dir.", "type": "select", "options": ["ingress", "egress"]},
        {"key": "action", "label": "Acción", "type": "select", "options": ["allow", "deny"]},
        {"key": "protocol", "label": "Proto", "type": "select", "options": ["tcp", "udp", "icmp", "all"]},
        {"key": "from_port", "label": "Desde", "type": "number"},
        {"key": "to_port", "label": "Hasta", "type": "number"},
        {"key": "cidr", "label": "CIDR", "type": "text", "placeholder": "0.0.0.0/0"},
    ], help="Recuerda: son stateless. Las respuestas necesitan puertos efímeros 1024-65535 en la dirección contraria."),
])
C("rtb", "Route Table", "network", "RTB", vpc="vpc",
  desc="Tabla de rutas. Dentro de una subnet = asociada a ella; dentro de la VPC (fuera de subnets) = tabla principal.",
  fields=[
    b("main", "Tabla principal de la VPC"),
    b("propagation", "Propagación de rutas desde VGW"),
    F("routes", "Rutas", "rules", columns=[
        {"key": "destination", "label": "Destino", "type": "text", "placeholder": "0.0.0.0/0 · 10.1.0.0/16 · pl-s3"},
        {"key": "target_type", "label": "Target", "type": "select",
         "options": ["igw", "nat", "vpce", "tgw", "pcx", "vgw", "nfw", "eni", "blackhole"]},
        {"key": "target", "label": "Nombre del target", "type": "text", "placeholder": "nat-a"},
    ], help="La ruta 'local' de la VPC siempre existe; no hace falta agregarla."),
])

# ───────────────────────────── Cómputo ─────────────────────────────
C("ec2", "EC2", "compute", "EC2", vpc="required", principal="ec2.amazonaws.com", desc="Instancias virtuales.", fields=[
    F("instance_type", "Tipo de instancia", required=True, placeholder="m7g.large"),
    sel("os", "Sistema operativo / AMI", ["Amazon Linux 2023", "Ubuntu 24.04", "RHEL 9", "Windows Server 2022", "AMI propia"],
        required=True),
    num("count", "Cantidad de instancias", default=1, required=True),
    sel("purchase", "Modelo de compra", ["On-Demand", "Spot", "Reserved", "Savings Plan"]),
    num("ebs_size", "EBS raíz (GiB)", default=30),
    sel("ebs_type", "Tipo de EBS", ["gp3", "gp2", "io2", "st1"], default="gp3"),
    b("ebs_encrypted", "EBS cifrado", True, required=True),
    b("imdsv2", "IMDSv2 obligatorio", True, required=True),
    b("public_ip", "IP pública"),
    sel("access", "Acceso administrativo", ["SSM Session Manager", "EC2 Instance Connect", "SSH vía bastion", "SSH directo"],
        required=True),
    b("backup", "AWS Backup / snapshots"),
    num("port", "Puerto de la aplicación", placeholder="8080"),
    ta("user_data", "User data / bootstrap (notas)"),
])
C("asg", "Auto Scaling Group", "compute", "ASG", vpc="required", principal="ec2.amazonaws.com",
  desc="Flota de EC2 con escalamiento automático.", fields=[
    F("instance_type", "Tipo(s) de instancia", required=True, placeholder="m7g.large, m6g.large"),
    num("min", "Mínimo", default=2, required=True),
    num("desired", "Deseado", default=2),
    num("max", "Máximo", default=4, required=True),
    sel("scaling_policy", "Política de escalamiento", ["Target tracking CPU", "Target tracking ALB requests", "Step scaling",
                                                       "Scheduled", "Predictive"], required=True),
    sel("health_check", "Health check", ["ELB", "EC2"], default="ELB"),
    num("spot_pct", "% Spot (mixed instances)", default=0),
    b("imdsv2", "IMDSv2 obligatorio", True),
    b("ebs_encrypted", "EBS cifrado", True),
    num("port", "Puerto de la aplicación", placeholder="8080"),
    b("instance_refresh", "Instance refresh en despliegues", True),
])
C("lambda", "Lambda", "compute", "λ", vpc="optional", principal="lambda.amazonaws.com", desc="Funciones serverless.", fields=[
    sel("runtime", "Runtime", ["python3.13", "python3.12", "nodejs22.x", "nodejs20.x", "java21", "dotnet8",
                               "provided.al2023 (Go/Rust)", "Imagen de contenedor"], required=True),
    num("memory", "Memoria (MB)", default=512, required=True),
    num("timeout", "Timeout (s)", default=30, required=True, help="Máximo 900 s."),
    sel("arch", "Arquitectura", ["arm64", "x86_64"], default="arm64"),
    sel("trigger", "Disparador principal", ["API Gateway", "ALB", "S3", "SQS", "SNS", "EventBridge", "Kinesis/DynamoDB Streams",
                                            "Step Functions", "Function URL", "Manual/SDK"]),
    num("reserved_concurrency", "Concurrencia reservada"),
    num("provisioned_concurrency", "Concurrencia aprovisionada"),
    b("dlq", "DLQ / on-failure destination"),
    num("ephemeral", "Almacenamiento /tmp (MB)", default=512),
    b("secrets_from_sm", "Lee secretos de Secrets Manager / Parameter Store"),
    b("xray", "X-Ray tracing"),
    ta("env_vars", "Variables de entorno (sin secretos)"),
])
C("ecs", "ECS / Fargate", "compute", "ECS", vpc="required", principal="ecs-tasks.amazonaws.com",
  desc="Servicio de contenedores.", fields=[
    sel("launch_type", "Launch type", ["Fargate", "Fargate Spot", "EC2", "ECS Managed Instances"], required=True),
    num("cpu", "CPU (unidades)", default=512, required=True),
    num("memory", "Memoria (MiB)", default=1024, required=True),
    num("desired", "Tareas deseadas", default=2, required=True),
    b("autoscaling", "Service auto scaling"),
    num("port", "Puerto del contenedor", placeholder="8080", required=True),
    sel("image_source", "Origen de imagen", ["ECR", "Docker Hub / público", "Otro registry"], required=True),
    sel("discovery", "Descubrimiento de servicios", ["Ninguno", "Service Connect", "Cloud Map"]),
    sel("logging", "Logging", ["awslogs (CloudWatch)", "FireLens"], default="awslogs (CloudWatch)"),
    b("exec", "ECS Exec habilitado"),
    b("public_ip", "IP pública en la tarea"),
    sel("deploy", "Despliegue", ["Rolling", "Blue/Green (CodeDeploy)", "Blue/Green nativo ECS"]),
])
C("eks", "EKS", "compute", "EKS", vpc="required", principal="pods.eks.amazonaws.com",
  desc="Kubernetes administrado.", fields=[
    F("version", "Versión de Kubernetes", required=True, placeholder="1.33"),
    sel("compute", "Cómputo de nodos", ["EKS Auto Mode", "Managed node groups", "Karpenter", "Fargate profiles"], required=True),
    F("instance_types", "Tipos de instancia", placeholder="m7g.large"),
    sel("endpoint_access", "Acceso al API server", ["Privado", "Público + privado", "Público"], required=True),
    sel("pod_iam", "IAM para pods", ["EKS Pod Identity", "IRSA (OIDC)", "Rol del nodo (no recomendado)"], required=True),
    ms("addons", "Add-ons", ["vpc-cni", "coredns", "kube-proxy", "aws-ebs-csi-driver", "aws-efs-csi-driver",
                             "aws-load-balancer-controller", "external-dns", "metrics-server", "cluster-autoscaler",
                             "karpenter", "cert-manager", "external-secrets"]),
    b("secrets_kms", "Cifrado de secrets con KMS", True),
    b("control_plane_logs", "Logs del control plane"),
    sel("access_mgmt", "Gestión de acceso", ["Access entries (API)", "aws-auth ConfigMap", "Ambos"]),
])
C("stepfn", "Step Functions", "compute", "SFN", principal="states.amazonaws.com", desc="Orquestación de flujos.", fields=[
    sel("type", "Tipo", ["Standard", "Express"], required=True),
    sel("logging", "Nivel de logging", ["OFF", "ERROR", "ALL"]),
    b("xray", "X-Ray tracing"),
    ta("states", "Estados / integraciones principales"),
])
C("batch", "AWS Batch", "compute", "BATCH", vpc="required", principal="ecs-tasks.amazonaws.com",
  desc="Jobs por lotes en contenedores (Fargate, EC2 o EKS) con colas y prioridades.", fields=[
    sel("compute", "Compute environment", ["Fargate", "Fargate Spot", "EC2 On-Demand", "EC2 Spot", "EKS"], required=True),
    num("min_vcpu", "vCPU mínimos", default=0),
    num("max_vcpu", "vCPU máximos", required=True),
    F("instance_types", "Tipos de instancia", placeholder="optimal · c7g, m7g", show_if={"compute": ["EC2 On-Demand", "EC2 Spot"]}),
    sel("allocation", "Estrategia de asignación", ["BEST_FIT_PROGRESSIVE", "SPOT_CAPACITY_OPTIMIZED", "SPOT_PRICE_CAPACITY_OPTIMIZED", "BEST_FIT"],
        show_if={"compute": ["EC2 On-Demand", "EC2 Spot"]}),
    ta("queues", "Job queues y prioridades", placeholder="alta (prio 100) → CE spot, CE on-demand\nbaja (prio 10)"),
    sel("scheduling", "Política de scheduling", ["FIFO", "Fair share"]),
    F("image", "Imagen del job", placeholder="<cuenta>.dkr.ecr.<región>.amazonaws.com/etl:1.4"),
    num("job_vcpu", "vCPU por job"),
    num("job_memory", "Memoria por job (MiB)"),
    num("retries", "Reintentos (1-10)"),
    num("timeout", "Timeout por job (s)"),
    b("array_jobs", "Array jobs"),
    sel("image_source", "Origen de imagen", ["ECR", "Docker Hub / público", "Otro registry"], default="ECR"),
    sel("trigger", "Disparador", ["EventBridge Scheduler", "Step Functions", "MWAA", "Manual/SDK"]),
])
C("apprunner", "App Runner", "compute", "AR", principal="tasks.apprunner.amazonaws.com",
  desc="Servicio web/API administrado desde imagen o código, con HTTPS y autoescalado incluidos.", fields=[
    sel("source", "Origen", ["Imagen ECR", "Imagen pública", "Repositorio de código"], required=True),
    sel("runtime", "Runtime (si es código)", ["Python 3.11", "Node.js 22", "Java (Corretto 21)", ".NET 8", "Go 1", "PHP 8.1", "Ruby 3.1"],
        show_if={"source": ["Repositorio de código"]}),
    sel("cpu", "CPU", ["0.25 vCPU", "0.5 vCPU", "1 vCPU", "2 vCPU", "4 vCPU"], required=True),
    sel("memory", "Memoria", ["0.5 GB", "1 GB", "2 GB", "3 GB", "4 GB", "6 GB", "8 GB", "10 GB", "12 GB"], required=True),
    num("port", "Puerto", default=8080),
    num("min_instances", "Instancias mínimas", default=1),
    num("max_instances", "Instancias máximas", default=25),
    num("concurrency", "Peticiones concurrentes por instancia", default=100),
    b("vpc_connector", "VPC connector (salida hacia recursos privados)",
      help="Sin él, App Runner no llega a RDS/ElastiCache/etc. en subnets privadas."),
    b("private_endpoint", "Endpoint privado (entrada sólo vía VPC interface endpoint)"),
    b("auto_deploy", "Despliegue automático", True),
    F("health_check", "Health check path", placeholder="/health"),
    F("custom_domain", "Dominio personalizado"),
    b("waf", "WAF asociado"),
    b("observability", "X-Ray / observabilidad"),
])
C("beanstalk", "Elastic Beanstalk", "compute", "EB", vpc="required", principal="ec2.amazonaws.com",
  desc="Plataforma administrada (EC2 + balanceador + autoescalado) para apps web y workers.", fields=[
    sel("platform", "Plataforma", ["Python", "Node.js", "Java SE", "Tomcat", ".NET on Linux", ".NET on Windows (IIS)", "Docker",
                                   "Go", "PHP", "Ruby"], required=True),
    sel("tier", "Tier", ["Web server", "Worker (SQS)"], required=True),
    sel("env_type", "Tipo de entorno", ["Load balanced", "Single instance"], required=True),
    sel("lb_type", "Balanceador", ["Application LB", "Network LB", "ALB compartido", "Classic (legado)"],
        show_if={"env_type": ["Load balanced"]}),
    F("instance_types", "Tipos de instancia", placeholder="t4g.medium"),
    num("min", "Instancias mínimas", default=2, show_if={"env_type": ["Load balanced"]}),
    num("max", "Instancias máximas", default=4, show_if={"env_type": ["Load balanced"]}),
    sel("deploy_policy", "Política de despliegue", ["All at once", "Rolling", "Rolling with additional batch", "Immutable",
                                                    "Traffic splitting", "Blue/Green (swap de URL)"], required=True),
    b("managed_updates", "Actualizaciones administradas de plataforma", True),
    b("enhanced_health", "Enhanced health reporting", True),
    b("log_streaming", "Logs a CloudWatch"),
    b("imdsv2", "IMDSv2 obligatorio", True),
    b("public_instances", "Instancias en subnets públicas"),
    num("port", "Puerto de la aplicación", placeholder="8000"),
])
C("ecr", "ECR", "compute", "ECR", desc="Registro de imágenes de contenedor.", fields=[
    b("scan_on_push", "Escaneo en push (Inspector)", True),
    b("immutable", "Tags inmutables", True),
    ta("lifecycle", "Lifecycle policy", placeholder="Mantener últimas 30 imágenes"),
    sel("encryption", "Cifrado", ["AES256", "KMS"]),
    b("replication", "Replicación cross-region"),
])

# ───────────────────────────── Almacenamiento ─────────────────────────────
C("s3", "S3", "storage", "S3", desc="Almacenamiento de objetos / data lake.", fields=[
    F("bucket_name", "Nombre del bucket", placeholder="empresa-raw-prod"),
    sel("purpose", "Uso del bucket", ["Data lake - raw/landing", "Data lake - curated/silver", "Data lake - analytics/gold",
                                      "Logs", "Sitio estático", "Artefactos / código", "Backups", "Intercambio con terceros",
                                      "Resultados de Athena", "General"], required=True),
    sel("table_format", "Formato de tablas", TABLE_FORMATS, required=True,
        help="Iceberg permite ACID, time travel, schema evolution y updates/deletes. Hive es la tabla clásica de Glue."),
    sel("file_format", "Formato de archivos", ["Parquet", "ORC", "Avro", "JSON", "CSV", "Mixto / binarios"], required=True),
    sel("catalog", "Catálogo", ["AWS Glue Data Catalog", "S3 Tables catalog", "Hive Metastore externo", "Ninguno"],
        show_if={"table_format": OPEN_TABLE_FORMATS + ["Hive (tablas Glue clásicas)"]}, required=True),
    F("partitioning", "Particionamiento", placeholder="year/month/day  ó  days(event_ts), bucket(16, id)"),
    sel("compaction", "Compactación", ["Glue automatic compaction", "S3 Tables (automático)", "Job EMR/Glue programado",
                                       "Athena OPTIMIZE", "Ninguna"],
        show_if={"table_format": OPEN_TABLE_FORMATS}, required=True),
    num("snapshot_retention_days", "Retención de snapshots (días)", show_if={"table_format": ICEBERG}, required=True,
        help="expire_snapshots / política de mantenimiento: controla time travel y costo."),
    num("retention_days", "¿Cuánto dura la data? (días, vacío = indefinido)", required=True,
        help="Expiración de objetos actuales. Usa 0 para indefinido explícito."),
    sel("storage_class", "Clase de almacenamiento inicial", ["STANDARD", "INTELLIGENT_TIERING", "STANDARD_IA", "ONEZONE_IA",
                                                             "GLACIER_IR", "EXPRESS_ONE_ZONE"], default="STANDARD"),
    num("ia_days", "Transición a Standard-IA (días)"),
    num("glacier_days", "Transición a Glacier (días)"),
    sel("glacier_tier", "Clase Glacier", ["Glacier Instant Retrieval", "Glacier Flexible Retrieval", "Glacier Deep Archive"]),
    b("versioning", "Versionado", True, required=True),
    num("noncurrent_days", "Expirar versiones no actuales (días)", show_if={"versioning": [True]}),
    sel("encryption", "Cifrado", ["SSE-S3", "SSE-KMS", "DSSE-KMS"], required=True),
    b("bucket_key", "S3 Bucket Key (reduce costo KMS)", True, show_if={"encryption": ["SSE-KMS", "DSSE-KMS"]}),
    b("block_public", "Block Public Access", True, required=True),
    b("tls_only", "Política: denegar sin TLS (aws:SecureTransport)", True),
    b("object_lock", "Object Lock (WORM)"),
    sel("object_lock_mode", "Modo Object Lock", ["GOVERNANCE", "COMPLIANCE"], show_if={"object_lock": [True]}),
    sel("replication", "Replicación", ["Ninguna", "Same-Region (SRR)", "Cross-Region (CRR)"]),
    ms("notifications", "Notificaciones de eventos", ["Lambda", "SQS", "SNS", "EventBridge"]),
    b("lake_formation", "Gobernado por Lake Formation"),
    b("access_logs", "Server access logs / CloudTrail data events"),
    ta("bucket_policy", "Bucket policy (JSON)", placeholder='{"Version": "2012-10-17", "Statement": [...]}',
       help="Pega la política para que el Copilot la revise (Principal '*', cuentas externas, comodines)."),
    F("volume", "Volumen estimado", placeholder="5 TB/mes, 200 GB/día"),
])
C("efs", "EFS", "storage", "EFS", vpc="required", desc="Sistema de archivos NFS compartido.", fields=[
    sel("throughput", "Modo de throughput", ["Elastic", "Bursting", "Provisioned"], default="Elastic"),
    sel("performance", "Modo de rendimiento", ["General Purpose", "Max I/O"]),
    b("encrypted", "Cifrado en reposo", True, required=True),
    num("ia_days", "Lifecycle a IA (días)"),
    b("one_zone", "One Zone"),
    b("backup", "AWS Backup"),
    b("access_points", "Access points"),
])
C("backup", "AWS Backup", "storage", "BKP", desc="Políticas centralizadas de respaldo.", fields=[
    ta("plan", "Plan de backup", placeholder="Diario 35 días, mensual 1 año"),
    b("vault_lock", "Vault Lock"),
    b("cross_region", "Copia cross-region"),
    b("cross_account", "Copia cross-account"),
])

# ───────────────────────────── Bases de datos ─────────────────────────────
C("rds", "RDS", "database", "RDS", vpc="required", desc="Base relacional administrada.", fields=[
    sel("engine", "Motor", ["PostgreSQL", "MySQL", "MariaDB", "Oracle", "SQL Server"], required=True),
    F("version", "Versión", placeholder="16.4"),
    F("instance_class", "Clase de instancia", required=True, placeholder="db.r7g.large"),
    num("storage", "Almacenamiento (GiB)", default=100),
    sel("storage_type", "Tipo de almacenamiento", ["gp3", "io2", "io1"], default="gp3"),
    b("multi_az", "Multi-AZ", True, required=True),
    num("read_replicas", "Read replicas", default=0),
    b("public", "Publicly accessible", False, required=True),
    b("encrypted", "Cifrado en reposo", True, required=True),
    num("backup_days", "Retención de backups (días)", default=7, required=True),
    b("deletion_protection", "Protección contra borrado", True),
    b("iam_auth", "Autenticación IAM"),
    b("managed_secret", "Password administrado en Secrets Manager", True),
    b("proxy", "RDS Proxy"),
    b("performance_insights", "Performance Insights / Database Insights"),
    num("port", "Puerto"),
])
C("aurora", "Aurora", "database", "AUR", vpc="required", desc="Aurora PostgreSQL/MySQL.", fields=[
    sel("engine", "Motor", ["Aurora PostgreSQL", "Aurora MySQL"], required=True),
    sel("mode", "Capacidad", ["Provisioned", "Serverless v2", "Aurora DSQL"], required=True),
    num("min_acu", "ACU mínimo", show_if={"mode": ["Serverless v2"]}),
    num("max_acu", "ACU máximo", show_if={"mode": ["Serverless v2"]}),
    F("instance_class", "Clase de instancia", show_if={"mode": ["Provisioned"]}),
    num("instances", "Instancias (writer + readers)", default=2, required=True),
    b("global", "Global Database"),
    b("encrypted", "Cifrado", True, required=True),
    num("backup_days", "Retención de backups (días)", default=7),
    b("deletion_protection", "Protección contra borrado", True),
    b("iam_auth", "Autenticación IAM"),
    b("managed_secret", "Password en Secrets Manager", True),
    b("data_api", "Data API"),
    b("public", "Publicly accessible", False),
])
C("dynamodb", "DynamoDB", "database", "DDB", desc="NoSQL clave-valor serverless.", fields=[
    F("table_name", "Nombre de tabla"),
    sel("capacity", "Modo de capacidad", ["On-Demand", "Provisioned"], required=True),
    F("pk", "Partition key", required=True, placeholder="pk (S)"),
    F("sk", "Sort key", placeholder="sk (S)"),
    ta("gsi", "GSIs / LSIs"),
    F("ttl", "Atributo TTL"),
    b("pitr", "Point-in-time recovery", True, required=True),
    sel("streams", "Streams", ["Deshabilitado", "NEW_IMAGE", "OLD_IMAGE", "NEW_AND_OLD_IMAGES", "KEYS_ONLY"]),
    b("global_tables", "Global tables"),
    sel("encryption", "Cifrado", ["AWS owned key", "AWS managed key", "Customer managed key (KMS)"]),
    sel("table_class", "Clase de tabla", ["Standard", "Standard-IA"]),
    b("deletion_protection", "Protección contra borrado", True),
])
C("elasticache", "ElastiCache", "database", "EC", vpc="required", desc="Caché en memoria.", fields=[
    sel("engine", "Motor", ["Valkey", "Redis OSS", "Memcached"], required=True),
    sel("mode", "Despliegue", ["Serverless", "Cluster aprovisionado"], required=True),
    F("node_type", "Tipo de nodo", show_if={"mode": ["Cluster aprovisionado"]}),
    num("replicas", "Réplicas por shard"),
    b("cluster_mode", "Cluster mode (sharding)"),
    b("transit_encryption", "Cifrado en tránsito", True, required=True),
    b("rest_encryption", "Cifrado en reposo", True),
    sel("auth", "Autenticación", ["IAM", "RBAC usuarios", "AUTH token", "Ninguna"]),
    b("multi_az", "Multi-AZ con failover", True),
])
C("redshift", "Redshift", "database", "RS", vpc="required", principal="redshift.amazonaws.com", desc="Data warehouse.", fields=[
    sel("deployment", "Despliegue", ["Serverless", "Provisioned RA3"], required=True),
    num("base_rpu", "RPU base", show_if={"deployment": ["Serverless"]}),
    num("max_rpu", "RPU máximo", show_if={"deployment": ["Serverless"]}),
    F("node_type", "Tipo de nodo", show_if={"deployment": ["Provisioned RA3"]}),
    num("nodes", "Nodos", show_if={"deployment": ["Provisioned RA3"]}),
    b("encrypted", "Cifrado", True, required=True),
    b("enhanced_vpc_routing", "Enhanced VPC Routing"),
    b("public", "Publicly accessible", False),
    b("spectrum", "Redshift Spectrum / tablas externas"),
    b("data_sharing", "Data sharing"),
    b("zero_etl", "Zero-ETL desde Aurora/RDS/DynamoDB"),
])
C("opensearch", "OpenSearch", "database", "OS", vpc="optional", desc="Búsqueda y analítica de logs.", fields=[
    sel("deployment", "Despliegue", ["Managed domain", "Serverless"], required=True),
    F("version", "Versión"),
    F("instance_type", "Tipo de instancia", show_if={"deployment": ["Managed domain"]}),
    num("instances", "Nodos de datos", show_if={"deployment": ["Managed domain"]}),
    b("dedicated_masters", "Masters dedicados", show_if={"deployment": ["Managed domain"]}),
    b("ultrawarm", "UltraWarm / cold storage", show_if={"deployment": ["Managed domain"]}),
    b("encrypted", "Cifrado en reposo y node-to-node", True, required=True),
    b("fgac", "Fine-grained access control", True),
    sel("network", "Acceso de red", ["VPC", "Público"], required=True),
])
C("documentdb", "DocumentDB", "database", "DOC", vpc="required", desc="Base documental compatible con MongoDB.", fields=[
    F("instance_class", "Clase de instancia"),
    num("instances", "Instancias", default=3),
    b("encrypted", "Cifrado", True, required=True),
    b("tls", "TLS obligatorio", True),
    num("backup_days", "Retención de backups (días)", default=7),
])

# ───────────────────────────── Analítica ─────────────────────────────
C("emr", "EMR", "analytics", "EMR", vpc="optional", principal="emr-serverless.amazonaws.com",
  desc="Spark/Hive/Trino/Flink administrado (Serverless, EC2 o EKS).", fields=[
    sel("deployment", "Tipo de EMR", ["EMR Serverless", "EMR on EC2", "EMR on EKS"], required=True),
    F("release", "Release label", required=True, placeholder="emr-7.9.0"),
    sel("app_type", "Tipo de aplicación", ["Spark", "Hive"], show_if={"deployment": ["EMR Serverless"]}, required=True),
    ms("applications", "Aplicaciones", ["Spark", "Hive", "Trino", "Presto", "Flink", "HBase", "Livy", "JupyterEnterpriseGateway",
                                        "Iceberg", "Hudi", "Delta"], show_if={"deployment": ["EMR on EC2"]}, required=True),
    b("initial_capacity", "Capacidad pre-inicializada", show_if={"deployment": ["EMR Serverless"]}),
    num("max_vcpu", "Máximo vCPU", show_if={"deployment": ["EMR Serverless"]}, required=True),
    num("max_memory", "Máximo memoria (GB)", show_if={"deployment": ["EMR Serverless"]}),
    num("idle_timeout", "Auto-stop por inactividad (min)", default=15, show_if={"deployment": ["EMR Serverless"]}),
    F("primary_type", "Primary: tipo de instancia", show_if={"deployment": ["EMR on EC2"]}, required=True, placeholder="m7g.xlarge"),
    num("primary_count", "Primary: cantidad (1 ó 3 HA)", show_if={"deployment": ["EMR on EC2"]}, default=1),
    F("core_type", "Core: tipo de instancia", show_if={"deployment": ["EMR on EC2"]}, required=True),
    num("core_count", "Core: cantidad", show_if={"deployment": ["EMR on EC2"]}),
    F("task_type", "Task: tipo de instancia", show_if={"deployment": ["EMR on EC2"]}),
    num("task_count", "Task: cantidad", show_if={"deployment": ["EMR on EC2"]}),
    b("task_spot", "Task nodes en Spot", show_if={"deployment": ["EMR on EC2"]}),
    sel("cluster_lifecycle", "Ciclo de vida", ["Transitorio (por job)", "Persistente"], show_if={"deployment": ["EMR on EC2"]},
        required=True),
    b("managed_scaling", "Managed scaling", show_if={"deployment": ["EMR on EC2"]}),
    num("auto_terminate", "Auto-terminación por inactividad (min)", show_if={"deployment": ["EMR on EC2"]}),
    sel("fleet", "Configuración", ["Instance fleets", "Instance groups"], show_if={"deployment": ["EMR on EC2"]}),
    F("eks_namespace", "Virtual cluster / namespace", show_if={"deployment": ["EMR on EKS"]}, required=True),
    sel("catalog", "Metastore / catálogo", ["AWS Glue Data Catalog", "S3 Tables catalog", "Hive Metastore (RDS)", "Ninguno"],
        required=True),
    b("iceberg", "Soporte Iceberg habilitado (spark.sql.extensions)"),
    b("lake_formation", "Integración Lake Formation (FGAC)"),
    F("log_uri", "Log URI (S3)", placeholder="s3://empresa-logs/emr/", required=True),
    b("encryption", "Security configuration: cifrado at-rest / in-transit", True),
    b("kerberos", "Kerberos", show_if={"deployment": ["EMR on EC2"]}),
    sel("orchestration", "Orquestación", ["Step Functions", "MWAA (Airflow)", "EventBridge Scheduler", "Manual", "Otro"]),
    F("runtime_role", "Rol de ejecución (job runtime role)"),
    ta("spark_conf", "Configuraciones Spark / classifications",
       placeholder="spark.sql.catalog.glue_catalog=org.apache.iceberg.spark.SparkCatalog\nspark.dynamicAllocation.enabled=true"),
    ta("bootstrap", "Bootstrap actions", show_if={"deployment": ["EMR on EC2"]}),
])
C("glue", "Glue", "analytics", "GLUE", vpc="optional", principal="glue.amazonaws.com",
  desc="ETL serverless, crawlers y Data Catalog.", fields=[
    sel("job_type", "Tipo de job", ["Spark ETL", "Spark Streaming", "Python shell", "Ray", "Sólo Data Catalog / Crawler"],
        required=True),
    sel("version", "Versión de Glue", ["5.0", "4.0", "3.0"]),
    sel("worker", "Tipo de worker", ["G.1X", "G.2X", "G.4X", "G.8X", "G.025X", "R.1X", "R.2X"]),
    num("workers", "Número de workers"),
    b("autoscaling", "Auto scaling"),
    b("flex", "Ejecución Flex (ahorro)"),
    b("bookmarks", "Job bookmarks"),
    ms("formats", "Formatos de tabla", ["Iceberg", "Hudi", "Delta", "Hive"]),
    b("crawler", "Crawler"),
    F("database", "Base de datos del catálogo"),
    b("vpc_connection", "Glue connection a VPC (JDBC/recursos privados)"),
    sel("trigger", "Disparador", ["Schedule", "Evento", "Workflow", "Step Functions", "MWAA", "On-demand"]),
])
C("athena", "Athena", "analytics", "ATH", desc="SQL serverless sobre S3.", fields=[
    F("workgroup", "Workgroup", required=True, placeholder="analytics"),
    sel("engine", "Motor", ["Athena engine v3", "Apache Spark"]),
    F("results_location", "Ubicación de resultados (S3)", required=True, placeholder="s3://empresa-athena-results/"),
    b("results_encrypted", "Resultados cifrados", True),
    num("scan_limit_gb", "Límite de datos escaneados por query (GB)"),
    b("federated", "Consultas federadas"),
    b("provisioned_capacity", "Capacidad aprovisionada"),
])
C("kinesis", "Kinesis Data Streams", "analytics", "KDS", desc="Streaming en tiempo real.", fields=[
    sel("capacity", "Modo de capacidad", ["On-demand", "Provisioned"], required=True),
    num("shards", "Shards", show_if={"capacity": ["Provisioned"]}),
    num("retention_hours", "Retención (horas)", default=24, required=True),
    b("encrypted", "Cifrado KMS", True),
    b("efo", "Enhanced fan-out"),
])
C("firehose", "Data Firehose", "analytics", "KDF", principal="firehose.amazonaws.com", desc="Entrega de streaming a destinos.", fields=[
    sel("source", "Origen", ["Direct PUT", "Kinesis Data Streams", "MSK"], required=True),
    sel("destination", "Destino", ["S3", "Apache Iceberg Tables", "Redshift", "OpenSearch", "Splunk", "HTTP endpoint", "Snowflake"],
        required=True),
    num("buffer_mb", "Buffer (MB)", default=64),
    num("buffer_s", "Buffer (s)", default=300),
    sel("conversion", "Conversión de formato", ["Ninguna", "Parquet", "ORC"]),
    b("transform", "Transformación con Lambda"),
    b("dynamic_partitioning", "Particionamiento dinámico"),
    sel("compression", "Compresión", ["Ninguna", "GZIP", "Snappy", "ZIP"]),
])
C("msk", "MSK (Kafka)", "analytics", "MSK", vpc="required", desc="Apache Kafka administrado.", fields=[
    sel("type", "Tipo", ["Provisioned (Standard)", "Express brokers", "Serverless"], required=True),
    F("kafka_version", "Versión de Kafka"),
    F("broker_type", "Tipo de broker"),
    num("brokers", "Brokers (múltiplo de AZs)"),
    num("storage", "Almacenamiento por broker (GiB)"),
    sel("auth", "Autenticación", ["IAM", "SASL/SCRAM", "mTLS", "Sin autenticación"], required=True),
    sel("transit", "Cifrado en tránsito", ["TLS", "TLS_PLAINTEXT", "PLAINTEXT"], default="TLS"),
    b("connect", "MSK Connect"),
])
C("lakeformation", "Lake Formation", "analytics", "LF", desc="Gobierno y permisos finos del data lake.", fields=[
    sel("model", "Modelo de permisos", ["LF-Tags (TBAC)", "Recursos nombrados", "Híbrido"], required=True),
    b("hybrid_access", "Hybrid access mode (IAM + LF)"),
    ta("admins", "Data lake admins"),
    ta("tags", "LF-Tags", placeholder="domain=ventas\nclassification=pii"),
    b("cross_account", "Compartición cross-account"),
])
C("mwaa", "MWAA (Airflow)", "analytics", "MWAA", vpc="required", principal="airflow-env.amazonaws.com",
  desc="Apache Airflow administrado. Requiere 2 subnets privadas en AZ distintas.", fields=[
    F("airflow_version", "Versión de Airflow", required=True, placeholder="2.10.3"),
    sel("env_class", "Clase de entorno", ["mw1.micro", "mw1.small", "mw1.medium", "mw1.large", "mw1.xlarge", "mw1.2xlarge"],
        required=True),
    num("min_workers", "Workers mínimos", default=1),
    num("max_workers", "Workers máximos", default=10),
    sel("webserver", "Acceso al webserver", ["Privado (VPC)", "Público"], required=True),
    F("dags_path", "Ruta de DAGs (S3)", placeholder="s3://empresa-mwaa/dags/"),
])
C("quicksight", "QuickSight", "analytics", "QS", desc="BI y dashboards.", fields=[
    sel("edition", "Edición", ["Enterprise", "Standard"]),
    b("vpc_connection", "VPC connection a fuentes privadas"),
    b("spice", "SPICE"),
    sel("auth", "Identidad", ["IAM Identity Center", "IAM", "Usuarios QuickSight"]),
])

# ───────────────────────────── Integración ─────────────────────────────
C("sqs", "SQS", "integration", "SQS", desc="Colas de mensajes.", fields=[
    sel("type", "Tipo", ["Standard", "FIFO"], required=True),
    num("visibility", "Visibility timeout (s)", default=30, required=True,
        help="Debe ser ≥ 6× el timeout de la Lambda consumidora."),
    num("retention", "Retención (s)", default=345600, help="60 s a 14 días (1209600)."),
    b("dlq", "Dead-letter queue", True, required=True),
    num("max_receive", "maxReceiveCount", default=5, show_if={"dlq": [True]}),
    sel("encryption", "Cifrado", ["SSE-SQS", "SSE-KMS"], default="SSE-SQS"),
    num("wait_time", "Long polling (s)", default=20),
])
C("sns", "SNS", "integration", "SNS", desc="Pub/sub y notificaciones.", fields=[
    sel("type", "Tipo", ["Standard", "FIFO"], required=True),
    ms("protocols", "Suscripciones", ["SQS", "Lambda", "Email", "HTTPS", "SMS", "Firehose"]),
    b("encrypted", "Cifrado KMS"),
    b("filtering", "Filtros de mensajes"),
    b("dlq", "DLQ en suscripciones"),
])
C("mq", "Amazon MQ", "integration", "MQ", vpc="required",
  desc="Broker administrado ActiveMQ o RabbitMQ (protocolos AMQP, MQTT, STOMP, OpenWire).", fields=[
    sel("engine", "Motor", ["RabbitMQ", "ActiveMQ"], required=True),
    F("version", "Versión", placeholder="3.13"),
    sel("deployment", "Despliegue", ["Single-instance", "Active/standby multi-AZ (ActiveMQ)", "Cluster multi-AZ (RabbitMQ)"],
        required=True),
    sel("instance", "Tipo de instancia", ["mq.t3.micro", "mq.m7g.medium", "mq.m7g.large", "mq.m5.large", "mq.m5.xlarge", "mq.m5.2xlarge"],
        required=True),
    ms("protocols", "Protocolos", ["AMQP", "MQTT", "STOMP", "OpenWire", "WSS"]),
    b("public", "Accesible públicamente", False, required=True),
    sel("auth", "Autenticación", ["Usuarios del broker", "LDAP (ActiveMQ)", "OAuth 2.0 (RabbitMQ)"]),
    b("kms", "Cifrado con CMK propia"),
    b("logs", "Logs a CloudWatch", True),
    sel("maintenance", "Actualizaciones menores automáticas", ["Sí", "No"]),
])
C("eventbridge", "EventBridge", "integration", "EB", principal="events.amazonaws.com", desc="Bus de eventos y scheduler.", fields=[
    sel("bus", "Bus", ["default", "custom", "partner"], required=True),
    ta("rules", "Reglas / patrones"),
    b("scheduler", "EventBridge Scheduler"),
    b("archive", "Archive & replay"),
    b("dlq", "DLQ en targets"),
    b("pipes", "EventBridge Pipes"),
])
C("appflow", "AppFlow / Transfer", "integration", "XFER", desc="Ingesta desde SaaS o SFTP.", fields=[
    sel("service", "Servicio", ["AppFlow", "Transfer Family (SFTP)", "DataSync", "DMS"], required=True),
    F("source", "Origen"),
    sel("schedule", "Frecuencia", ["On-demand", "Schedule", "Event"]),
])

# ───────────────────────────── Seguridad ─────────────────────────────
C("iam_role", "IAM Role", "security", "IAM", desc="Rol IAM. Conéctalo al componente que lo usa.", fields=[
    F("role_name", "Nombre del rol", required=True),
    sel("trusted", "Servicio de confianza (trust policy)", ["lambda.amazonaws.com", "ec2.amazonaws.com", "ecs-tasks.amazonaws.com",
                                                             "pods.eks.amazonaws.com", "emr-serverless.amazonaws.com",
                                                             "elasticmapreduce.amazonaws.com", "glue.amazonaws.com",
                                                             "states.amazonaws.com", "events.amazonaws.com",
                                                             "firehose.amazonaws.com", "redshift.amazonaws.com",
                                                             "apigateway.amazonaws.com", "Cuenta / usuarios (SSO)",
                                                             "OIDC (GitHub Actions / CI)"], required=True),
    ta("managed_policies", "Políticas administradas"),
    ta("inline", "Política inline (JSON)", placeholder='{"Version": "2012-10-17", "Statement": [...]}',
       help="Si pegas JSON válido, el Copilot revisa comodines, PassRole y privilegios de administrador."),
    b("boundary", "Permissions boundary"),
    num("max_session", "Duración máx. de sesión (h)", default=1),
])
C("kms", "KMS Key", "security", "KMS", desc="Llave de cifrado administrada por el cliente.", fields=[
    sel("key_spec", "Tipo", ["Simétrica (SYMMETRIC_DEFAULT)", "Asimétrica", "HMAC"], required=True),
    b("rotation", "Rotación automática", True, required=True),
    b("multi_region", "Multi-región"),
    F("alias", "Alias", placeholder="alias/datalake"),
    ta("key_policy", "Key policy (notas)"),
])
C("secrets", "Secrets Manager", "security", "SM", desc="Secretos y credenciales.", fields=[
    sel("secret_type", "Tipo de secreto", ["Credenciales de BD", "API key", "Certificado", "Otro"], required=True),
    b("rotation", "Rotación automática", required=True),
    num("rotation_days", "Rotar cada (días)", default=30, show_if={"rotation": [True]}),
    b("cmk", "Cifrado con CMK propia"),
    b("replication", "Replicación multi-región"),
])
C("cognito", "Cognito", "security", "COG", desc="Autenticación de usuarios.", fields=[
    sel("type", "Tipo", ["User pool", "Identity pool", "Ambos"], required=True),
    sel("mfa", "MFA", ["OFF", "OPTIONAL", "ON"], required=True),
    ms("federation", "Federación", ["SAML", "OIDC", "Google", "Apple", "Facebook", "Amazon"]),
    b("advanced_security", "Threat protection"),
])
C("acm", "ACM", "security", "ACM", desc="Certificados TLS.", fields=[
    F("domain", "Dominio", required=True),
    sel("validation", "Validación", ["DNS", "Email"], default="DNS"),
    sel("cert_type", "Tipo", ["Público", "Privado (Private CA)"]),
])
C("guardduty", "GuardDuty / Security Hub", "security", "GD", desc="Detección de amenazas y postura.", fields=[
    ms("services", "Servicios", ["GuardDuty", "Security Hub", "Inspector", "Macie", "Config", "Detective"]),
    b("org_wide", "Habilitado a nivel organización"),
])

# ───────────────────────────── Operación ─────────────────────────────
C("cloudwatch", "CloudWatch", "management", "CW", desc="Logs, métricas y alarmas.", fields=[
    num("log_retention", "Retención de logs (días)", required=True, default=30),
    ta("alarms", "Alarmas clave"),
    b("dashboards", "Dashboards"),
    b("container_insights", "Container Insights"),
    b("app_signals", "Application Signals / X-Ray"),
])
C("cloudtrail", "CloudTrail", "management", "CT", desc="Auditoría de llamadas a la API.", fields=[
    b("multi_region", "Multi-región", True),
    b("org_trail", "Trail de organización"),
    b("data_events", "Data events (S3/Lambda)"),
    b("validation", "Log file validation", True),
    F("bucket", "Bucket destino"),
])
C("ssm", "Systems Manager", "management", "SSM", desc="Parameter Store, Session Manager, Patch.", fields=[
    ms("features", "Capacidades", ["Parameter Store", "Session Manager", "Patch Manager", "Run Command", "Automation"]),
])

# ───────────────────────────── Cuentas y gobierno ─────────────────────────────
ENVIRONMENTS = ["prod", "staging", "qa", "dev", "sandbox", "shared-services", "network", "security-tooling", "log-archive",
                "management"]
C("account", "Cuenta AWS", "governance", "ACCT", container=True,
  desc="Cuenta AWS (contenedor). Arrastra dentro sus VPCs y servicios; marca su línea base de seguridad.", fields=[
    F("account_id", "ID de cuenta", required=True, placeholder="123456789012"),
    sel("environment", "Ambiente / propósito", ENVIRONMENTS, required=True),
    F("ou", "Unidad organizacional (OU)", placeholder="Workloads/Prod"),
    F("regions", "Regiones permitidas", placeholder="us-east-1, us-west-2"),
    b("root_mfa", "Root con MFA (de hardware o passkey)", required=True),
    b("root_no_keys", "Root sin access keys", required=True),
    b("identity_center", "Acceso humano por IAM Identity Center (SSO)", required=True),
    num("iam_users_keys", "Usuarios IAM con access keys de larga duración", default=0),
    b("password_policy", "Política de contraseñas IAM", show_if={"identity_center": [False, None]}),
    b("guardduty", "GuardDuty habilitado", required=True),
    b("securityhub", "Security Hub habilitado", required=True),
    ms("sh_standards", "Estándares de Security Hub", ["AWS Foundational Security Best Practices", "CIS AWS Foundations",
                                                     "PCI DSS", "NIST SP 800-53"], show_if={"securityhub": [True]}),
    b("config", "AWS Config grabando todos los recursos", required=True),
    b("access_analyzer", "IAM Access Analyzer", required=True),
    b("cloudtrail", "Cubierta por CloudTrail (trail de organización o propio)", required=True),
    b("macie", "Macie (descubrimiento de datos sensibles)"),
    b("inspector", "Inspector (vulnerabilidades EC2/ECR/Lambda)"),
    b("ebs_default_encryption", "Cifrado EBS por defecto", required=True),
    b("s3_account_bpa", "S3 Block Public Access a nivel cuenta", required=True),
    b("imdsv2_default", "IMDSv2 por defecto a nivel cuenta"),
    b("central_logs", "Logs enviados a la cuenta log-archive"),
    b("findings_alerts", "Hallazgos enrutados a alertas (EventBridge → SNS/Chat/SIEM)"),
    b("security_contact", "Contacto alterno de seguridad configurado"),
    b("budget_alerts", "Alertas de presupuesto / anomalías de costo"),
])
C("organization", "AWS Organizations", "governance", "ORG",
  desc="Organización, Control Tower, SCPs y administradores delegados de seguridad.", fields=[
    b("control_tower", "Control Tower / landing zone"),
    F("management_account", "Cuenta de administración", placeholder="111111111111"),
    ms("scps", "Guardrails (SCP/RCP)", ["Denegar salir de la organización", "Denegar desactivar CloudTrail",
                                       "Denegar desactivar GuardDuty / Security Hub / Config", "Restringir regiones",
                                       "Denegar uso de root", "Exigir IMDSv2", "Denegar S3 público", "Exigir cifrado EBS",
                                       "Denegar crear usuarios IAM / access keys",
                                       "Sólo identidades de la organización (RCP)"], required=True),
    ms("delegated", "Administradores delegados (cuenta security-tooling)",
       ["GuardDuty", "Security Hub", "Config", "IAM Access Analyzer", "Macie", "Inspector", "Firewall Manager", "Detective",
        "Backup"]),
    b("tag_policies", "Tag policies"),
    b("backup_policies", "Backup policies"),
])

# ───────────────────────────── Usuario final ─────────────────────────────
C("directory", "Directory Service", "enduser", "AD", vpc="required",
  desc="Directorio para WorkSpaces/AppStream: Managed Microsoft AD, AD Connector o Simple AD. Requiere 2 subnets en AZ distintas.",
  fields=[
    sel("type", "Tipo", ["AWS Managed Microsoft AD (Standard)", "AWS Managed Microsoft AD (Enterprise)", "AD Connector",
                         "Simple AD"], required=True),
    F("domain", "Dominio", required=True, placeholder="corp.empresa.com"),
    b("mfa", "MFA vía RADIUS"),
    b("trust", "Trust con AD on-premise", show_if={"type": ["AWS Managed Microsoft AD (Standard)", "AWS Managed Microsoft AD (Enterprise)"]}),
    b("ldaps", "LDAPS habilitado"),
])
C("workspaces", "Amazon WorkSpaces", "enduser", "WS", vpc="required",
  desc="Escritorios virtuales (Personal o Pools). Viven en subnets privadas de 2 AZ y requieren un directorio.", fields=[
    sel("mode", "Tipo", ["WorkSpaces Personal", "WorkSpaces Pools"], required=True),
    sel("protocol", "Protocolo de streaming", ["Amazon DCV", "PCoIP"], required=True),
    F("bundle", "Bundle / imagen", placeholder="Windows Server 2022 Performance"),
    num("count", "Cantidad de escritorios / usuarios"),
    sel("running_mode", "Modo de ejecución", ["AutoStop", "AlwaysOn"], show_if={"mode": ["WorkSpaces Personal"]}),
    num("autostop_hours", "AutoStop tras (horas)", default=1, show_if={"running_mode": ["AutoStop"]}),
    b("root_encryption", "Cifrado del volumen raíz (KMS)", required=True),
    b("user_encryption", "Cifrado del volumen de usuario (KMS)", required=True),
    b("mfa", "MFA para usuarios", required=True),
    ta("ip_groups", "IP access control groups (CIDR permitidos)", placeholder="203.0.113.0/24 oficina\n198.51.100.10/32 VPN"),
    b("trusted_devices", "Sólo dispositivos de confianza (certificados)"),
    ms("clients", "Clientes permitidos", ["Windows", "macOS", "Linux", "iPad/iOS", "Android", "Web", "Chromebook"]),
    b("clipboard", "Portapapeles hacia el equipo local permitido"),
    b("local_drives", "Unidades locales / USB redirigidas"),
    b("printing", "Impresión local permitida"),
    b("internet", "Acceso a internet desde el escritorio"),
    b("public_ip", "IP pública por escritorio (en vez de NAT)"),
])
C("appstream", "AppStream 2.0", "enduser", "AS2", vpc="required",
  desc="Streaming de aplicaciones a navegador sin instalar escritorios completos.", fields=[
    sel("fleet", "Tipo de fleet", ["Elastic", "On-demand", "Always-on"], required=True),
    F("instance_type", "Tipo de instancia", placeholder="stream.standard.medium"),
    num("max_capacity", "Capacidad máxima"),
    sel("auth", "Autenticación", ["SAML 2.0 (IdP corporativo)", "User pool de AppStream", "Directorio (AD)"], required=True),
    b("default_internet", "Acceso a internet por defecto (IP pública)"),
    b("clipboard", "Portapapeles hacia el equipo local permitido"),
    b("file_transfer", "Subir/descargar archivos permitido"),
    b("printing", "Impresión local permitida"),
    num("session_hours", "Duración máxima de sesión (h)", default=16),
    b("persistence", "Persistencia de configuración de usuario"),
])
C("securebrowser", "WorkSpaces Secure Browser", "enduser", "WSB",
  desc="Navegador administrado para acceder a apps web internas/SaaS sin VPN.", fields=[
    sel("idp", "Proveedor de identidad", ["SAML 2.0", "IAM Identity Center"], required=True),
    b("clipboard", "Copiar hacia el equipo local permitido"),
    b("download", "Descargas permitidas"),
    b("upload", "Subidas permitidas"),
    b("printing", "Impresión permitida"),
    ta("ip_access", "IP access settings (CIDR permitidos)"),
    ta("allowed_urls", "URLs / dominios permitidos"),
    b("vpc_access", "Accede a apps dentro de la VPC"),
])

# ───────────────────────────── Externos ─────────────────────────────
C("users", "Usuarios / Internet", "external", "WWW", terraformable=False, desc="Clientes externos que llegan por internet.",
  fields=[F("audience", "Audiencia", placeholder="Clientes B2C, ~10k usuarios/día")])
C("onprem", "On-premise / Data center", "external", "DC", terraformable=False, desc="Sistemas en tu centro de datos.",
  fields=[
      F("cidr", "CIDR on-premise", "cidr"),
      sel("connectivity", "Conectividad", ["Site-to-Site VPN", "Direct Connect", "Internet público", "Por definir"], required=True),
      ta("systems", "Sistemas involucrados"),
  ])
C("saas", "API externa / SaaS", "external", "EXT", terraformable=False, desc="Servicio de terceros consumido por internet.",
  fields=[
      F("endpoint", "Endpoint / dominio"),
      sel("auth", "Autenticación", ["API key", "OAuth2", "mTLS", "Ninguna"]),
      b("ip_allowlist", "Requiere IP fija de salida (allowlist)"),
  ])
C("note", "Nota libre", "external", "📝", terraformable=False, desc="Etiqueta de texto en el lienzo.", fields=[])


COMPONENTS_BY_ID = {c["id"]: c for c in COMPONENTS}
CATEGORY_COLOR = {c["id"]: c["color"] for c in CATEGORIES}
for _c in COMPONENTS:
    _c["color"] = CATEGORY_COLOR[_c["category"]]


def catalog():
    return {"categories": CATEGORIES, "components": COMPONENTS}


def visible_fields(comp, config):
    """Campos visibles según show_if."""
    out = []
    for f in comp["fields"]:
        cond = f.get("show_if")
        if cond and not all(_matches(config.get(k), vals) for k, vals in cond.items()):
            continue
        out.append(f)
    return out


def _matches(value, allowed):
    if isinstance(value, list):
        return any(v in allowed for v in value)
    if value is None:
        return None in allowed
    return value in allowed


def missing_required(comp, config):
    missing = []
    for f in visible_fields(comp, config):
        if not f.get("required"):
            continue
        v = config.get(f["key"])
        if f["type"] == "bool":
            if v is None and f.get("default") is None:
                missing.append(f["label"])
            continue
        if v is None or v == "" or v == []:
            missing.append(f["label"])
    return missing


def effective_config(comp, config):
    """Config con defaults aplicados."""
    cfg = {}
    for f in comp["fields"]:
        if "default" in f:
            cfg[f["key"]] = f["default"]
    cfg.update({k: v for k, v in (config or {}).items() if v is not None and v != ""})
    return cfg
