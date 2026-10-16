#!/usr/bin/env bash
# Exporta la red de una cuenta/región con comandos de SÓLO LECTURA de la AWS CLI,
# para importarla en InfraTrack (Proyecto → Importar desde AWS). InfraTrack nunca recibe credenciales.
#
#   ./scripts/export-aws-network.sh [región] [carpeta-salida]
#   AWS_PROFILE=mi-perfil ./scripts/export-aws-network.sh us-east-1 ./aws-export
set -euo pipefail
REGION="${1:-${AWS_REGION:-us-east-1}}"
OUT="${2:-./aws-export-$REGION}"
mkdir -p "$OUT"
for cmd in describe-vpcs describe-subnets describe-route-tables describe-internet-gateways describe-nat-gateways \
           describe-vpc-endpoints describe-security-groups describe-network-acls describe-transit-gateways; do
  echo "aws ec2 $cmd"
  aws ec2 "$cmd" --region "$REGION" --output json > "$OUT/$cmd.json"
done
echo "Listo: sube los archivos de $OUT en InfraTrack (Proyecto → Importar desde AWS)."
