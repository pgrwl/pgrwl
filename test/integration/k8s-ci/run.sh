#!/bin/bash
set -euo pipefail

######################################################################
### setup kind cluster
######################################################################

echo "> Stopping and removing registry container..."
docker rm -f kind-registry 2>/dev/null || echo "Registry container not running"

echo "> Disconnecting registry from 'kind' network..."
docker network disconnect kind kind-registry 2>/dev/null || echo "Already disconnected"

echo "> Deleting kind cluster..."
kind delete cluster --name pgrwl || echo "Kind cluster not found"

echo "> Running local registry..."
docker run -d --restart=always -p 5000:5000 --name kind-registry registry:2

# setup cluster with kind, to safely test in a sandbox
kind create cluster --config=kind-config.yaml
kubectl config set-context "kind-pgrwl"
docker network connect kind kind-registry

######################################################################
### build images
######################################################################

(
  cd ../../../ && make image && make image-ui
)

######################################################################
### apply manifests
######################################################################

kubectl create ns pgrwl-test --dry-run=client -oyaml | kubectl apply -f -

# create seaweedfs certs
kubectl -n pgrwl-test create secret generic seaweedfs-certs \
  --from-file=public.crt=./files/seaweedfs/certs/public.crt \
  --from-file=private.key=./files/seaweedfs/certs/private.key \
  --dry-run=client -oyaml | kubectl apply -f -

# deploy workloads
kubectl apply -f manifests/

######################################################################
### wait until WALs and backups are available (rough check)
######################################################################

# timeout = 5m

timeout 300 bash -c '
until \
  curl -fsS http://127.0.0.1:30266/api/v1/wals    | jq -e "type == \"array\" and length > 0" >/dev/null && \
  curl -fsS http://127.0.0.1:30266/api/v1/backups | jq -e "type == \"array\" and length > 0" >/dev/null
do
  echo "waiting: WALs/backups are not available yet"
  sleep 5
done
echo "OK: WALs and backups are available"
'

timeout 180 bash -c '
until [[ "$(curl -sS -o /dev/null -w "%{http_code}" http://127.0.0.1:30272/healthz)" == "200" ]]; do
  echo "waiting: UI healthz is not 200 yet"
  sleep 2
done
echo "OK: UI healthz returned 200"
'
