#!/usr/bin/env bash
# Smoke test of the Kubernetes manifests (deploy/kubernetes) on a throw-away kind cluster, against a published image.
#
#   deploy/smoke/kubernetes.sh <image reference>     (needs kind, kubectl, kustomize, python3; the cluster pulls the image anonymously)
#
#   1. SQLite variant (StatefulSet + PVC): becomes Ready through its probes, the bootstrap administrator signs in, the pod is deleted,
#      comes back on the same volume and the administrator still signs in (the data survived).
#   2. PostgreSQL variant + the Unbound component, against a throw-away postgres:17 in the cluster: Ready, capabilities say postgres,
#      the Unbound sidecar validates DNSSEC (AD flag) and the pod has Dns:TrustAuthenticatedData set.
# NetworkPolicy objects are applied (the API server validates them); kind's default CNI may not ENFORCE them, so enforcement is not tested.
set -euo pipefail

ref=${1:?usage: kubernetes.sh <image reference>}
here=$(cd "$(dirname "$0")" && pwd)
work=$(mktemp -d)
cluster=eggmail-smoke
password=$(openssl rand -hex 12)Aa1
db_password=$(openssl rand -hex 12)
forward_pid=""

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "::group::cluster state"
    kubectl get pods,pvc,svc,networkpolicy -A 2>&1 | grep -v kube-system || true
    for ns in eggmail eggmail-pg; do
      kubectl -n "$ns" describe pods 2>&1 | tail -n 60 || true
      kubectl -n "$ns" logs --all-containers --tail 60 -l app.kubernetes.io/name=eggmail 2>&1 || true
    done
    echo "::endgroup::"
  fi
  [ -z "$forward_pid" ] || kill "$forward_pid" 2>/dev/null || true
  kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
  rm -rf "$work"
}
trap cleanup EXIT

# Copy the manifests; pin the image to the digest under test (the overlays use a tag for readability).
cp -R "$here/../kubernetes" "$work/kubernetes"
case "$ref" in
  *@sha256:*) pin="digest: ${ref##*@}" ;;
  *) pin="newTag: ${ref##*:}" ;;
esac
for overlay in sqlite postgres; do
  sed -i "s|^    newTag: .*|    ${pin}|" "$work/kubernetes/$overlay/kustomization.yaml"
done
# A copy of the PostgreSQL overlay with the Unbound component (the base overlays stay minimal).
mkdir "$work/kubernetes/postgres-unbound"
cat > "$work/kubernetes/postgres-unbound/kustomization.yaml" <<'EOF'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../postgres
components:
  - ../components/unbound
EOF

kustomize build "$work/kubernetes/sqlite" > "$work/sqlite.yaml"
kustomize build "$work/kubernetes/postgres-unbound" > "$work/postgres-unbound.yaml"
echo "manifests render: sqlite $(grep -c '^kind:' "$work/sqlite.yaml") objects, postgres+unbound $(grep -c '^kind:' "$work/postgres-unbound.yaml") objects"

echo "-- kind cluster"
kind create cluster --name "$cluster" --wait 180s

forward() { # forward <namespace> <local port>
  [ -z "$forward_pid" ] || kill "$forward_pid" 2>/dev/null || true
  kubectl -n "$1" port-forward svc/eggmail "$2:8080" >"$work/forward.log" 2>&1 &
  forward_pid=$!
  for _ in $(seq 1 30); do curl -fsS "http://127.0.0.1:$2/healthz" >/dev/null 2>&1 && return 0; sleep 1; done
  cat "$work/forward.log"; return 1
}

echo "-- 1. SQLite variant"
kubectl create namespace eggmail
kubectl -n eggmail create secret generic eggmail-admin --from-literal=admin-password="$password"
kubectl -n eggmail apply -f "$work/sqlite.yaml"
kubectl -n eggmail rollout status statefulset/eggmail --timeout=240s
kubectl -n eggmail get pvc data-eggmail-0 -o jsonpath='{.status.phase}{"\n"}' | grep -qx Bound
forward eggmail 18080
python3 "$here/smoke.py" --api http://127.0.0.1:18080 --admin-user admin --admin-password "$password" --expect-backend sqlite --stop-after signin
curl -fsS http://127.0.0.1:18080/readyz; echo

echo "-- the pod is deleted: the replacement mounts the same volume and the administrator is still there"
kubectl -n eggmail delete pod eggmail-0 --wait=true
kubectl -n eggmail rollout status statefulset/eggmail --timeout=240s
forward eggmail 18080
python3 "$here/smoke.py" --api http://127.0.0.1:18080 --admin-user admin --admin-password "$password" --expect-backend sqlite --stop-after signin
kubectl delete namespace eggmail --wait=false

echo "-- 2. PostgreSQL variant with the Unbound sidecar"
kubectl create namespace eggmail-pg
kubectl -n eggmail-pg apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: postgres
  labels: { app.kubernetes.io/name: postgres }
spec:
  containers:
    - name: postgres
      image: postgres:17
      env:
        - { name: POSTGRES_USER, value: eggmail }
        - { name: POSTGRES_PASSWORD, value: "${db_password}" }
        - { name: POSTGRES_DB, value: eggmail }
      ports: [{ containerPort: 5432 }]
      readinessProbe: { exec: { command: [pg_isready, -U, eggmail, -d, eggmail] }, periodSeconds: 3 }
---
apiVersion: v1
kind: Service
metadata: { name: postgres }
spec:
  selector: { app.kubernetes.io/name: postgres }
  ports: [{ port: 5432 }]
EOF
kubectl -n eggmail-pg wait --for=condition=Ready pod/postgres --timeout=180s
connection="Host=postgres;Database=eggmail;Username=eggmail;Password=${db_password}"
kubectl -n eggmail-pg create secret generic eggmail-admin --from-literal=admin-password="$password"
kubectl -n eggmail-pg create secret generic eggmail-postgres --from-literal=owner-connection-string="$connection" --from-literal=runtime-connection-string="$connection"
kubectl -n eggmail-pg apply -f "$work/postgres-unbound.yaml"
kubectl -n eggmail-pg rollout status deployment/eggmail --timeout=240s
forward eggmail-pg 18081
python3 "$here/smoke.py" --api http://127.0.0.1:18081 --admin-user admin --admin-password "$password" --expect-backend postgres --stop-after signin

echo "-- Unbound sidecar: a DNSSEC-signed name (cloudflare.com) answers with the AD flag; EggMail is configured to trust it"
# Unbound has just started: its first validations (trust anchor, DNSKEY fetches) can answer SERVFAIL for a moment, so ask a few times.
signed=""
for _ in $(seq 1 10); do
  signed=$(kubectl -n eggmail-pg exec deploy/eggmail -c unbound -- drill -D cloudflare.com @127.0.0.1 A || true)
  if echo "$signed" | grep -qE '^;; flags:.* ad[ ;]'; then break; fi
  sleep 3
done
if ! echo "$signed" | grep -qE '^;; flags:.* ad[ ;]'; then
  echo "$signed"
  echo "::group::Unbound diagnostics"
  kubectl -n eggmail-pg logs deploy/eggmail -c unbound --tail 40 || true
  kubectl -n eggmail-pg get networkpolicy -o name || true
  echo "::endgroup::"
  echo "::error::no AD flag from the sidecar"
  exit 1
fi
kubectl -n eggmail-pg get deploy/eggmail -o jsonpath='{.spec.template.spec.containers[?(@.name=="eggmail")].env[*].name}' | grep -q Dns__TrustAuthenticatedData
echo "kubernetes smoke test passed"
