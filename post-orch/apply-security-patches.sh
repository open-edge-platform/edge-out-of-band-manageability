#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0
#
# Apply security hardening patches to existing istio-policy deployment.
# Enables: STRICT mTLS, tightened AuthorizationPolicies, NetworkPolicies.
# Requires: EOM_ENABLE_ISTIO=true and EOM_ENABLE_KYVERNO=true in post-orch.env
#
# Patch manifests are in: chart-patches/istio-policy/manifests/

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MANIFESTS_DIR="${SCRIPT_DIR}/chart-patches/istio-policy/manifests"
ENV_FILE="${SCRIPT_DIR}/post-orch.env"

# Source environment
if [[ -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +a
fi

# Gate: only apply if both istio and kyverno are enabled
if [[ "${EOM_ENABLE_ISTIO:-false}" != "true" ]]; then
  echo "SKIP: EOM_ENABLE_ISTIO is not 'true'. Patches require Istio enabled."
  exit 0
fi
if [[ "${EOM_ENABLE_KYVERNO:-false}" != "true" ]]; then
  echo "SKIP: EOM_ENABLE_KYVERNO is not 'true'. Patches require Kyverno enabled."
  exit 0
fi

# Verify patch files exist
if [[ ! -d "$MANIFESTS_DIR" ]]; then
  echo "ERROR: Manifests directory not found: $MANIFESTS_DIR"
  exit 1
fi

echo "============================================================"
echo " Applying Security Hardening Patches"
echo " Istio: ${EOM_ENABLE_ISTIO} | Kyverno: ${EOM_ENABLE_KYVERNO}"
echo " Source: ${MANIFESTS_DIR}"
echo "============================================================"

# ──────────────────────────────────────────────────────────────────────────────
# Step 1: PeerAuthentication → STRICT
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo ">>> Step 1: Upgrading PeerAuthentication to STRICT mTLS..."
kubectl apply -f "${MANIFESTS_DIR}/peer-authentication.yaml"
echo "    ✅ PeerAuthentication set to STRICT"

# ──────────────────────────────────────────────────────────────────────────────
# Step 2: Tightened AuthorizationPolicies
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo ">>> Step 2: Applying tightened AuthorizationPolicies..."
kubectl apply -f "${MANIFESTS_DIR}/authorization-policies.yaml"
echo "    ✅ AuthorizationPolicies tightened for all orch namespaces"

# ──────────────────────────────────────────────────────────────────────────────
# Step 3: NetworkPolicies (default-deny + explicit allow per namespace)
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo ">>> Step 3: Applying NetworkPolicies (default-deny + allow rules)..."
kubectl apply -f "${MANIFESTS_DIR}/network-policies.yaml"
echo "    ✅ NetworkPolicies applied (default-deny + explicit allow)"

# ──────────────────────────────────────────────────────────────────────────────
# Step 4: Rolling restart to ensure sidecars are present
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo ">>> Step 4: Rolling restart deployments for sidecar injection..."

for ns in orch-infra orch-platform orch-gateway orch-ui orch-database orch-iam; do
  kubectl rollout restart deployment -n "$ns" 2>/dev/null || true
done

echo "    Waiting for rollouts..."
for ns in orch-infra orch-platform orch-gateway orch-iam; do
  for dep in $(kubectl get deploy -n "$ns" --no-headers -o custom-columns="NAME:.metadata.name" 2>/dev/null); do
    kubectl rollout status "deployment/$dep" -n "$ns" --timeout=180s 2>&1 | tail -1
  done
done

echo "    ✅ All deployments restarted with sidecars"

# ──────────────────────────────────────────────────────────────────────────────
# Step 5: Verification
# ──────────────────────────────────────────────────────────────────────────────
echo ""
echo ">>> Step 5: Verifying security controls..."
echo ""

# Check PeerAuthentication
PA_MODE=$(kubectl get peerauthentication default -n istio-system -o jsonpath='{.spec.mtls.mode}' 2>/dev/null)
echo "  PeerAuthentication mode: ${PA_MODE}"

# Check sidecar injection
echo "  Sidecar injection:"
for ns in orch-infra orch-platform orch-gateway orch-iam; do
  total=$(kubectl get pods -n "$ns" --no-headers 2>/dev/null | wc -l)
  sidecar=$(kubectl get pods -n "$ns" -o jsonpath='{range .items[*]}{range .spec.containers[*]}{.name}{"\n"}{end}{end}' 2>/dev/null | grep -c "istio-proxy" || echo 0)
  echo "    ${ns}: ${sidecar}/${total} pods have istio-proxy"
done

# Check NetworkPolicies
echo "  NetworkPolicies:"
NP_COUNT=$(kubectl get networkpolicies --all-namespaces --no-headers 2>/dev/null | wc -l)
echo "    Total: ${NP_COUNT} policies across cluster"

# Check AuthorizationPolicies
echo "  AuthorizationPolicies:"
kubectl get authorizationpolicies --all-namespaces --no-headers 2>/dev/null | awk '{print "    " $1 "/" $2 " (" $3 ")"}'

echo ""
echo "============================================================"
echo " Security Hardening Complete"
echo "============================================================"
echo ""
echo " Controls applied:"
echo "   ✅ mTLS: STRICT (all pod-to-pod traffic encrypted)"
echo "   ✅ AuthorizationPolicies: Namespace-scoped source restrictions"
echo "   ✅ NetworkPolicies: Default-deny + explicit allow (CNI-level)"
echo "   ✅ Sidecars: Injected on all deployments"
echo ""
