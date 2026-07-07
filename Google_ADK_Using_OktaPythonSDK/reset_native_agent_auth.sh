#!/usr/bin/env bash
#
# reset_native_agent_auth.sh — force re-consent for the "Native Agent" (ADK, direct
# ID-JAG) by rotating its OAuth authorization to a fresh id.
#
# Thin wrapper over reset_agent_auth.py with this agent's values hardcoded:
#   agent  : 16214105338853924015  (Native Agent)
#   engine : bc-app_1782050792358
#   auth   : okta-authorization_native-<timestamp>  (Okta Custom AS aus10mn2tcfNdnFbh1d8)
#
# Run in Cloud Shell (uses your gcloud login). Any extra flags are passed through
# to reset_agent_auth.py, e.g.:  ./reset_native_agent_auth.sh --client-secret '...'
#
set -euo pipefail

AGENT_ID="16214105338853924015"
AUTH_BASE="okta-authorization_native"
ENGINE="bc-app_1782050792358"
AUTH_URI="https://itpoktane24.oktapreview.com/oauth2/aus10mn2tcfNdnFbh1d8/v1/authorize?response_type=code&scope=openid%20profile%20email%20offline_access&resource=https%3A%2F%2Fsmarttriage.com%2Faud"
TOKEN_URI="https://itpoktane24.oktapreview.com/oauth2/aus10mn2tcfNdnFbh1d8/v1/token"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

exec python3 "${SCRIPT_DIR}/reset_agent_auth.py" \
  --agent-id  "${AGENT_ID}" \
  --auth-base "${AUTH_BASE}" \
  --engine    "${ENGINE}" \
  --auth-uri  "${AUTH_URI}" \
  --token-uri "${TOKEN_URI}" \
  "$@"
