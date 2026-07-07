# Deploying the Direct ID-JAG ADK Agent (`cloudshell_adk_idjag.py`)

End-to-end guide for deploying the ADK agent that performs the Okta **ID-JAG**
(Identity Assertion Authorization Grant / Cross-App Access) token exchange itself
and calls the **Smart Triage** MCP directly — no middleware adapter.

> Secrets (private key, client secret) live only in a git-ignored `.env`. This doc
> uses placeholders — never commit real secret values.

---

## 1. Architecture

### Component + data-flow diagram

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                              END USER (browser)                                │
└──────────────┬───────────────────────────────────────────────────▲───────────┘
     (1) chat / first-use consent                          (9) answer│
               ▼                                                      │
┌──────────────────────────────────────────────────────────────────┴───────────┐
│              GEMINI ENTERPRISE / AGENTSPACE  (Discovery Engine, global)         │
│  • Agent  →  reasoning engine  +  authorization (okta-authorization_native)     │
│  • Authorization.serverSideOauth2: clientId, clientSecret, tokenUri,            │
│    authorizationUri (?response_type=code&scope=...&resource=https://smart...)   │
│                                                                                 │
│  (2) STEP1/STEP2  OAuth login + code→token  ───────────►  Okta CUSTOM AS        │
│      authorize?...&resource=https://smarttriage.com/aud                          │
│      ◄──────────────  access_token  (aud = https://smarttriage.com/aud)         │
│  (3) inject token → session.state["okta-authorization_native-..."]              │
└──────────────┬───────────────────────────────────────────────────▲───────────┘
     (4) invoke agent (token in state)                  (8) tool result│
               ▼                                                      │
┌──────────────────────────────────────────────────────────────────┴───────────┐
│      VERTEX AI AGENT ENGINE  —  cloudshell_adk_idjag.py                         │
│                                                                                 │
│   _instruction_provider  (fires before tools/list)                              │
│     └─ _ensure_resource_token(session.state)                                    │
│          ├─ _find_token(state) ─────────────► user access_token                 │
│          ├─ STEP3  access_token → ID-JAG      ──►  Okta ORG AS                   │
│          │        (grant=token-exchange, audience=RESOURCE_AS, +client_assertion)│
│          ├─ STEP4  ID-JAG → resource token    ──►  Okta RESOURCE AS              │
│          │        (grant=jwt-bearer, assertion=ID-JAG, +client_assertion)       │
│          └─ _token_store.set(resource_token, exp)   [cached until exp-60s]       │
│                                                                                 │
│   SanitizingMcpToolset  ──(5) tools/list + tool calls──►  header:               │
│                                Authorization: Bearer <resource token>           │
└──────────────┬───────────────────────────────────────────────────▲───────────┘
     (6) MCP request (Bearer)                              (7) data  │
               ▼                                                      │
┌──────────────────────────────────────────────────────────────────┴───────────┐
│                SMART TRIAGE MCP   (https://smarttriage-1.onrender.com/mcp)       │
│                Okta-protected — validates the resource-AS access token          │
└─────────────────────────────────────────────────────────────────────────────── ┘
```

### Okta authorization servers involved

```
Okta tenant  (itpoktane24.oktapreview.com)
├─ CUSTOM AS   aus10mn2tcfNdnFbh1d8   → issues the USER access_token (aud=smarttriage)   [STEP1/2, Agentspace]
├─ ORG AS      /oauth2/v1             → token-exchange: access_token → ID-JAG            [STEP3, agent]
└─ RESOURCE AS auszrn0q77tsoa7001d7   → jwt-bearer: ID-JAG → resource token              [STEP4, agent]

Agent identity (client_assertion signer): AI agent  wlp10mv0rrvI9zG9M1d8  (RSA key kid=fa21…c38c)
Delegation / Cross-App-Access policy authorizes wlp10mv0… to exchange the user token for Smart Triage.
```

### Token-exchange sequence (what the agent owns)

```
access_token (aud=https://smarttriage.com/aud)          ← from Agentspace (session.state)
        │
        │  STEP3  POST {ORG}/oauth2/v1/token
        │         grant_type            = urn:ietf:params:oauth:grant-type:token-exchange
        │         subject_token         = <access_token>
        │         subject_token_type    = urn:ietf:params:oauth:token-type:access_token
        │         requested_token_type  = urn:ietf:params:oauth:token-type:id-jag
        │         audience              = {ORG}/oauth2/{RESOURCE_AUTHZ_SERVER}
        │         scope                 = smarttriage:read
        │         client_assertion      = private_key_jwt (aud = this endpoint)
        ▼
   ID-JAG  (issued_token_type = ...id-jag, ~300s, one-time use)
        │
        │  STEP4  POST {ORG}/oauth2/{RESOURCE_AUTHZ_SERVER}/v1/token
        │         grant_type            = urn:ietf:params:oauth:grant-type:jwt-bearer
        │         assertion             = <ID-JAG>
        │         client_assertion      = private_key_jwt (aud = this endpoint)
        ▼
   resource token  (Bearer, ~3600s, scope=smarttriage:read)  →  Smart Triage MCP
```

- **STEP1/STEP2** are performed by Agentspace (login + code→token). They must use the
  **Custom AS** with a `resource` param so the issued token's `aud` is the resource.
  An **Org-AS** token is rejected at STEP3.
- **STEP3/STEP4** are performed by the agent (`_exchange_for_resource_token`), signing a
  `private_key_jwt` client assertion with the agent's RSA key.
- The resource token is cached (`_token_store`) until ~60s before expiry.

### Where the `resource` value comes from (`resource` vs `audience`)

A common point of confusion: **the agent code does NOT read the `resource` value from
anywhere.** After the `AT_RESOURCE_URI` fallback was removed, `resource`
(`https://smarttriage.com/aud`) appears **nowhere** in the agent's STEP3/STEP4 requests.

The `resource` is set **at login (by Agentspace), not in the agent**, and it materializes
as the **`aud` claim inside the access token** the agent receives:

```
Authorizer config (Discovery Engine)
  authorizationUri = ".../aus10mn2tcfNdnFbh1d8/v1/authorize?...&resource=https%3A%2F%2Fsmarttriage.com%2Faud"
        │
        ▼  Agentspace does STEP1/STEP2 (login + code→token) — sends resource= to Okta
Okta Custom AS  →  mints an access_token with  aud = "https://smarttriage.com/aud"
        │
        ▼  Agentspace drops the token into session.state["okta-authorization_native-…"]
ADK agent  →  _find_token(state) reads that token; its aud is ALREADY "https://smarttriage.com/aud"
```

So the agent just receives a token whose `aud` was already bound — it never sees or sends a
`resource` parameter. Don't confuse `resource` with the **`audience`** the agent *does*
send at STEP3 (a different value):

| Term | Value | Where the agent gets it | What it's for |
|---|---|---|---|
| `resource` (RFC 8707) | `https://smarttriage.com/aud` | **NOT in agent code** — set on the authorizer's `authorizationUri`; becomes the token's `aud` | Binds the target app onto the user's access token at login |
| `audience` (STEP3) | `https://itpoktane24.oktapreview.com/oauth2/auszrn0q77tsoa7001d7` | env var `IDJAG_AUDIENCE` → `_cfg("IDJAG_AUDIENCE")` | Tells Okta which resource authz server the ID-JAG targets |

**Why:** Okta's Org-AS token-exchange endpoint **rejects** a `resource` param (that was the
`invalid_target` error). It keys the ID-JAG on the subject token's existing `aud` (set by
the login-time `resource`) plus the `audience` param. If you'd rather not depend on the
fragile authorize-URL query param, use **option 1**: configure the Custom AS
`aus10mn2tcfNdnFbh1d8` to stamp `aud=https://smarttriage.com/aud` by default — the agent
behaves identically and the authorizer URI needs no `resource=`.

---

## 2. Prerequisites

- A Google Cloud project with Vertex AI enabled (this guide uses `jo-dev-portal`).
- A GCS staging bucket (`gs://jo-dev-portal-adk-staging`).
- Okta tenant with:
  - A **Custom Authorization Server** (e.g. `aus10mn2tcfNdnFbh1d8`) that issues the user
    access token, configured to carry `aud=https://smarttriage.com/aud`.
  - A **resource authorization server** for Smart Triage (e.g. `auszrn0q77tsoa7001d7`).
  - An **AI agent identity** (workload principal, e.g. `wlp10mv0rrvI9zG9M1d8`) with an
    RSA key pair registered, and a **Cross-App Access / delegation policy** authorizing it
    to exchange the user token for the Smart Triage ID-JAG.
  - An OIDC client app (e.g. `0oazcw1tofOwmHfPD1d7`) used by the Agentspace authorizer.
- `cloudshell_adk_idjag.py` (the agent) and `reset_agent_auth.py` (+ optional
  `reset_native_agent_auth.sh`) in your working folder.

---

## 3. `.env` parameters

The agent reads these at runtime via `os.getenv()` (locally from `.env`; on the deployed
worker from `env_vars`). `PROJECT` / `LOCATION` / `BUCKET` are hardcoded in the `.py`, so
they are **not** in `.env`.

| Env var | Example / value | Purpose |
|---|---|---|
| `OKTA_DOMAIN` | `https://itpoktane24.oktapreview.com` | Okta org base URL |
| `IDJAG_AUDIENCE` | `https://itpoktane24.oktapreview.com/oauth2/auszrn0q77tsoa7001d7` | STEP3 `audience` (the resource authz server) |
| `RESOURCE_AUTHZ_SERVER` | `auszrn0q77tsoa7001d7` | id used in the STEP4 token endpoint |
| `IDJAG_SCOPES` | `smarttriage:read` | STEP3 `scope` |
| `AT_AI_AGENT_ID` | `wlp10mv0rrvI9zG9M1d8` | `iss`/`sub` of the client assertion (agent identity) |
| `AT_AGENT_PRIVATE_KEY_ID` | `fa21…c38c` | `kid` of the signing key |
| `AT_AGENT_PRIVATE_KEY_PEM` | *(RSA PEM)* | private key signing the client assertion |
| `SMARTTRIAGE_MCP_URL` | `https://smarttriage-1.onrender.com/mcp` | Smart Triage MCP endpoint |

### Create `.env` in Cloud Shell

```bash
cd ~/native   # folder containing cloudshell_adk_idjag.py

cat > .env <<'EOF'
OKTA_DOMAIN=https://itpoktane24.oktapreview.com
IDJAG_AUDIENCE=https://itpoktane24.oktapreview.com/oauth2/auszrn0q77tsoa7001d7
RESOURCE_AUTHZ_SERVER=auszrn0q77tsoa7001d7
IDJAG_SCOPES=smarttriage:read
AT_AI_AGENT_ID=wlp10mv0rrvI9zG9M1d8
AT_AGENT_PRIVATE_KEY_ID=fa2160f751150a2076cb1d073465c38c
SMARTTRIAGE_MCP_URL=https://smarttriage-1.onrender.com/mcp
AT_AGENT_PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----
<PASTE ALL PEM LINES HERE>
-----END PRIVATE KEY-----"
EOF
```

`.env` is git-ignored — never commit it. The quoted heredoc (`<<'EOF'`) keeps the PEM
literal, and python-dotenv supports the multiline quoted value.

---

## 4. Deploy from Google Cloud Shell

```bash
# 1. Set project
gcloud config set project jo-dev-portal

# 2. (If ADC complains) authorize application-default credentials
gcloud auth application-default login

# 3. Upload cloudshell_adk_idjag.py + create .env (section 3)

# 4. Install deps needed to RUN the deploy script
pip install --user google-adk==1.33.0 \
  "google-cloud-aiplatform[adk,reasoningengine]" \
  httpx pyjwt cryptography python-dotenv

# 5. Ensure the staging bucket exists
gcloud storage buckets describe gs://jo-dev-portal-adk-staging >/dev/null 2>&1 \
  || gcloud storage buckets create gs://jo-dev-portal-adk-staging --location=us-central1

# 6. Deploy (runs AgentEngine.create under the __main__ guard)
python cloudshell_adk_idjag.py
```

On success it prints:

```
Done! Resource name: projects/jo-dev-portal/locations/us-central1/reasoningEngines/<ID>
```

- `_build_env_vars()` copies the 8 `.env` keys into `env_vars`, so the deployed worker's
  `os.environ` has them (private key stays out of the cloudpickle payload).
- **`create()` makes a NEW engine each run.** Note the new resource name and re-point your
  Gemini agent to it (section 6). Delete stale engines (section 9).
- If deploy raises `TypeError: unexpected keyword 'env_vars'`, your SDK version lacks
  `env_vars` support — switch to baked constants.

---

## 5. Configure the Agentspace (Gemini Enterprise) authorization

The authorizer performs STEP1/STEP2. **Agentspace only appends `client_id`, `state`,
`redirect_uri`** — you must bake `response_type`, `scope`, and `resource` into the
Authorization URI yourself.

Authorization resource (Discovery Engine, location `global`):

- **clientId**: `0oazcw1tofOwmHfPD1d7`
- **clientSecret**: *(the app secret)*
- **tokenUri**: `https://itpoktane24.oktapreview.com/oauth2/aus10mn2tcfNdnFbh1d8/v1/token`
- **authorizationUri**:
  ```
  https://itpoktane24.oktapreview.com/oauth2/aus10mn2tcfNdnFbh1d8/v1/authorize?response_type=code&scope=openid%20profile%20email%20offline_access&resource=https%3A%2F%2Fsmarttriage.com%2Faud
  ```

Create it via the API (the UI dialog has no field for extra authorize params):

```bash
PROJECT=jo-dev-portal
PROJNUM=531214469428
CLIENT_SECRET='<client secret>'

curl -s -X POST \
  "https://discoveryengine.googleapis.com/v1alpha/projects/${PROJNUM}/locations/global/authorizations?authorizationId=okta-authorization_native" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "X-Goog-User-Project: ${PROJECT}" -H "Content-Type: application/json" \
  -d '{
    "name": "projects/'"${PROJNUM}"'/locations/global/authorizations/okta-authorization_native",
    "displayName": "okta-authorization_native",
    "serverSideOauth2": {
      "clientId": "0oazcw1tofOwmHfPD1d7",
      "clientSecret": "'"$CLIENT_SECRET"'",
      "tokenUri": "https://itpoktane24.oktapreview.com/oauth2/aus10mn2tcfNdnFbh1d8/v1/token",
      "authorizationUri": "https://itpoktane24.oktapreview.com/oauth2/aus10mn2tcfNdnFbh1d8/v1/authorize?response_type=code&scope=openid%20profile%20email%20offline_access&resource=https%3A%2F%2Fsmarttriage.com%2Faud"
    }
  }'
```

> The state-key the agent looks for (`AUTH_ID_PREFIX` in the code) must match this
> authorization id prefix (`okta-authorization_native`).

Update the URI later (in place, even while linked to an agent):

```bash
curl -s -X PATCH \
  "https://discoveryengine.googleapis.com/v1alpha/projects/${PROJNUM}/locations/global/authorizations/okta-authorization_native?updateMask=serverSideOauth2.authorizationUri" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "X-Goog-User-Project: ${PROJECT}" -H "Content-Type: application/json" \
  -d '{"serverSideOauth2":{"authorizationUri":"...NEW URI..."}}'
```

---

## 6. Register / link the agent in Gemini Enterprise

Create the ADK ("Native") agent in Gemini Enterprise and attach:
- the deployed **reasoning engine** resource name from section 4, and
- the **authorization** `okta-authorization_native`.

Find which agent a given authorization is linked to:

```bash
PROJECT=jo-dev-portal
ENGINE=bc-app_1782050792358
curl -s "https://discoveryengine.googleapis.com/v1alpha/projects/531214469428/locations/global/collections/default_collection/engines/${ENGINE}/assistants/default_assistant/agents" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "X-Goog-User-Project: ${PROJECT}" \
| jq -r '.agents[]? | select(tostring | test("okta-authorization_native")) | "\(.name)\n  \(.displayName)"'
```

---

## 7. Verify

### End user authorizes
First use of the agent shows an Okta consent popup → user signs in.

### Confirm Agentspace passed the token (ask the agent: `dump_state`)
`dump_state` returns an `agentspace_auth` block:
```json
"agentspace_auth": {
  "agentspace_token_received": true,
  "matched_key": "okta-authorization_native-...",
  "subject_claims": {"iss": ".../oauth2/aus10mn2tcfNdnFbh1d8", "aud": "https://smarttriage.com/aud", ...},
  "resource_token_cached": true
}
```

### Read the ID-JAG trace (Cloud Logging)
```bash
gcloud logging read \
  'resource.type="aiplatform.googleapis.com/ReasoningEngine" AND textPayload:"[idjag]"' \
  --project=jo-dev-portal --freshness=1h --limit=40 \
  --format='value(timestamp,textPayload)' --order=asc
```
Expected sequence: `STEP1/2 … access_token received` → `STEP3 … response[200]` →
`STEP3 ok: ID-JAG obtained` → `STEP4 … response[200]` → `STEP4 ok: resource token cached`.
Secrets are redacted as `<name: N chars>`.

> The exchange logs only on a **cache miss**. On a warm worker with a valid cached token,
> no trace prints — redeploy (cold worker) or wait out the ~1hr expiry to see a fresh run.
> The `Regional Access Boundary … Account not found` line is a benign gcloud warning.

---

## 8. Force the end user to re-authenticate

Agentspace caches per-user consent keyed to the authorization **id**. Recreating the *same*
id keeps the old consent (no re-prompt); **rotating to a new id** clears it and forces a
fresh prompt. Two tools do this:

- **`reset_native_agent_auth.sh`** — thin wrapper with **this** deployment's values
  (Native Agent `16214105338853924015`, engine `bc-app_1782050792358`, the Custom-AS
  URIs) hardcoded. Use it for the **one-command** reset of the Native Agent.
- **`reset_agent_auth.py`** — the underlying, fully-parameterized script. Use it directly
  for **any other agent / engine / OAuth app** by passing `--agent-id`, `--auth-base`,
  `--engine`, `--auth-uri`, `--token-uri`, `--client-id`, `--client-secret`.

### When to use `reset_native_agent_auth.sh`

Run it whenever you need the Native Agent's end user (e.g. tina) to be **prompted to
authorize again** instead of silently reusing a cached consent — typically:

- **Demos / clean runs** — you want the reviewer to see the consent flow from scratch.
- **After changing the authorization** — new `scope`, `resource`, `authorizationUri`,
  client, or token endpoint; the old cached consent would otherwise mask the change.
- **Testing the auth path end-to-end** — to re-exercise STEP1/STEP2 → STEP3/STEP4.
- **A user is stuck / consent looks stale** — force a fresh grant.

```bash
chmod +x reset_native_agent_auth.sh
./reset_native_agent_auth.sh          # extra flags pass through, e.g. --client-secret '...'
```

Equivalent explicit invocation of the underlying script:

```bash
python3 reset_agent_auth.py \
  --agent-id 16214105338853924015 \
  --auth-base okta-authorization_native \
  --engine bc-app_1782050792358 \
  --auth-uri 'https://itpoktane24.oktapreview.com/oauth2/aus10mn2tcfNdnFbh1d8/v1/authorize?response_type=code&scope=openid%20profile%20email%20offline_access&resource=https%3A%2F%2Fsmarttriage.com%2Faud' \
  --token-uri 'https://itpoktane24.oktapreview.com/oauth2/aus10mn2tcfNdnFbh1d8/v1/token'
```

Either way it creates `okta-authorization_native-<timestamp>`, relinks the agent, and
deletes the old auth. **Also redeploy** (or wait ~1hr) so the worker's cached resource
token (`_token_store`) doesn't mask the test.

> The script needs the OAuth client secret. Prefer supplying it at runtime via
> `--client-secret` or the `OKTA_CLIENT_SECRET` env var rather than hardcoding it.

---

## 9. Cleanup

```bash
# List reasoning engines and delete stale ones (keep the one the agent points to)
gcloud ai reasoning-engines list --project=jo-dev-portal --region=us-central1 \
  --format='table(name, displayName, createTime)'
gcloud ai reasoning-engines delete <ENGINE_ID> --project=jo-dev-portal --region=us-central1

# List authorizations
PROJECT=jo-dev-portal
curl -s "https://discoveryengine.googleapis.com/v1alpha/projects/${PROJECT}/locations/global/authorizations" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "X-Goog-User-Project: ${PROJECT}" | jq -r '.authorizations[].name'

# Delete one (must be UNLINKED from any agent first)
curl -s -X DELETE \
  "https://discoveryengine.googleapis.com/v1alpha/projects/531214469428/locations/global/authorizations/<AUTH_ID>" \
  -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  -H "X-Goog-User-Project: ${PROJECT}"
```

---

## 10. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Popup: **`unsupported_response_type`** | `response_type` missing — Agentspace doesn't add it | Bake `response_type=code&scope=...` into `authorizationUri` (section 5) |
| STEP3 **`invalid_target: 'resource' is invalid`** | `resource` sent on the token-exchange (Org AS doesn't accept it) | Don't send `resource` on STEP3 — uses `audience` only (current code is correct) |
| STEP3 **`invalid_request: no delegation policy authorizes this token`** | (a) token `aud` isn't `https://smarttriage.com/aud`, or (b) Okta Cross-App Access grant missing | Check logged `subject_token claims.aud`. Fix authorize-time `resource`, or configure the Okta delegation/XAA policy |
| MCP **`401 Bearer token required`** | `_token_store` empty (exchange didn't run/failed) | Read `[idjag]` logs; ensure STEP3/STEP4 succeed and the instruction provider ran |
| `dump_state` shows empty `state_keys` | `tool_context.state` is empty by design | Use `agentspace_auth` block / instruction-provider logs instead |
| No `[idjag]` logs | cache hit (warm worker) or no recent chat | Redeploy (cold worker) then send one message; widen `--freshness` |
| Delete auth: **`FAILED_PRECONDITION … linked to a resource`** | Authorization is attached to an agent | Rotate via `reset_agent_auth.py`, or recreate the agent (the agent `authorizations` field is immutable) |
| Deploy: `TypeError: unexpected keyword 'env_vars'` | SDK version lacks `env_vars` | Bake config as module constants instead |

---

## 11. Second resource: GitHub via Okta STS (SDK variant)

`cloudshell_adk_idjag_sdk.py` is a variant that (a) runs the Smart Triage ID-JAG
exchange through Okta's **`okta-client-python`** SDK (`CrossAppAccessFlow`) instead
of hand-rolled httpx, and (b) adds a **second resource connection — the GitHub MCP —
via the Okta STS / brokered-consent flow**. Both resources are connected to the same
AI agent (`wlp10mv0rrvI9zG9M1d8`) in Okta and both exchanges start from the same
Agentspace access token.

> The manual variant `cloudshell_adk_idjag.py` is Smart Triage only. Deploy the SDK
> variant as a separate Agent Engine ("Jo direct ID-JAG + GitHub STS agent (SDK)").

### GitHub STS flow (single RFC 8693 exchange)

Unlike ID-JAG's two steps, GitHub is one token exchange (SDK `TokenExchangeFlow`)
at the Org AS `{ORG}/oauth2/v1/token`:

```
grant_type            = urn:ietf:params:oauth:grant-type:token-exchange
requested_token_type  = urn:okta:params:oauth:token-type:oauth-sts
subject_token         = <Agentspace access token>
subject_token_type    = urn:ietf:params:oauth:token-type:access_token
client_assertion_type = urn:ietf:params:oauth:client-assertion-type:jwt-bearer
client_assertion      = <private_key_jwt, aud = this token endpoint>   (SDK key_provider-signed)
resource              = <GITHUB_RESOURCE_ORN>                          (Okta ORN, not the API URL)
```

- **200** → `access_token` → cached in a **second store** and used as `Bearer` to the
  GitHub MCP (`GITHUB_MCP_URL`).
- **400 `interaction_required`** (brokered consent not yet granted) →
  ```json
  { "error": "interaction_required", "interaction_uri": "https://.../oauth2/v1/sts/redirect?dataHandle=..." }
  ```
  The agent captures `interaction_uri` and the instruction provider appends an
  "🔐 Authorize GitHub →" directive, so the model renders it as a clickable consent
  link and waits. After the user consents, the same exchange returns `200` + token.

The GitHub MCP toolset tolerates a pre-consent `401` on `tools/list` (returns no
tools until authorized) so Smart Triage still works; GitHub tools light up once a
token is cached.

### Extra `.env` keys (add to the base 8)

```
GITHUB_MCP_URL=https://api.githubcopilot.com/mcp
GITHUB_RESOURCE_ORN=orn:oktapreview:idp:github
# Optional — only if the SDK derives the wrong Org-AS token URL:
# OKTA_ORG_ISSUER=https://itpoktane24.oktapreview.com/oauth2/v1
```

### Deps (SDK variant)

```bash
pip install --user google-adk==1.33.0 "google-cloud-aiplatform[adk,reasoningengine]" \
  mcp httpx okta-client-python cryptography python-dotenv
python cloudshell_adk_idjag_sdk.py
```

### Verify (logs use the `[idjag-sdk]` prefix)

```bash
gcloud logging read \
  'resource.type="aiplatform.googleapis.com/ReasoningEngine" AND textPayload:"[idjag-sdk]"' \
  --project=jo-dev-portal --freshness=15m --limit=40 \
  --format='value(timestamp,textPayload)' --order=asc
```

- Smart Triage: `CrossAppAccessFlow.start()` → `resume()` → resource token cached.
- GitHub: `GitHub STS access_token -> oauth-sts` → `GitHub STS response`; on
  `interaction_required` the `interaction_uri` is logged and injected into the prompt.
- `dump_state` reports `github_token_cached` and `github_interaction_uri`.

If GitHub STS returns `invalid_target` / `invalid_resource`, the `GITHUB_RESOURCE_ORN`
value is wrong for the `resource` param — fix it to what Okta expects.

---

## 12. Notes / production hardening

- The token stores (`_token_store`, and `_gh_token_store` in the SDK variant) are
  **shared module-level singletons** — fine for single-user prototype testing;
  replace with `ContextVar`s for multi-user isolation before production. Note this
  also means GitHub tools only appear on a worker whose store already holds a token,
  so after first consent a fresh chat/turn may be needed for them to show.
- Remove the `dump_state` diagnostic tool (and the `[idjag]` verbose traces) before
  production.
- Rotate the RSA private key after prototyping; keep it only in the git-ignored `.env` /
  the deploy `env_vars`.
- Prefer binding `aud=https://smarttriage.com/aud` in the **Custom AS** config directly,
  rather than relying on the fragile `resource=` query param on the authorize URL.
