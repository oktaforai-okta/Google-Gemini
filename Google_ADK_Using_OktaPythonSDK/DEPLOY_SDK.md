# Deploying the SDK Agent (`cloudshell_adk_idjag_sdk.py`)

End-to-end guide for the ADK agent that connects **two Okta resource connections** for
the same AI agent, both starting from the Agentspace access token:

- **Smart Triage** — Cross-App Access / **ID-JAG**, via the `okta-client-python` SDK
  (`CrossAppAccessFlow`).
- **GitHub MCP** — Okta **STS / brokered consent**, a single RFC 8693 token exchange
  done with **manual `httpx`** (see note in §1).

> Secrets (private key) live only in a git-ignored `.env`. This doc uses placeholders.
> The sibling `DEPLOY.md` documents the adapter-free **manual** variant
> (`cloudshell_adk_idjag.py`), which is Smart Triage only.

---

## 1. Architecture

```
┌──────────────────────────── END USER (browser) ─────────────────────────────┐
└───────────────┬──────────────────────────────────────────────▲──────────────┘
    (1) chat / consent                                  (9) answer│
                ▼                                                 │
┌───────────────────────────── GEMINI ENTERPRISE / AGENTSPACE ─────────────────┐
│  (2) OAuth login via Okta CUSTOM AS (authorizationUri carries resource=...)   │
│      → access_token (aud = https://smarttriage.com/aud)                       │
│  (3) token → session.state["okta-authorization_native..."]                    │
└───────────────┬──────────────────────────────────────────────▲──────────────┘
    (4) invoke agent (token in state)                (8) tool result│
                ▼                                                 │
┌──────────── VERTEX AI AGENT ENGINE — cloudshell_adk_idjag_sdk.py ────────────┐
│  _instruction_provider → _ensure_tokens(session.state):                       │
│    • Smart Triage: CrossAppAccessFlow.start()->resume()  (SDK)  → _token_store │
│    • GitHub:       POST {ORG}/oauth2/v1/token  oauth-sts  (httpx)→ _gh_token_store│
│         └─ 200 → GitHub token;  interaction_required → interaction_uri (consent)│
│  Toolset A (Smart Triage MCP)   Bearer from _token_store                       │
│  Toolset B (GitHub MCP)         Bearer from _gh_token_store (tolerant 401)     │
└───────────────┬──────────────────────────────────────────────▲──────────────┘
    (5/6) tools/list + tool calls (Bearer)             (7) data │
                ▼                                                 │
   Smart Triage MCP (SMARTTRIAGE_MCP_URL)      GitHub MCP (GITHUB_MCP_URL)
```

**Okta authorization servers**

```
CUSTOM AS   aus10mn2tcfNdnFbh1d8   → issues the USER access_token (aud=smarttriage)  [Agentspace login]
ORG AS      /oauth2/v1             → ID-JAG (Smart Triage) AND oauth-sts (GitHub)    [agent]
RESOURCE AS auszrn0q77tsoa7001d7   → jwt-bearer: ID-JAG → Smart Triage resource token[agent, via SDK]
```

**Why GitHub uses manual httpx (not the SDK):** CONFIRMED on 2026-07-07 that the SDK's
`TokenExchangeFlow` parses an `interaction_required` response into an `OAuth2Error`
keeping only `error`/`error_description` and **drops Okta's non-standard `interaction_uri`**
(`additional_fields` came back `{}`). Even Okta's own notebook sample reads
`interaction_uri` from a side-channel global, not the SDK. Manual `httpx` reads the full
JSON body, so we can surface the `sts/redirect` consent link. Smart Triage's ID-JAG has
no such consent step, so it stays on the SDK.

---

## 2. Prerequisites

- GCP project with Vertex AI enabled + a GCS staging bucket.
- Okta tenant with: the Custom AS (issues the user token with `aud`), the Smart Triage
  resource authz server, an AI agent identity (`wlp...`) + RSA key + Cross-App-Access
  delegation policy, a GitHub **MCP-server resource connection** attached to that agent,
  and an OIDC client for the Agentspace authorizer.
- The files `cloudshell_adk_idjag_sdk.py` (and `reset_agent_auth.py` /
  `reset_native_agent_auth.sh` for forcing re-auth).

---

## 3. `.env` parameters

Read at runtime via `os.getenv()` (from `.env` locally; from `env_vars` on the worker).
The code's built-in defaults are generic, so **set `GCP_PROJECT` / `GCP_BUCKET`** (and the
Okta/GitHub values) explicitly.

| Env var | Example | Purpose |
|---|---|---|
| `GCP_PROJECT` | `jo-dev-portal` | Vertex AI project |
| `GCP_LOCATION` | `us-central1` | Agent Engine region |
| `GCP_BUCKET` | `gs://jo-dev-portal-adk-staging` | ADK staging bucket |
| `OKTA_DOMAIN` | `https://itpoktane24.oktapreview.com` | Okta org base URL |
| `OKTA_ORG_ISSUER` | *(optional)* | Org-AS issuer for the SDK (default `OKTA_DOMAIN`) |
| `IDJAG_AUDIENCE` | `https://itpoktane24.oktapreview.com/oauth2/auszrn0q77tsoa7001d7` | Smart Triage resource AS (SDK `target`) |
| `RESOURCE_AUTHZ_SERVER` | `auszrn0q77tsoa7001d7` | Smart Triage resource authz server id |
| `IDJAG_SCOPES` | `smarttriage:read` | Smart Triage scope |
| `AT_AI_AGENT_ID` | `wlp10mv0rrvI9zG9M1d8` | client-assertion iss/sub (agent identity) |
| `AT_AGENT_PRIVATE_KEY_ID` | `fa21…c38c` | signing key `kid` |
| `AT_AGENT_PRIVATE_KEY_PEM` | *(RSA PEM)* | signs the client assertion |
| `SMARTTRIAGE_MCP_URL` | `https://smarttriage-1.onrender.com/mcp` | Smart Triage MCP endpoint |
| `GITHUB_MCP_URL` | `https://api.githubcopilot.com/mcp` | GitHub MCP endpoint |
| `GITHUB_RESOURCE_ORN` | `orn:oktapreview:idp:github` | Okta resource ORN for the GitHub STS `resource=` |
| `AUTH_ID_PREFIX` | *(optional)* | state-key prefix (default `okta-authorization_native`) |

### Create `.env` in Cloud Shell

```bash
cd ~/native   # folder containing cloudshell_adk_idjag_sdk.py

cat > .env <<'EOF'
GCP_PROJECT=jo-dev-portal
GCP_LOCATION=us-central1
GCP_BUCKET=gs://jo-dev-portal-adk-staging
OKTA_DOMAIN=https://itpoktane24.oktapreview.com
IDJAG_AUDIENCE=https://itpoktane24.oktapreview.com/oauth2/auszrn0q77tsoa7001d7
RESOURCE_AUTHZ_SERVER=auszrn0q77tsoa7001d7
IDJAG_SCOPES=smarttriage:read
AT_AI_AGENT_ID=wlp10mv0rrvI9zG9M1d8
AT_AGENT_PRIVATE_KEY_ID=fa2160f751150a2076cb1d073465c38c
SMARTTRIAGE_MCP_URL=https://smarttriage-1.onrender.com/mcp
GITHUB_MCP_URL=https://api.githubcopilot.com/mcp
GITHUB_RESOURCE_ORN=orn:oktapreview:idp:github
# Optional — only if the SDK derives the wrong Org-AS token URL:
# OKTA_ORG_ISSUER=https://itpoktane24.oktapreview.com/oauth2/v1
AT_AGENT_PRIVATE_KEY_PEM="-----BEGIN PRIVATE KEY-----
<PASTE ALL PEM LINES HERE>
-----END PRIVATE KEY-----"
EOF
```

`.env` is git-ignored — never commit it. The quoted heredoc keeps the PEM literal.

---

## 4. Deploy from Google Cloud Shell

```bash
gcloud config set project jo-dev-portal
gcloud auth application-default login          # if ADC complains

# deps needed to RUN the deploy script (note okta-client-python + pyjwt)
pip install --user google-adk==1.33.0 \
  "google-cloud-aiplatform[adk,reasoningengine]" \
  mcp httpx okta-client-python cryptography pyjwt python-dotenv

gcloud storage buckets describe gs://jo-dev-portal-adk-staging >/dev/null 2>&1 \
  || gcloud storage buckets create gs://jo-dev-portal-adk-staging --location=us-central1

python cloudshell_adk_idjag_sdk.py
```

On success it prints `Done! Resource name: projects/.../reasoningEngines/<ID>`
(display name **"Jo direct ID-JAG + GitHub STS agent (SDK)"**). `_build_env_vars()` copies
the config keys into `env_vars` so the worker's `os.environ` has them.

- `create()` makes a **NEW** engine each run — re-point the Gemini agent to the new
  resource name and delete stale engines (§8).

---

## 5. Agentspace authorization

The authorizer performs the login. **Agentspace only appends `client_id`, `state`,
`redirect_uri`** — so bake `response_type`, `scope`, and `resource` into the
`authorizationUri`:

```
https://itpoktane24.oktapreview.com/oauth2/aus10mn2tcfNdnFbh1d8/v1/authorize?response_type=code&scope=openid%20profile%20email%20offline_access&resource=https%3A%2F%2Fsmarttriage.com%2Faud
```

Create/patch it via the Discovery Engine API (see `DEPLOY.md` §5 for the exact curls). The
authorization id prefix must match `AUTH_ID_PREFIX` (`okta-authorization_native`).

---

## 6. GitHub STS + brokered consent

On the first GitHub request, the agent runs the STS exchange:

```
POST {ORG}/oauth2/v1/token
  grant_type=urn:ietf:params:oauth:grant-type:token-exchange
  requested_token_type=urn:okta:params:oauth:token-type:oauth-sts
  subject_token=<Agentspace access token>
  subject_token_type=urn:ietf:params:oauth:token-type:access_token
  client_assertion=<private_key_jwt (PyJWT)>, client_assertion_type=jwt-bearer
  resource=orn:oktapreview:idp:github
```

- **200** → GitHub token cached (`_gh_token_store`), used as Bearer to `GITHUB_MCP_URL`.
- **400 `interaction_required`** → the agent captures `interaction_uri` and the instruction
  provider appends an "🔐 Authorize GitHub →" directive so the model shows the clickable
  consent link and waits. After the user authorizes, the next turn's STS returns `200`.

**Consent UX caveat:** the first GitHub ask shows the consent link but **no GitHub tools
yet** — `tools/list` ran before consent and the tolerant toolset returned `[]`. After
authorizing, GitHub tools populate on a **fresh chat** (discovery re-runs with a token).

---

## 7. Verify (`[idjag-sdk]` logs)

```bash
gcloud logging read \
  'resource.type="aiplatform.googleapis.com/ReasoningEngine" AND textPayload:"[idjag-sdk]"' \
  --project=jo-dev-portal --freshness=20m --limit=60 \
  --format='value(timestamp,textPayload)'
```

Expected sequence:
- `STEP1/2 (Agentspace) access_token received` (with `aud=https://smarttriage.com/aud`)
- `SmartTriage STEP3 … start()` → `STEP3 ok` → `STEP4 … resume()` → `STEP4 ok: resource token cached`
- `GitHub STS access_token -> oauth-sts (POST …)` → `GitHub STS response` →
  either `200`+token or `interaction_required` + `interaction_uri`.

Or ask the agent `dump_state` → `agentspace_auth` block reports
`smarttriage_token_cached`, `github_token_cached`, `github_interaction_uri`.

> Exchanges log only on a cache miss; a warm worker with valid cached tokens prints nothing.
> The `Regional Access Boundary … Account not found` line is a benign gcloud warning.

---

## 8. Force re-auth & cleanup

Force per-user re-consent by rotating the authorization id (see `DEPLOY.md` §8):
```bash
./reset_native_agent_auth.sh
```
List/delete stale reasoning engines:
```bash
gcloud ai reasoning-engines list --project=jo-dev-portal --region=us-central1 \
  --format='table(name, displayName, createTime)'
gcloud ai reasoning-engines delete <ENGINE_ID> --project=jo-dev-portal --region=us-central1
```

---

## 9. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Smart Triage `no delegation policy authorizes this token` | subject token's `aud` isn't `https://smarttriage.com/aud`, or XAA policy missing | fix authorize-time `resource`; check the Okta delegation policy |
| GitHub STS `invalid_target: 'resource' is invalid` | `resource` sent as a bare string (SDK) or wrong ORN | use manual httpx (current) sending `resource=<ORN>`; confirm `GITHUB_RESOURCE_ORN` |
| GitHub STS `interaction_required`, no consent link | SDK dropped `interaction_uri` | use manual httpx (current) — reads `interaction_uri` from the body |
| `ValueError: Tool 'list_tools' not found` (turn crash) | LLM invented a tool because GitHub tools absent + no consent directive | fixed: consent link now surfaces + instruction forbids inventing tools |
| GitHub MCP `401` on tools/list | no GitHub token yet (consent pending) | expected pre-consent; tolerant toolset returns `[]`; tools appear post-consent |
| Deploy `500 INTERNAL` | worker build failure (dep conflict) or transient | retry; check build logs; adjust requirements |
| `TypeError: unexpected keyword 'env_vars'` | old SDK | bake config as constants instead |

---

## 10. Notes / production hardening

- `_token_store` and `_gh_token_store` are **shared module-level singletons** — fine for
  single-user prototype testing; use `ContextVar`s for multi-user isolation. (Also why
  GitHub tools appear only after a fresh turn post-consent.)
- Remove the `dump_state` diagnostic before production.
- Rotate the RSA private key after prototyping; keep it only in the git-ignored `.env` /
  the deploy `env_vars`.
- GitHub STS uses manual `httpx` deliberately — do not "upgrade" it to the SDK
  `TokenExchangeFlow` unless a future SDK version surfaces `interaction_uri`.
