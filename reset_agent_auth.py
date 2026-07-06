#!/usr/bin/env python3
"""
reset_agent_auth.py

Force re-consent on ANY Gemini Enterprise / Agentspace agent by ROTATING its
OAuth authorization to a new id.

Why rotate (not delete+recreate same id): Agentspace keys per-user consent to
the authorization *name*; a same-name recreate keeps the old consent, so it
does NOT re-prompt. A *new* authorization id has no stored consent => fresh
prompt. So each run:

    create new auth (auth-base-<timestamp>) -> relink agent -> delete old auth(s)

Auth uses your gcloud login (run in Cloud Shell).

Examples
--------
    # same front-door app (gemini-enterprisetools) as the defaults:
    python3 reset_agent_auth.py --agent-id 5739256021619792487 --auth-base corporate-assistant

    # a different front-door OAuth app:
    python3 reset_agent_auth.py \
        --agent-id 1750392573605282600 --auth-base activehelper \
        --client-id 0oaXXXX --client-secret '...' \
        --auth-uri https://okta-mcp-adapter.onrender.com/oauth/authorize \
        --token-uri https://okta-mcp-adapter.onrender.com/oauth2/v1/token

The client secret may also be supplied via env var OKTA_CLIENT_SECRET.
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

# Defaults (match the gemini-enterprisetools front door + adapter BFF)
DEFAULT_PROJECT = "531214469428"
DEFAULT_LOCATION = "global"
DEFAULT_ENGINE = "enterprisetoolsapp_1780771479314"
DEFAULT_ASSISTANT = "default_assistant"
DEFAULT_CLIENT_ID = "0oazcw1tofOwmHfPD1d7"
DEFAULT_AUTH_URI = "https://okta-mcp-adapter-0tld.onrender.com/oauth/authorize"
DEFAULT_TOKEN_URI = "https://okta-mcp-adapter-0tld.onrender.com/oauth2/v1/token"
# No hardcoded secret — supply at runtime via --client-secret or OKTA_CLIENT_SECRET env.

DE = "https://discoveryengine.googleapis.com/v1alpha"


def parse_args():
    p = argparse.ArgumentParser(description="Rotate an Agentspace agent's OAuth authorization to force re-consent.")
    p.add_argument("--agent-id", required=True, help="Agentspace agent id (the trailing id in the agent resource name)")
    p.add_argument("--auth-base", required=True, help="Base name for the rotated authorization (id becomes <base>-<timestamp>)")
    p.add_argument("--client-id", default=DEFAULT_CLIENT_ID)
    p.add_argument("--client-secret", default=os.environ.get("OKTA_CLIENT_SECRET", ""))
    p.add_argument("--auth-uri", default=DEFAULT_AUTH_URI)
    p.add_argument("--token-uri", default=DEFAULT_TOKEN_URI)
    p.add_argument("--project", default=DEFAULT_PROJECT)
    p.add_argument("--location", default=DEFAULT_LOCATION)
    p.add_argument("--engine", default=DEFAULT_ENGINE)
    p.add_argument("--assistant", default=DEFAULT_ASSISTANT)
    return p.parse_args()


def gcloud_token():
    return subprocess.check_output(["gcloud", "auth", "print-access-token"], text=True).strip()


def main():
    args = parse_args()
    if not args.client_secret:
        sys.exit("No client secret. Pass --client-secret or set OKTA_CLIENT_SECRET.")

    token = gcloud_token()
    project = args.project
    auths_url = f"{DE}/projects/{project}/locations/{args.location}/authorizations"
    agent_name = (
        f"projects/{project}/locations/{args.location}/collections/default_collection/"
        f"engines/{args.engine}/assistants/{args.assistant}/agents/{args.agent_id}"
    )
    agent_url = f"{DE}/{agent_name}"

    def call(method, url, body=None):
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(
            url, data=data, method=method,
            headers={
                "Authorization": f"Bearer {token}",
                "X-Goog-User-Project": project,
                "Content-Type": "application/json",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                raw = r.read().decode() or "{}"
                return r.status, json.loads(raw)
        except urllib.error.HTTPError as e:
            raw = e.read().decode() or "{}"
            try:
                return e.code, json.loads(raw)
            except json.JSONDecodeError:
                return e.code, {"raw": raw}

    def set_agent_auths(auths):
        url = f"{agent_url}?updateMask=authorizationConfig.toolAuthorizations"
        st, body = call("PATCH", url, {"authorizationConfig": {"toolAuthorizations": auths}})
        print(f"   PATCH agent -> HTTP {st}  {auths or '[]'}")
        if st != 200:
            sys.exit(f"   FAILED: {body}")

    new_id = f"{args.auth_base}-{int(time.time())}"
    new_name = f"projects/{project}/locations/{args.location}/authorizations/{new_id}"
    print(f"Agent   : {agent_name}")
    print(f"New auth: {new_name}\n")

    # 0. read current authorizations (rotated out)
    st, agent = call("GET", agent_url)
    if st != 200:
        sys.exit(f"Cannot read agent (HTTP {st}): {agent}")
    old_auths = agent.get("authorizationConfig", {}).get("toolAuthorizations", [])
    print(f"1) current agent authorizations: {old_auths}")

    # 1. create the NEW authorization (new id => forces re-consent)
    create_body = {
        "name": new_name,
        "serverSideOauth2": {
            "clientId": args.client_id,
            "clientSecret": args.client_secret,
            "authorizationUri": args.auth_uri,
            "tokenUri": args.token_uri,
        },
    }
    st, body = call("POST", f"{auths_url}?authorizationId={new_id}", create_body)
    print(f"2) CREATE {new_id} -> HTTP {st}")
    if st not in (200, 201):
        sys.exit(f"   FAILED to create: {body}")

    # 2. relink agent to the new authorization
    print("3) relinking agent to new authorization...")
    set_agent_auths([new_name])

    # 3. delete old authorization(s) — now unlinked from this agent
    for old in old_auths:
        if old == new_name:
            continue
        st, body = call("DELETE", f"{DE}/{old}")
        print(f"4) DELETE old {old.split('/')[-1]} -> HTTP {st}")
        if st not in (200, 404):
            print(f"   (left in place: {body})")

    # 4. verify
    st, agent = call("GET", agent_url)
    final = agent.get("authorizationConfig", {}).get("toolAuthorizations", [])
    print(f"\nDone. Agent authorizations now: {final}")
    print("Log in as the demo user, start a NEW chat with this agent -> fresh consent prompt.")


if __name__ == "__main__":
    main()

