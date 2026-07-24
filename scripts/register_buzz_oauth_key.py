#!/usr/bin/env python3
"""Register an RSA public key with Buzz for OAuth 2.0 authentication.

Usage:
    python scripts/register_buzz_oauth_key.py -s SERVER_URL -u USER_ID -k KID -p PUBLIC_KEY_PATH

The admin Bearer token is read (in order of preference) from:
    --token,  the BUZZ_ADMIN_TOKEN environment variable,  or an interactive prompt.
Preferring the env var / prompt keeps the token out of shell history and process listings.

PUTting an existing kid REPLACES the key immediately — use a new kid to rotate.
"""

from __future__ import annotations

import argparse
import getpass
import os
import re
import sys

# Ensure scripts/ helpers and the project root are importable.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import delete_public_key, register_public_key  # noqa: E402

KID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Register an RSA public key with Buzz.")
    parser.add_argument("-s", "--server", required=True, help="Buzz API server URL (no trailing slash)")
    parser.add_argument("-t", "--token", help="Admin Bearer token (prefer BUZZ_ADMIN_TOKEN or the prompt)")
    parser.add_argument("-u", "--user-id", required=True, help="userid of the Application Identity account")
    parser.add_argument("-k", "--kid", required=True, help="Key id, e.g. 2025-q2")
    parser.add_argument("-p", "--public-key", required=True, help="Path to the SPKI PEM public key")
    args = parser.parse_args(argv)

    server = args.server.rstrip("/")
    if not KID_RE.match(args.kid):
        print("Error: invalid kid. Allowed: ASCII letters, digits, -, _, .  Max 128 chars.", file=sys.stderr)
        return 1
    if not os.path.isfile(args.public_key):
        print(f"Error: public key file not found: {args.public_key}", file=sys.stderr)
        return 1

    pem = open(args.public_key, "rb").read()
    if b"BEGIN PUBLIC KEY" not in pem:
        print("Error: file does not look like a SubjectPublicKeyInfo PEM ('-----BEGIN PUBLIC KEY-----').",
              file=sys.stderr)
        return 1

    token = args.token or os.environ.get("BUZZ_ADMIN_TOKEN") or getpass.getpass("Admin Bearer token: ")
    if not token:
        print("Error: admin token is required.", file=sys.stderr)
        return 1

    url = f"{server}/api/users/{args.user_id}/keys/{args.kid}"
    print("Registering public key...")
    print(f"  URL  : {url}")
    print(f"  Kid  : {args.kid}")
    print(f"  File : {os.path.abspath(args.public_key)}\n")

    status, body = register_public_key(server, args.user_id, args.kid, pem, token)
    return _report(status, body, args.user_id, args.kid)


def _report(status: int, body: str, user_id: str, kid: str) -> int:
    if status == 204:
        print("Public key registered successfully (HTTP 204).\n")
        print("Configure your application:")
        print(f"  BUZZ_OAUTH_USER_ID = {user_id}")
        print(f"  BUZZ_OAUTH_KID     = {kid}")
        return 0
    if status == 400:
        print("Error: HTTP 400 Bad Request", file=sys.stderr)
        print("  - Public key must be SubjectPublicKeyInfo (SPKI) PEM and at least 2048 bits.", file=sys.stderr)
        print(f"  - Account {user_id} must have been created with type=applicationidentity.", file=sys.stderr)
    elif status in (401, 403):
        print(f"Error: HTTP {status} — admin token lacks Update User rights on account {user_id}.", file=sys.stderr)
    elif status == 404:
        print("Error: HTTP 404 — server URL or user id not found.", file=sys.stderr)
    else:
        print(f"Error: unexpected HTTP {status}", file=sys.stderr)
    if body:
        print(f"Response: {body}", file=sys.stderr)
    return 1


# Re-export so setup can reuse it if needed.
__all__ = ["main", "register_public_key", "delete_public_key"]

if __name__ == "__main__":
    raise SystemExit(main())
