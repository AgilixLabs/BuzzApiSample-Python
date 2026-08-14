"""Shared helpers for the Buzz API sample setup/run/cleanup scripts.

These helpers talk to the Buzz API for one-time setup tasks (admin login, key
registration, account management).  They use the legacy ``login3`` command only
to obtain a short-lived admin session token for setup — the sample application
itself never uses login3, only OAuth.

Interactive prompts fall back to environment variables when set, so the scripts
can also run unattended (useful for automated testing):

    BUZZ_SERVER_URL, BUZZ_ADMIN_USERNAME, BUZZ_ADMIN_PASSWORD, BUZZ_ADMIN_MFA
"""

from __future__ import annotations

import getpass
import os
import sys
from typing import Any, Dict, Optional, Tuple

import requests

# Make the project root importable so scripts can `import buzz_api_client`, etc.
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

TIMEOUT = 60


# ── Console output ─────────────────────────────────────────────────────────────
def section(title: str) -> None:
    print(f"\n--- {title} " + "-" * max(0, 50 - len(title)))


def ok(msg: str) -> None:
    print(msg)


def info(msg: str) -> None:
    print(f"  {msg}")


def die(msg: str) -> "None":
    print(f"\nError: {msg}", file=sys.stderr)
    raise SystemExit(1)


# ── Prompts (with environment-variable fallbacks) ───────────────────────────────
def prompt_required(label: str, default: str = "", env: Optional[str] = None) -> str:
    if env and os.environ.get(env):
        return os.environ[env]
    while True:
        suffix = f" [{default}]" if default else ""
        try:
            value = input(f"{label}{suffix}: ").strip() or default
        except EOFError:
            value = default
            if not value:
                die(f"'{label}' is required but no value was provided"
                    + (f" (set {env})" if env else ""))
        if value:
            return value
        print("  (required)")


def prompt_optional(label: str, env: Optional[str] = None) -> str:
    if env and os.environ.get(env):
        return os.environ[env]
    try:
        return input(f"{label} (optional, press Enter to skip): ").strip()
    except EOFError:
        return ""


def prompt_password(label: str, env: Optional[str] = None) -> str:
    if env and os.environ.get(env):
        return os.environ[env]
    try:
        return getpass.getpass(f"{label}: ")
    except EOFError:
        die(f"'{label}' is required but no value was provided"
            + (f" (set {env})" if env else ""))


def confirm(label: str, default_yes: bool = False) -> bool:
    suffix = "[Y/n]" if default_yes else "[y/N]"
    try:
        answer = input(f"{label} {suffix} ").strip().lower()
    except EOFError:
        return default_yes
    if not answer:
        return default_yes
    return answer.startswith("y")


# ── Buzz API calls ──────────────────────────────────────────────────────────────
# Session tokens travel in an Authorization: Bearer header on both /cmd/* and
# /api/* endpoints.  A _token query parameter is also accepted by /cmd/*, but a
# credential in a URL is recorded by server and proxy access logs.
# Buzz returns XML unless JSON is requested via Accept.
def _auth_headers(token: Optional[str]) -> Dict[str, str]:
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def buzz_post(server: str, cmd: str, body: Any, token: Optional[str] = None) -> Dict[str, Any]:
    resp = requests.post(f"{server}/cmd/{cmd}", json=body,
                         headers=_auth_headers(token), timeout=TIMEOUT)
    return _safe_json(resp)


def buzz_get(server: str, cmd: str, params: Optional[Dict[str, Any]] = None,
             token: Optional[str] = None) -> Dict[str, Any]:
    resp = requests.get(f"{server}/cmd/{cmd}", params=dict(params or {}),
                        headers=_auth_headers(token), timeout=TIMEOUT)
    return _safe_json(resp)


def register_public_key(server: str, user_id: str, kid: str, public_key_pem: bytes,
                        token: str) -> Tuple[int, str]:
    """PUT a public key to /api/users/{id}/keys/{kid}.  Returns (http_status, body)."""
    url = f"{server}/api/users/{user_id}/keys/{kid}"
    resp = requests.put(url, data=public_key_pem, timeout=TIMEOUT,
                        headers={"Authorization": f"Bearer {token}",
                                 "Content-Type": "application/x-pem-file"})
    return resp.status_code, resp.text


def delete_public_key(server: str, user_id: str, kid: str, token: str) -> Tuple[int, str]:
    url = f"{server}/api/users/{user_id}/keys/{kid}"
    resp = requests.delete(url, timeout=TIMEOUT, headers={"Authorization": f"Bearer {token}"})
    return resp.status_code, resp.text


def response_code(resp: Dict[str, Any]) -> str:
    if isinstance(resp, dict):
        inner = resp.get("response")
        if isinstance(inner, dict) and "code" in inner:
            return inner.get("code", "")
        return resp.get("code", "")
    return ""


def response_message(resp: Dict[str, Any]) -> str:
    inner = resp.get("response", resp) if isinstance(resp, dict) else {}
    return inner.get("message", "") if isinstance(inner, dict) else ""


def item_result(resp: Dict[str, Any]) -> Dict[str, str]:
    """The per-entity result of a multi-object command (CreateUsers2, DeleteUsers).

    Those commands report each entity's outcome under response.responses.response,
    while the OUTER code is OK whenever the request was merely well formed.  A
    per-entity AccessDenied therefore arrives inside an "OK" envelope, so the outer
    code alone cannot tell you whether the entity was actually created or deleted.
    Returns {} when the response carries no per-entity result at all.
    """
    if not isinstance(resp, dict):
        return {}
    inner = resp.get("response", resp)
    if not isinstance(inner, dict):
        return {}
    node = (inner.get("responses") or {}).get("response") if isinstance(inner.get("responses"), dict) else None
    if isinstance(node, list):
        node = node[0] if node else None
    if not isinstance(node, dict):
        return {}
    return {"code": node.get("code", "") or "", "message": node.get("message", "") or "",
            "userid": ((node.get("user") or {}).get("userid", "") or "") if isinstance(node.get("user"), dict) else ""}


def _second_factor_token(resp: Dict[str, Any]) -> str:
    """The short-lived token login3 returns alongside SecondFactorRequired.

    Observed shape: response.token, duplicated at response.body.token.  There is no
    "user" node on that response, so response.user.token (where the session token
    lives on a *successful* login) does not exist yet.  remembermfa.token is
    deliberately ignored: it remembers a device and cannot complete this login.
    """
    inner = resp.get("response", resp) if isinstance(resp, dict) else {}
    if not isinstance(inner, dict):
        return ""
    for candidate in (
        ((inner.get("user") or {}).get("token") if isinstance(inner.get("user"), dict) else None),
        inner.get("token"),
        ((inner.get("body") or {}).get("token") if isinstance(inner.get("body"), dict) else None),
    ):
        if isinstance(candidate, str) and candidate:
            return candidate
    return ""


def _safe_json(resp: requests.Response) -> Dict[str, Any]:
    try:
        return resp.json()
    except ValueError:
        return {"code": "", "_raw": resp.text}


# ── Admin login (login3, with optional MFA) ─────────────────────────────────────
def admin_login(server: str) -> str:
    """Log in as a Buzz admin and return a session token.  Supports MFA.

    Used only to perform one-time setup/cleanup.  Reads credentials from the
    BUZZ_ADMIN_USERNAME / BUZZ_ADMIN_PASSWORD / BUZZ_ADMIN_MFA environment
    variables when present, otherwise prompts interactively.
    """
    while True:
        username = _read_admin_username()
        password = prompt_password("Admin password", env="BUZZ_ADMIN_PASSWORD")

        print("Logging in...", end="", flush=True)
        resp = buzz_post(server, "login3", {"request": {"cmd": "login3",
                                                        "username": username, "password": password}})
        code = response_code(resp)

        # Multi-factor authentication.  login3 answers SecondFactorRequired when the
        # password was correct but the account has MFA configured, and returns a
        # short-lived token at response.token (there is no "user" node on that
        # response).  That token is presented in an Authorization: Bearer header to
        # secondfactorauthenticate, which returns the real session token.  Putting it
        # in the request body instead is ignored and answers AccessDenied userId='-1'.
        #   https://api.agilixbuzz.com/docs/entry/Command/Login3.md
        #   https://api.agilixbuzz.com/docs/entry/Command/SecondFactorAuthenticate.md
        if code == "SecondFactorConfigurationNowRequired":
            print("\n  This account must configure multi-factor authentication before it can")
            print("  be used.  Complete MFA setup in Buzz, then re-run this script.")
            if os.environ.get("BUZZ_ADMIN_PASSWORD"):
                die("Admin account requires multi-factor authentication setup.")
            print("  Press Ctrl+C to abort.\n")
            continue

        if code == "SecondFactorRequired":
            print(" multi-factor authentication required.")
            mfa_token = _second_factor_token(resp)
            if not mfa_token:
                print("\n  Buzz asked for a second factor but no token could be found in its reply.")
                if os.environ.get("BUZZ_ADMIN_PASSWORD"):
                    die("No second-factor token was returned.")
                print("  Press Ctrl+C to abort.\n")
                continue
            otp = prompt_required("One-time code from your authenticator app or email",
                                  env="BUZZ_ADMIN_MFA")
            resp = buzz_post(server, "secondfactorauthenticate",
                             {"request": {"cmd": "secondfactorauthenticate", "otp": otp}},
                             token=mfa_token)
            code = response_code(resp)

        if code != "OK":
            msg = response_message(resp)
            print(f"\n  Login failed (code: {code}){': ' + msg if msg else ''}")
            if os.environ.get("BUZZ_ADMIN_PASSWORD"):
                die("Login failed with credentials from environment variables.")
            print("  Please check your credentials and try again.  Press Ctrl+C to abort.\n")
            continue

        token = ((resp.get("response", {}) or {}).get("user", {}) or {}).get("token", "") \
            or (resp.get("user", {}) or {}).get("token", "")
        if not token:
            print("\n  Login succeeded but no token was returned.  Press Ctrl+C to abort.\n")
            continue

        print(" OK")
        return token


def _read_admin_username() -> str:
    env = os.environ.get("BUZZ_ADMIN_USERNAME")
    if env:
        return env
    while True:
        value = input("Admin username (userspace/username, e.g. myschool/admin): ").strip()
        if value.count("/") == 1 and all(value.split("/")):
            return value
        print("  Username must be in userspace/username format.")
