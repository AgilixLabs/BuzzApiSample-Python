#!/usr/bin/env python3
"""Interactive guided setup for Buzz OAuth 2.0 authentication.

Performs the one-time setup so the sample can authenticate without a password:
  1. Prompt for the Buzz server URL.
  2. Log in as a Buzz administrator (supports MFA) to perform setup.
  3. Create (or reuse) an Application Identity account.
  4. Generate an RSA key pair (private key stored as a PEM file).
  5. Register the public key with Buzz.
  6. Write the .env configuration file so `python sample.py` works immediately.

Usage:
    python scripts/setup_buzz_oauth.py [--server URL] [--bits N] [--key-dir DIR]

Every interactive prompt falls back to an environment variable when set, so the
whole flow can run unattended (see _common.py and the BUZZ_SETUP_* vars below).
"""

from __future__ import annotations

import argparse
import datetime
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (  # noqa: E402
    admin_login, buzz_get, buzz_post, confirm, die, info, item_result, ok,
    prompt_optional, prompt_required, response_code, section, PROJECT_ROOT,
)
from new_buzz_oauth_key import generate_key_pair  # noqa: E402
from register_buzz_oauth_key import register_public_key  # noqa: E402

sys.path.insert(0, PROJECT_ROOT)
from buzz_config import write_env  # noqa: E402

KID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Interactive Buzz OAuth 2.0 setup.")
    parser.add_argument("-s", "--server", default="", help="Buzz API server URL")
    parser.add_argument("-b", "--bits", type=int, default=0, help="RSA key size in bits (default 2048)")
    parser.add_argument("--key-dir", default=PROJECT_ROOT, help="Directory for the private key PEM")
    args = parser.parse_args(argv)

    print("\n==========================================================")
    print("  Buzz OAuth 2.0 Application Setup (Python)")
    print("==========================================================\n")

    # ── Step 1: Server URL ────────────────────────────────────────────────────
    section("Step 1: Buzz Server URL")
    server = (args.server or prompt_required(
        "Buzz API server URL (e.g. https://backgroundapi.agilixbuzz.com)", env="BUZZ_SERVER_URL")).rstrip("/")
    ok(f"  Server: {server}")

    # ── Step 2: Admin login ───────────────────────────────────────────────────
    section("Step 2: Admin Login")
    print("Log in as a Buzz administrator to perform the one-time setup.")
    print("This session is used only during setup and is not stored anywhere.\n")
    admin_token = admin_login(server)

    # ── Step 3: Application info ───────────────────────────────────────────────
    section("Step 3: Application Information")
    print("Included in the User-Agent header so Agilix support can identify your integration.\n")
    contact = prompt_required("Your contact info (name, email, or URL)", env="BUZZ_CONTACT_INFORMATION")
    app_name = prompt_required("Application name (e.g. SisSync)", env="BUZZ_APPLICATION_INFORMATION")

    # ── Step 4: Application Identity account ───────────────────────────────────
    section("Step 4: Application Identity Account")
    print("This Buzz user represents your application.  It authenticates via OAuth only.\n")
    oauth_user_id = _get_or_create_account(server, admin_token)

    # ── Step 5: RSA key pair ───────────────────────────────────────────────────
    section("Step 5: RSA Key Generation")
    bits = args.bits or int(os.environ.get("BUZZ_SETUP_KEY_BITS", "0") or 0) or \
        _prompt_int("RSA key size in bits", 2048)
    default_kid = _default_kid()
    kid = os.environ.get("BUZZ_SETUP_KID") or prompt_required("Key id (kid) for this key", default=default_kid)
    if not KID_RE.match(kid):
        die(f"Invalid kid '{kid}'. Allowed: ASCII letters, digits, -, _, .  Max 128 chars.")
    info(f"Kid : {kid}")

    priv_path, pub_path = generate_key_pair(args.key_dir, bits, overwrite=True)
    ok(f"  Private key: {priv_path}")

    # ── Step 6: Register public key ────────────────────────────────────────────
    section("Step 6: Registering Public Key with Buzz")
    url = f"{server}/api/users/{oauth_user_id}/keys/{kid}"
    info(f"PUT {url}")
    status, body = register_public_key(server, oauth_user_id, kid, open(pub_path, "rb").read(), admin_token)
    if status == 204:
        ok(" 204 OK")
    else:
        die(f"Key registration returned HTTP {status}. {body}")

    # ── Step 7: Write config ───────────────────────────────────────────────────
    section("Step 7: Writing Configuration")
    config = {
        "server_url": server,
        "contact_information": contact,
        "application_information": app_name,
        "oauth_user_id": oauth_user_id,
        "oauth_kid": kid,
        "private_key_path": priv_path,
    }
    env_path = write_env(config)
    ok(f"  Written: {env_path}")

    print("\n==========================================================")
    print("  Setup complete!")
    print("==========================================================")
    print(f"OAuth User ID : {oauth_user_id}")
    print(f"Key ID (kid)  : {kid}")
    print(f"Private key   : {priv_path}")
    print(f"Config file   : {env_path}")
    print("\nTo test:  python sample.py\n")
    return 0


def _get_or_create_account(server: str, admin_token: str) -> str:
    create_new = os.environ.get("BUZZ_SETUP_CREATE_NEW")
    do_create = create_new.lower().startswith("y") if create_new else confirm(
        "Create a new Application Identity account?", default_yes=True)

    if not do_create:
        return prompt_required("Existing Application Identity account userid",
                               env="BUZZ_SETUP_OAUTH_USER_ID")

    # Try to list domains to help the user choose.
    target_domain = os.environ.get("BUZZ_SETUP_DOMAINID", "")
    if not target_domain:
        print("Fetching available domains...", end="", flush=True)
        domains = _list_domains(server, admin_token)
        if domains:
            print(" done\n")
            for i, (did, name) in enumerate(domains, 1):
                print(f"  {i:2d}. {name:<30} (id: {did})")
            choice = prompt_required("\nEnter domain number or type the domainid directly")
            if choice.isdigit() and 1 <= int(choice) <= len(domains):
                target_domain = domains[int(choice) - 1][0]
            else:
                target_domain = choice
        else:
            # An empty list is normal when the admin holds no ReadDomain right anywhere,
            # or when the domain simply has no child domains.  Not an error -- just ask.
            print(" done\n")
            print("  No domains were listed for this account, so enter the target domain directly.")
            target_domain = prompt_required("Domain id for the new account (e.g. //myschool or a numeric id)")

    username = prompt_required("Username for the account (e.g. sis-sync)", env="BUZZ_SETUP_APP_USERNAME")
    firstname = prompt_required("First name (e.g. SIS)", env="BUZZ_SETUP_APP_FIRSTNAME")
    lastname = prompt_required("Last name (e.g. Sync)", env="BUZZ_SETUP_APP_LASTNAME")
    email = prompt_optional("Email address", env="BUZZ_SETUP_APP_EMAIL")

    user = {"domainid": target_domain, "type": "applicationidentity",
            "username": username, "firstname": firstname, "lastname": lastname}
    if email:
        user["email"] = email

    print(f"\nCreating Application Identity account '{username}'...", end="", flush=True)
    resp = buzz_post(server, "createusers2", {"requests": {"user": [user]}}, admin_token)
    if response_code(resp) != "OK":
        die(f"CreateUsers2 failed (code: {response_code(resp)}).  Response: {resp}")

    # The outer OK only means the request parsed; CreateUsers2 reports the outcome for
    # the user it created under responses.response, so a denial arrives inside an "OK"
    # envelope and must be checked separately.
    item = item_result(resp)
    if item.get("code") and item["code"] != "OK":
        detail = f" - {item['message']}" if item.get("message") else ""
        if item["code"] == "AccessDenied":
            die(f"CreateUsers2 was denied (code: {item['code']}{detail}).\n"
                f"  The admin account needs the CreateUser right on domain {target_domain}.\n"
                f"  Grant it that right (and UpdateUser, so it can register the OAuth key), then re-run.")
        die(f"CreateUsers2 failed for the requested user (code: {item['code']}{detail}).")

    user_id = _extract_created_userid(resp)
    if not user_id:
        die(f"CreateUsers2 succeeded but returned no userid.  Response: {resp}")
    ok(f" OK (userid: {user_id})")
    return user_id


def _list_domains(server: str, token: str):
    # ListDomains, not "getdomains" -- the latter is not a Buzz command and always
    # answered "Unknown API command", so this silently returned [] on every run.
    # domainid=0 means "every domain this account has ReadDomain rights on"; limit=0
    # lifts the default 100-domain cap (capped server-side at 1000 for domainid=0).
    #   https://api.agilixbuzz.com/docs/entry/Command/ListDomains.md
    resp = buzz_get(server, "listdomains", params={"domainid": 0, "limit": 0}, token=token)
    if response_code(resp) != "OK":
        return []
    # When the account can read no domains the server answers OK with "domains":{},
    # so every level has to tolerate a missing or empty node.
    node = (resp.get("response", {}) or {}).get("domains") or {}
    domains = (node.get("domain") if isinstance(node, dict) else None) or []
    if isinstance(domains, dict):
        domains = [domains]
    # The Domain schema names the identifier "id"; "domainid" is what you *send*.
    return [(str(d.get("id", "")), str(d.get("name", ""))) for d in domains if d]


def _extract_created_userid(resp: dict) -> str:
    r = resp.get("response", resp)
    inner = (r.get("responses", {}) or {}).get("response", {})
    if isinstance(inner, list):
        inner = inner[0] if inner else {}
    user = inner.get("user", {}) if isinstance(inner, dict) else {}
    return str(user.get("userid") or user.get("id") or "")


def _default_kid() -> str:
    now = datetime.datetime.now(datetime.timezone.utc)
    return f"{now.year}-q{(now.month + 2) // 3}"


def _prompt_int(label: str, default: int) -> int:
    raw = input(f"{label} [{default}]: ").strip()
    return int(raw) if raw.isdigit() else default


if __name__ == "__main__":
    raise SystemExit(main())
