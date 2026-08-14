#!/usr/bin/env python3
"""Remove all artifacts created by setup_buzz_oauth.py.

  1. Read configuration (.env) to find the OAuth account details.
  2. Log in as a Buzz admin (supports MFA).
  3. Delete the registered OAuth public key from Buzz.
  4. Delete the Application Identity account from Buzz.
  5. Delete the local private/public key files and the .env file.

After running, the environment is back to a clean state.

Usage:
    python scripts/cleanup_buzz_sample.py [--yes]

    --yes   Skip the confirmation prompt (useful for automated cleanup).
"""

from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from _common import (  # noqa: E402
    admin_login, buzz_post, confirm, delete_public_key, item_result, response_code,
    PROJECT_ROOT,
)

sys.path.insert(0, PROJECT_ROOT)
from buzz_config import ENV_VARS, default_env_path, load_env  # noqa: E402


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Clean up the Buzz API sample setup.")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")
    args = parser.parse_args(argv)

    env_path = default_env_path()
    if not load_env(env_path):
        print(".env not found — nothing to clean up.")
        return 0

    server = os.environ.get(ENV_VARS["server_url"], "").rstrip("/")
    oauth_user_id = os.environ.get(ENV_VARS["oauth_user_id"], "")
    oauth_kid = os.environ.get(ENV_VARS["oauth_kid"], "")
    private_key_path = os.environ.get(ENV_VARS["private_key_path"], "")

    if not server or not oauth_user_id:
        print(".env is missing required fields (server url, oauth user id).", file=sys.stderr)
        return 1

    print("\n========================================================")
    print("  Buzz API Sample - Cleanup")
    print("========================================================\n")
    print("This will:")
    print(f"  * Delete OAuth public key (kid: {oauth_kid}) from Buzz")
    print(f"  * Delete Application Identity account (userid: {oauth_user_id}) from Buzz")
    if private_key_path:
        print(f"  * Delete local key files near: {private_key_path}")
    print("  * Delete .env")
    if not args.yes and not confirm("\nThis action is irreversible.  Continue?"):
        print("Aborted.")
        return 0

    print("\n-- Admin login -----------------------------------------")
    admin_token = admin_login(server)

    # Delete OAuth public key.
    if oauth_kid:
        print(f"\n-- Deleting OAuth key (kid: {oauth_kid}) ----------------")
        status, body = delete_public_key(server, oauth_user_id, oauth_kid, admin_token)
        if status in (200, 204):
            print(f"OAuth key deleted (HTTP {status}).")
        elif status == 404:
            print("OAuth key not found (already deleted or never registered).")
        else:
            print(f"Warning: HTTP {status} deleting key. Continuing.", file=sys.stderr)

    # Delete Application Identity account.
    print(f"\n-- Deleting Application Identity account (userid: {oauth_user_id}) --")
    resp = buzz_post(server, "deleteusers", {"requests": {"user": [{"userid": oauth_user_id}]}}, admin_token)
    # The per-user outcome is authoritative.  The OUTER code is OK whenever the request
    # was merely well formed, so checking it first would report success for a delete
    # that was actually denied or whose target did not exist.
    item = item_result(resp)
    code = item.get("code") or response_code(resp)
    detail = f" - {item['message']}" if item.get("message") else ""
    if code == "OK":
        print("Application Identity account deleted.")
    else:
        print(f'Warning: delete returned code "{code}"{detail}. Continuing.', file=sys.stderr)

    # Remove local files.
    print("\n-- Removing local files --------------------------------")
    key_dir = os.path.dirname(private_key_path) if private_key_path else PROJECT_ROOT
    for name in ("private_key.pem", "public_key.pem"):
        _remove(os.path.join(key_dir, name))
    if private_key_path:
        _remove(private_key_path)
    _remove(env_path)

    print("\n========================================================")
    print("  Cleanup complete.  Environment is back to a clean state.")
    print("========================================================\n")
    return 0


def _remove(path: str) -> None:
    if path and os.path.isfile(path):
        try:
            os.remove(path)
            print(f"Removed: {path}")
        except OSError as e:
            print(f"Warning: could not remove {path}: {e}", file=sys.stderr)


if __name__ == "__main__":
    raise SystemExit(main())
