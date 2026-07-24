"""Buzz API OAuth 2.0 sample — read-only demo.

Demonstrates read-only access to the Buzz API:
  1. Configuring :class:`BuzzApiClient` with OAuth credentials.
  2. Calling ``getuser2`` to verify authentication and discover the home domain.
  3. Calling ``getdomain2`` to read domain details.

The sample is intentionally read-only — it can be run repeatedly without
modifying any data in the target domain.

Quickest start:  python scripts/run_buzz_sample.py
"""

from __future__ import annotations

import logging
import sys

from buzz_api_client import BuzzApiClient
from buzz_config import read_config


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s", stream=sys.stdout)
    log = logging.getLogger("sample")

    config = read_config()
    user_agent = (
        "BuzzApiClient/1.0.0 (Python; "
        f"{config['application_information']}; {config['contact_information']})"
    )

    with BuzzApiClient.from_pem_file(
        server_url=config["server_url"],
        user_agent=user_agent,
        oauth_user_id=config["oauth_user_id"],
        oauth_kid=config["oauth_kid"],
        private_key_path=config["private_key_path"],
    ) as client:
        run_sample(client, log)


def run_sample(client: BuzzApiClient, log: logging.Logger) -> None:
    print()
    print("========================================================")
    print("  Buzz API OAuth 2.0 Sample - Read-Only Demo (Python)")
    print("========================================================")
    print()

    # getuser2: verify authentication is working and discover the domain this
    # Application Identity account belongs to.
    print("-- getuser2 (verify authentication) --------------------")
    user_node = client.verify_response(client.json_request("GET", "getuser2"))
    user = user_node.get("user", {})

    # This server returns the identifier as "id"; older servers use "userid".
    user_id = user.get("userid") or user.get("id")
    username = user.get("username")
    first_name = user.get("firstname")
    last_name = user.get("lastname")
    domain_id = user.get("domainid")

    log.info('Authenticated as user %s ("%s %s", userid: %s)', username, first_name, last_name, user_id)
    log.info("Home domain: %s", domain_id)

    # ── getdomain2 ────────────────────────────────────────────────────────────
    # Fetch details about the domain the Application Identity account belongs to.
    if domain_id:
        print()
        print("-- getdomain2 (read domain details) --------------------")
        domain_node = client.verify_response(
            client.json_request("GET", "getdomain2", params={"domainid": domain_id})
        )
        domain = domain_node.get("domain", {})
        log.info("Domain name: %s", domain.get("name"))
        log.info("Userspace  : %s", domain.get("userspace"))
        if domain.get("type"):
            log.info("Type       : %s", domain.get("type"))

    print()
    print("========================================================")
    print("  All API calls succeeded.  OAuth integration is working.")
    print("  No data was created or modified.")
    print("========================================================")
    print()


if __name__ == "__main__":
    main()
