# BuzzApiSample-Python

A Python sample and reusable client library for the Buzz API. The `BuzzApiClient` class handles
OAuth 2.0 authentication, automatic token refresh, exponential backoff, and rate-limit
compliance so your integration code can focus on business logic.

Targets **Python 3.8+** for broad compatibility.

## Authentication

The only authentication method supported by the client is **OAuth 2.0 JWT Client Credentials**
([RFC 6749](https://www.rfc-editor.org/rfc/rfc6749) +
[RFC 7523](https://www.rfc-editor.org/rfc/rfc7523)).
An RSA private key signs a short-lived JWT assertion; Buzz verifies the signature against the
registered public key and returns a Bearer access token valid for one hour. The private key
never leaves your system — there is no shared secret to intercept.

> The legacy username/password (`login3`) flow is **not** used by new integrations and is not
> part of this client. It appears only inside the setup/cleanup scripts, where an administrator
> must briefly authenticate to create the Application Identity account and register keys.

---

## Overview

The Buzz API is an HTTP API consisting of GET and POST requests, accepting and returning JSON.
The typical workflow is: authenticate, then perform operations.

**sample.py** demonstrates read-only access:
1. Configuring `BuzzApiClient` with OAuth credentials and a Buzz server URL.
2. Calling `getuser2` to verify authentication and discover the home domain.
3. Calling `getdomain2` to read domain details.

The sample is intentionally read-only — it can be run repeatedly without modifying any data.

**BuzzApiClient** simplifies integration by:
- Managing OAuth tokens automatically — requesting and refreshing Bearer tokens as needed.
- Retrying transient failures with exponential backoff (1 s → 64 s, up to 5 retries).
- Honouring `Retry-After` and `X-RateLimit-Reset` headers from the server.
- Providing `json_request` and `verify_response` helpers for common JSON API patterns.

---

## Requirements

- Python 3.8 or newer
- Packages from `requirements.txt`: [`cryptography`](https://pypi.org/project/cryptography/) and
  [`requests`](https://pypi.org/project/requests/)

```bash
python -m pip install -r requirements.txt
```

## Compatibility

Written for **Python 3.8** for broad reach, and verified to run unchanged on every version
through the current release (**3.8 – 3.14**). The code avoids 3.9+-only syntax, and the
dependencies are lower-bounded only (`cryptography`, `requests`), so the newest releases install
and work without changes. Nothing here discourages running on the latest Python.

## Configuration

Configuration uses **environment variables** (12-factor style). For local development you can put
them in a `.env` file in the project root — it is loaded automatically and is gitignored.

| Variable | Meaning |
|---|---|
| `BUZZ_SERVER_URL` | Buzz API server URL (no trailing slash) |
| `BUZZ_CONTACT_INFORMATION` | Contact info for the User-Agent header |
| `BUZZ_APPLICATION_INFORMATION` | Application name for the User-Agent header |
| `BUZZ_OAUTH_USER_ID` | `userid` of the Application Identity account (the OAuth `client_id`) |
| `BUZZ_OAUTH_KID` | Key id (`kid`) chosen when registering the public key |
| `BUZZ_PRIVATE_KEY_PATH` | Path to the RSA private key PEM |

Copy `.env.example` to `.env` and fill it in, or let the setup script generate it (below).

---

## Quickest start

### Run (setup + demo in one command)

The run script checks whether one-time setup has been completed. If not, it runs the interactive
setup first, then executes the read-only demo.

```bash
python -m pip install -r requirements.txt
python scripts/run_buzz_sample.py
```

Force re-running setup even when already configured:

```bash
python scripts/run_buzz_sample.py --setup
```

### Cleanup (return to a clean state)

Deletes the Application Identity account from Buzz, removes the registered OAuth key, and deletes
the local key files and `.env`.

```bash
python scripts/cleanup_buzz_sample.py
```

---

## OAuth setup (one time per application)

The setup script automates all of the following, but you can also perform the steps manually.

### Step 1 — Create an Application Identity account

An Application Identity account is a special user type that authenticates exclusively via OAuth.
Create it with the `createusers2` API and `type=applicationidentity`, using an admin account with
the Create User right in the target domain. Record the returned `userid` — this is your
**OAuth User ID** (`BUZZ_OAUTH_USER_ID`), used as the OAuth `client_id`.

### Step 2 — Generate an RSA key pair

```bash
python scripts/new_buzz_oauth_key.py                 # writes private_key.pem + public_key.pem
python scripts/new_buzz_oauth_key.py -o secrets -b 4096
```

Choose a **Key ID** (`kid`) — a short string identifying the key, e.g. `2025-q2`. Allowed
characters: ASCII letters, digits, `-`, `_`, `.` (max 128).

> **SECURITY** — `private_key.pem` is gitignored. Store it in a secrets manager (HashiCorp Vault,
> AWS/Azure/GCP secret managers) or encrypted storage for production. Never commit it.

### Step 3 — Register the public key with Buzz

```bash
python scripts/register_buzz_oauth_key.py \
    -s https://backgroundapi.agilixbuzz.com \
    -u 12345678 \
    -k 2025-q2 \
    -p public_key.pem
# Admin Bearer token via --token, the BUZZ_ADMIN_TOKEN env var, or an interactive prompt.
```

A `204 No Content` response means the key is stored.

### Step 4 — Configure and run

Create `.env` (see Configuration above) or run `python scripts/run_buzz_sample.py`, then:

```bash
python sample.py
```

---

## Using BuzzApiClient in your own code

```python
from buzz_api_client import BuzzApiClient

with BuzzApiClient.from_pem_file(
    server_url="https://backgroundapi.agilixbuzz.com",
    user_agent="MyApp/1.0 (Python; MyApp; admin@example.com)",
    oauth_user_id="12345678",
    oauth_kid="2025-q2",
    private_key_path="private_key.pem",
) as client:
    # BuzzApiClient obtains and refreshes Bearer tokens automatically.
    # domainid=0 lists every domain this account has ReadDomain rights on.
    domains = client.verify_response(
        client.json_request("GET", "listdomains", params={"domainid": 0}))
    user = client.verify_response(client.json_request("GET", "getuser2"))
    domain = client.verify_response(
        client.json_request("GET", "getdomain2", params={"domainid": "6"}))
```

`json_request(method, cmd, params=None, json_body=None, include_token=True)` returns the parsed
JSON response. `verify_response(node)` raises `BuzzApiError` unless `response.code == "OK"` (and
recursively checks child responses from multi-object commands such as CreateUsers2).

---

## Key management

### Rotating a key (zero downtime)

1. Generate a new key pair and choose a new `kid`.
2. Register the new public key (PUTting a new `kid` leaves the old key active).
3. Update `BUZZ_OAUTH_KID` and `BUZZ_PRIVATE_KEY_PATH` to the new key.
4. Once all instances have switched over, delete the old key:
   `DELETE {server}/api/users/{userid}/keys/{old-kid}` with an admin Bearer token.

### Revoking a compromised key

Register a new key, switch your app to it, then delete the compromised public key and revoke
outstanding tokens (`POST {server}/api/oauth/revoke` with form body `token=<access_token>`, or the
`TerminateUserSessions` command as an administrator).

---

## Troubleshooting OAuth

| Error | Cause | Fix |
|-------|-------|-----|
| `invalid_client: The client_assertion JWT has expired.` | Clock skew or a slow retry. | Sync your system clock (NTP). A fresh JWT is built for every token request. |
| `invalid_client: No active key found for the specified 'kid'.` | `BUZZ_OAUTH_KID` doesn't match a registered key. | Re-register the key and verify the `kid` matches exactly. |
| `invalid_client: ... signature or claims are invalid.` | Wrong private key, or `iss`/`sub` mismatch. | Confirm `BUZZ_OAUTH_USER_ID` is the Application Identity account's `userid` and the key matches the registered public key. |
| HTTP 400 registering a key | Wrong PEM format or key too small. | Use an SPKI PEM (`-----BEGIN PUBLIC KEY-----`), minimum 2048 bits. |
| HTTP 401/403 registering a key | Admin token lacks Update User rights. | Use an admin with the Update User right on the account. |
