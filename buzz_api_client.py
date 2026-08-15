"""Buzz API client library.

Makes requests to a Buzz API server, authenticating with OAuth 2.0 JWT client
credentials (RFC 6749 + RFC 7523).  The client handles token acquisition and
automatic refresh, exponential backoff, and rate-limit compliance so integration
code can focus on business logic.

Requires Python 3.8+ and the ``cryptography`` and ``requests`` packages
(see requirements.txt).
"""

from __future__ import annotations

import base64
import json
import logging
import threading
import time
import uuid
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, Mapping, Optional, Union

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

__all__ = ["BuzzApiClient", "BuzzApiError"]

# Retry/backoff configuration — mirrors the reference C# client.
_RETRIES_TO_MAKE = 5
_INITIAL_WAIT_SECONDS = 1.0
_MAX_RETRY_WAIT_SECONDS = 64.0

# How far before token expiry to proactively refresh.  Tokens are valid for one
# hour; refreshing five minutes early gives a comfortable window for slow
# networks or clock skew.
_OAUTH_TOKEN_REFRESH_MARGIN_SECONDS = 5 * 60

# Fields that must never be written to logs.
_SENSITIVE_FIELDS = frozenset(
    {"token", "access_token", "refresh_token", "password", "client_assertion", "client_secret"}
)

# HTTP status codes that must NOT be retried (client errors + a few server
# errors that will never succeed on retry).  Everything else — network errors,
# timeouts, 500, 502, 504, 429, 503 — is retried.
_NO_RETRY_STATUS = frozenset(
    {
        400, 401, 402, 403, 405, 406, 407, 410, 411, 412, 413, 414, 415, 416,
        417, 421, 422, 424, 426, 428, 431, 451,  # client errors
        501, 505, 506, 508, 510, 511,            # server errors
    }
)


class BuzzApiError(Exception):
    """Raised when a Buzz API call fails or returns a non-OK response code."""


class _HttpStatusError(Exception):
    """Internal: a non-success HTTP status was received."""

    def __init__(self, status_code: int, body: str = "") -> None:
        super().__init__(f"Server returned HTTP {status_code}")
        self.status_code = status_code
        self.body = body


class BuzzApiClient:
    """A client for the Buzz API using OAuth 2.0 JWT client credentials.

    Construct with an RSA private key whose public key is registered with Buzz,
    the Application Identity account's user id, and the key id (``kid``).  The
    client obtains and refreshes Bearer access tokens automatically — no
    password is ever sent over the network.

    Typical use::

        with BuzzApiClient.from_pem_file(
            server_url="https://backgroundapi.agilixbuzz.com",
            user_agent="MyApp/1.0 (Python; MyApp; admin@example.com)",
            oauth_user_id="12345678",
            oauth_kid="2025-q2",
            private_key_path="private_key.pem",
        ) as client:
            user = client.verify_response(client.json_request("GET", "getuser2"))
    """

    def __init__(
        self,
        server_url: str,
        user_agent: str,
        oauth_user_id: str,
        oauth_kid: str,
        private_key: RSAPrivateKey,
        *,
        verbose: bool = False,
        timeout: float = 600.0,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        """Create a client.

        :param server_url: Buzz server URL, including protocol, without a trailing ``/``.
        :param user_agent: User-Agent header value sent on every request.
        :param oauth_user_id: ``userid`` of the Application Identity account.  Used
            as the OAuth ``client_id`` and the JWT ``iss``/``sub`` claims.
        :param oauth_kid: The key id (``kid``) chosen when the public key was
            registered with Buzz.
        :param private_key: An RSA private key object (see :meth:`from_pem_file`).
        :param verbose: Log request URLs at INFO level instead of DEBUG.
        :param timeout: Per-request timeout in seconds.
        :param logger: Logger to use; defaults to ``logging.getLogger("buzz_api_client")``.
        """
        if not oauth_user_id:
            raise ValueError("oauth_user_id is required")
        if not oauth_kid:
            raise ValueError("oauth_kid is required")
        if private_key is None:
            raise ValueError("private_key is required")

        self.server_url = server_url.strip().rstrip("/")
        self.user_agent = user_agent
        self.verbose = verbose
        self.timeout = timeout
        self.token: Optional[str] = None

        self._logger = logger or logging.getLogger("buzz_api_client")
        self._oauth_user_id = oauth_user_id
        self._oauth_kid = oauth_kid
        self._private_key = private_key
        self._oauth_token_endpoint = f"{self.server_url}/api/oauth/token"
        self._token_expiry = 0.0  # epoch seconds
        self._token_lock = threading.Lock()

        self._session = requests.Session()
        self._session.headers["User-Agent"] = user_agent

    # ── Construction helpers ──────────────────────────────────────────────────
    @classmethod
    def from_pem_file(
        cls,
        server_url: str,
        user_agent: str,
        oauth_user_id: str,
        oauth_kid: str,
        private_key_path: str,
        **kwargs: Any,
    ) -> "BuzzApiClient":
        """Create a client, loading the RSA private key from a PEM file."""
        with open(private_key_path, "rb") as fh:
            private_key = serialization.load_pem_private_key(fh.read(), password=None)
        if not isinstance(private_key, RSAPrivateKey):
            raise ValueError(f"{private_key_path} does not contain an RSA private key")
        return cls(server_url, user_agent, oauth_user_id, oauth_kid, private_key, **kwargs)

    # ── Context management ────────────────────────────────────────────────────
    def __enter__(self) -> "BuzzApiClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    def close(self) -> None:
        """Release the underlying HTTP session."""
        self._session.close()

    # ── Public API ────────────────────────────────────────────────────────────
    def json_request(
        self,
        method: str,
        cmd: Optional[str] = None,
        params: Optional[Mapping[str, Any]] = None,
        json_body: Optional[Any] = None,
        include_token: bool = True,
    ) -> Optional[Any]:
        """Make a request to a Buzz command that returns JSON.

        :param method: HTTP method, e.g. ``"GET"`` or ``"POST"``.
        :param cmd: The command to call, e.g. ``"getuser2"``.
        :param params: Query-string parameters.
        :param json_body: Object serialized as the JSON request body.
        :param include_token: Attach the OAuth Bearer token (obtaining/refreshing
            it first if necessary).
        :returns: The parsed JSON response, or ``None`` if the body was empty.
        """
        if include_token:
            self._ensure_token()

        content = None
        if json_body is not None:
            content = json.dumps(json_body).encode("utf-8")

        response = self._request_with_retry(method, cmd, params, content, include_token)
        node = self._parse_json(response)
        self._trace_response(node)

        # If the token expired or was revoked, re-authenticate and retry once.
        if include_token and self.token is not None and _response_code(node) == "NoAuthentication":
            self._logger.debug('Re-authenticating because the request returned code "NoAuthentication"')
            with self._token_lock:
                self._authenticate_oauth()
            response = self._request_with_retry(method, cmd, params, content, include_token)
            node = self._parse_json(response)
            self._trace_response(node)

        return node

    def verify_response(self, response_json: Optional[Any], check_child_responses: bool = True) -> Any:
        """Verify that a Buzz JSON response indicates success.

        :param response_json: The parsed response to check.
        :param check_child_responses: Also verify each nested child response
            (returned by multi-object commands such as CreateUsers2).
        :returns: The verified (non-null) response node.
        :raises BuzzApiError: If the response code is not ``OK``.
        """
        if response_json is None:
            self._logger.error("Buzz API call failed. Expected response.code to be OK, found: null")
            raise BuzzApiError("Buzz API call failed. Expected response.code to be OK, found: null")

        json_to_verify = response_json
        child_response = response_json.get("response") if isinstance(response_json, dict) else None
        if child_response is not None:
            json_to_verify = child_response

        if not isinstance(json_to_verify, dict) or json_to_verify.get("code") != "OK":
            redacted = json.dumps(_clone_and_redact(response_json))
            self._logger.error("Buzz API call failed. Expected response.code to be OK, found: %s", redacted)
            raise BuzzApiError(f"Buzz API call failed. Expected response.code to be OK, found: {redacted}")

        if check_child_responses:
            responses = json_to_verify.get("responses")
            if isinstance(responses, dict):
                child = responses.get("response")
                if isinstance(child, list):
                    for item in child:
                        self.verify_response(item)
                elif isinstance(child, dict):
                    self.verify_response(child)

        return json_to_verify

    # ── OAuth ─────────────────────────────────────────────────────────────────
    def _ensure_token(self) -> None:
        if self.token is not None and time.time() < self._token_expiry - _OAUTH_TOKEN_REFRESH_MARGIN_SECONDS:
            return
        with self._token_lock:
            if self.token is None or time.time() >= self._token_expiry - _OAUTH_TOKEN_REFRESH_MARGIN_SECONDS:
                self._authenticate_oauth()

    def _authenticate_oauth(self) -> None:
        """Request a new Bearer access token using a signed JWT client assertion.

        Called with ``_token_lock`` held.
        """
        self._logger.info("Requesting OAuth access token")

        retries_remaining = _RETRIES_TO_MAKE
        base_wait = _INITIAL_WAIT_SECONDS
        while True:
            # Build a fresh assertion on every attempt: JWTs expire in two minutes
            # and a long Retry-After backoff can push a reused assertion past exp.
            assertion = self._build_client_assertion()
            form = {
                "grant_type": "client_credentials",
                "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                "client_assertion": assertion,
            }
            retry_after = None
            try:
                response = self._session.post(self._oauth_token_endpoint, data=form, timeout=self.timeout)
                retry_after = response.headers.get("Retry-After")

                if response.status_code in (429, 503) and retries_remaining > 0:
                    wait = _wait_from_response(response, base_wait)
                    self._logger.warning(
                        "OAuth token request rate-limited (%s), backing off %.0fms, %d retries remaining",
                        response.status_code, wait * 1000, retries_remaining,
                    )
                    time.sleep(wait)
                    retries_remaining -= 1
                    base_wait *= 2
                    continue

                if not response.ok:
                    body = response.text
                    self._logger.error("OAuth token request failed: %s %s", response.status_code, body)
                    raise _HttpStatusError(response.status_code, body)

                token_json = response.json()
                access_token = token_json.get("access_token")
                if not access_token:
                    raise BuzzApiError("OAuth token response did not contain an access_token.")
                expires_in = _coerce_int(token_json.get("expires_in"), 3600)
                if expires_in <= 0:
                    expires_in = 3600
                self.token = access_token
                self._token_expiry = time.time() + expires_in
                self._logger.info("OAuth token obtained, expires in %ds", expires_in)
                return
            except _HttpStatusError as e:
                if retries_remaining > 0 and _status_allows_retry(e.status_code):
                    wait = _wait_from_retry_header(retry_after, base_wait)
                    self._logger.debug("OAuth token request retrying after HTTP %s", e.status_code)
                    time.sleep(wait)
                    retries_remaining -= 1
                    base_wait *= 2
                    continue
                raise
            except (requests.ConnectionError, requests.Timeout) as e:
                if retries_remaining > 0:
                    wait = _wait_from_retry_header(retry_after, base_wait)
                    self._logger.debug("OAuth token request retrying after %s", type(e).__name__)
                    time.sleep(wait)
                    retries_remaining -= 1
                    base_wait *= 2
                    continue
                raise

    def _build_client_assertion(self) -> str:
        """Build a signed JWT client assertion for the token endpoint (RFC 7523 §3).

        Signed with RS256 (RSASSA-PKCS1-v1_5 + SHA-256).  Includes iss, sub, aud,
        iat, exp, and a unique jti to prevent replay attacks.
        """
        now = int(time.time())
        header = {"alg": "RS256", "kid": self._oauth_kid, "typ": "JWT"}
        payload = {
            "iss": self._oauth_user_id,                 # issuer = client
            "sub": self._oauth_user_id,                 # subject = client (must equal iss per RFC 7523)
            "aud": self._oauth_token_endpoint,          # audience = token endpoint URL
            "iat": now,                                 # issued at
            "exp": now + 120,                           # expires (2-minute lifetime; max allowed is 5 min)
            "jti": uuid.uuid4().hex,                    # unique id — prevents replay attacks
        }
        header_encoded = _b64url(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        payload_encoded = _b64url(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        signing_input = f"{header_encoded}.{payload_encoded}"
        signature = self._private_key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input}.{_b64url(signature)}"

    # ── HTTP with retry ───────────────────────────────────────────────────────
    def _request_with_retry(
        self,
        method: str,
        cmd: Optional[str],
        params: Optional[Mapping[str, Any]],
        content: Optional[bytes],
        include_token: bool,
    ) -> requests.Response:
        url = self.server_url + "/cmd" + (f"/{cmd}" if cmd else "")
        headers: Dict[str, str] = {"Accept": "application/json"}
        if content is not None:
            headers["Content-Type"] = "application/json"
        # OAuth always uses the Authorization: Bearer header.
        if include_token and self.token is not None:
            headers["Authorization"] = f"Bearer {self.token}"

        retries_remaining = _RETRIES_TO_MAKE
        base_wait = _INITIAL_WAIT_SECONDS
        while True:
            retry_after = None
            try:
                self._trace_request(url, params)
                response = self._session.request(
                    method, url, params=params, data=content, headers=headers, timeout=self.timeout
                )
                retry_after = response.headers.get("Retry-After")

                # Rate/time limiting: 429 Too Many Requests / 503 Service Unavailable.
                if response.status_code in (429, 503):
                    if retries_remaining > 0:
                        wait = _wait_from_response(response, base_wait)
                        self._logger.warning(
                            "Request rate/time limited (%s), backing off %.0fms, %d retries remaining",
                            response.status_code, wait * 1000, retries_remaining,
                        )
                        time.sleep(wait)
                        retries_remaining -= 1
                        base_wait *= 2
                        continue
                    raise BuzzApiError(f"Server returned {response.status_code} (rate/time limited). No retries remaining.")

                if not response.ok:
                    raise _HttpStatusError(response.status_code, response.text)
                return response
            except _HttpStatusError as e:
                if retries_remaining > 0 and _status_allows_retry(e.status_code):
                    wait = _wait_from_retry_header(retry_after, base_wait)
                    self._logger.debug("Retrying %s after HTTP %s", cmd, e.status_code)
                    time.sleep(wait)
                    retries_remaining -= 1
                    base_wait *= 2
                    continue
                raise BuzzApiError(f"Request to {cmd or url} failed: HTTP {e.status_code}") from e
            except (requests.ConnectionError, requests.Timeout) as e:
                if retries_remaining > 0:
                    wait = _wait_from_retry_header(retry_after, base_wait)
                    self._logger.debug("Retryable network error invoking %s: %s", cmd, type(e).__name__)
                    time.sleep(wait)
                    retries_remaining -= 1
                    base_wait *= 2
                    continue
                raise

    # ── Logging helpers ───────────────────────────────────────────────────────
    def _trace_request(self, url: str, params: Optional[Mapping[str, Any]]) -> None:
        # Bodies are never logged: request bodies contain credentials.  The
        # _token query parameter (used only by legacy auth, not this client) is
        # stripped as a defensive measure.
        display = _redact_query_param(url, "_token")
        if params:
            display += "?" + "&".join(f"{k}=..." if k in _SENSITIVE_FIELDS or k == "_token" else f"{k}={v}"
                                     for k, v in params.items())
        if self.verbose:
            self._logger.info("Request: %s", display)
        else:
            self._logger.debug("Request: %s", display)

    def _trace_response(self, node: Optional[Any]) -> None:
        if not self._logger.isEnabledFor(logging.DEBUG):
            return
        if node is not None:
            text = json.dumps(_clone_and_redact(node))
            self._logger.debug("Response: %s", text[:1000])
        else:
            self._logger.debug("Response was empty or not JSON")

    @staticmethod
    def _parse_json(response: requests.Response) -> Optional[Any]:
        text = response.text
        if not text:
            return None
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return None


# ── Module-level helpers ───────────────────────────────────────────────────────
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _response_code(node: Optional[Any]) -> Optional[str]:
    if isinstance(node, dict):
        response = node.get("response")
        if isinstance(response, dict):
            return response.get("code")
        return node.get("code")
    return None


def _coerce_int(value: Any, default: int) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return default


def _retry_after_seconds(retry_after: Optional[str]) -> Optional[float]:
    """Parse a Retry-After header value (delta-seconds or an HTTP date)."""
    if not retry_after:
        return None
    retry_after = retry_after.strip()
    if retry_after.isdigit():
        return float(retry_after)
    try:
        when = parsedate_to_datetime(retry_after)
    except (TypeError, ValueError):
        return None
    if when is None:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return max(0.0, (when - datetime.now(timezone.utc)).total_seconds())


def _wait_from_response(response: requests.Response, base_wait: float) -> float:
    """Backoff duration from rate-limit headers: Retry-After, else X-RateLimit-Reset."""
    seconds = _retry_after_seconds(response.headers.get("Retry-After"))
    if seconds and seconds > 0:
        return _clamp(seconds, base_wait, _MAX_RETRY_WAIT_SECONDS)

    reset = response.headers.get("X-RateLimit-Reset")
    if reset and reset.strip().isdigit():
        reset_secs = int(reset.strip())
        if reset_secs > 0:
            return _clamp(float(reset_secs), base_wait, _MAX_RETRY_WAIT_SECONDS)

    # Fall back to the current base wait plus a little jitter, capped at the max.
    return min(_MAX_RETRY_WAIT_SECONDS, base_wait + _jitter())


def _wait_from_retry_header(retry_after: Optional[str], base_wait: float) -> float:
    """Backoff from a Retry-After header, else exponential backoff with jitter."""
    seconds = _retry_after_seconds(retry_after)
    if seconds is not None:
        return min(_MAX_RETRY_WAIT_SECONDS, max(base_wait, seconds))
    return min(_MAX_RETRY_WAIT_SECONDS, base_wait + _jitter())


def _jitter() -> float:
    # 1–1000 ms of jitter, matching the reference client.  Uses the hash of a
    # fresh uuid so we avoid seeding a global PRNG.
    return (uuid.uuid4().int % 1000 + 1) / 1000.0


def _clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def _status_allows_retry(status_code: Optional[int]) -> bool:
    if status_code is None:
        return True
    return status_code not in _NO_RETRY_STATUS


def _redact_query_param(uri: str, param_name: str) -> str:
    q = uri.find("?")
    if q < 0:
        return uri
    kept = [p for p in uri[q + 1:].split("&") if not p.lower().startswith(param_name.lower() + "=")]
    return f"{uri[:q]}?{'&'.join(kept)}" if kept else uri[:q]


def _clone_and_redact(node: Any) -> Any:
    """Deep-copy a JSON value, masking any sensitive field values."""
    if isinstance(node, dict):
        return {k: ("[REDACTED]" if k in _SENSITIVE_FIELDS else _clone_and_redact(v)) for k, v in node.items()}
    if isinstance(node, list):
        return [_clone_and_redact(v) for v in node]
    return node
