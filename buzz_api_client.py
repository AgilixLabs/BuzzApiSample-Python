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
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Dict, List, Mapping, Optional, Sequence, Union

import requests
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

__all__ = ["BuzzApiClient", "BuzzApiError", "BuzzApiThrottledError"]

# Retry/backoff configuration — mirrors the reference C# client.
_RETRIES_TO_MAKE = 5
_INITIAL_WAIT_SECONDS = 1.0
_MAX_RETRY_WAIT_SECONDS = 64.0

# The longest server-directed wait (Retry-After / X-RateLimit-Reset) the client
# will sit out before retrying.  Rate-limit windows are five minutes and the
# server adds jitter, so a Retry-After of several minutes is normal.  Retrying
# before the server says to only burns quota, so a longer wait fails the request
# instead of retrying early.
_MAX_SERVER_DIRECTED_WAIT_SECONDS = 10 * 60.0

# Response codes the server uses in the XML/JSON envelope to say "slow down and
# retry later" (compared case-insensitively).  Throttles are usually reported
# with HTTP 200 (the server wraps them for legacy clients), so the envelope code
# must be checked even when the HTTP status is a success.  "TooManyRequests" is
# what every throttle collapses to when the server is set to report throttles
# generically; "Service Unavailable" is the code written when the server sheds
# load before a request is authenticated.
_THROTTLE_CODES = frozenset(
    code.lower()
    for code in (
        "TooManyRequests", "RetryLater", "LimitExceeded", "RateLimit", "TimeLimit",
        "ServerOverwhelmed", "BackendPressure", "Service Unavailable", "ServiceUnavailable",
    )
)

# Throttle codes that stand for HTTP 503 (backend pressure / overload) rather than 429.
_THROTTLE_CODES_503 = frozenset(
    code.lower() for code in ("ServerOverwhelmed", "BackendPressure", "Service Unavailable", "ServiceUnavailable")
)

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
        400, 401, 402, 403, 404, 405, 406, 407, 409, 410, 411, 412, 413, 414,
        415, 416, 417, 421, 422, 424, 426, 428, 431, 451,  # client errors
        501, 505, 506, 508, 510, 511,                      # server errors
    }
)


class BuzzApiError(Exception):
    """Raised when a Buzz API call fails or returns a non-OK response code.

    :ivar status_code: The HTTP status that caused the failure, if there was one.
    """

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class BuzzApiThrottledError(BuzzApiError):
    """Raised when the Buzz API throttles a request (rate limit, time limit, or
    backend pressure) and the client has run out of retries, or when items
    within a batch or multi-object request were throttled.

    Derives from :class:`BuzzApiError`, so existing handlers still catch it.

    :ivar status_code: 429 or 503, even when the server wrapped the throttle in HTTP 200.
    :ivar code: The throttle code from the response envelope (for example
        ``"TimeLimit"``, ``"RateLimit"``, ``"BackendPressure"``, or
        ``"TooManyRequests"``), or the OAuth error code for the token endpoint.
        ``None`` if the server sent no code.
    :ivar retry_after: How long, in seconds, the server asked the client to wait
        (Retry-After or X-RateLimit-Reset), or ``None`` if it didn't say.
    :ivar response: The full response envelope, including the results of any
        items that were not throttled.
    :ivar throttled_item_indexes: For batch and multi-object requests, the
        indexes of the items that were throttled and should be resubmitted.
        Items not listed completed normally (or failed for other reasons) and
        should not be resubmitted.  Empty when the whole request was throttled.
    """

    def __init__(
        self,
        message: str,
        code: Optional[str],
        response: Optional[Any],
        throttled_item_indexes: Sequence[int] = (),
        retry_after: Optional[float] = None,
        status_code: int = 429,
    ) -> None:
        super().__init__(message, status_code)
        self.code = code
        self.response = response
        self.throttled_item_indexes: List[int] = list(throttled_item_indexes)
        self.retry_after = retry_after


class _HttpStatusError(Exception):
    """Internal: a non-success HTTP status was received."""

    def __init__(self, status_code: int, body: str = "", code: Optional[str] = None) -> None:
        super().__init__(f"Server returned HTTP {status_code}")
        self.status_code = status_code
        self.body = body
        self.code = code


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

        # time.monotonic() before which no request from this client should be
        # sent.  Set whenever the server signals throttling or backend pressure,
        # so threads sharing this client back off together instead of each
        # discovering the throttle separately.
        self._throttled_until = 0.0
        self._throttle_lock = threading.Lock()

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
        :returns: The parsed JSON response (XML responses are converted to the
            same shape), or ``None`` if the body was empty.
        :raises BuzzApiThrottledError: If the request was still throttled after
            the allowed retries, or the server asked to wait longer than 10 minutes.
        """
        if include_token:
            self._ensure_token()

        content = None
        if json_body is not None:
            content = json.dumps(json_body).encode("utf-8")

        try:
            node = self._request_with_retry(method, cmd, params, content, include_token)
            self._trace_response(node)
            authentication_rejected = _response_code(node) == "NoAuthentication"
        except BuzzApiError as e:
            # REST-style endpoints report an expired or revoked token as HTTP 401,
            # possibly with no envelope.
            if not (e.status_code == 401 and include_token and self.token is not None):
                raise
            node = None
            authentication_rejected = True

        # If the token expired or was revoked, re-authenticate and retry once.
        if include_token and self.token is not None and authentication_rejected:
            self._logger.debug('Re-authenticating because the request returned "NoAuthentication" or HTTP 401')
            with self._token_lock:
                self._authenticate_oauth()
            node = self._request_with_retry(method, cmd, params, content, include_token)
            self._trace_response(node)

        return node

    def verify_response(self, response_json: Optional[Any], check_child_responses: bool = True) -> Any:
        """Verify that a Buzz JSON response indicates success.

        :param response_json: The parsed response to check.
        :param check_child_responses: Also verify each nested child response
            (returned by multi-object commands such as CreateUsers2).
        :returns: The verified (non-null) response node.
        :raises BuzzApiThrottledError: If the response, or any child response,
            has a throttle code.  For child responses, ``throttled_item_indexes``
            lists the items to resubmit.
        :raises BuzzApiError: If the response code is not ``OK``.
        """
        if response_json is None:
            self._logger.error("Buzz API call failed. Expected response.code to be OK, found: null")
            raise BuzzApiError("Buzz API call failed. Expected response.code to be OK, found: null")

        json_to_verify = response_json
        child_response = response_json.get("response") if isinstance(response_json, dict) else None
        if child_response is not None:
            json_to_verify = child_response

        code = json_to_verify.get("code") if isinstance(json_to_verify, dict) else None
        if code != "OK":
            redacted = json.dumps(_clone_and_redact(response_json))
            self._logger.error("Buzz API call failed. Expected response.code to be OK, found: %s", redacted)
            if _is_throttle_code(code):
                raise BuzzApiThrottledError(
                    f"Buzz API call was throttled ({code}): {redacted}",
                    code, response_json, status_code=_throttle_status_code(200, code),
                )
            raise BuzzApiError(f"Buzz API call failed. Expected response.code to be OK, found: {redacted}")

        if check_child_responses:
            responses = _child_responses(json_to_verify)

            # Batch and multi-object commands report per-item throttles under an
            # outer OK.  Report them together so the caller can resubmit just
            # those items.  Throttled batch items were rejected without running;
            # a multi-object row that hit BackendPressure (e.g. a database
            # timeout) may have partially run.
            throttled_indexes = [i for i, item in enumerate(responses) if _is_throttle_code(_item_code(item))]
            if throttled_indexes:
                first_code = _item_code(responses[throttled_indexes[0]])
                indexes = ",".join(str(i) for i in throttled_indexes)
                self._logger.warning(
                    "%d of %d items were throttled (%s); resubmit items %s",
                    len(throttled_indexes), len(responses), first_code, indexes,
                )
                raise BuzzApiThrottledError(
                    f"{len(throttled_indexes)} of {len(responses)} items were throttled ({first_code}). "
                    f"Resubmit the items at indexes {indexes}.",
                    first_code, response_json, throttled_indexes,
                    status_code=_throttle_status_code(200, first_code),
                )

            for item in responses:
                self.verify_response(item)

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

            self._wait_for_throttle_window()

            retry_after = None
            try:
                response = self._session.post(self._oauth_token_endpoint, data=form, timeout=self.timeout)
                retry_after = response.headers.get("Retry-After")

                if not response.ok:
                    body = response.text
                    # The token endpoint answers with RFC 6749 errors rather than
                    # the Buzz envelope: rate limits and backend pressure are
                    # 429/503 with error "temporarily_unavailable" and Retry-After.
                    error_json = _try_parse_envelope(response)
                    oauth_error = error_json.get("error") if isinstance(error_json, dict) else None
                    if response.status_code in (429, 503) or oauth_error == "temporarily_unavailable":
                        server_wait = _server_directed_wait(response.headers)
                        wait = _throttle_wait(server_wait, base_wait)
                        if retries_remaining > 0 and wait <= _MAX_SERVER_DIRECTED_WAIT_SECONDS:
                            self._logger.warning(
                                "OAuth token request throttled (%s, %s), backing off %.0fms, %d retries remaining",
                                response.status_code, oauth_error, wait * 1000, retries_remaining,
                            )
                            self._extend_throttle_window(wait)
                            retries_remaining -= 1
                            base_wait *= 2
                            continue  # the throttle window is waited out at the top of the loop
                        self._extend_throttle_window(min(wait, _MAX_SERVER_DIRECTED_WAIT_SECONDS))
                        raise BuzzApiThrottledError(
                            f"OAuth token request was throttled ({response.status_code}): {body}",
                            oauth_error, None, retry_after=server_wait,
                            status_code=_throttle_status_code(response.status_code, None),
                        )
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
    ) -> Optional[Any]:
        """Send a request, retrying transient failures, and return the parsed
        response envelope (XML or JSON, normalized to JSON).

        Throttling is recognized from the HTTP status (429/503) or from the
        envelope code, since the server usually reports throttles as HTTP 200
        with a code like "TimeLimit" or "BackendPressure" in the body.
        """
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
            self._wait_for_throttle_window()

            retry_after = None
            try:
                self._trace_request(url, params)
                response = self._session.request(
                    method, url, params=params, data=content, headers=headers, timeout=self.timeout
                )
                retry_after = response.headers.get("Retry-After")

                # Parse strictly on success (a garbled success body is an error);
                # on failure the envelope is optional (e.g. an HTML proxy page).
                # A success body that fails to parse is not retried: the server
                # already ran the command, and resending a mutation (or a batch)
                # could repeat it.
                if response.ok:
                    try:
                        envelope = _parse_envelope(response)
                    except _PARSE_ERRORS as e:
                        raise BuzzApiError(
                            f"Could not parse the response to {cmd or url}: {e}", response.status_code
                        ) from e
                else:
                    envelope = _try_parse_envelope(response)
                code = _response_code(envelope)

                # API time/rate limiting and backend pressure: HTTP 429/503
                # (REST-style), or an envelope throttle code (usually with HTTP
                # 200).  Retry-After is sent either way; X-RateLimit-Reset
                # (seconds until the window resets) is the fallback.
                if response.status_code in (429, 503) or _is_throttle_code(code):
                    server_wait = _server_directed_wait(response.headers)
                    wait = _throttle_wait(server_wait, base_wait)
                    message = _response_message(envelope)
                    if retries_remaining > 0 and wait <= _MAX_SERVER_DIRECTED_WAIT_SECONDS:
                        self._logger.warning(
                            "Request throttled (HTTP %s, code %s: %s; pressure: %s %s), "
                            "backing off %.0fms, %d retries remaining",
                            response.status_code, code, message,
                            response.headers.get("X-Backend-Pressure-Service"),
                            response.headers.get("X-Backend-Pressure-Level"),
                            wait * 1000, retries_remaining,
                        )
                        self._extend_throttle_window(wait)
                        retries_remaining -= 1
                        base_wait *= 2
                        continue  # the throttle window is waited out at the top of the loop
                    self._extend_throttle_window(min(wait, _MAX_SERVER_DIRECTED_WAIT_SECONDS))
                    if retries_remaining > 0:
                        reason = (f"server asked to wait {wait:.0f}s, longer than the "
                                  f"{_MAX_SERVER_DIRECTED_WAIT_SECONDS:.0f}s limit")
                    else:
                        reason = "no retries remaining"
                    raise BuzzApiThrottledError(
                        f"Buzz API request was throttled (HTTP {response.status_code}, "
                        f"code {code or 'none'}): {message} ({reason})",
                        code, envelope, retry_after=server_wait,
                        status_code=_throttle_status_code(response.status_code, code),
                    )

                if response.ok:
                    self._extend_throttle_window_for_throttled_items(envelope, response.headers)
                    return envelope

                # A REST-style error status with an envelope (e.g. 400 BadRequest,
                # 404 ResourceNotFound): return it so the caller sees the server's
                # code and message, just as it would for the same error wrapped in
                # HTTP 200.  401 raises instead so json_request re-authenticates
                # whether or not an envelope came with it.
                if code is not None and not _status_allows_retry(response.status_code) \
                        and response.status_code != 401:
                    return envelope

                raise _HttpStatusError(response.status_code, response.text, code)
            except _HttpStatusError as e:
                if retries_remaining > 0 and _status_allows_retry(e.status_code):
                    wait = _wait_from_retry_header(retry_after, base_wait)
                    self._logger.debug("Retrying %s after HTTP %s", cmd, e.status_code)
                    time.sleep(wait)
                    retries_remaining -= 1
                    base_wait *= 2
                    continue
                detail = f" (code {e.code})" if e.code else ""
                raise BuzzApiError(f"Request to {cmd or url} failed: HTTP {e.status_code}{detail}", e.status_code) from e
            except (requests.ConnectionError, requests.Timeout) as e:
                if retries_remaining > 0:
                    wait = _wait_from_retry_header(retry_after, base_wait)
                    self._logger.debug("Retryable network error invoking %s: %s", cmd, type(e).__name__)
                    time.sleep(wait)
                    retries_remaining -= 1
                    base_wait *= 2
                    continue
                raise

    # ── Client-wide throttle window ───────────────────────────────────────────
    def _extend_throttle_window(self, wait: float) -> None:
        """Move the client-wide throttle window out to at least ``wait`` seconds from now (never back)."""
        until = time.monotonic() + wait
        with self._throttle_lock:
            if until > self._throttled_until:
                self._throttled_until = until

    def _wait_for_throttle_window(self) -> None:
        """Block until the client-wide throttle window has passed."""
        while True:
            with self._throttle_lock:
                remaining = self._throttled_until - time.monotonic()
            if remaining <= 0:
                return
            self._logger.debug("Waiting %.0fms for the server's throttle window to pass", remaining * 1000)
            time.sleep(remaining)

    def _extend_throttle_window_for_throttled_items(
        self, envelope: Optional[Any], headers: Mapping[str, str]
    ) -> None:
        """Back off the whole client when a successful batch or multi-object
        response contains throttled items, so resubmitting them (and any other
        requests sharing this client) waits as the server asked.
        """
        response = envelope.get("response") if isinstance(envelope, dict) else None
        if not isinstance(response, dict):
            response = envelope
        throttled = _count_throttled_items(response)
        if throttled == 0:
            return
        wait = min(_throttle_wait(_server_directed_wait(headers), _INITIAL_WAIT_SECONDS),
                   _MAX_SERVER_DIRECTED_WAIT_SECONDS)
        self._logger.warning(
            "%d items in the response were throttled; backing off %.0fms before the next request",
            throttled, wait * 1000,
        )
        self._extend_throttle_window(wait)

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


def _server_directed_wait(headers: Mapping[str, str]) -> Optional[float]:
    """The wait, in seconds, the server asked for: Retry-After (delta-seconds or
    an HTTP date) first, then X-RateLimit-Reset, which Buzz sends as seconds
    until the rate-limit window resets (not a Unix time).  The server sends these
    on throttled responses whether the HTTP status is 200 or 429/503.

    :returns: The server-directed wait, or ``None`` if the server gave none.
    """
    seconds = _retry_after_seconds(headers.get("Retry-After"))
    if seconds is not None and seconds > 0:
        return seconds
    reset_secs = _coerce_int(headers.get("X-RateLimit-Reset"), 0)
    if reset_secs > 0:
        return float(reset_secs)
    return None


def _throttle_wait(server_wait: Optional[float], base_wait: float) -> float:
    """How long to back off from a throttle: the server-directed wait if there is
    one (never less than the current exponential base), otherwise exponential
    backoff with jitter.  A server-directed wait is not capped here; the caller
    compares it with ``_MAX_SERVER_DIRECTED_WAIT_SECONDS`` rather than retrying
    before the server said to.
    """
    if server_wait is not None:
        return max(server_wait, base_wait)
    return min(_MAX_RETRY_WAIT_SECONDS, base_wait + _jitter())


def _throttle_status_code(status_code: int, code: Optional[str]) -> int:
    """The HTTP status to report for a throttle: the real one when the server
    sent 429/503, otherwise the status the envelope code stands for (the server
    wraps these in HTTP 200 for legacy clients).
    """
    if status_code in (429, 503):
        return status_code
    return 503 if isinstance(code, str) and code.lower() in _THROTTLE_CODES_503 else 429


def _is_throttle_code(code: Optional[Any]) -> bool:
    return isinstance(code, str) and code.lower() in _THROTTLE_CODES


def _response_message(envelope: Optional[Any]) -> Optional[str]:
    response = envelope.get("response") if isinstance(envelope, dict) else None
    return response.get("message") if isinstance(response, dict) else None


def _item_code(item: Any) -> Optional[Any]:
    return item.get("code") if isinstance(item, dict) else None


def _child_responses(response: Any) -> List[Any]:
    """The per-item results of a batch or multi-object command
    (``responses.response``).  JSON always gives a list; a single item
    converted from XML is a dict.
    """
    responses = response.get("responses") if isinstance(response, dict) else None
    items = responses.get("response") if isinstance(responses, dict) else None
    if isinstance(items, list):
        return list(items)
    return [items] if isinstance(items, dict) else []


def _count_throttled_items(response: Any) -> int:
    """Count throttled items at any depth, since a batch item can itself be a
    multi-object command with per-row results."""
    return sum(
        (1 if _is_throttle_code(_item_code(item)) else 0) + _count_throttled_items(item)
        for item in _child_responses(response)
    )


# Exceptions raised by _parse_envelope for a body that is not valid JSON or XML
# (json.JSONDecodeError and UnicodeDecodeError are ValueErrors).
_PARSE_ERRORS = (ValueError, ET.ParseError)


def _parse_envelope(response: requests.Response) -> Optional[Any]:
    """Parse a response body as the XML or JSON envelope.

    The server returns XML unless JSON is requested, and some error paths may
    ignore the Accept header, so XML is converted to the equivalent JSON shape:
    attributes and child elements become properties, repeated elements become
    lists, and text content becomes ``"$value"``.

    :returns: The envelope as JSON, or ``None`` for an empty body.
    :raises ValueError, xml.etree.ElementTree.ParseError: If the body is not valid JSON or XML.
    """
    body = response.content
    if body.startswith(b"\xef\xbb\xbf"):  # UTF-8 byte order mark
        body = body[3:]
    body = body.lstrip()
    if not body:
        return None
    if "xml" in response.headers.get("Content-Type", "").lower() or body.startswith(b"<"):
        root = ET.fromstring(body)
        return {_xml_local_name(root.tag): _xml_to_json(root)}
    return json.loads(response.text)


def _try_parse_envelope(response: requests.Response) -> Optional[Any]:
    """Like :func:`_parse_envelope`, but returns ``None`` instead of raising when
    the body is not XML or JSON (for example, an HTML error page from a proxy)."""
    try:
        return _parse_envelope(response)
    except _PARSE_ERRORS:
        return None


def _xml_local_name(name: str) -> str:
    # ElementTree writes namespaced names as "{uri}local".
    return name.rsplit("}", 1)[-1]


def _xml_to_json(element: ET.Element) -> Dict[str, Any]:
    obj: Dict[str, Any] = {}
    for name, value in element.attrib.items():
        obj[_xml_local_name(name)] = value
    groups: Dict[str, List[ET.Element]] = {}
    for child in element:
        if isinstance(child.tag, str):  # skip comments / processing instructions
            groups.setdefault(_xml_local_name(child.tag), []).append(child)
    for name, children in groups.items():
        obj[name] = _xml_to_json(children[0]) if len(children) == 1 else [_xml_to_json(c) for c in children]
    # Direct text only: the element's leading text plus the text after each child.
    text = (element.text or "") + "".join(child.tail or "" for child in element)
    if text.strip():
        obj["$value"] = text
    return obj


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
