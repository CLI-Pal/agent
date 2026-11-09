"""
CLI Pal Agent - REST API Client Module

Handles ONE-WAY communication: agent -> server via HTTP POST.
Used for sending metrics (with query stats), EXPLAIN plans, schema, and deadlocks.

This is SEPARATE from WebSocket (which is for terminal sessions only).
"""

import gzip
import json
import random
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
from typing import Any, Optional


class MetricsAPIClient:
    """REST API client for sending metrics to CLI Pal platform

    Handles all metrics communication via HTTP POST requests.
    Includes retry logic, version headers, and instruction parsing.
    """

    # Socket timeout for connecting, sending and waiting for the response
    TIMEOUT = 30
    # Bodies at least this big are gzipped once the server says it accepts gzip
    GZIP_MIN_BYTES = 1024
    # Retry delay: BASE * 2^(attempt-1) seconds, capped, randomised to 50-100%
    BACKOFF_BASE = 5.0
    BACKOFF_CAP = 30.0
    # Don't hold the metrics loop for a Retry-After longer than this
    MAX_RETRY_WAIT = 30
    # How long to leave an endpoint alone after a 429 without Retry-After
    DEFAULT_RATE_LIMIT_WAIT = 60
    # Responses meaning the request never reached the application, so it is safe
    # to send again: 503, and Cloudflare 521/522/523 (origin down or unreachable)
    NOT_PROCESSED_STATUSES = (503, 521, 522, 523)

    def __init__(self, server_url: str, token: str, version: str, logger):
        """Initialize API client

        Args:
            server_url: WebSocket URL (will be converted to HTTPS)
            token: Agent authentication token
            version: Agent version string
            logger: Logger instance
        """
        # Convert wss://app.clipal.me/ws to https://app.clipal.me
        self.base_url = server_url.replace('wss://', 'https://').replace('ws://', 'http://')
        if self.base_url.endswith('/ws'):
            self.base_url = self.base_url[:-3]

        self.token = token
        self.version = version
        self.logger = logger

        # Server instructions (updated from API responses)
        self.instructions = {
            'metrics_interval': 60,
            'query_stats_interval': 300,
            'explains_interval': 600,
            'collect_query_stats': True,
            'collect_explains': True,
            'collect_schema': True,
            'collect_deadlocks': True,
            'accepts_gzip': False,   # Server can read gzipped request bodies
            'watched_digests': []  # Digests to always collect regardless of speed
        }

        # endpoint -> time.monotonic() before which we don't send (Retry-After)
        self._blocked_until = {}

    def send_metrics(self, metrics: dict) -> bool:
        """POST metrics to /api/v1/metrics

        Args:
            metrics: System and database metrics dict

        Returns:
            True if the server stored them
        """
        return self._accepted(self._post('/api/v1/metrics', metrics))

    def send_query_explains(self, explains: list) -> bool:
        """POST EXPLAIN plans to /api/v1/query-explains

        Args:
            explains: List of EXPLAIN plan dicts

        Returns:
            True if successful
        """
        if not self.instructions.get('collect_explains', True):
            self.logger.debug("EXPLAIN collection disabled by server")
            return True
        # Stored as an upsert per (server, digest), so retries are safe
        return self._accepted(self._post('/api/v1/query-explains', {'explains': explains}, idempotent=True))

    def send_schema_update(self, schema_info: dict, tables_involved: list,
                           changed_only: bool = False) -> bool:
        """POST schema info to /api/v1/schema

        Args:
            schema_info: Schema information dict
            tables_involved: List of [schema, table] pairs
            changed_only: The tables are new or changed since the last upload, and
                should replace what the server has

        Returns:
            True if the server stored it
        """
        if not self.instructions.get('collect_schema', True):
            self.logger.debug("Schema collection disabled by server")
            return True
        payload = {
            'schema_info': schema_info,
            'tables_involved': tables_involved
        }
        if changed_only:
            payload['schema_mode'] = 'changed'
        return self._accepted(self._post('/api/v1/schema', payload))

    def send_deadlock(self, deadlock_info: dict) -> bool:
        """POST deadlock event to /api/v1/deadlocks

        Args:
            deadlock_info: Deadlock event information

        Returns:
            True if the server has it (including "already recorded")
        """
        if not self.instructions.get('collect_deadlocks', True):
            self.logger.debug("Deadlock collection disabled by server")
            return True
        # The server dedupes on section_hash, so retries are safe
        return self._accepted(self._post('/api/v1/deadlocks', deadlock_info, idempotent=True))

    def _post(self, endpoint: str, data: dict, idempotent: bool = False,
              max_attempts: int = 3) -> Optional[dict]:
        """POST a JSON body, retrying only when that is safe

        - Connect/send failures and "never reached the app" statuses are retried
          for every endpoint: the server didn't get the request.
        - Other 5xx and missing responses (e.g. read timeout) are retried only for
          idempotent endpoints. Metrics and schema aren't: the server has usually
          stored them already, and it refuses a second upload as too soon.
        - 429 is never retried in the same call; Retry-After is honoured by not
          sending to that endpoint until then.

        Args:
            endpoint: API endpoint path
            data: Data to send as JSON
            idempotent: Sending the same data twice is harmless
            max_attempts: Maximum attempts

        Returns:
            Parsed JSON response on HTTP 2xx, None on failure or when skipped
        """
        wait = self._seconds_blocked(endpoint)
        if wait > 0:
            self.logger.info(f"Not sending to {endpoint}: server asked to wait {wait}s more", always=True)
            return None

        url = f"{self.base_url}{endpoint}"
        try:
            payload = json.dumps(data, cls=MySQLJSONEncoder).encode('utf-8')
        except (TypeError, ValueError) as e:
            self.logger.error(f"Cannot encode data for {endpoint}: {e}")
            return None

        use_gzip = bool(self.instructions.get('accepts_gzip')) and len(payload) >= self.GZIP_MIN_BYTES
        attempt = 0

        while True:
            attempt += 1
            headers = {
                'Content-Type': 'application/json',
                'X-Agent-Token': self.token,
                'X-Agent-Version': self.version,
                'User-Agent': f'CliPalAgent/{self.version}'
            }
            body = payload
            if use_gzip:
                body = gzip.compress(payload)
                headers['Content-Encoding'] = 'gzip'

            req = urllib.request.Request(url, data=body, headers=headers, method='POST')

            try:
                with urllib.request.urlopen(req, timeout=self.TIMEOUT) as response:
                    status = response.status
                    raw = response.read()

            except urllib.error.HTTPError as e:
                retry_after = self._parse_retry_after(e.headers.get('Retry-After') if e.headers else None)

                if use_gzip and e.code in (400, 415):
                    # The server couldn't read the compressed body: stop compressing
                    self.logger.warn(f"HTTP {e.code} for gzipped {endpoint}, sending uncompressed from now on")
                    self.instructions['accepts_gzip'] = False
                    use_gzip = False
                    attempt -= 1
                    continue

                if e.code == 429:
                    wait = retry_after if retry_after is not None else self.DEFAULT_RATE_LIMIT_WAIT
                    self._block(endpoint, wait)
                    self.logger.warn(f"HTTP 429 for {endpoint}: rate limited, not sending again for {wait}s")
                    return None

                self.logger.error(f"HTTP Error {e.code} for {endpoint}: {e.reason}")
                if e.code == 503 and retry_after:
                    self._block(endpoint, retry_after)
                if not (e.code in self.NOT_PROCESSED_STATUSES or (idempotent and e.code >= 500)):
                    return None
                delay = retry_after if retry_after is not None else self._backoff(attempt)

            except urllib.error.URLError as e:
                # Raised while connecting or sending: the request never fully
                # reached the server, so any endpoint can be retried
                self.logger.error(f"URL Error for {endpoint}: {e.reason} (attempt {attempt}/{max_attempts})")
                delay = self._backoff(attempt)

            except Exception as e:
                # Sent, but no complete response (read timeout, dropped connection)
                if not idempotent:
                    self.logger.warn(
                        f"No response from {endpoint} ({type(e).__name__}: {e}); "
                        "not retrying, the server has probably stored it"
                    )
                    return None
                self.logger.error(f"Error sending to {endpoint}: {e} (attempt {attempt}/{max_attempts})")
                delay = self._backoff(attempt)

            else:
                return self._handle_response(endpoint, status, raw)

            if attempt >= max_attempts:
                self.logger.error(f"Failed to send to {endpoint} after {attempt} attempts")
                return None
            if delay > self.MAX_RETRY_WAIT:
                self.logger.warn(f"Not retrying {endpoint} now: server asked to wait {int(delay)}s")
                return None
            time.sleep(delay)

    def _handle_response(self, endpoint: str, status: int, raw: bytes) -> Optional[dict]:
        """Parse a 2xx response and apply instructions / too-soon hints"""
        try:
            result = json.loads(raw.decode('utf-8')) if raw else {}
        except (UnicodeDecodeError, ValueError):
            self.logger.error(f"Invalid JSON response from {endpoint} (HTTP {status})")
            return None
        if not isinstance(result, dict):
            result = {}

        if isinstance(result.get('instructions'), dict):
            self._update_instructions(result['instructions'])

        if result.get('reason') == 'too_soon':
            retry_after = self._to_seconds(result.get('retry_after'))
            self._block(endpoint, retry_after)
            self.logger.info(
                f"POST {endpoint}: not stored, sent too soon after the previous one"
                + (f" (accepted again in {retry_after}s)" if retry_after else ""),
                always=True
            )
        else:
            self.logger.debug(f"POST {endpoint}: {status} - {result.get('message', 'OK')}")

        return result

    @staticmethod
    def _accepted(result: Optional[dict]) -> bool:
        """The server took the upload (not refused as too soon)"""
        return result is not None and result.get('reason') != 'too_soon'

    def _backoff(self, attempt: int) -> float:
        """Exponential backoff with jitter"""
        delay = min(self.BACKOFF_CAP, self.BACKOFF_BASE * (2 ** (attempt - 1)))
        return random.uniform(delay / 2, delay)

    def _block(self, endpoint: str, seconds: Optional[int]) -> None:
        if seconds:
            self._blocked_until[endpoint] = time.monotonic() + seconds

    def _seconds_blocked(self, endpoint: str) -> int:
        until = self._blocked_until.get(endpoint)
        if until is None:
            return 0
        remaining = until - time.monotonic()
        if remaining <= 0:
            del self._blocked_until[endpoint]
            return 0
        return int(remaining + 0.999)

    @staticmethod
    def _to_seconds(value: Any) -> Optional[int]:
        try:
            return max(0, int(value))
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _parse_retry_after(value: Optional[str]) -> Optional[int]:
        """Parse a Retry-After header: delay in seconds, or an HTTP date"""
        if not value:
            return None
        value = str(value).strip()
        if value.isdigit():
            return int(value)
        try:
            when = parsedate_to_datetime(value)
        except (TypeError, ValueError, IndexError, OverflowError):
            return None
        if when is None:
            return None
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        return max(0, int((when - datetime.now(timezone.utc)).total_seconds()))

    def _update_instructions(self, new_instructions: dict) -> None:
        """Update local instructions from server response

        Args:
            new_instructions: Instructions dict from server
        """
        # A server that doesn't mention gzip can't read it (older or rolled back)
        new_instructions = dict(new_instructions)
        new_instructions.setdefault('accepts_gzip', False)

        for key, value in new_instructions.items():
            if key in self.instructions:
                old_value = self.instructions[key]
                if old_value != value:
                    self.logger.info(f"Instruction updated: {key} = {value} (was {old_value})", always=True)
                self.instructions[key] = value


class MySQLJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder for MySQL types

    Handles Decimal, datetime, and bytes objects from MySQL.
    """

    def default(self, obj: Any) -> Any:
        if hasattr(obj, 'to_eng_string'):  # Decimal
            return float(obj)
        if hasattr(obj, 'isoformat'):  # datetime
            return obj.isoformat()
        if isinstance(obj, bytes):
            return obj.decode('utf-8', errors='replace')
        return super().default(obj)
