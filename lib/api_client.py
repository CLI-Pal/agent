"""
CLI Pal Agent - REST API Client Module

Handles ONE-WAY communication: agent -> server via HTTP POST.
Used for sending metrics, query stats, EXPLAIN plans, schema, and deadlocks.

This is SEPARATE from WebSocket (which is for terminal sessions only).
"""

import json
import time
import urllib.request
import urllib.error
from datetime import datetime
from typing import Any


class MetricsAPIClient:
    """REST API client for sending metrics to CLI Pal platform

    Handles all metrics communication via HTTP POST requests.
    Includes retry logic, version headers, and instruction parsing.
    """

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
            'watched_digests': []  # Digests to always collect regardless of speed
        }

    def send_metrics(self, metrics: dict) -> bool:
        """POST metrics to /api/v1/metrics

        Args:
            metrics: System and database metrics dict

        Returns:
            True if successful
        """
        return self._post('/api/v1/metrics', metrics)

    def send_query_stats(self, query_stats: list) -> bool:
        """POST query stats to /api/v1/query-stats

        Args:
            query_stats: List of query statistics

        Returns:
            True if successful
        """
        if not self.instructions.get('collect_query_stats', True):
            self.logger.debug("Query stats collection disabled by server")
            return True
        return self._post('/api/v1/query-stats', {'query_stats': query_stats})

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
        return self._post('/api/v1/query-explains', {'explains': explains})

    def send_schema_update(self, schema_info: dict, tables_involved: list) -> bool:
        """POST schema info to /api/v1/schema

        Args:
            schema_info: Schema information dict
            tables_involved: List of [schema, table] pairs

        Returns:
            True if successful
        """
        if not self.instructions.get('collect_schema', True):
            self.logger.debug("Schema collection disabled by server")
            return True
        return self._post('/api/v1/schema', {
            'schema_info': schema_info,
            'tables_involved': tables_involved
        })

    def send_deadlock(self, deadlock_info: dict) -> bool:
        """POST deadlock event to /api/v1/deadlocks

        Args:
            deadlock_info: Deadlock event information

        Returns:
            True if successful
        """
        if not self.instructions.get('collect_deadlocks', True):
            self.logger.debug("Deadlock collection disabled by server")
            return True
        return self._post('/api/v1/deadlocks', deadlock_info)

    def _post(self, endpoint: str, data: dict, max_retries: int = 3) -> bool:
        """Make POST request with JSON body and retry logic

        Args:
            endpoint: API endpoint path
            data: Data to send as JSON
            max_retries: Maximum retry attempts

        Returns:
            True if successful
        """
        url = f"{self.base_url}{endpoint}"

        for attempt in range(max_retries):
            try:
                json_data = json.dumps(data, cls=MySQLJSONEncoder).encode('utf-8')

                req = urllib.request.Request(
                    url,
                    data=json_data,
                    headers={
                        'Content-Type': 'application/json',
                        'X-Agent-Token': self.token,
                        'X-Agent-Version': self.version,
                        'User-Agent': f'CliPalAgent/{self.version}'
                    },
                    method='POST'
                )

                with urllib.request.urlopen(req, timeout=30) as response:
                    result = json.loads(response.read().decode('utf-8'))

                    # Update instructions if provided
                    if 'instructions' in result:
                        self._update_instructions(result['instructions'])

                    self.logger.debug(f"POST {endpoint}: {response.status} - {result.get('message', 'OK')}")
                    return response.status == 200

            except urllib.error.HTTPError as e:
                self.logger.error(f"HTTP Error {e.code} for {endpoint}: {e.reason}")
                if e.code in [401, 403, 404]:  # Don't retry auth/not-found errors
                    return False
            except urllib.error.URLError as e:
                self.logger.error(f"URL Error for {endpoint}: {e.reason} (attempt {attempt + 1}/{max_retries})")
            except Exception as e:
                self.logger.error(f"Error sending to {endpoint}: {e} (attempt {attempt + 1}/{max_retries})")

            # Exponential backoff before retry
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                time.sleep(wait_time)

        self.logger.error(f"Failed to send to {endpoint} after {max_retries} attempts")
        return False

    def _update_instructions(self, new_instructions: dict) -> None:
        """Update local instructions from server response

        Args:
            new_instructions: Instructions dict from server
        """
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
