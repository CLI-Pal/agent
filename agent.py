#!/usr/bin/env python3
"""
CLI Pal Agent - Main Entry Point

Modular agent for server monitoring and terminal access.

Features:
- System metrics collection (CPU, RAM, disk, network)
- MySQL/MariaDB monitoring and query optimization
- Secure terminal access via WebSocket
- REST API for metrics delivery
"""

import sys
import json
import time
import signal
import asyncio
import hashlib
import argparse
from typing import Optional

# Local imports
from lib.config import load_config, validate_secure_server
from lib.logger import setup_logger
from lib.system_metrics import SystemMetrics
from lib.api_client import MetricsAPIClient
from lib.websocket_client import WebSocketClient
from lib.terminal_handler import TerminalHandler
from lib.database import create_database_monitor

VERSION = "0.1.3"

# Optional PHP monitor (only loaded if enabled)
def _create_php_monitor(config: dict, logger):
    """Create PHP monitor if enabled and available"""
    if not config.get('php_enabled'):
        return None
    try:
        from lib.php_monitor import PHPMonitor
        monitor = PHPMonitor(config, logger.create_child("PHP"))
        if monitor.is_available():
            return monitor
        else:
            logger.warn("PHP-FPM not accessible, disabling PHP monitoring")
            return None
    except ImportError:
        logger.debug("PHP monitor module not available")
        return None
    except Exception as e:
        logger.error(f"Failed to initialize PHP monitor: {e}")
        return None


class SchemaUploadTracker:
    """Remembers which table schemas the server has, so only changes are uploaded

    Each table's columns and indexes are hashed, leaving out index cardinality
    (an estimate that changes all the time). Tables matching the last successful
    upload are skipped, except for a full upload on the first run and once a day.
    """

    FULL_UPLOAD_SECONDS = 24 * 3600
    VOLATILE_FIELDS = ('CARDINALITY', 'cardinality')

    def __init__(self):
        self._uploaded = {}            # (schema, table) -> hash
        self._last_full_upload = None  # time.monotonic() of the last full upload

    def prepare(self, schema_info: dict, tables) -> Optional[dict]:
        """Work out what to upload this cycle

        Args:
            schema_info: {'columns': [...], 'indexes': [...]} for the tables
            tables: (schema, table) pairs the schema was collected for

        Returns:
            {'schema_info', 'tables', 'hashes', 'full'} for new or changed tables,
            or None when there is nothing to upload
        """
        rows = {}
        for kind in ('columns', 'indexes'):
            for row in schema_info.get(kind) or []:
                key = (self._field(row, 'TABLE_SCHEMA'), self._field(row, 'TABLE_NAME'))
                rows.setdefault(key, {'columns': [], 'indexes': []})[kind].append(row)

        full = (self._last_full_upload is None
                or time.monotonic() - self._last_full_upload >= self.FULL_UPLOAD_SECONDS)

        hashes = {}
        for key in sorted(set(tables)):
            table_rows = rows.get(key)
            if not table_rows or not table_rows['columns']:
                continue  # Dropped or not visible: nothing to replace it with
            table_hash = self._hash(table_rows)
            if full or self._uploaded.get(key) != table_hash:
                hashes[key] = table_hash

        if not hashes:
            return None

        return {
            'schema_info': {
                'indexes': [row for key in hashes for row in rows[key]['indexes']],
                'columns': [row for key in hashes for row in rows[key]['columns']],
            },
            'tables': [[schema, table] for schema, table in hashes],
            'hashes': hashes,
            'full': full,
        }

    def mark_uploaded(self, upload: dict) -> None:
        """Record a successful upload returned by prepare()"""
        self._uploaded.update(upload['hashes'])
        if upload['full']:
            self._last_full_upload = time.monotonic()

    @staticmethod
    def _field(row: dict, name: str):
        value = row.get(name, row.get(name.lower()))
        if isinstance(value, (bytes, bytearray)):
            value = value.decode('utf-8', errors='replace')
        return value

    def _hash(self, table_rows: dict) -> str:
        parts = []
        for kind in ('columns', 'indexes'):
            for row in table_rows[kind]:
                stable = {k: v for k, v in row.items() if k not in self.VOLATILE_FIELDS}
                parts.append(kind + json.dumps(stable, sort_keys=True, default=str))
        return hashlib.sha1('\n'.join(sorted(parts)).encode('utf-8')).hexdigest()


class CliPalAgent:
    """Main agent class coordinating all components

    Runs two independent loops:
    - Metrics loop: Sends system/database metrics via REST API
    - WebSocket loop: Handles terminal sessions via WebSocket
    """

    def __init__(self, config: dict, logger):
        """Initialize the agent

        Args:
            config: Configuration dict from load_config()
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self.running = True

        # Initialize components
        self.system_metrics = SystemMetrics(logger.create_child("System"))
        self.database_monitor = create_database_monitor(config, logger)
        self.php_monitor = _create_php_monitor(config, logger)

        # REST API client for metrics (one-way HTTP POST)
        self.api_client = MetricsAPIClient(
            config['server_url'],
            config['token'],
            VERSION,
            logger.create_child("API")
        )

        # Terminal handler and WebSocket client (bidirectional for terminal)
        self.terminal = TerminalHandler(None, logger.create_child("Terminal"))
        self.ws_client = WebSocketClient(
            config['server_url'],
            config['token'],
            VERSION,
            self.terminal,
            logger.create_child("WebSocket")
        )
        # Set circular reference for terminal output
        self.terminal.ws = self.ws_client

        # Tracking for collection intervals
        self.metrics_cycle_count = 0
        self.optimization_cycle_count = 0
        self.metrics_interval = 60  # seconds

        # Schema already on the server, so unchanged tables aren't re-uploaded
        self.schema_tracker = SchemaUploadTracker()

    async def run(self):
        """Main agent loop

        Runs metrics loop and WebSocket loop concurrently.
        """
        self.logger.info(f"CLI Pal Agent v{VERSION} starting...", always=True)

        # Send initial metrics
        if self.system_metrics.available:
            self.logger.info("📊 System monitoring enabled", always=True)
            await self._send_metrics()
        else:
            self.logger.warn("⚠️  System monitoring DISABLED - psutil not available")

        # Log database monitor status with details
        if self.database_monitor.enabled:
            # Try to get MySQL version for detailed logging
            try:
                test_metrics = self.database_monitor.get_metrics()
                mysql_version = test_metrics.get('mysql_version', 'unknown')
                slow_threshold = getattr(self.database_monitor, 'slow_threshold_ms', 200)
                self.logger.info(f"📊 MySQL monitoring enabled (slow threshold: {slow_threshold}ms)", always=True)
                self.logger.info(f"  ✅ Connected to MySQL {mysql_version}", always=True)
            except Exception:
                self.logger.info("📊 Database monitoring enabled", always=True)
        else:
            self.logger.info("Database monitoring disabled", always=True)

        # Log PHP monitor status
        if self.php_monitor:
            self.logger.info("📊 PHP-FPM monitoring enabled", always=True)
        elif self.config.get('php_enabled'):
            self.logger.warn("⚠️  PHP-FPM monitoring requested but unavailable")

        # Run both loops concurrently
        await asyncio.gather(
            self._metrics_loop(),
            self.ws_client.run()
        )

    async def _metrics_loop(self):
        """Periodically send metrics via REST API

        Independent of WebSocket connection.
        """
        while self.running:
            try:
                await asyncio.sleep(self.metrics_interval)

                if self.system_metrics.available:
                    await self._send_metrics()

                # EXPLAIN & Schema collection based on server instructions
                self.optimization_cycle_count += 1
                explains_cycles = self.api_client.instructions.get('explains_interval', 600) // 60

                if self.optimization_cycle_count >= explains_cycles:
                    self.optimization_cycle_count = 0

                    if self.database_monitor.enabled and self.api_client.instructions.get('collect_explains', True):
                        await self._collect_and_send_explains()

            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Metrics loop error: {e}")

    async def _send_metrics(self):
        """Collect and send all metrics via REST API"""
        # Get system metrics
        metrics = self.system_metrics.get_metrics()

        # Increment cycle counter
        self.metrics_cycle_count += 1

        # Add failed logins
        try:
            failed_logins = self.system_metrics.get_failed_logins(max_entries=50)
            if failed_logins:
                metrics['failed_logins'] = failed_logins
                self.logger.info(f"Collected {len(failed_logins)} failed login attempts", always=True)
        except Exception as e:
            self.logger.error(f"Error collecting failed logins: {e}")

        # Add database metrics
        if self.database_monitor.enabled:
            try:
                db_metrics = self.database_monitor.get_metrics()
                if db_metrics:
                    # Monitors that still attach a single deadlock event (PostgreSQL)
                    deadlock_info = db_metrics.pop('deadlock', None)
                    metrics['mysql'] = db_metrics

                    # Send deadlock via dedicated endpoint
                    if deadlock_info:
                        await self._send_in_executor(
                            self.api_client.send_deadlock,
                            deadlock_info
                        )

                    # Query stats based on server instructions
                    query_stats_cycles = self.api_client.instructions.get('query_stats_interval', 300) // 60
                    if self.metrics_cycle_count % query_stats_cycles == 0:
                        if self.api_client.instructions.get('collect_query_stats', True):
                            watched = self.api_client.instructions.get('watched_digests', [])
                            query_stats = self.database_monitor.get_query_stats(watched_digests=set(watched))
                            if query_stats:
                                metrics['mysql']['query_stats'] = query_stats
                                self.logger.info(f"Collected {len(query_stats)} query stats", always=True)
            except Exception as e:
                self.logger.error(f"Error collecting database metrics: {e}")

            # Also runs when this cycle's DB collection failed, to retry earlier deadlocks
            await self._flush_pending_deadlocks()

        # Add PHP-FPM metrics if available
        if self.php_monitor:
            try:
                php_metrics = self.php_monitor.collect_metrics()
                if php_metrics and php_metrics.get('pools'):
                    metrics['php_status'] = php_metrics

                # Collect slow traces (tails slowlog files)
                slow_traces = self.php_monitor.collect_slow_traces()
                if slow_traces:
                    metrics['php_slow_traces'] = slow_traces
                    self.logger.info(f"Collected {len(slow_traces)} PHP slow traces", always=True)
            except Exception as e:
                self.logger.error(f"Error collecting PHP metrics: {e}")

        # Send via REST API
        await self._send_in_executor(self.api_client.send_metrics, metrics)

    async def _flush_pending_deadlocks(self):
        """Send queued deadlocks, oldest first

        A deadlock is marked as reported only after the server accepts it. On the
        first failure the rest stay queued for the next cycle.
        """
        for deadlock_info in self.database_monitor.get_pending_deadlocks():
            section_hash = deadlock_info.get('section_hash')
            try:
                sent = await self._send_in_executor(self.api_client.send_deadlock, deadlock_info)
            except Exception as e:
                self.logger.error(f"Error sending deadlock {section_hash}: {e}")
                sent = False

            if not sent:
                self.logger.warn(f"Deadlock {section_hash} not delivered, will retry next cycle")
                return

            self.database_monitor.mark_deadlock_reported(section_hash)
            self.logger.info(f"Deadlock {section_hash} reported", always=True)

    async def _collect_and_send_explains(self):
        """Collect EXPLAIN plans and schema, send via REST API"""
        self.logger.info("Starting query optimization analysis...", always=True)

        watched = self.api_client.instructions.get('watched_digests', [])
        query_stats = self.database_monitor.get_query_stats(watched_digests=set(watched))
        if not query_stats:
            return

        explains, tables = self.database_monitor.get_query_explains(query_stats)

        if explains:
            # Send EXPLAIN plans
            success = await self._send_in_executor(
                self.api_client.send_query_explains,
                explains
            )
            if success:
                self.logger.info(f"Sent {len(explains)} EXPLAIN plans", always=True)

            # Send schema for involved tables that are new or changed
            if tables and self.api_client.instructions.get('collect_schema', True):
                schema_info = self.database_monitor.get_targeted_schema_info(tables)
                if schema_info:
                    upload = self.schema_tracker.prepare(schema_info, tables)
                    if not upload:
                        self.logger.info(f"Schema unchanged for {len(tables)} tables, not uploading", always=True)
                    else:
                        success = await self._send_in_executor(
                            self.api_client.send_schema_update,
                            upload['schema_info'],
                            upload['tables'],
                            True
                        )
                        if success:
                            self.schema_tracker.mark_uploaded(upload)
                            self.logger.info(
                                f"Sent schema for {len(upload['tables'])} of {len(tables)} tables",
                                always=True
                            )

    async def _send_in_executor(self, func, *args):
        """Run blocking function in executor

        Args:
            func: Function to call
            *args: Arguments to pass

        Returns:
            Function result
        """
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, func, *args)

    def stop(self):
        """Gracefully stop the agent"""
        self.logger.info("Shutting down...", always=True)
        self.running = False
        self.ws_client.stop()


def parse_args(config: dict) -> argparse.Namespace:
    """Parse command-line arguments

    Args:
        config: Configuration dict for defaults

    Returns:
        Parsed arguments
    """
    parser = argparse.ArgumentParser(description='CLI Pal Agent')
    parser.add_argument(
        '--token',
        help='Agent authentication token',
        default=config.get('token')
    )
    parser.add_argument(
        '--server',
        help='WebSocket server URL (wss:// required; ws:// only for localhost dev)',
        default=config.get('server_url')
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='Enable debug logging'
    )
    parser.add_argument(
        '--version',
        action='version',
        version=f'CLI Pal Agent v{VERSION}'
    )

    return parser.parse_args()


def main():
    """Main entry point"""
    # Load configuration
    config = load_config()

    # Parse command-line arguments
    args = parse_args(config)

    # Override config with command-line args
    if args.token:
        config['token'] = args.token
    if args.server:
        config['server_url'] = args.server
    if args.debug:
        config['debug'] = True

    # Validate token
    if not config['token']:
        print("ERROR: Token required but not found in config file.")
        print()
        print("Please ensure /opt/clipal/clipal.conf contains:")
        print("  api_key=YOUR_TOKEN_HERE")
        print()
        print("Or reinstall the agent:")
        print("  curl -sSL https://clipal.me/install.sh | sudo bash -s -- --token=YOUR_TOKEN")
        sys.exit(1)

    # Validate secure connection
    config['server_url'] = validate_secure_server(config['server_url'])

    # Setup logger
    logger = setup_logger(debug=config.get('debug', False))

    # Create and run agent
    agent = CliPalAgent(config, logger)

    # Signal handlers for graceful shutdown
    def signal_handler(sig, frame):
        agent.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Run agent
    try:
        asyncio.run(agent.run())
    except KeyboardInterrupt:
        agent.stop()


if __name__ == '__main__':
    main()
