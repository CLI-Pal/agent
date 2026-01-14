"""
CLI Pal Agent - PostgreSQL Monitor Module

PostgreSQL/Postgres monitoring implementation.
Collects metrics, query stats, and deadlock information.
"""

import json
import hashlib
from datetime import datetime
from typing import Optional, Set, Tuple

from .base_monitor import DatabaseMonitor

# Try to import psycopg2
try:
    import psycopg2
    from psycopg2.extras import RealDictCursor
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False


class PostgreSQLMonitor(DatabaseMonitor):
    """PostgreSQL monitoring implementation

    Supports PostgreSQL 12+ with pg_stat_statements extension.
    """

    def __init__(self, host: str = 'localhost', port: int = 5432,
                 user: str = None, password: str = None,
                 database: str = 'postgres', debug: bool = False,
                 slow_threshold_ms: int = 200, logger=None):
        """Initialize PostgreSQL monitor

        Args:
            host: Database host
            port: Database port (default 5432)
            user: Database username
            password: Database password
            database: Database name to connect to (default 'postgres')
            debug: Enable debug logging
            slow_threshold_ms: Minimum avg time to consider a query "slow"
            logger: Logger instance
        """
        super().__init__(host, port, user, password, debug, logger)

        self.database = database
        self.slow_threshold_ms = slow_threshold_ms
        self.enabled = PSYCOPG2_AVAILABLE and user and password

        # Track config changes via hash
        self.last_settings_hash = None

        # Deadlock tracking
        self.last_deadlock_count = None

        # Check if pg_stat_statements is available
        self.pg_stat_statements_available = False

        if not PSYCOPG2_AVAILABLE:
            if self.logger:
                self.logger.warn("psycopg2 not installed - PostgreSQL monitoring disabled")
        elif not self.enabled:
            if self.logger:
                self.logger.warn("PostgreSQL credentials not configured - monitoring disabled")

    def _connect(self):
        """Establish PostgreSQL connection

        Returns:
            Connection object or None if failed
        """
        if not self.enabled:
            return None

        try:
            if self.logger:
                self.logger.debug(f"Connecting to PostgreSQL {self.user}@{self.host}:{self.port}/{self.database}")

            conn = psycopg2.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                database=self.database,
                connect_timeout=5
            )

            if self.logger:
                self.logger.debug("PostgreSQL connection successful")

            return conn

        except psycopg2.Error as e:
            if self.logger:
                self.logger.error(f"PostgreSQL connection error: {e}")
            return None
        except Exception as e:
            if self.logger:
                self.logger.error(f"PostgreSQL connection error (unexpected): {type(e).__name__}: {e}")
            return None

    def get_metrics(self) -> dict:
        """Collect PostgreSQL metrics

        Returns:
            dict with database metrics including:
            - Basic metrics (version, uptime, connections)
            - pg_stat_database stats
            - Settings (only if changed)
        """
        if not self.enabled:
            return {}

        metrics = {}
        conn = None

        try:
            conn = self._connect()
            if not conn:
                if self.logger:
                    self.logger.error("PostgreSQL get_metrics: Connection failed")
                return {}

            cursor = conn.cursor(cursor_factory=RealDictCursor)

            # Get PostgreSQL version
            cursor.execute("SELECT version()")
            result = cursor.fetchone()
            metrics['db_version'] = result['version'] if result else 'unknown'
            # Also store as mysql_version for backward compatibility in UI
            metrics['mysql_version'] = metrics['db_version']

            # Get uptime
            cursor.execute("""
                SELECT EXTRACT(EPOCH FROM (now() - pg_postmaster_start_time()))::bigint AS uptime_seconds
            """)
            result = cursor.fetchone()
            metrics['uptime_seconds'] = result['uptime_seconds'] if result else 0

            # Get connection stats
            cursor.execute("""
                SELECT 
                    (SELECT count(*) FROM pg_stat_activity) AS connections_current,
                    (SELECT setting::int FROM pg_settings WHERE name = 'max_connections') AS connections_limit
            """)
            result = cursor.fetchone()
            metrics['connections_current'] = result['connections_current'] if result else 0
            metrics['connections_limit'] = result['connections_limit'] if result else 0
            metrics['connections_max_used'] = metrics['connections_current']  # PG doesn't track this

            # Get database stats from pg_stat_database
            cursor.execute("""
                SELECT 
                    sum(numbackends) AS total_backends,
                    sum(xact_commit) AS xact_commit,
                    sum(xact_rollback) AS xact_rollback,
                    sum(blks_read) AS blks_read,
                    sum(blks_hit) AS blks_hit,
                    sum(tup_returned) AS tup_returned,
                    sum(tup_fetched) AS tup_fetched,
                    sum(tup_inserted) AS tup_inserted,
                    sum(tup_updated) AS tup_updated,
                    sum(tup_deleted) AS tup_deleted,
                    sum(deadlocks) AS deadlocks,
                    sum(temp_files) AS temp_files,
                    sum(temp_bytes) AS temp_bytes
                FROM pg_stat_database
            """)
            db_stats = cursor.fetchone()

            if db_stats:
                # Calculate buffer cache hit rate
                blks_hit = db_stats['blks_hit'] or 0
                blks_read = db_stats['blks_read'] or 0
                total_blocks = blks_hit + blks_read
                if total_blocks > 0:
                    metrics['buffer_pool_hit_rate'] = round((blks_hit / total_blocks) * 100, 2)
                else:
                    metrics['buffer_pool_hit_rate'] = 100.0

                # Store raw counters for rate calculation in backend
                metrics['questions_total'] = (db_stats['xact_commit'] or 0) + (db_stats['xact_rollback'] or 0)
                metrics['total_queries'] = metrics['questions_total']

                # Store in status dict for compatibility
                metrics['status'] = {
                    'xact_commit': str(db_stats['xact_commit'] or 0),
                    'xact_rollback': str(db_stats['xact_rollback'] or 0),
                    'blks_read': str(blks_read),
                    'blks_hit': str(blks_hit),
                    'tup_returned': str(db_stats['tup_returned'] or 0),
                    'tup_fetched': str(db_stats['tup_fetched'] or 0),
                    'tup_inserted': str(db_stats['tup_inserted'] or 0),
                    'tup_updated': str(db_stats['tup_updated'] or 0),
                    'tup_deleted': str(db_stats['tup_deleted'] or 0),
                    'deadlocks': str(db_stats['deadlocks'] or 0),
                    'temp_files': str(db_stats['temp_files'] or 0),
                    'temp_bytes': str(db_stats['temp_bytes'] or 0),
                }

                # Check for deadlocks
                current_deadlocks = db_stats['deadlocks'] or 0
                deadlock_info = self._check_deadlock_counter(current_deadlocks)
                if deadlock_info:
                    metrics['deadlock'] = deadlock_info

            # Get shared_buffers size
            cursor.execute("""
                SELECT 
                    setting,
                    unit
                FROM pg_settings 
                WHERE name = 'shared_buffers'
            """)
            result = cursor.fetchone()
            if result:
                # Convert to bytes (setting is in 8KB blocks by default)
                setting = int(result['setting'])
                unit = result['unit'] or '8kB'
                if unit == '8kB':
                    buffer_pool_bytes = setting * 8 * 1024
                elif unit == 'kB':
                    buffer_pool_bytes = setting * 1024
                elif unit == 'MB':
                    buffer_pool_bytes = setting * 1024 * 1024
                else:
                    buffer_pool_bytes = setting * 8 * 1024  # Default to 8kB blocks

                metrics['buffer_pool_size_bytes'] = buffer_pool_bytes
                metrics['buffer_pool_size_mb'] = round(buffer_pool_bytes / 1024 / 1024, 2)

            # Get total database size
            cursor.execute("""
                SELECT sum(pg_database_size(datname)) / 1024 / 1024 AS size_mb
                FROM pg_database
                WHERE datistemplate = false
            """)
            result = cursor.fetchone()
            metrics['total_database_size_mb'] = round(result['size_mb'], 2) if result and result['size_mb'] else 0

            # Get table count (user tables only)
            cursor.execute("""
                SELECT count(*) AS table_count
                FROM pg_stat_user_tables
            """)
            result = cursor.fetchone()
            metrics['table_count'] = result['table_count'] if result else 0

            # Get all settings (like SHOW GLOBAL VARIABLES in MySQL)
            cursor.execute("SELECT name, setting FROM pg_settings ORDER BY name")
            settings_rows = cursor.fetchall()
            settings = {row['name']: row['setting'] for row in settings_rows}

            # Check if settings changed
            settings_json = json.dumps(settings, sort_keys=True)
            current_hash = hashlib.md5(settings_json.encode()).hexdigest()

            if current_hash != self.last_settings_hash:
                metrics['variables'] = settings
                metrics['variables_changed'] = True
                self.last_settings_hash = current_hash
                if self.logger:
                    self.logger.info(f"PostgreSQL config changed (hash: {current_hash[:8]}...)")
            else:
                metrics['variables_changed'] = False

            # Check if pg_stat_statements is available
            cursor.execute("""
                SELECT EXISTS (
                    SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'
                ) AS available
            """)
            result = cursor.fetchone()
            self.pg_stat_statements_available = result['available'] if result else False

            if not self.pg_stat_statements_available and self.logger:
                self.logger.debug("pg_stat_statements extension not available")

            cursor.close()

            if self.logger:
                self.logger.debug(f"Collected PostgreSQL metrics: {len(metrics)} items")

        except psycopg2.Error as e:
            if self.logger:
                self.logger.error(f"PostgreSQL error: {e}")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error collecting PostgreSQL metrics: {type(e).__name__}: {e}")
        finally:
            if conn:
                conn.close()

        return metrics

    def get_query_stats(self, watched_digests: Optional[Set[str]] = None) -> list:
        """Collect query statistics from pg_stat_statements

        Args:
            watched_digests: Optional set of query IDs to always include

        Returns:
            list: Query statistics from pg_stat_statements
        """
        if not self.enabled or not self.pg_stat_statements_available:
            return []

        try:
            conn = self._connect()
            if not conn:
                return []

            cursor = conn.cursor(cursor_factory=RealDictCursor)

            # Check PostgreSQL version for column names
            # PG 13+ uses total_exec_time, older uses total_time
            cursor.execute("SHOW server_version_num")
            result = cursor.fetchone()
            pg_version = int(result['server_version_num']) if result else 0

            # Column names differ between versions
            if pg_version >= 130000:
                time_col = 'total_exec_time'
                mean_col = 'mean_exec_time'
            else:
                time_col = 'total_time'
                mean_col = 'mean_time'

            # Get top 100 queries by total time
            query = f"""
                SELECT
                    pss.userid,
                    pss.dbid,
                    pd.datname AS schema_name,
                    pss.queryid::text AS digest,
                    pss.query AS digest_text,
                    pss.calls AS count_star,
                    pss.{time_col} * 1000000000 AS sum_timer_wait,
                    pss.{mean_col} * 1000000000 AS avg_timer_wait,
                    pss.rows AS sum_rows_sent,
                    pss.shared_blks_hit,
                    pss.shared_blks_read,
                    pss.temp_blks_written,
                    CASE WHEN pss.shared_blks_read > 0 THEN 1 ELSE 0 END AS sum_no_index_used
                FROM pg_stat_statements pss
                JOIN pg_database pd ON pd.oid = pss.dbid
                WHERE pss.query NOT LIKE '%pg_stat%'
                  AND pss.query NOT LIKE '%pg_catalog%'
                ORDER BY pss.{time_col} DESC
                LIMIT 100
            """

            cursor.execute(query)
            all_queries = cursor.fetchall()

            # Filter queries similar to MySQL monitor
            queries = []
            filtered_stats = {
                'total': len(all_queries),
                'kept': 0,
                'kept_slow': 0,
                'kept_no_index': 0,
                'kept_watched': 0,
                'filtered_fast': 0,
            }

            watched_set = set(watched_digests) if watched_digests else set()

            for query_data in all_queries:
                # Convert to MySQL-compatible format
                avg_time_ps = query_data.get('avg_timer_wait', 0) or 0
                avg_time_ms = avg_time_ps / 1000000000  # picoseconds to milliseconds

                is_missing_index = (query_data.get('shared_blks_read', 0) or 0) > 0
                digest = query_data.get('digest', '')
                is_watched = digest in watched_set
                is_slow = avg_time_ms >= self.slow_threshold_ms

                if not is_slow and not is_missing_index and not is_watched:
                    filtered_stats['filtered_fast'] += 1
                    continue

                digest_text = query_data.get('digest_text', '')
                is_valid, _ = self.is_valid_query_for_optimization(digest_text)

                if is_valid:
                    # Convert to MySQL-compatible column names for backend
                    compatible_data = {
                        'SCHEMA_NAME': query_data.get('schema_name'),
                        'DIGEST': digest,
                        'DIGEST_TEXT': digest_text,
                        'COUNT_STAR': query_data.get('count_star', 0),
                        'SUM_TIMER_WAIT': query_data.get('sum_timer_wait', 0),
                        'AVG_TIMER_WAIT': query_data.get('avg_timer_wait', 0),
                        'SUM_ROWS_SENT': query_data.get('sum_rows_sent', 0),
                        'SUM_ROWS_EXAMINED': query_data.get('sum_rows_sent', 0),  # Approximate
                        'SUM_NO_INDEX_USED': query_data.get('sum_no_index_used', 0),
                        'SUM_NO_GOOD_INDEX_USED': 0,
                        'FIRST_SEEN': None,
                        'LAST_SEEN': None,
                    }
                    queries.append(compatible_data)
                    filtered_stats['kept'] += 1

                    if is_slow:
                        filtered_stats['kept_slow'] += 1
                    if is_missing_index:
                        filtered_stats['kept_no_index'] += 1
                    if is_watched:
                        filtered_stats['kept_watched'] += 1

            if self.logger:
                self.logger.info(
                    f"Query stats filter: {filtered_stats['kept']}/{filtered_stats['total']} kept "
                    f"({filtered_stats['kept_slow']} slow, {filtered_stats['kept_no_index']} disk reads, "
                    f"{filtered_stats['kept_watched']} watched), "
                    f"filtered: {filtered_stats['filtered_fast']} fast"
                )

            cursor.close()
            conn.close()

            return queries

        except psycopg2.Error as e:
            if self.logger:
                self.logger.error(f"Error collecting PostgreSQL query stats: {e}")
            return []
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error collecting PostgreSQL query stats: {type(e).__name__}: {e}")
            return []

    def get_query_explains(self, query_digests: list) -> Tuple[list, set]:
        """Run EXPLAIN on queries and extract table names

        Args:
            query_digests: List of query digest dicts

        Returns:
            Tuple of (explains_list, tables_set)
        """
        if not self.enabled or not query_digests:
            return [], set()

        conn = self._connect()
        if not conn:
            return [], set()

        cursor = conn.cursor(cursor_factory=RealDictCursor)
        explains = []
        all_tables = set()

        try:
            # Sort by average time and take top 30
            sorted_queries = sorted(
                query_digests,
                key=lambda q: q.get('AVG_TIMER_WAIT', 0),
                reverse=True
            )[:30]

            for query_data in sorted_queries:
                schema = query_data.get('SCHEMA_NAME')
                digest_text = query_data.get('DIGEST_TEXT', '')
                digest = query_data.get('DIGEST', '')

                # Skip system schemas
                if schema in ('pg_catalog', 'information_schema', None):
                    continue

                # Only EXPLAIN SELECT queries (PostgreSQL is stricter)
                if not digest_text or not digest_text.strip().upper().startswith('SELECT'):
                    continue

                try:
                    # Switch to correct database if needed
                    # Note: In PostgreSQL, you'd need a new connection for different databases
                    # For now, we'll work within the current database

                    # Replace $1, $2 placeholders with NULL for EXPLAIN
                    explain_query = self._replace_placeholders_for_explain(digest_text)

                    cursor.execute(f"EXPLAIN (FORMAT JSON) {explain_query}")
                    result = cursor.fetchone()

                    if result:
                        explain_json = json.dumps(result['QUERY PLAN'] if 'QUERY PLAN' in result else result)

                        # Extract tables from EXPLAIN
                        query_tables = self._extract_tables_from_explain(explain_json, schema)
                        all_tables.update(query_tables)

                        avg_time_ms = None
                        if query_data.get('AVG_TIMER_WAIT'):
                            avg_time_ms = round(query_data['AVG_TIMER_WAIT'] / 1000000000, 2)

                        explains.append({
                            'digest': digest,
                            'schema_name': schema,
                            'digest_text': digest_text,
                            'explain_json': explain_json,
                            'tables_involved': list(query_tables),
                            'avg_time_ms': avg_time_ms,
                            'exec_count': query_data.get('COUNT_STAR'),
                            'sum_no_index_used': query_data.get('SUM_NO_INDEX_USED', 0)
                        })

                except psycopg2.Error as e:
                    if self.logger:
                        self.logger.debug(f"EXPLAIN failed for query: {e}")
                    continue

            if self.logger:
                self.logger.info(f"Collected {len(explains)} EXPLAIN plans covering {len(all_tables)} tables")

        except Exception as e:
            if self.logger:
                self.logger.error(f"Error collecting EXPLAIN plans: {type(e).__name__}: {e}")
        finally:
            cursor.close()
            conn.close()

        return explains, all_tables

    def _replace_placeholders_for_explain(self, query: str) -> str:
        """Replace PostgreSQL placeholders ($1, $2) with NULL for EXPLAIN

        Args:
            query: Query with placeholders

        Returns:
            Query with placeholders replaced
        """
        import re

        # Replace $1, $2, etc. with NULL
        result = re.sub(r'\$\d+', 'NULL', query)

        # Also handle ? placeholders (sometimes used)
        result = result.replace('?', 'NULL')

        return result

    def _extract_tables_from_explain(self, explain_json: str, schema: str) -> set:
        """Extract table names from EXPLAIN JSON output

        Args:
            explain_json: JSON output from EXPLAIN
            schema: Default schema name

        Returns:
            Set of (schema_name, table_name) tuples
        """
        tables = set()

        try:
            explain_data = json.loads(explain_json)

            def find_tables(obj, current_schema=schema):
                if isinstance(obj, dict):
                    # Look for Relation Name in PostgreSQL EXPLAIN
                    if 'Relation Name' in obj:
                        table = obj['Relation Name']
                        table_schema = obj.get('Schema', current_schema)
                        tables.add((table_schema, table))

                    for value in obj.values():
                        find_tables(value, current_schema)
                elif isinstance(obj, list):
                    for item in obj:
                        find_tables(item, current_schema)

            find_tables(explain_data)

        except Exception as e:
            if self.logger:
                self.logger.debug(f"Error parsing EXPLAIN JSON: {e}")

        return tables

    def get_targeted_schema_info(self, tables: set) -> dict:
        """Collect indexes and columns for specified tables

        Args:
            tables: Set of (schema_name, table_name) tuples

        Returns:
            dict: Schema info with 'indexes' and 'columns'
        """
        if not self.enabled or not tables:
            return {}

        conn = self._connect()
        if not conn:
            return {}

        cursor = conn.cursor(cursor_factory=RealDictCursor)
        schema_info = {'indexes': [], 'columns': []}

        try:
            for schema, table in tables:
                # Get indexes
                cursor.execute("""
                    SELECT
                        schemaname AS table_schema,
                        tablename AS table_name,
                        indexname AS index_name,
                        indexdef
                    FROM pg_indexes
                    WHERE schemaname = %s AND tablename = %s
                """, (schema, table))

                for row in cursor.fetchall():
                    schema_info['indexes'].append({
                        'TABLE_SCHEMA': row['table_schema'],
                        'TABLE_NAME': row['table_name'],
                        'INDEX_NAME': row['index_name'],
                        'INDEX_DEF': row['indexdef'],
                    })

                # Get columns
                cursor.execute("""
                    SELECT
                        table_schema,
                        table_name,
                        column_name,
                        ordinal_position,
                        data_type,
                        udt_name AS column_type,
                        is_nullable
                    FROM information_schema.columns
                    WHERE table_schema = %s AND table_name = %s
                    ORDER BY ordinal_position
                """, (schema, table))

                for row in cursor.fetchall():
                    schema_info['columns'].append({
                        'TABLE_SCHEMA': row['table_schema'],
                        'TABLE_NAME': row['table_name'],
                        'COLUMN_NAME': row['column_name'],
                        'ORDINAL_POSITION': row['ordinal_position'],
                        'DATA_TYPE': row['data_type'],
                        'COLUMN_TYPE': row['column_type'],
                        'IS_NULLABLE': row['is_nullable'],
                    })

            if self.logger:
                self.logger.debug(
                    f"Collected schema for {len(tables)} tables: "
                    f"{len(schema_info['indexes'])} indexes, {len(schema_info['columns'])} columns"
                )

        except psycopg2.Error as e:
            if self.logger:
                self.logger.error(f"Error collecting PostgreSQL schema: {e}")
        except Exception as e:
            if self.logger:
                self.logger.error(f"Error collecting PostgreSQL schema: {type(e).__name__}: {e}")
        finally:
            cursor.close()
            conn.close()

        return schema_info

    def _check_deadlock_counter(self, current_count: int) -> Optional[dict]:
        """Check if a new deadlock occurred by comparing counter

        Args:
            current_count: Current deadlock count from pg_stat_database

        Returns:
            Deadlock info dict if new deadlock detected, None otherwise
        """
        # First run - store baseline
        if self.last_deadlock_count is None:
            self.last_deadlock_count = current_count
            if self.logger:
                self.logger.debug(f"Deadlock monitoring initialized (baseline: {current_count})")
            return None

        # No new deadlock
        if current_count <= self.last_deadlock_count:
            return None

        # New deadlock detected
        deadlocks_since_last = current_count - self.last_deadlock_count
        if self.logger:
            self.logger.info(
                f"🔴 Deadlock detected! Counter: {self.last_deadlock_count} → {current_count} "
                f"(+{deadlocks_since_last})"
            )
        self.last_deadlock_count = current_count

        # PostgreSQL doesn't provide detailed deadlock info in system tables
        # You'd need to parse the PostgreSQL log file for details
        # For now, return basic info
        return {
            'detected_at': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'deadlock_count': current_count,
            'new_deadlocks': deadlocks_since_last,
            'raw_deadlock_output': 'Check PostgreSQL log for details',
            'section_hash': hashlib.md5(f"{current_count}".encode()).hexdigest()[:16],
            'query_pair_fingerprint': '',
            'tables_involved': '',
            'transactions': [],
        }

    def check_for_deadlock(self, current_status: dict) -> Optional[dict]:
        """Check for deadlock from status dict

        Args:
            current_status: Dict containing 'deadlocks' counter

        Returns:
            Deadlock info if new deadlock detected
        """
        current_count = int(current_status.get('deadlocks', 0))
        return self._check_deadlock_counter(current_count)

