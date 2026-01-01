"""
CLI Pal Agent - MySQL Monitor Module

MySQL/MariaDB monitoring implementation.
Collects metrics, query stats, EXPLAIN plans, and deadlock detection.
"""

import re
import json
import hashlib
from datetime import datetime
from typing import Optional, Set, Tuple

from .base_monitor import DatabaseMonitor

try:
    import mysql.connector
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False


class MySQLMonitor(DatabaseMonitor):
    """MySQL/MariaDB monitoring implementation

    Phase 1: Collects ALL SHOW GLOBAL STATUS and SHOW GLOBAL VARIABLES
    Phase 2: Collects query stats from performance_schema
    Phase 3: Deadlock detection and parsing
    """

    def __init__(self, host: str = 'localhost', port: int = 3306,
                 user: str = None, password: str = None,
                 debug: bool = False, slow_threshold_ms: int = 200, logger=None):
        """Initialize MySQL monitor

        Args:
            host: MySQL host
            port: MySQL port
            user: MySQL username
            password: MySQL password
            debug: Enable debug logging
            slow_threshold_ms: Minimum avg time to consider a query "slow"
            logger: Logger instance
        """
        super().__init__(host, port, user, password, debug, logger)

        self.enabled = MYSQL_AVAILABLE and bool(user) and bool(password)
        self.slow_threshold_ms = slow_threshold_ms

        # Track config changes via hash (Phase 1)
        self.last_variables_hash = None

        # Track collection cycles for query stats
        self.metrics_count = 0

        # Deadlock tracking (Phase 3)
        self.last_deadlock_count = None
        self.last_deadlock_hash = None

        if not MYSQL_AVAILABLE:
            self.logger.warn("mysql-connector-python not installed")
        elif not self.enabled:
            self.logger.warn("MySQL monitoring disabled (no credentials)")

    def _connect(self):
        """Establish MySQL connection

        Returns:
            MySQL connection or None on failure
        """
        if not self.enabled:
            return None

        try:
            self.logger.debug(f"Connecting to {self.user}@{self.host}:{self.port}")
            conn = mysql.connector.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                connect_timeout=5
            )
            self.logger.debug("MySQL connection successful")
            return conn
        except mysql.connector.Error as e:
            self.logger.error(f"MySQL connection error: {e.msg} (Error {e.errno})")
            return None
        except Exception as e:
            self.logger.error(f"MySQL connection error: {type(e).__name__}: {e}")
            return None

    def get_metrics(self) -> dict:
        """Collect MySQL metrics

        Returns:
            dict with basic metrics, status, variables (if changed), and deadlock info
        """
        if not self.enabled:
            return {}

        metrics = {}
        conn = None

        try:
            conn = self._connect()
            if not conn:
                return {}

            cursor = conn.cursor(dictionary=True)

            # Collect SHOW GLOBAL STATUS
            cursor.execute("SHOW GLOBAL STATUS")
            status_rows = cursor.fetchall()
            status = {row['Variable_name']: row['Value'] for row in status_rows}
            metrics['status'] = status

            # Extract key metrics
            metrics['mysql_version'] = status.get('Version', 'unknown')

            if metrics['mysql_version'] == 'unknown':
                cursor.execute("SELECT VERSION() as version")
                result = cursor.fetchone()
                metrics['mysql_version'] = result['version'] if result else 'unknown'

            metrics['uptime_seconds'] = int(status.get('Uptime', 0))
            metrics['connections_current'] = int(status.get('Threads_connected', 0))
            metrics['connections_max_used'] = int(status.get('Max_used_connections', 0))
            metrics['questions_total'] = int(status.get('Questions', 0))
            metrics['slow_queries_total'] = int(status.get('Slow_queries', 0))
            metrics['total_queries'] = metrics['questions_total']
            metrics['slow_queries'] = metrics['slow_queries_total']

            # Buffer pool metrics
            metrics['buffer_pool_read_requests'] = int(status.get('Innodb_buffer_pool_read_requests', 0))
            metrics['buffer_pool_reads'] = int(status.get('Innodb_buffer_pool_reads', 0))

            buffer_pool_pages_total = int(status.get('Innodb_buffer_pool_pages_total', 0))
            buffer_pool_pages_free = int(status.get('Innodb_buffer_pool_pages_free', 0))
            if buffer_pool_pages_total > 0:
                buffer_pool_used = buffer_pool_pages_total - buffer_pool_pages_free
                metrics['buffer_pool_usage_percent'] = round((buffer_pool_used / buffer_pool_pages_total) * 100, 2)
            else:
                metrics['buffer_pool_usage_percent'] = 0

            # Collect SHOW GLOBAL VARIABLES (only if changed)
            cursor.execute("SHOW GLOBAL VARIABLES")
            variables_rows = cursor.fetchall()
            variables = {row['Variable_name']: row['Value'] for row in variables_rows}

            variables_json = json.dumps(variables, sort_keys=True)
            current_hash = hashlib.md5(variables_json.encode()).hexdigest()

            if current_hash != self.last_variables_hash:
                metrics['variables'] = variables
                metrics['variables_changed'] = True
                self.last_variables_hash = current_hash
                self.logger.info(f"MySQL config changed (hash: {current_hash[:8]}...)", always=True)
            else:
                metrics['variables_changed'] = False

            metrics['connections_limit'] = int(variables.get('max_connections', 0))
            buffer_pool_size = int(variables.get('innodb_buffer_pool_size', 0))
            metrics['buffer_pool_size_bytes'] = buffer_pool_size
            metrics['buffer_pool_size_mb'] = round(buffer_pool_size / 1024 / 1024, 2)

            # Database size stats
            cursor.execute("""
                SELECT SUM(data_length + index_length) / 1024 / 1024 AS size_mb
                FROM information_schema.tables
            """)
            result = cursor.fetchone()
            metrics['total_database_size_mb'] = round(result['size_mb'], 2) if result and result['size_mb'] else 0

            cursor.execute("""
                SELECT COUNT(*) as table_count
                FROM information_schema.tables
                WHERE table_schema NOT IN ('information_schema', 'performance_schema', 'mysql', 'sys')
            """)
            result = cursor.fetchone()
            metrics['table_count'] = int(result['table_count']) if result else 0

            cursor.close()
            self.logger.debug(f"Collected metrics: {len(metrics)} items + full status ({len(status)} vars)")

            # Check for deadlocks
            try:
                deadlock_info = self.check_for_deadlock(status)
                if deadlock_info:
                    metrics['deadlock'] = deadlock_info
            except Exception as e:
                self.logger.error(f"Error checking for deadlocks: {e}")

        except mysql.connector.Error as e:
            self.logger.error(f"MySQL error: {e.msg} (Error {e.errno})")
        except Exception as e:
            self.logger.error(f"Error collecting MySQL metrics: {type(e).__name__}: {e}")
        finally:
            if conn and conn.is_connected():
                conn.close()

        return metrics

    def get_query_stats(self, watched_digests: Optional[Set[str]] = None) -> list:
        """Collect top slow queries from performance_schema

        Args:
            watched_digests: Set of digest hashes to always include

        Returns:
            list: Query stats from events_statements_summary_by_digest
        """
        if not self.enabled:
            return []

        try:
            conn = self._connect()
            if not conn:
                return []

            cursor = conn.cursor(dictionary=True)

            # Check if performance_schema is enabled
            cursor.execute("SHOW VARIABLES LIKE 'performance_schema'")
            result = cursor.fetchone()
            if not result or result['Value'] != 'ON':
                self.logger.warn("Performance schema is disabled")
                cursor.close()
                conn.close()
                return []

            # Get top 100 queries by total time
            query = """
                SELECT
                    SCHEMA_NAME,
                    DIGEST,
                    DIGEST_TEXT,
                    COUNT_STAR,
                    SUM_TIMER_WAIT,
                    AVG_TIMER_WAIT,
                    MAX_TIMER_WAIT,
                    SUM_ROWS_AFFECTED,
                    SUM_ROWS_SENT,
                    SUM_ROWS_EXAMINED,
                    SUM_LOCK_TIME,
                    SUM_CREATED_TMP_DISK_TABLES,
                    SUM_CREATED_TMP_TABLES,
                    SUM_SORT_ROWS,
                    SUM_SORT_SCAN,
                    SUM_SORT_RANGE,
                    SUM_NO_INDEX_USED,
                    SUM_NO_GOOD_INDEX_USED,
                    FIRST_SEEN,
                    LAST_SEEN
                FROM performance_schema.events_statements_summary_by_digest
                WHERE SCHEMA_NAME IS NOT NULL
                  AND DIGEST_TEXT IS NOT NULL
                  AND DIGEST_TEXT NOT LIKE '%performance_schema%'
                  AND DIGEST_TEXT NOT LIKE '%information_schema%'
                ORDER BY SUM_TIMER_WAIT DESC
                LIMIT 100
            """

            cursor.execute(query)
            all_queries = cursor.fetchall()

            # Filter out invalid queries and fast queries (below threshold)
            # BUT keep queries missing indexes even if fast (preventive optimization)
            # AND keep watched queries (bookmarked, AI-analyzed) regardless of speed
            queries = []
            filtered_stats = {
                'total': len(all_queries),
                'kept': 0,
                'kept_slow': 0,          # Kept because slow (>= threshold)
                'kept_no_index': 0,      # Kept because missing index (even if fast)
                'kept_watched': 0,       # Kept because in watched list
                'filtered_fast': 0,      # Below threshold AND has index AND not watched
                'filtered_no_cache': 0,
                'filtered_truncated': 0,
            }

            # Convert watched_digests to set for O(1) lookup
            watched_set = set(watched_digests) if watched_digests else set()
            if watched_set:
                self.logger.info(f"Watching {len(watched_set)} digests for performance tracking", always=True)

            for query_data in all_queries:
                # Convert AVG_TIMER_WAIT from picoseconds to milliseconds
                avg_time_ps = query_data.get('AVG_TIMER_WAIT', 0)
                avg_time_ms = avg_time_ps / 1000000000  # picoseconds to milliseconds

                # Check if query is missing indexes
                no_index_used = query_data.get('SUM_NO_INDEX_USED', 0) or 0
                is_missing_index = int(no_index_used) > 0

                # Check if query is in watched list
                digest = query_data.get('DIGEST', '')
                is_watched = digest in watched_set

                # Keep criteria: slow (>= threshold) OR missing index OR watched
                is_slow = avg_time_ms >= self.slow_threshold_ms

                # Skip only if BOTH fast AND has proper indexes AND not watched
                if not is_slow and not is_missing_index and not is_watched:
                    filtered_stats['filtered_fast'] += 1
                    continue

                digest_text = query_data.get('DIGEST_TEXT', '')
                is_valid, skip_reason = self.is_valid_query_for_optimization(digest_text)

                if is_valid:
                    queries.append(query_data)
                    filtered_stats['kept'] += 1
                    # Track why we kept it (can have multiple reasons)
                    if is_slow:
                        filtered_stats['kept_slow'] += 1
                    if is_missing_index:
                        filtered_stats['kept_no_index'] += 1
                    if is_watched:
                        filtered_stats['kept_watched'] += 1
                else:
                    if 'SQL_NO_CACHE' in skip_reason:
                        filtered_stats['filtered_no_cache'] += 1
                    if 'truncated' in skip_reason:
                        filtered_stats['filtered_truncated'] += 1

                    # Log first few filtered queries for debugging
                    if (filtered_stats['filtered_no_cache'] + filtered_stats['filtered_truncated']) <= 3:
                        self.logger.debug(f"Filtered query: {skip_reason} - {digest_text[:100]}...")

            cursor.close()
            conn.close()

            # Log summary
            self.logger.info(
                f"Query stats filter: {filtered_stats['kept']}/{filtered_stats['total']} kept "
                f"({filtered_stats['kept_slow']} slow, {filtered_stats['kept_no_index']} missing index, "
                f"{filtered_stats['kept_watched']} watched), "
                f"filtered: {filtered_stats['filtered_fast']} fast, "
                f"{filtered_stats['filtered_no_cache']} SQL_NO_CACHE, "
                f"{filtered_stats['filtered_truncated']} truncated",
                always=True
            )

            return queries

        except mysql.connector.Error as e:
            self.logger.error(f"Error collecting query stats: {e.msg}")
            return []
        except Exception as e:
            self.logger.error(f"Error collecting query stats: {type(e).__name__}: {e}")
            return []

    def get_query_explains(self, query_digests: list) -> Tuple[list, set]:
        """Run EXPLAIN on slow queries and extract table names

        Args:
            query_digests: List of query digest dicts

        Returns:
            Tuple of (explains_list, tables_set)
        """
        if not self.enabled or not query_digests:
            self.logger.debug("get_query_explains: enabled=False or query_digests is empty")
            return [], set()

        self.logger.info(f"get_query_explains: Processing {len(query_digests)} query digests", always=True)

        conn = self._connect()
        if not conn:
            self.logger.error("get_query_explains: Failed to connect to MySQL")
            return [], set()

        cursor = conn.cursor(dictionary=True)
        explains = []
        all_tables = set()

        # Debug counters
        stats = {
            'total': len(query_digests),
            'sorted': 0,
            'skipped_type': 0,
            'skipped_system_schema': 0,
            'skipped_schema_switch_failed': 0,
            'skipped_explain_failed': 0,
            'success': 0
        }

        try:
            # Limit to top 30 queries by AVERAGE execution time (matches frontend display)
            sorted_queries = sorted(
                query_digests,
                key=lambda q: q.get('AVG_TIMER_WAIT', 0),
                reverse=True
            )[:30]
            stats['sorted'] = len(sorted_queries)
            self.logger.info(f"get_query_explains: Top {len(sorted_queries)} queries by avg time selected for EXPLAIN", always=True)

            for idx, query_data in enumerate(sorted_queries):
                schema = query_data.get('SCHEMA_NAME')
                digest_text = query_data.get('DIGEST_TEXT', '')
                digest = query_data.get('DIGEST', '')
                digest_log = digest[:30] + '...' if digest and len(digest) > 30 else (digest or 'N/A')

                self.logger.debug(f"Processing query #{idx+1}/{len(sorted_queries)}: schema={schema}, digest={digest_log}")

                # Skip system schemas
                if schema in ('mysql', 'information_schema', 'performance_schema', 'sys', None):
                    stats['skipped_system_schema'] += 1
                    self.logger.debug(f"SKIPPED: System schema or NULL (schema={schema})")
                    continue

                # Check query type - allow SELECT, INSERT, UPDATE, DELETE
                valid_types = ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
                if not digest_text or not any(digest_text.lstrip().upper().startswith(t) for t in valid_types):
                    stats['skipped_type'] += 1
                    self.logger.debug(f"SKIPPED: Not a supported query type")
                    continue

                # Switch to correct schema
                try:
                    cursor.execute(f"USE `{schema}`")
                    self.logger.debug(f"Switched to schema: {schema}")
                except Exception as e:
                    stats['skipped_schema_switch_failed'] += 1
                    self.logger.debug(f"SKIPPED: Could not switch to schema {schema}: {e}")
                    continue

                # Convert DELETE/UPDATE to SELECT to avoid permission issues
                query_for_explain = self._convert_to_select_for_explain(digest_text)
                was_converted = (query_for_explain != digest_text)
                if was_converted:
                    self.logger.debug("Converted to SELECT for EXPLAIN")

                # Replace ? placeholders with executable values
                explain_queries = self._replace_placeholders_for_explain(query_for_explain)
                self.logger.debug(f"Generated {len(explain_queries)} placeholder replacement strategies")

                explain_json = None
                explain_errors = []
                strategy_names = ['smart-numeric', 'smart-string', 'smart-null', 'smart-zero', 'smart-neg1']

                for attempt_idx, attempt in enumerate(explain_queries):
                    try:
                        strategy_name = strategy_names[attempt_idx] if attempt_idx < len(strategy_names) else 'unknown'
                        self.logger.debug(f"Running EXPLAIN attempt {attempt_idx+1} (strategy: {strategy_name})...")

                        cursor.execute(f"EXPLAIN FORMAT=JSON {attempt}")
                        result = cursor.fetchone()
                        explain_json = result['EXPLAIN'] if result else None
                        if explain_json:
                            self.logger.debug(f"EXPLAIN succeeded on attempt {attempt_idx+1}{' (converted)' if was_converted else ''}")
                            break
                        else:
                            explain_errors.append(f"Attempt {attempt_idx+1}: No result returned")
                    except mysql.connector.Error as e:
                        error_msg = f"Attempt {attempt_idx+1}: MySQL Error {e.errno}: {e.msg[:100]}"
                        explain_errors.append(error_msg)

                        # Log syntax errors with the failed query
                        if e.errno == 1064:  # Syntax error
                            self.logger.debug(f"Syntax Error in: {attempt[:200]}...")
                    except Exception as e:
                        error_msg = f"Attempt {attempt_idx+1}: {type(e).__name__}: {str(e)[:100]}"
                        explain_errors.append(error_msg)
                        continue

                if explain_json:
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
                    stats['success'] += 1
                    self.logger.debug(f"Successfully collected EXPLAIN for {schema} (found {len(query_tables)} tables)")
                else:
                    stats['skipped_explain_failed'] += 1
                    self.logger.debug(f"SKIPPED: All EXPLAIN attempts failed. Errors: {', '.join(explain_errors)}")

            # Log summary statistics
            self.logger.info(
                f"get_query_explains: Summary - Total: {stats['total']}, Sorted: {stats['sorted']}, "
                f"Skipped (type): {stats['skipped_type']}, "
                f"Skipped (system schema): {stats['skipped_system_schema']}, "
                f"Skipped (schema switch failed): {stats['skipped_schema_switch_failed']}, "
                f"Skipped (EXPLAIN failed): {stats['skipped_explain_failed']}, "
                f"Success: {stats['success']}",
                always=True
            )
            self.logger.info(f"Collected {len(explains)} EXPLAIN plans covering {len(all_tables)} unique tables", always=True)

        except Exception as e:
            self.logger.error(f"Error collecting EXPLAIN plans: {type(e).__name__}: {e}")
            import traceback
            self.logger.debug(f"Traceback: {traceback.format_exc()}")
        finally:
            cursor.close()
            conn.close()

        return explains, all_tables

    def get_targeted_schema_info(self, tables: set) -> dict:
        """Collect indexes and columns for specified tables

        Args:
            tables: Set of (schema_name, table_name) tuples

        Returns:
            dict with 'indexes' and 'columns' for those tables
        """
        if not self.enabled or not tables:
            return {}

        conn = self._connect()
        if not conn:
            return {}

        cursor = conn.cursor(dictionary=True)
        schema_info = {'indexes': [], 'columns': []}

        try:
            placeholders = []
            params = []
            for schema, table in tables:
                placeholders.append("(TABLE_SCHEMA = %s AND TABLE_NAME = %s)")
                params.extend([schema, table])

            where_clause = ' OR '.join(placeholders)

            # Get indexes
            query = f"""
                SELECT
                    TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, NON_UNIQUE,
                    SEQ_IN_INDEX, COLUMN_NAME, COLLATION, CARDINALITY, INDEX_TYPE
                FROM information_schema.STATISTICS
                WHERE {where_clause}
                ORDER BY TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX
            """
            cursor.execute(query, params)
            schema_info['indexes'] = cursor.fetchall()

            # Get columns
            query = f"""
                SELECT
                    TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME, ORDINAL_POSITION,
                    DATA_TYPE, COLUMN_TYPE, COLUMN_KEY, IS_NULLABLE
                FROM information_schema.COLUMNS
                WHERE {where_clause}
                ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION
            """
            cursor.execute(query, params)
            schema_info['columns'] = cursor.fetchall()

            self.logger.debug(f"Collected schema for {len(tables)} tables")

        except Exception as e:
            self.logger.error(f"Error collecting schema: {type(e).__name__}: {e}")
        finally:
            cursor.close()
            conn.close()

        return schema_info

    def check_for_deadlock(self, current_status: dict) -> Optional[dict]:
        """Check if a new deadlock occurred

        Args:
            current_status: Dict from SHOW GLOBAL STATUS

        Returns:
            Parsed deadlock info dict if new deadlock detected, None otherwise
        """
        current_count = int(current_status.get('Innodb_deadlocks', 0))

        if self.last_deadlock_count is None:
            self.last_deadlock_count = current_count
            self.logger.debug(f"Deadlock monitoring initialized (baseline: {current_count})")
            return None

        if current_count <= self.last_deadlock_count:
            return None

        deadlocks_since_last = current_count - self.last_deadlock_count
        self.logger.warn(f"Deadlock detected! Counter: {self.last_deadlock_count} -> {current_count}")
        self.last_deadlock_count = current_count

        return self._get_deadlock_info()

    def _get_deadlock_info(self) -> Optional[dict]:
        """Fetch and parse SHOW ENGINE INNODB STATUS for deadlock info

        Returns:
            Dict with parsed deadlock info, or None
        """
        conn = self._connect()
        if not conn:
            return None

        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SHOW ENGINE INNODB STATUS")
            result = cursor.fetchone()
            cursor.close()
            conn.close()

            if not result:
                return None

            raw_status = result.get('Status', '')
            if not raw_status:
                return None

            return self._parse_deadlock_section(raw_status)

        except Exception as e:
            self.logger.error(f"Error fetching INNODB STATUS: {e}")
            if conn and conn.is_connected():
                conn.close()
            return None

    def _parse_deadlock_section(self, innodb_status: str) -> Optional[dict]:
        """Parse the LATEST DETECTED DEADLOCK section from INNODB STATUS

        Handles MySQL 5.7, 8.0, and MariaDB variations.
        Fault-tolerant: returns partial data if parsing fails.

        Args:
            innodb_status: Full output from SHOW ENGINE INNODB STATUS

        Returns:
            Dict with deadlock info, or None if no deadlock section found
        """
        parse_errors = []

        # Extract deadlock section
        deadlock_section = self._extract_deadlock_section(innodb_status)
        if not deadlock_section:
            self.logger.info("No LATEST DETECTED DEADLOCK section found in INNODB STATUS", always=True)
            return None

        # Dedupe check - hash the raw section to avoid re-sending same deadlock
        section_hash = hashlib.md5(deadlock_section.encode()).hexdigest()[:16]
        if section_hash == self.last_deadlock_hash:
            self.logger.info("Deadlock already reported (same hash), skipping duplicate", always=True)
            return None
        self.last_deadlock_hash = section_hash

        # Parse transactions
        transactions = self._parse_transactions(deadlock_section, parse_errors)

        # Generate fingerprint for grouping (normalized queries)
        fingerprint = self._generate_deadlock_fingerprint(transactions)

        # Extract tables involved
        tables_involved = self._extract_tables_from_transactions(transactions)

        # Build locks summary
        locks_summary = self._build_locks_summary(transactions)

        result = {
            'detected_at': datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
            'raw_deadlock_output': deadlock_section[:65536],  # 64KB cap
            'section_hash': section_hash,
            'query_pair_fingerprint': fingerprint,
            'tables_involved': tables_involved,
            'locks_summary': locks_summary,
            'transactions': transactions,
            'parse_errors': parse_errors if parse_errors else None
        }

        # Log summary
        tx_count = len(transactions)
        query_preview = transactions[0].get('query', '')[:50] if transactions else 'N/A'
        self.logger.info(f"Parsed deadlock: {tx_count} transactions, fingerprint={fingerprint[:8]}..., tables={tables_involved}", always=True)

        return result

    def _extract_deadlock_section(self, innodb_status: str) -> Optional[str]:
        """Extract just the LATEST DETECTED DEADLOCK section"""
        patterns = [
            r'LATEST DETECTED DEADLOCK\n-+\n(.*?)(?=\n-{3,}\n[A-Z]|\nTRANSACTIONS\n|\Z)',
            r'LATEST DETECTED DEADLOCK\n(.*?)(?=\n[A-Z]{3,}[A-Z\s]+\n|\Z)',
            r'LATEST DETECTED DEADLOCK\n(.*?)(?=\nFILE I/O|\nLOG|\nROW OPERATIONS|\Z)',
        ]

        for pattern in patterns:
            match = re.search(pattern, innodb_status, re.DOTALL | re.IGNORECASE)
            if match:
                section = match.group(1).strip()
                if section and len(section) > 50:
                    return section

        return None

    def _parse_transactions(self, deadlock_section: str, parse_errors: list = None) -> list:
        """Parse transaction details from deadlock section

        Args:
            deadlock_section: The extracted deadlock section text
            parse_errors: Optional list to append any parse errors to

        Returns:
            List of transaction dicts
        """
        transactions = []
        if parse_errors is None:
            parse_errors = []

        tx_pattern = r'\*\*\*\s*\((\d+)\)\s*TRANSACTION:'
        tx_splits = re.split(tx_pattern, deadlock_section)

        for i in range(1, len(tx_splits), 2):
            try:
                tx_num = tx_splits[i]
                tx_content = tx_splits[i + 1] if i + 1 < len(tx_splits) else ''

                transactions.append({
                    'transaction_id': tx_num,
                    'role': self._determine_role(tx_content),
                    'query': self._extract_query(tx_content),
                    'tables_locked': self._extract_locked_tables(tx_content),
                    'lock_mode': self._extract_lock_mode(tx_content),
                    'lock_type': self._extract_lock_type(tx_content),
                    'waiting_for': self._extract_waiting_for(tx_content),
                    'thread_id': self._extract_thread_id(tx_content),
                })
            except Exception as e:
                parse_errors.append(f"Error parsing transaction {i}: {str(e)[:100]}")
                self.logger.error(f"Error parsing transaction: {e}")

        return transactions

    def _determine_role(self, tx_content: str) -> str:
        """Determine if transaction is WAITING or HOLDING"""
        tx_upper = tx_content.upper()

        if 'WAITING FOR THIS LOCK' in tx_upper or 'LOCK WAIT' in tx_upper:
            return 'WAITING'
        if 'HOLDS THE LOCK' in tx_upper:
            return 'HOLDING'
        if 'WE ROLL BACK' in tx_upper:
            return 'VICTIM'

        return 'UNKNOWN'

    def _extract_query(self, tx_content: str) -> str:
        """Extract the SQL query from transaction content"""
        sql_keywords = ['SELECT', 'UPDATE', 'DELETE', 'INSERT', 'REPLACE', 'CALL']
        lines = tx_content.split('\n')
        query_lines = []
        in_query = False

        for line in lines:
            line_stripped = line.strip()
            line_upper = line_stripped.upper()

            if not line_stripped:
                if in_query:
                    break
                continue

            skip_patterns = [
                'MYSQL THREAD ID', 'TRANSACTION:', 'LOCK WAIT', 'RECORD LOCKS',
                'TABLE LOCK', 'HOLDS THE LOCK', 'WAITING FOR THIS LOCK', 'ACTIVE ',
                'STARTING INDEX', 'SPACE ID', 'PAGE NO', 'N BITS', 'INDEX', 'TRX'
            ]
            if any(skip in line_upper for skip in skip_patterns):
                if in_query:
                    break
                continue

            if any(line_upper.startswith(kw) for kw in sql_keywords):
                in_query = True
                query_lines.append(line_stripped)
            elif in_query:
                query_lines.append(line_stripped)

        return re.sub(r'\s+', ' ', ' '.join(query_lines)).strip()

    def _extract_locked_tables(self, tx_content: str) -> list:
        """Extract table names involved in locks"""
        tables = set()
        patterns = [
            r'table\s+`([^`]+)`\.`([^`]+)`',
            r'table\s+`([^`]+)`(?!\s*\.)',
        ]

        for pattern in patterns:
            for match in re.finditer(pattern, tx_content, re.IGNORECASE):
                if match.lastindex == 2:
                    tables.add(f"{match.group(1)}.{match.group(2)}")
                else:
                    tables.add(match.group(1))

        return list(tables)

    def _extract_lock_mode(self, tx_content: str) -> str:
        """Extract lock mode (X, S, IX, IS, etc.)"""
        patterns = [
            r'lock[_\s]mode\s+(\w+)',
            r'\b(X|S|IX|IS)\s+lock',
        ]

        for pattern in patterns:
            match = re.search(pattern, tx_content, re.IGNORECASE)
            if match:
                return match.group(1).upper()

        return ''

    def _extract_lock_type(self, tx_content: str) -> str:
        """Extract lock type (TABLE LOCK, RECORD LOCK, etc.)"""
        tx_upper = tx_content.upper()

        if 'RECORD LOCKS' in tx_upper or 'RECORD LOCK' in tx_upper:
            return 'RECORD'
        if 'TABLE LOCK' in tx_upper:
            return 'TABLE'
        if 'GAP' in tx_upper:
            return 'GAP'

        return 'UNKNOWN'

    def _extract_thread_id(self, tx_content: str) -> str:
        """Extract MySQL thread ID"""
        match = re.search(r'MySQL\s+thread\s+id\s+(\d+)', tx_content, re.IGNORECASE)
        return match.group(1) if match else ''

    def _extract_waiting_for(self, tx_content: str) -> str:
        """Extract what the transaction is waiting for"""
        match = re.search(
            r'WAITING FOR THIS LOCK TO BE GRANTED[:\s]*(.*?)(?=\n\*\*\*|\n[A-Z]{3,}[A-Z\s]+:|\Z)',
            tx_content,
            re.DOTALL | re.IGNORECASE
        )
        if match:
            return match.group(1).strip()[:500]  # Cap at 500 chars
        return ''

    def _generate_deadlock_fingerprint(self, transactions: list) -> str:
        """Generate fingerprint for grouping identical deadlock patterns"""
        queries = []
        for tx in transactions:
            normalized = self.normalize_query_for_fingerprint(tx.get('query', ''))
            queries.append(normalized)

        queries.sort()
        return hashlib.md5('|||'.join(queries).encode()).hexdigest()

    def _extract_tables_from_transactions(self, transactions: list) -> str:
        """Extract unique tables from all transactions"""
        tables = set()
        for tx in transactions:
            tables.update(tx.get('tables_locked', []))
        return ','.join(sorted(tables))

    def _build_locks_summary(self, transactions: list) -> str:
        """Build a JSON summary of locks involved"""
        summary = []
        for tx in transactions:
            summary.append({
                'tx_id': tx.get('transaction_id'),
                'role': tx.get('role'),
                'lock_mode': tx.get('lock_mode'),
                'lock_type': tx.get('lock_type'),
                'tables': tx.get('tables_locked', []),
            })
        return json.dumps(summary)

    def _convert_to_select_for_explain(self, query: str) -> str:
        """Convert DELETE/UPDATE queries to SELECT for EXPLAIN"""
        query_upper = query.strip().upper()

        if query_upper.startswith('DELETE'):
            return re.sub(r'^DELETE\s+FROM\s+', 'SELECT * FROM ', query.strip(),
                         count=1, flags=re.IGNORECASE)

        if query_upper.startswith('UPDATE'):
            match = re.match(
                r'^UPDATE\s+(`?\w+`?(?:\s*\.\s*`?\w+`?)?)\s+SET\s+.*?(WHERE\s+.*)$',
                query.strip(), flags=re.IGNORECASE | re.DOTALL
            )
            if match:
                return f'SELECT * FROM {match.group(1)} {match.group(2)}'

            match = re.match(
                r'^UPDATE\s+(`?\w+`?(?:\s*\.\s*`?\w+`?)?)\s+SET\s+',
                query.strip(), flags=re.IGNORECASE
            )
            if match:
                return f'SELECT * FROM {match.group(1)} LIMIT 1'

        return query

    def _replace_placeholders_for_explain(self, digest_text: str) -> list:
        """Replace ? placeholders with executable values for EXPLAIN"""
        strategies = []

        def normalize_sql(query: str) -> str:
            query = re.sub(r'(\w+)\s*\(\s*([*?])\s*\)', r'\1(\2)', query)
            query = re.sub(r'(\w+)\s*\(\s+', r'\1(', query)
            query = re.sub(r'\s+\)', ')', query)
            return query

        def smart_replace(query: str, default_value: str) -> str:
            result = query

            # Handle truncated queries
            result = re.sub(r'LIMIT\s+(\d+)\s*,\s*\.\.\..*$', r'LIMIT \1, 100', result, flags=re.IGNORECASE)
            result = re.sub(r'LIMIT\s+\.\.\..*$', 'LIMIT 100', result, flags=re.IGNORECASE)
            result = re.sub(r'IN\s*\(\s*\.\.\.\s*\)', f'IN ({default_value})', result, flags=re.IGNORECASE)

            if result.rstrip().endswith('...'):
                result = result.rstrip()[:-3].rstrip()
                result = re.sub(r'[,\s]+$', '', result)
                result = re.sub(r'\s+(AND|OR)\s*$', '', result, flags=re.IGNORECASE)

            # Handle LIMIT/OFFSET
            result = re.sub(r'LIMIT\s+\?', 'LIMIT 1000', result, flags=re.IGNORECASE)
            result = re.sub(r'OFFSET\s+\?', 'OFFSET 0', result, flags=re.IGNORECASE)
            result = re.sub(r'LIMIT\s+\?\s*,\s*\?', 'LIMIT 0, 1000', result, flags=re.IGNORECASE)
            result = re.sub(r'LIMIT\s+(\d+)\s*,\s*\?', r'LIMIT \1, 1000', result, flags=re.IGNORECASE)

            # Handle IN clauses
            result = re.sub(r'IN\s*\(\s*\?\s*\)', f'IN ({default_value})', result, flags=re.IGNORECASE)
            result = re.sub(r'IN\s*\(\s*\?(?:\s*,\s*\?)+\s*\)', f'IN ({default_value})', result, flags=re.IGNORECASE)

            # Handle LIKE
            result = re.sub(r"LIKE\s+\?", "LIKE '%'", result, flags=re.IGNORECASE)

            # Handle BETWEEN
            result = re.sub(r'BETWEEN\s+\?\s+AND\s+\?', f'BETWEEN {default_value} AND {default_value}',
                          result, flags=re.IGNORECASE)

            # Handle date functions
            result = re.sub(r"DATE\s*\(\s*\?\s*\)", "DATE('2024-01-01')", result, flags=re.IGNORECASE)
            result = re.sub(r"STR_TO_DATE\s*\(\s*\?\s*,", "STR_TO_DATE('2024-01-01',", result, flags=re.IGNORECASE)
            result = re.sub(r"UNIX_TIMESTAMP\s*\(\s*\?\s*\)", "UNIX_TIMESTAMP('2024-01-01')", result, flags=re.IGNORECASE)
            result = re.sub(r"FROM_UNIXTIME\s*\(\s*\?\s*\)", "FROM_UNIXTIME(0)", result, flags=re.IGNORECASE)

            # Handle ORDER BY
            result = re.sub(r'ORDER\s+BY\s+\?', 'ORDER BY 1', result, flags=re.IGNORECASE)

            # Replace remaining ?
            result = result.replace('?', default_value)

            return result

        try:
            normalized_query = normalize_sql(digest_text)
            strategies.append(smart_replace(normalized_query, '1'))
            strategies.append(smart_replace(normalized_query, "''"))
            strategies.append(smart_replace(normalized_query, 'NULL'))
            strategies.append(smart_replace(normalized_query, '0'))
            strategies.append(smart_replace(normalized_query, '-1'))
        except Exception:
            normalized_query = normalize_sql(digest_text)
            strategies = [
                normalized_query.replace('?', '1'),
                normalized_query.replace('?', "''"),
                normalized_query.replace('?', 'NULL'),
            ]

        return strategies

    def _extract_tables_from_explain(self, explain_json: str, schema: str) -> set:
        """Extract table names from EXPLAIN JSON output"""
        tables = set()

        try:
            explain_data = json.loads(explain_json)

            def find_tables(obj, current_schema=schema):
                if isinstance(obj, dict):
                    if 'table_name' in obj:
                        tables.add((current_schema, obj['table_name']))
                    elif 'table' in obj and isinstance(obj['table'], str):
                        table = obj['table']
                        if table not in ('<subquery>', '<derived>', '<union>'):
                            tables.add((current_schema, table))

                    for value in obj.values():
                        find_tables(value, current_schema)
                elif isinstance(obj, list):
                    for item in obj:
                        find_tables(item, current_schema)

            find_tables(explain_data)

        except Exception:
            pass

        return tables
