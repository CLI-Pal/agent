#!/usr/bin/env python3


import asyncio
import websockets
import json
import sys
import os
import pty
import select
import termios
import struct
import fcntl
import signal
import argparse
import platform
import socket
import time
import re
import subprocess
import hashlib
from datetime import datetime
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    print("=" * 60)
    print("⚠️  WARNING: psutil module not installed!")
    print("   System monitoring (CPU/RAM/OS info) is DISABLED")
    print("   To fix: pip3 install psutil")
    print("=" * 60)

try:
    import mysql.connector
    MYSQL_AVAILABLE = True
except ImportError:
    MYSQL_AVAILABLE = False

import urllib.request

VERSION = "0.0.4"

# Configuration file path
CONFIG_FILE = "/opt/clipal/clipal.conf"

def load_config():
    """Load configuration from /opt/clipal/clipal.conf
    
    This is the ONLY source of configuration - no fallbacks.
    Config file must exist and be readable.
    
    Returns dict with configuration keys
    """
    if not os.path.exists(CONFIG_FILE):
        print(f"❌ Error: Configuration file not found: {CONFIG_FILE}")
        print(f"")
        print(f"The config file is required to run the agent.")
        print(f"Please install the agent using:")
        print(f"  curl -sSL https://clipal.me/install.sh | sudo bash -s -- --token=YOUR_TOKEN")
        sys.exit(1)
    
    config = {}
    
    try:
        with open(CONFIG_FILE, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                # Parse key=value
                if '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()
        print(f"✅ Loaded configuration from {CONFIG_FILE}")
    except Exception as e:
        print(f"❌ Error: Could not read config file {CONFIG_FILE}: {e}")
        print(f"Please check file permissions and format")
        sys.exit(1)
    
    # Return configuration with defaults where appropriate
    return {
        'token': config.get('api_key', ''),
        'server_url': config.get('server_url', 'wss://app.clipal.me/ws'),
        'mysql_enabled': config.get('mysql_enabled', 'false').lower() == 'true',
        'mysql_host': config.get('mysql_host', 'localhost'),
        'mysql_port': int(config.get('mysql_port', '3306')),
        'mysql_user': config.get('mysql_user', ''),
        'mysql_password': config.get('mysql_password', ''),
        'mysql_cnf_file': config.get('mysql_cnf_file', ''),
        'mysql_slow_threshold_ms': int(config.get('mysql_slow_threshold_ms', '200')),
    }

class MySQLMonitor:
    """MySQL monitoring and metrics collection
    
    Phase 1: Collects ALL SHOW GLOBAL STATUS and SHOW GLOBAL VARIABLES
    Phase 2: Collects query stats from performance_schema
    Phase 3: Deadlock detection and parsing
    """
    
    def __init__(self, host: str = 'localhost', port: int = 3306, user: str = None, password: str = None, debug: bool = False, slow_threshold_ms: int = 200):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.debug = debug
        self.enabled = MYSQL_AVAILABLE and user and password
        self.slow_threshold_ms = slow_threshold_ms  # Minimum avg time to consider a query "slow"
        
        # Track config changes via hash (Phase 1)
        self.last_variables_hash = None
        
        # Track collection cycles for query stats (Phase 2 - every 5 minutes)
        self.metrics_count = 0
        
        # Deadlock tracking (Phase 3)
        self.last_deadlock_count = None  # Track Innodb_deadlocks counter
        self.last_deadlock_hash = None   # Prevent duplicate submissions
    
    def log(self, message: str, always: bool = False) -> None:
        """Log with timestamp
        
        Args:
            message: Message to log
            always: If True, log even when debug=False (for errors)
        """
        if self.debug or always:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] MySQL: {message}", flush=True)
    
    def _connect(self):
        """Establish MySQL connection"""
        if not self.enabled:
            return None
        
        try:
            self.log(f"Attempting MySQL connection to {self.user}@{self.host}:{self.port}", always=False)
            conn = mysql.connector.connect(
                host=self.host,
                port=self.port,
                user=self.user,
                password=self.password,
                connect_timeout=5
            )
            self.log(f"MySQL connection successful", always=False)
            return conn
        except mysql.connector.Error as e:
            self.log(f"MySQL connection error: {e.msg} (Error {e.errno}) - Check host={self.host}, port={self.port}, user={self.user}", always=True)
            return None
        except Exception as e:
            self.log(f"MySQL connection error (unexpected): {type(e).__name__}: {e} - Check host={self.host}, port={self.port}, user={self.user}", always=True)
            return None
    
    def get_metrics(self) -> dict:
        """Collect MySQL metrics (Phase 1: Full status + variables)
        
        Returns a dict with:
        - Basic metrics (backward compatible)
        - 'status': Full SHOW GLOBAL STATUS as dict
        - 'variables': Full SHOW GLOBAL VARIABLES as dict (only if changed)
        - 'variables_changed': True if variables were included (config changed)
        """
        if not self.enabled:
            return {}
        
        metrics = {}
        conn = None
        
        try:
            conn = self._connect()
            if not conn:
                self.log("MySQL get_metrics: Connection failed - unable to collect metrics", always=True)
                return {}
            
            cursor = conn.cursor(dictionary=True)
            
            # ==========================================
            # PHASE 1: Collect ALL Global Status (~500 vars)
            # ==========================================
            cursor.execute("SHOW GLOBAL STATUS")
            status_rows = cursor.fetchall()
            status = {row['Variable_name']: row['Value'] for row in status_rows}
            metrics['status'] = status
            
            # Extract key metrics for backward compatibility
            metrics['mysql_version'] = status.get('Version', 'unknown')
            
            # If Version not in status, try SELECT VERSION()
            if metrics['mysql_version'] == 'unknown':
                cursor.execute("SELECT VERSION() as version")
                result = cursor.fetchone()
                metrics['mysql_version'] = result['version'] if result else 'unknown'
            
            metrics['uptime_seconds'] = int(status.get('Uptime', 0))
            metrics['connections_current'] = int(status.get('Threads_connected', 0))
            metrics['connections_max_used'] = int(status.get('Max_used_connections', 0))
            
            # Cumulative counters (for rate calculation in backend)
            metrics['questions_total'] = int(status.get('Questions', 0))
            metrics['slow_queries_total'] = int(status.get('Slow_queries', 0))
            
            # Backward compatibility aliases
            metrics['total_queries'] = metrics['questions_total']
            metrics['slow_queries'] = metrics['slow_queries_total']
            
            # Buffer pool metrics (for hit rate calculation)
            metrics['buffer_pool_read_requests'] = int(status.get('Innodb_buffer_pool_read_requests', 0))
            metrics['buffer_pool_reads'] = int(status.get('Innodb_buffer_pool_reads', 0))
            
            # Calculate buffer pool usage percent
            buffer_pool_pages_total = int(status.get('Innodb_buffer_pool_pages_total', 0))
            buffer_pool_pages_free = int(status.get('Innodb_buffer_pool_pages_free', 0))
            if buffer_pool_pages_total > 0:
                buffer_pool_used = buffer_pool_pages_total - buffer_pool_pages_free
                metrics['buffer_pool_usage_percent'] = round((buffer_pool_used / buffer_pool_pages_total) * 100, 2)
            else:
                metrics['buffer_pool_usage_percent'] = 0
            
            # ==========================================
            # PHASE 1: Collect ALL Global Variables (~700 vars)
            # Only send if changed (saves bandwidth)
            # ==========================================
            cursor.execute("SHOW GLOBAL VARIABLES")
            variables_rows = cursor.fetchall()
            variables = {row['Variable_name']: row['Value'] for row in variables_rows}
            
            # Check if variables changed using hash
            variables_json = json.dumps(variables, sort_keys=True)
            current_hash = hashlib.md5(variables_json.encode()).hexdigest()
            
            if current_hash != self.last_variables_hash:
                metrics['variables'] = variables
                metrics['variables_changed'] = True
                self.last_variables_hash = current_hash
                self.log(f"MySQL config changed (hash: {current_hash[:8]}...)", always=True)
            else:
                metrics['variables_changed'] = False
            
            # Extract key variable values (backward compatibility)
            metrics['connections_limit'] = int(variables.get('max_connections', 0))
            buffer_pool_size = int(variables.get('innodb_buffer_pool_size', 0))
            metrics['buffer_pool_size_bytes'] = buffer_pool_size
            metrics['buffer_pool_size_mb'] = round(buffer_pool_size / 1024 / 1024, 2)
            
            # ==========================================
            # Database size stats (existing)
            # ==========================================
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
            self.log(f"Collected metrics: {len(metrics)} items + full status ({len(status)} vars)")
            
            # ==========================================
            # PHASE 3: Check for new deadlocks
            # ==========================================
            try:
                deadlock_info = self.check_for_deadlock(status)
                if deadlock_info:
                    metrics['deadlock'] = deadlock_info
            except Exception as e:
                self.log(f"Error checking for deadlocks: {type(e).__name__}: {e}", always=True)
            
        except mysql.connector.Error as e:
            self.log(f"MySQL error: {e.msg} (Error {e.errno})", always=True)
        except Exception as e:
            self.log(f"Error collecting MySQL metrics: {type(e).__name__}: {e}", always=True)
        finally:
            if conn and conn.is_connected():
                conn.close()
        
        return metrics
    
    def get_query_stats(self) -> list:
        """
        Phase 2: Collect top slow queries from performance_schema
        Called every 5 minutes (less frequent than main metrics)
        
        Returns list of query stats from events_statements_summary_by_digest
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
                self.log("Performance schema is disabled - cannot collect query stats", always=True)
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
            queries = []
            filtered_stats = {
                'total': len(all_queries),
                'kept': 0,
                'kept_slow': 0,          # Kept because slow (>= threshold)
                'kept_no_index': 0,      # Kept because missing index (even if fast)
                'filtered_fast': 0,      # Below threshold AND has index
                'filtered_no_cache': 0,
                'filtered_truncated': 0,
            }

            for query_data in all_queries:
                # Convert AVG_TIMER_WAIT from picoseconds to milliseconds
                # MySQL stores times in picoseconds (10^-12 seconds)
                avg_time_ps = query_data.get('AVG_TIMER_WAIT', 0)
                avg_time_ms = avg_time_ps / 1000000000  # picoseconds to milliseconds
                
                # Check if query is missing indexes
                no_index_used = query_data.get('SUM_NO_INDEX_USED', 0) or 0
                is_missing_index = int(no_index_used) > 0
                
                # Keep criteria: slow (>= threshold) OR missing index
                is_slow = avg_time_ms >= self.slow_threshold_ms
                
                # Skip only if BOTH fast AND has proper indexes
                if not is_slow and not is_missing_index:
                    filtered_stats['filtered_fast'] += 1
                    continue
                
                digest_text = query_data.get('DIGEST_TEXT', '')
                is_valid, skip_reason = self.is_valid_query_for_optimization(digest_text)

                if is_valid:
                    queries.append(query_data)
                    filtered_stats['kept'] += 1
                    # Track why we kept it
                    if is_slow:
                        filtered_stats['kept_slow'] += 1
                    if is_missing_index:
                        filtered_stats['kept_no_index'] += 1
                else:
                    if 'SQL_NO_CACHE' in skip_reason:
                        filtered_stats['filtered_no_cache'] += 1
                    if 'truncated' in skip_reason:
                        filtered_stats['filtered_truncated'] += 1

                    # Log first few filtered queries for debugging
                    if (filtered_stats['filtered_no_cache'] + filtered_stats['filtered_truncated']) <= 3:
                        self.log(f"Filtered query: {skip_reason} - {digest_text[:100]}...", always=False)

            # Log summary
            self.log(
                f"Query stats filter: {filtered_stats['kept']}/{filtered_stats['total']} kept "
                f"({filtered_stats['kept_slow']} slow, {filtered_stats['kept_no_index']} missing index), "
                f"filtered: {filtered_stats['filtered_fast']} fast, "
                f"{filtered_stats['filtered_no_cache']} SQL_NO_CACHE, "
                f"{filtered_stats['filtered_truncated']} truncated",
                always=True
            )

            cursor.close()
            conn.close()

            return queries
            
        except mysql.connector.Error as e:
            self.log(f"Error collecting query stats: {e.msg} (Error {e.errno})", always=True)
            return []
        except Exception as e:
            self.log(f"Error collecting query stats: {type(e).__name__}: {e}", always=True)
            return []

    # ==========================================================================
    # PHASE 3: Deadlock Detection and Parsing
    # ==========================================================================
    
    def check_for_deadlock(self, current_status: dict) -> dict:
        """Check if a new deadlock occurred by comparing Innodb_deadlocks counter
        
        Args:
            current_status: Dict from SHOW GLOBAL STATUS
            
        Returns:
            Parsed deadlock info dict if new deadlock detected, None otherwise
        """
        current_count = int(current_status.get('Innodb_deadlocks', 0))
        
        # First run - just store the baseline
        if self.last_deadlock_count is None:
            self.last_deadlock_count = current_count
            self.log(f"Deadlock monitoring initialized (baseline count: {current_count})")
            return None
        
        # No new deadlock
        if current_count <= self.last_deadlock_count:
            return None
        
        # NEW DEADLOCK DETECTED!
        deadlocks_since_last = current_count - self.last_deadlock_count
        self.log(f"🔴 Deadlock detected! Counter: {self.last_deadlock_count} → {current_count} (+{deadlocks_since_last})", always=True)
        self.last_deadlock_count = current_count
        
        # Fetch and parse SHOW ENGINE INNODB STATUS
        return self.get_deadlock_info()
    
    def get_deadlock_info(self) -> dict:
        """Fetch SHOW ENGINE INNODB STATUS and parse the LATEST DETECTED DEADLOCK section
        
        Returns:
            Dict with parsed deadlock info, or None if parsing fails
        """
        conn = self._connect()
        if not conn:
            self.log("Failed to connect to MySQL for deadlock info", always=True)
            return None
        
        try:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SHOW ENGINE INNODB STATUS")
            result = cursor.fetchone()
            cursor.close()
            conn.close()
            
            if not result:
                self.log("SHOW ENGINE INNODB STATUS returned no result", always=True)
                return None
            
            # The output is in the 'Status' column
            raw_status = result.get('Status', '')
            
            if not raw_status:
                self.log("INNODB STATUS is empty", always=True)
                return None
            
            return self.parse_deadlock_section(raw_status)
            
        except Exception as e:
            self.log(f"Error fetching INNODB STATUS: {type(e).__name__}: {e}", always=True)
            if conn and conn.is_connected():
                conn.close()
            return None
    
    def parse_deadlock_section(self, innodb_status: str) -> dict:
        """Parse the LATEST DETECTED DEADLOCK section from INNODB STATUS
        
        Handles MySQL 5.7, 8.0, and MariaDB variations.
        Fault-tolerant: returns partial data if parsing fails.
        
        Args:
            innodb_status: Full output from SHOW ENGINE INNODB STATUS
            
        Returns:
            Dict with deadlock info, or None if no deadlock section found
        """
        parse_errors = []
        
        # Extract the deadlock section
        deadlock_section = self._extract_deadlock_section(innodb_status)
        if not deadlock_section:
            self.log("No LATEST DETECTED DEADLOCK section found in INNODB STATUS", always=True)
            return None
        
        # Dedupe check - hash the raw section to avoid re-sending same deadlock
        section_hash = hashlib.md5(deadlock_section.encode()).hexdigest()[:16]
        if section_hash == self.last_deadlock_hash:
            self.log("Deadlock already reported (same hash), skipping duplicate", always=True)
            return None
        self.last_deadlock_hash = section_hash
        
        # Parse transactions
        transactions = self._parse_transactions(deadlock_section, parse_errors)
        
        # Generate fingerprint for grouping (normalized queries)
        fingerprint = self._generate_query_fingerprint(transactions)
        
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
        self.log(f"Parsed deadlock: {tx_count} transactions, fingerprint={fingerprint[:8]}..., tables={tables_involved}", always=True)
        
        return result
    
    def _extract_deadlock_section(self, innodb_status: str) -> str:
        """Extract just the LATEST DETECTED DEADLOCK section
        
        Args:
            innodb_status: Full INNODB STATUS output
            
        Returns:
            The deadlock section text, or None if not found
        """
        # Multiple patterns to handle MySQL 5.7, 8.0, MariaDB variations
        patterns = [
            # Standard format with dashes
            r'LATEST DETECTED DEADLOCK\n-+\n(.*?)(?=\n-{3,}\n[A-Z]|\nTRANSACTIONS\n|\Z)',
            # Without dashes (some MariaDB versions)
            r'LATEST DETECTED DEADLOCK\n(.*?)(?=\n[A-Z]{3,}[A-Z\s]+\n|\Z)',
            # Fallback: capture until next major section
            r'LATEST DETECTED DEADLOCK\n(.*?)(?=\nFILE I/O|\nLOG|\nROW OPERATIONS|\nINSERT BUFFER|\nBUFFER POOL|\Z)',
        ]
        
        for pattern in patterns:
            match = re.search(pattern, innodb_status, re.DOTALL | re.IGNORECASE)
            if match:
                section = match.group(1).strip()
                if section and len(section) > 50:  # Sanity check - should have meaningful content
                    return section
        
        return None
    
    def _parse_transactions(self, deadlock_section: str, parse_errors: list) -> list:
        """Parse transaction details from deadlock section
        
        Args:
            deadlock_section: The extracted deadlock section text
            parse_errors: List to append any parse errors to
            
        Returns:
            List of transaction dicts with: id, role, query, tables, lock_info
        """
        transactions = []
        
        # Split by transaction markers
        # MySQL format: "*** (1) TRANSACTION:" or "*** (2) TRANSACTION:"
        tx_pattern = r'\*\*\*\s*\((\d+)\)\s*TRANSACTION:'
        tx_splits = re.split(tx_pattern, deadlock_section)
        
        # tx_splits = ['...header...', '1', '...tx1 content...', '2', '...tx2 content...']
        for i in range(1, len(tx_splits), 2):
            try:
                tx_num = tx_splits[i]
                tx_content = tx_splits[i + 1] if i + 1 < len(tx_splits) else ''
                
                tx_info = {
                    'transaction_id': tx_num,
                    'role': self._determine_role(tx_content),
                    'query': self._extract_query(tx_content),
                    'tables_locked': self._extract_locked_tables(tx_content),
                    'lock_mode': self._extract_lock_mode(tx_content),
                    'lock_type': self._extract_lock_type(tx_content),
                    'waiting_for': self._extract_waiting_for(tx_content),
                    'thread_id': self._extract_thread_id(tx_content),
                }
                transactions.append(tx_info)
            except Exception as e:
                parse_errors.append(f"Error parsing transaction {i}: {str(e)[:100]}")
                self.log(f"Error parsing transaction: {e}", always=True)
        
        return transactions
    
    def _determine_role(self, tx_content: str) -> str:
        """Determine if transaction is WAITING or HOLDING a lock"""
        tx_upper = tx_content.upper()
        
        # Check for waiting indicators
        if 'WAITING FOR THIS LOCK' in tx_upper:
            return 'WAITING'
        if 'LOCK WAIT' in tx_upper:
            return 'WAITING'
            
        # Check for holding indicators
        if 'HOLDS THE LOCK' in tx_upper:
            return 'HOLDING'
        
        # Check victim status
        if 'WE ROLL BACK' in tx_upper:
            return 'VICTIM'
        
        return 'UNKNOWN'
    
    def _extract_query(self, tx_content: str) -> str:
        """Extract the SQL query from transaction content
        
        The query appears after lock info, typically near the end of each transaction block.
        """
        # Common SQL keywords that start queries
        sql_keywords = ['SELECT', 'UPDATE', 'DELETE', 'INSERT', 'REPLACE', 'CALL']
        
        lines = tx_content.split('\n')
        query_lines = []
        in_query = False
        
        for line in lines:
            line_stripped = line.strip()
            line_upper = line_stripped.upper()
            
            # Skip empty lines and InnoDB metadata
            if not line_stripped:
                if in_query:
                    break  # End of query
                continue
            
            # Skip InnoDB info lines
            if any(skip in line_upper for skip in [
                'MYSQL THREAD ID', 'TRANSACTION:', 'LOCK WAIT', 
                'RECORD LOCKS', 'TABLE LOCK', 'HOLDS THE LOCK',
                'WAITING FOR THIS LOCK', 'ACTIVE ', 'STARTING INDEX',
                'SPACE ID', 'PAGE NO', 'N BITS', 'INDEX', 'TRX'
            ]):
                if in_query:
                    break  # End of query (hit metadata)
                continue
            
            # Check if this line starts a query
            if any(line_upper.startswith(kw) for kw in sql_keywords):
                in_query = True
                query_lines.append(line_stripped)
            elif in_query:
                # Continue multi-line query
                query_lines.append(line_stripped)
        
        query = ' '.join(query_lines)
        
        # Clean up common artifacts
        query = re.sub(r'\s+', ' ', query).strip()
        
        return query
    
    def _extract_locked_tables(self, tx_content: str) -> list:
        """Extract table names involved in locks"""
        tables = set()
        
        # Pattern: table `schema`.`table` or table `table`
        # MySQL INNODB STATUS format examples:
        # - "TABLE LOCK table `db`.`tablename`"
        # - "RECORD LOCKS space id 123 page no 456 n bits 789 index `idx` of table `db`.`tablename`"
        table_patterns = [
            r'table\s+`([^`]+)`\.`([^`]+)`',  # schema.table format
            r'table\s+`([^`]+)`(?!\s*\.)',     # just table (no dot after)
        ]
        
        for pattern in table_patterns:
            for match in re.finditer(pattern, tx_content, re.IGNORECASE):
                if match.lastindex == 2:
                    # schema.table format
                    tables.add(f"{match.group(1)}.{match.group(2)}")
                else:
                    # just table
                    tables.add(match.group(1))
        
        return list(tables)
    
    def _extract_lock_mode(self, tx_content: str) -> str:
        """Extract lock mode (X, S, IX, IS, etc.)"""
        # Pattern: "lock mode X" or "lock_mode X" or "X lock"
        patterns = [
            r'lock[_\s]mode\s+(\w+)',
            r'\b(X|S|IX|IS)\s+lock',
            r'locks\s+(\w+)\s+lock',
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
    
    def _extract_thread_id(self, tx_content: str) -> str:
        """Extract MySQL thread ID"""
        match = re.search(r'MySQL\s+thread\s+id\s+(\d+)', tx_content, re.IGNORECASE)
        return match.group(1) if match else ''
    
    def _generate_query_fingerprint(self, transactions: list) -> str:
        """Generate a fingerprint for grouping identical deadlock patterns
        
        Normalizes queries by stripping literals, then hashes the pair.
        """
        queries = []
        for tx in transactions:
            normalized = self._normalize_query_for_fingerprint(tx.get('query', ''))
            queries.append(normalized)
        
        # Sort to ensure consistent fingerprint regardless of transaction order
        queries.sort()
        combined = '|||'.join(queries)
        
        return hashlib.md5(combined.encode()).hexdigest()
    
    def _normalize_query_for_fingerprint(self, query: str) -> str:
        """Normalize query for fingerprinting - strip literals
        
        'UPDATE users SET status = 'active' WHERE id = 105'
        becomes:
        'UPDATE USERS SET STATUS = ? WHERE ID = ?'
        """
        if not query:
            return ''
        
        # Replace string literals: 'value' -> ?
        normalized = re.sub(r"'[^']*'", '?', query)
        # Replace double-quoted strings: "value" -> ?
        normalized = re.sub(r'"[^"]*"', '?', normalized)
        # Replace numeric literals: 123 -> ?
        normalized = re.sub(r'\b\d+\.?\d*\b', '?', normalized)
        # Replace hex literals: 0x1234 -> ?
        normalized = re.sub(r'0x[0-9a-fA-F]+', '?', normalized)
        # Collapse whitespace
        normalized = re.sub(r'\s+', ' ', normalized).strip().upper()
        
        return normalized
    
    def _extract_tables_from_transactions(self, transactions: list) -> str:
        """Extract unique tables from all transactions as comma-separated string"""
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
    
    # ==========================================================================
    # Query Validation (existing)
    # ==========================================================================
    
    def is_valid_query_for_optimization(self, digest_text: str) -> tuple[bool, str]:
        """
        Check if a query is valid for optimization analysis

        Filter out queries that have BOTH:
        1. SQL_NO_CACHE keyword (MySQL internal notation)
        2. No WHERE clause (the WHERE word is missing, indicates truncation or system query)

        Args:
            digest_text: The DIGEST_TEXT from performance_schema

        Returns:
            tuple: (is_valid: bool, skip_reason: str)
        """
        if not digest_text:
            return False, "Empty digest text"

        digest_upper = digest_text.upper()

        # Check for SQL_NO_CACHE
        has_no_cache = 'SQL_NO_CACHE' in digest_upper

        # Only proceed with further checks if SQL_NO_CACHE is present
        if not has_no_cache:
            return True, ""  # Valid - no SQL_NO_CACHE, so we keep it

        # SQL_NO_CACHE is present - now check if it also lacks WHERE clause
        # (which indicates truncation or system-generated query)

        if digest_upper.strip().startswith('SELECT'):
            # Check if query has WHERE clause
            has_where = 'WHERE' in digest_upper

            if not has_where:
                # Query has SQL_NO_CACHE AND no WHERE - likely truncated or system query
                # Additional check: does it end properly?
                digest_trimmed = digest_text.rstrip()

                # Properly ended queries should have one of these:
                # - Semicolon: SELECT SQL_NO_CACHE * FROM users;
                # - LIMIT clause: SELECT SQL_NO_CACHE * FROM users LIMIT ?
                # - ORDER BY: SELECT SQL_NO_CACHE * FROM users ORDER BY created_at
                # - Closing backtick/quote: SELECT SQL_NO_CACHE * FROM `users`
                # - GROUP BY: SELECT SQL_NO_CACHE COUNT(*) FROM users GROUP BY status

                valid_endings = (
                    ';',           # Explicit query end
                    'LIMIT ?',     # Pagination
                    '`',           # Table name end
                    "'",           # String literal end
                )

                # Also check for valid clauses at the end
                valid_clause_patterns = [
                    'LIMIT ?',
                    'LIMIT ?, ?',
                    'ORDER BY ?',
                    'GROUP BY ?',
                ]

                ends_properly = (
                    digest_trimmed.endswith(valid_endings) or
                    any(digest_trimmed.endswith(pattern) for pattern in valid_clause_patterns)
                )

                if not ends_properly:
                    # Has SQL_NO_CACHE AND no WHERE AND doesn't end properly = truncated
                    return False, "SQL_NO_CACHE + no WHERE + appears truncated"
                else:
                    # Has SQL_NO_CACHE AND no WHERE but ends properly
                    # Still suspicious - likely a full table scan system query
                    return False, "SQL_NO_CACHE + no WHERE (system query)"
            else:
                # Has SQL_NO_CACHE but also has WHERE clause - keep it
                # This might be a legitimate user query with query cache disabled
                return True, ""

        # SQL_NO_CACHE present but not a SELECT, or other edge case - keep it
        return True, ""

    def extract_tables_from_explain(self, explain_json: str, schema: str) -> set:
        """Extract table names from EXPLAIN JSON output
        
        Args:
            explain_json: JSON output from EXPLAIN FORMAT=JSON
            schema: Default schema name
            
        Returns:
            Set of (schema_name, table_name) tuples
        """
        tables = set()
        
        try:
            explain_data = json.loads(explain_json)
            
            # Recursively search for 'table_name' and 'table' keys in EXPLAIN JSON
            def find_tables(obj, current_schema=schema):
                if isinstance(obj, dict):
                    # Look for table references
                    if 'table_name' in obj:
                        table = obj['table_name']
                        tables.add((current_schema, table))
                    elif 'table' in obj and isinstance(obj['table'], str):
                        table = obj['table']
                        if table not in ('<subquery>', '<derived>', '<union>'):
                            tables.add((current_schema, table))
                    
                    # Recurse into nested structures
                    for value in obj.values():
                        find_tables(value, current_schema)
                elif isinstance(obj, list):
                    for item in obj:
                        find_tables(item, current_schema)
            
            find_tables(explain_data)
            
        except Exception as e:
            self.log(f"Error parsing EXPLAIN JSON: {e}", always=False)
        
        return tables
    
    def get_targeted_schema_info(self, tables: set) -> dict:
        """Collect indexes and columns for ONLY the specified tables
        
        Args:
            tables: Set of (schema_name, table_name) tuples
        
        Returns:
            Dict with 'indexes' and 'columns' for those tables only
        """
        if not self.enabled or not tables:
            return {}
        
        conn = self._connect()
        if not conn:
            return {}
        
        cursor = conn.cursor(dictionary=True)
        schema_info = {'indexes': [], 'columns': []}
        
        try:
            # Build parameterized WHERE clause for specific tables
            # Using parameterized queries to prevent SQL injection
            placeholders = []
            params = []
            for schema, table in tables:
                placeholders.append("(TABLE_SCHEMA = %s AND TABLE_NAME = %s)")
                params.extend([schema, table])
            
            where_clause = ' OR '.join(placeholders)
            
            # Get indexes for these specific tables only
            query = f"""
                SELECT
                    TABLE_SCHEMA,
                    TABLE_NAME,
                    INDEX_NAME,
                    NON_UNIQUE,
                    SEQ_IN_INDEX,
                    COLUMN_NAME,
                    COLLATION,
                    CARDINALITY,
                    INDEX_TYPE
                FROM information_schema.STATISTICS
                WHERE {where_clause}
                ORDER BY TABLE_SCHEMA, TABLE_NAME, INDEX_NAME, SEQ_IN_INDEX
            """
            cursor.execute(query, params)
            schema_info['indexes'] = cursor.fetchall()
            
            # Get column info for these specific tables only
            query = f"""
                SELECT
                    TABLE_SCHEMA,
                    TABLE_NAME,
                    COLUMN_NAME,
                    ORDINAL_POSITION,
                    DATA_TYPE,
                    COLUMN_TYPE,
                    COLUMN_KEY,
                    IS_NULLABLE
                FROM information_schema.COLUMNS
                WHERE {where_clause}
                ORDER BY TABLE_SCHEMA, TABLE_NAME, ORDINAL_POSITION
            """
            cursor.execute(query, params)
            schema_info['columns'] = cursor.fetchall()
            
            self.log(f"Collected schema for {len(tables)} tables: {len(schema_info['indexes'])} indexes, {len(schema_info['columns'])} columns")
            
        except mysql.connector.Error as e:
            self.log(f"Error collecting targeted schema: {e.msg} (Error {e.errno})", always=True)
        except Exception as e:
            self.log(f"Error collecting targeted schema: {type(e).__name__}: {e}", always=True)
        finally:
            cursor.close()
            conn.close()
        
        return schema_info
    
    def convert_to_select_for_explain(self, query: str) -> str:
        """Convert DELETE/UPDATE queries to SELECT for EXPLAIN
        
        MySQL requires DELETE/UPDATE privileges to run EXPLAIN DELETE/UPDATE.
        Since we only need the execution plan (table access patterns), we can
        convert these to equivalent SELECT queries.
        
        Args:
            query: Original query (DELETE/UPDATE/INSERT)
            
        Returns:
            Equivalent SELECT query for EXPLAIN, or original if already SELECT
        """
        query_upper = query.strip().upper()
        
        # DELETE FROM table WHERE ... → SELECT * FROM table WHERE ...
        if query_upper.startswith('DELETE'):
            # Pattern: DELETE FROM `table` WHERE ...
            # Convert to: SELECT * FROM `table` WHERE ...
            converted = re.sub(
                r'^DELETE\s+FROM\s+',
                'SELECT * FROM ',
                query.strip(),
                count=1,
                flags=re.IGNORECASE
            )
            return converted
        
        # UPDATE table SET ... WHERE ... → SELECT * FROM table WHERE ...
        if query_upper.startswith('UPDATE'):
            # Pattern: UPDATE `table` SET col=val, ... WHERE ...
            # Convert to: SELECT * FROM `table` WHERE ...
            # We need to extract the table name and WHERE clause
            match = re.match(
                r'^UPDATE\s+(`?\w+`?(?:\s*\.\s*`?\w+`?)?)\s+SET\s+.*?(WHERE\s+.*)$',
                query.strip(),
                flags=re.IGNORECASE | re.DOTALL
            )
            if match:
                table_name = match.group(1)
                where_clause = match.group(2)
                return f'SELECT * FROM {table_name} {where_clause}'
            else:
                # UPDATE without WHERE clause - just select from table
                match = re.match(
                    r'^UPDATE\s+(`?\w+`?(?:\s*\.\s*`?\w+`?)?)\s+SET\s+',
                    query.strip(),
                    flags=re.IGNORECASE
                )
                if match:
                    table_name = match.group(1)
                    return f'SELECT * FROM {table_name} LIMIT 1'
        
        # INSERT queries - harder to convert meaningfully, skip for now
        # The execution plan for INSERT is usually just "insert into table"
        
        # Return original for SELECT or unsupported types
        return query
    
    def replace_placeholders_for_explain(self, digest_text: str) -> list:
        """Replace ? placeholders in DIGEST_TEXT with executable values for EXPLAIN

        DIGEST_TEXT from performance_schema contains ? placeholders that can't be
        executed directly. This function generates context-aware replacement strategies.

        Key insight: EXPLAIN doesn't execute the query, it just analyzes the plan.
        So we need syntactically valid values, not semantically meaningful ones.

        Args:
            digest_text: Query text with ? placeholders

        Returns:
            List of query strings with placeholders replaced using different strategies
        """
        strategies = []

        def normalize_sql(query: str) -> str:
            """Normalize SQL syntax issues from DIGEST_TEXT

            MySQL's performance_schema DIGEST_TEXT sometimes contains syntax that's
            not valid for execution, like spaces in function calls: COUNT ( * )
            This function fixes these issues.
            """
            # Fix function calls with spaces: COUNT ( * ) -> COUNT(*)
            # Also handles COUNT ( ? ), SUM ( * ), AVG ( ? ), etc.
            query = re.sub(r'(\w+)\s*\(\s*([*?])\s*\)', r'\1(\2)', query)

            # Fix function calls with spaces around parameters: FUNC ( param ) -> FUNC(param)
            query = re.sub(r'(\w+)\s*\(\s+', r'\1(', query)
            query = re.sub(r'\s+\)', ')', query)

            return query

        def smart_replace(query: str, default_value: str) -> str:
            """Context-aware placeholder replacement
            
            Args:
                query: SQL query with ? placeholders
                default_value: Value to use for remaining placeholders after context-aware replacements
                
            Returns:
                Query with all ? replaced with appropriate values
            """
            try:
                result = query
                
                # ==============================================
                # FIRST: Handle truncated queries (ends with ...)
                # MySQL truncates long digest_text and adds ...
                # ==============================================
                
                # Handle truncated LIMIT: "LIMIT 1000, ..." or "LIMIT ..."
                result = re.sub(r'LIMIT\s+(\d+)\s*,\s*\.\.\..*$', r'LIMIT \1, 100', result, flags=re.IGNORECASE)
                result = re.sub(r'LIMIT\s+\.\.\..*$', 'LIMIT 100', result, flags=re.IGNORECASE)
                
                # Handle truncated IN clause: "IN (...)" - MySQL's way of showing variable-length IN
                # This is different from regular truncation - it's a digest notation
                result = re.sub(r'IN\s*\(\s*\.\.\.\s*\)', f'IN ({default_value})', result, flags=re.IGNORECASE)
                
                # Remove trailing ... (truncated query) - try to make it valid
                if result.rstrip().endswith('...'):
                    result = result.rstrip()[:-3].rstrip()
                    # If it now ends with a comma or operator, remove that too
                    result = re.sub(r'[,\s]+$', '', result)
                    # If it ends with AND/OR, remove the incomplete condition
                    result = re.sub(r'\s+(AND|OR)\s*$', '', result, flags=re.IGNORECASE)
                
                # ==============================================
                # Handle LIMIT/OFFSET - must be positive integers
                # ==============================================
                result = re.sub(r'LIMIT\s+\?', 'LIMIT 1000', result, flags=re.IGNORECASE)
                result = re.sub(r'OFFSET\s+\?', 'OFFSET 0', result, flags=re.IGNORECASE)
                result = re.sub(r'LIMIT\s+\?\s*,\s*\?', 'LIMIT 0, 1000', result, flags=re.IGNORECASE)
                result = re.sub(r'LIMIT\s+(\d+)\s*,\s*\?', r'LIMIT \1, 1000', result, flags=re.IGNORECASE)
                
                # ==============================================
                # Handle IN clauses
                # ==============================================
                # IN (?) -> IN (default_value)
                result = re.sub(r'IN\s*\(\s*\?\s*\)', f'IN ({default_value})', result, flags=re.IGNORECASE)
                # IN (?, ?, ...) -> IN (default_value) - simplify multi-value IN
                result = re.sub(r'IN\s*\(\s*\?(?:\s*,\s*\?)+\s*\)', f'IN ({default_value})', result, flags=re.IGNORECASE)
                
                # Handle LIKE - use wildcard pattern
                result = re.sub(r"LIKE\s+\?", "LIKE '%'", result, flags=re.IGNORECASE)
                
                # Handle BETWEEN - use same value for both bounds
                result = re.sub(r'BETWEEN\s+\?\s+AND\s+\?', f'BETWEEN {default_value} AND {default_value}', result, flags=re.IGNORECASE)
                
                # Handle date/time functions - ALWAYS use valid date strings regardless of default_value
                # DATE(), STR_TO_DATE(), etc. need string date arguments
                result = re.sub(r"DATE\s*\(\s*\?\s*\)", "DATE('2024-01-01')", result, flags=re.IGNORECASE)
                result = re.sub(r"STR_TO_DATE\s*\(\s*\?\s*,", "STR_TO_DATE('2024-01-01',", result, flags=re.IGNORECASE)
                result = re.sub(r"UNIX_TIMESTAMP\s*\(\s*\?\s*\)", "UNIX_TIMESTAMP('2024-01-01')", result, flags=re.IGNORECASE)
                result = re.sub(r"FROM_UNIXTIME\s*\(\s*\?\s*\)", "FROM_UNIXTIME(0)", result, flags=re.IGNORECASE)
                result = re.sub(r"DATE_FORMAT\s*\(\s*\?\s*,", "DATE_FORMAT('2024-01-01',", result, flags=re.IGNORECASE)
                result = re.sub(r"DATEDIFF\s*\(\s*\?\s*,\s*\?\s*\)", "DATEDIFF('2024-01-01', '2024-01-01')", result, flags=re.IGNORECASE)
                result = re.sub(r"TIMESTAMPDIFF\s*\(\s*\w+\s*,\s*\?\s*,\s*\?\s*\)",
                               lambda m: m.group(0).replace('?', "'2024-01-01'"), result, flags=re.IGNORECASE)
                
                # Handle ORDER BY ? (dynamic ordering) - use column position
                result = re.sub(r'ORDER\s+BY\s+\?', 'ORDER BY 1', result, flags=re.IGNORECASE)
                
                # Replace remaining ? with default value
                result = result.replace('?', default_value)
                
                return result
            except Exception as e:
                # If smart replacement fails, fall back to simple replacement
                return query.replace('?', default_value)
        
        # Always wrap strategy generation in try-except to ensure we return something usable
        try:
            # Normalize the query first to fix syntax issues from DIGEST_TEXT
            normalized_query = normalize_sql(digest_text)

            # Strategy 1: Smart replacement with numeric default (best for most queries)
            strategies.append(smart_replace(normalized_query, '1'))

            # Strategy 2: Smart replacement with string default
            strategies.append(smart_replace(normalized_query, "''"))

            # Strategy 3: Smart replacement with NULL (handles nullable columns)
            strategies.append(smart_replace(normalized_query, 'NULL'))

            # Strategy 4: Use 0 as default (sometimes works better for IDs)
            strategies.append(smart_replace(normalized_query, '0'))

            # Strategy 5: Use -1 as default (for cases where 0 might match real data)
            strategies.append(smart_replace(normalized_query, '-1'))
        except Exception as e:
            # Fallback: if all smart strategies fail, provide basic replacements
            self.log(f"Warning: smart_replace failed ({e}), using basic fallback", always=True)
            # Apply normalization even in fallback
            normalized_query = normalize_sql(digest_text)
            strategies = [
                normalized_query.replace('?', '1'),
                normalized_query.replace('?', "''"),
                normalized_query.replace('?', 'NULL'),
            ]

        return strategies
    
    def get_query_explains(self, query_digests: list) -> tuple:
        """Run EXPLAIN on slow queries and extract table names from EXPLAIN output
        
        Returns:
            Tuple of (explains_list, tables_set)
            - explains_list: List of EXPLAIN plan dicts
            - tables_set: Set of (schema, table) tuples found across all explains
        """
        if not self.enabled or not query_digests:
            self.log("get_query_explains: enabled=False or query_digests is empty", always=True)
            return [], set()
        
        self.log(f"get_query_explains: Processing {len(query_digests)} query digests", always=True)
        
        conn = self._connect()
        if not conn:
            self.log("get_query_explains: Failed to connect to MySQL", always=True)
            return [], set()
        
        cursor = conn.cursor(dictionary=True)
        explains = []
        all_tables = set()  # Accumulate all tables across queries
        
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
            # Frontend sorts by avg_time_ms DESC, so we must collect EXPLAIN for the same queries
            sorted_queries = sorted(
                query_digests,
                key=lambda q: q.get('AVG_TIMER_WAIT', 0),
                reverse=True
            )[:30]
            stats['sorted'] = len(sorted_queries)
            self.log(f"get_query_explains: Top {len(sorted_queries)} queries by avg time selected for EXPLAIN", always=True)
            
            # Debug: Log first few queries
            for idx, q in enumerate(sorted_queries[:5]):
                schema = q.get('SCHEMA_NAME', 'NULL')
                digest_text = q.get('DIGEST_TEXT', '')[:100] if q.get('DIGEST_TEXT') else 'EMPTY'
                self.log(f"  Query #{idx+1}: schema={schema}, digest_text={digest_text}...", always=True)
            
            for idx, query_data in enumerate(sorted_queries):
                schema = query_data.get('SCHEMA_NAME')
                digest_text = query_data.get('DIGEST_TEXT', '')
                # Keep full digest for data, use truncated version only for logging
                digest = query_data.get('DIGEST', '')
                digest_log = digest[:30] + '...' if digest and len(digest) > 30 else (digest or 'N/A')
                
                self.log(f"  Processing query #{idx+1}/{len(sorted_queries)}: schema={schema}, digest={digest_log}", always=False)
                
                # Skip system schemas
                if schema in ('mysql', 'information_schema', 'performance_schema', 'sys', None):
                    stats['skipped_system_schema'] += 1
                    self.log(f"    SKIPPED: System schema or NULL (schema={schema})", always=True)
                    continue

                # Check query type - allow SELECT, INSERT, UPDATE, DELETE
                # EXPLAIN works on all of these in modern MySQL/MariaDB
                valid_types = ('SELECT', 'INSERT', 'UPDATE', 'DELETE')
                if not digest_text or not any(digest_text.lstrip().upper().startswith(t) for t in valid_types):
                    stats['skipped_type'] += 1
                    self.log(f"    SKIPPED: Not a supported query type (digest_text starts with: {digest_text[:50] if digest_text else 'EMPTY'}...)", always=True)
                    continue
                
                # Switch to correct schema
                try:
                    cursor.execute(f"USE `{schema}`")
                    self.log(f"    Switched to schema: {schema}", always=False)
                except Exception as e:
                    stats['skipped_schema_switch_failed'] += 1
                    self.log(f"    SKIPPED: Could not switch to schema {schema}: {e}", always=True)
                    continue
                
                # Convert DELETE/UPDATE to SELECT to avoid permission issues
                # EXPLAIN DELETE/UPDATE requires write privileges, but SELECT only needs read
                query_for_explain = self.convert_to_select_for_explain(digest_text)
                was_converted = (query_for_explain != digest_text)
                if was_converted:
                    self.log(f"    Converted to SELECT for EXPLAIN (avoids write privilege requirement)", always=False)
                
                # Replace ? placeholders with executable values for EXPLAIN
                # DIGEST_TEXT contains ? placeholders that can't be executed directly
                explain_queries = self.replace_placeholders_for_explain(query_for_explain)
                self.log(f"    Generated {len(explain_queries)} placeholder replacement strategies", always=False)
                
                explain_json = None
                explain_errors = []
                strategy_names = ['smart-numeric', 'smart-string', 'smart-null', 'smart-zero', 'smart-neg1']
                for attempt_idx, attempt in enumerate(explain_queries):
                    try:
                        strategy_name = strategy_names[attempt_idx] if attempt_idx < len(strategy_names) else 'unknown'
                        self.log(f"    Running EXPLAIN attempt {attempt_idx+1} (strategy: {strategy_name})...", always=False)
                        
                        # Log the actual query being attempted if debug is on
                        if self.debug:
                            self.log(f"    SQL: EXPLAIN FORMAT=JSON {attempt[:200]}...", always=False)
                            
                        cursor.execute(f"EXPLAIN FORMAT=JSON {attempt}")
                        result = cursor.fetchone()
                        explain_json = result['EXPLAIN'] if result else None
                        if explain_json:
                            self.log(f"    ✅ EXPLAIN succeeded on attempt {attempt_idx+1}{' (converted)' if was_converted else ''}", always=True)
                            break
                        else:
                            explain_errors.append(f"Attempt {attempt_idx+1}: No result returned")
                    except mysql.connector.Error as e:
                        # Log specific MySQL errors for debugging
                        error_msg = f"Attempt {attempt_idx+1}: MySQL Error {e.errno}: {e.msg[:100]}"
                        explain_errors.append(error_msg)
                        
                        # Log the failed query for debugging syntax errors
                        if e.errno == 1064: # Syntax error
                            self.log(f"    ❌ Syntax Error in: {attempt}", always=True)
                        
                        if attempt_idx < 2:
                            self.log(f"    EXPLAIN failed: {error_msg}", always=True)
                    except Exception as e:
                        error_msg = f"Attempt {attempt_idx+1}: {type(e).__name__}: {str(e)[:100]}"
                        explain_errors.append(error_msg)
                        if attempt_idx < 2:
                            self.log(f"    EXPLAIN error: {error_msg}", always=True)
                        continue
                
                if explain_json:
                    # Extract tables from this EXPLAIN plan
                    query_tables = self.extract_tables_from_explain(explain_json, schema)
                    all_tables.update(query_tables)
                    
                    # Convert timers from picoseconds to milliseconds
                    avg_time_ms = None
                    if query_data.get('AVG_TIMER_WAIT'):
                        avg_time_ms = round(query_data['AVG_TIMER_WAIT'] / 1000000000, 2)
                    
                    explains.append({
                        'digest': digest,
                        'schema_name': schema,
                        'digest_text': digest_text,
                        'explain_json': explain_json,
                        'tables_involved': list(query_tables),  # Store table names for backend
                        'avg_time_ms': avg_time_ms,
                        'exec_count': query_data.get('COUNT_STAR'),
                        'sum_no_index_used': query_data.get('SUM_NO_INDEX_USED', 0)
                    })
                    stats['success'] += 1
                    self.log(f"    ✅ Successfully collected EXPLAIN for {schema} (found {len(query_tables)} tables)", always=True)
                else:
                    stats['skipped_explain_failed'] += 1
                    self.log(f"    SKIPPED: All EXPLAIN attempts failed. Errors: {', '.join(explain_errors)}", always=True)
            
            # Log summary statistics
            self.log(f"get_query_explains: Summary - Total: {stats['total']}, Sorted: {stats['sorted']}, "
                    f"Skipped (type): {stats['skipped_type']}, "
                    f"Skipped (system schema): {stats['skipped_system_schema']}, "
                    f"Skipped (schema switch failed): {stats['skipped_schema_switch_failed']}, "
                    f"Skipped (EXPLAIN failed): {stats['skipped_explain_failed']}, "
                    f"Success: {stats['success']}", always=True)
            
            self.log(f"Collected {len(explains)} EXPLAIN plans covering {len(all_tables)} unique tables", always=True)
            
        except mysql.connector.Error as e:
            self.log(f"Error collecting EXPLAIN plans: {e.msg} (Error {e.errno})", always=True)
            import traceback
            self.log(f"Traceback: {traceback.format_exc()}", always=True)
        except Exception as e:
            self.log(f"Error collecting EXPLAIN plans: {type(e).__name__}: {e}", always=True)
            import traceback
            self.log(f"Traceback: {traceback.format_exc()}", always=True)
        finally:
            cursor.close()
            conn.close()
        
        return explains, all_tables


class MetricsAPIClient:
    """REST API client for sending metrics to CLI Pal platform
    
    Handles all metrics communication via HTTP POST requests.
    Includes retry logic, version headers, and instruction parsing.
    """
    
    def __init__(self, server_url: str, token: str, debug: bool = False):
        # Convert wss://app.clipal.me/ws to https://app.clipal.me
        self.base_url = server_url.replace('wss://', 'https://').replace('ws://', 'http://')
        if self.base_url.endswith('/ws'):
            self.base_url = self.base_url[:-3]
        self.token = token
        self.debug = debug
        
        # Server instructions (updated from API responses)
        self.instructions = {
            'metrics_interval': 60,
            'query_stats_interval': 300,
            'explains_interval': 600,
            'collect_query_stats': True,
            'collect_explains': True,
            'collect_schema': True,
            'collect_deadlocks': True
        }
    
    def log(self, message: str, always: bool = False):
        if self.debug or always:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"[{timestamp}] API: {message}", flush=True)
    
    def send_metrics(self, metrics: dict) -> bool:
        """POST metrics to /api/v1/metrics"""
        return self._post('/api/v1/metrics', metrics)
    
    def send_query_stats(self, query_stats: list) -> bool:
        """POST query stats to /api/v1/query-stats"""
        if not self.instructions.get('collect_query_stats', True):
            self.log("Query stats collection disabled by server")
            return True
        return self._post('/api/v1/query-stats', {'query_stats': query_stats})
    
    def send_query_explains(self, explains: list) -> bool:
        """POST EXPLAIN plans to /api/v1/query-explains"""
        if not self.instructions.get('collect_explains', True):
            self.log("EXPLAIN collection disabled by server")
            return True
        return self._post('/api/v1/query-explains', {'explains': explains})
    
    def send_schema_update(self, schema_info: dict, tables_involved: list) -> bool:
        """POST schema info to /api/v1/schema"""
        if not self.instructions.get('collect_schema', True):
            self.log("Schema collection disabled by server")
            return True
        return self._post('/api/v1/schema', {
            'schema_info': schema_info,
            'tables_involved': tables_involved
        })
    
    def send_deadlock(self, deadlock_info: dict) -> bool:
        """POST deadlock event to /api/v1/deadlocks"""
        if not self.instructions.get('collect_deadlocks', True):
            self.log("Deadlock collection disabled by server")
            return True
        return self._post('/api/v1/deadlocks', deadlock_info)
    
    def _post(self, endpoint: str, data: dict, max_retries: int = 3) -> bool:
        """Make POST request with JSON body and retry logic"""
        url = f"{self.base_url}{endpoint}"
        
        for attempt in range(max_retries):
            try:
                # Encode JSON with custom encoder for MySQL types
                class MySQLEncoder(json.JSONEncoder):
                    def default(self, obj):
                        if hasattr(obj, 'to_eng_string'):  # Decimal
                            return float(obj)
                        if hasattr(obj, 'isoformat'):  # datetime
                            return obj.isoformat()
                        if isinstance(obj, bytes):
                            return obj.decode('utf-8', errors='replace')
                        return super().default(obj)
                
                json_data = json.dumps(data, cls=MySQLEncoder).encode('utf-8')
                
                req = urllib.request.Request(
                    url,
                    data=json_data,
                    headers={
                        'Content-Type': 'application/json',
                        'X-Agent-Token': self.token,
                        'X-Agent-Version': VERSION,
                        'User-Agent': f'CliPalAgent/{VERSION}'
                    },
                    method='POST'
                )
                
                with urllib.request.urlopen(req, timeout=30) as response:
                    result = json.loads(response.read().decode('utf-8'))
                    
                    # Update instructions if provided
                    if 'instructions' in result:
                        self._update_instructions(result['instructions'])
                    
                    self.log(f"POST {endpoint}: {response.status} - {result.get('message', 'OK')}")
                    return response.status == 200
                    
            except urllib.error.HTTPError as e:
                self.log(f"HTTP Error {e.code} for {endpoint}: {e.reason}", always=True)
                if e.code in [401, 403, 404]:  # Don't retry auth/not-found errors
                    return False
            except urllib.error.URLError as e:
                self.log(f"URL Error for {endpoint}: {e.reason} (attempt {attempt + 1}/{max_retries})", always=True)
            except Exception as e:
                self.log(f"Error sending to {endpoint}: {e} (attempt {attempt + 1}/{max_retries})", always=True)
            
            # Exponential backoff before retry
            if attempt < max_retries - 1:
                wait_time = 2 ** attempt
                time.sleep(wait_time)
        
        self.log(f"Failed to send to {endpoint} after {max_retries} attempts", always=True)
        return False
    
    def _update_instructions(self, new_instructions: dict):
        """Update local instructions from server response"""
        for key, value in new_instructions.items():
            if key in self.instructions:
                old_value = self.instructions[key]
                if old_value != value:
                    self.log(f"Instruction updated: {key} = {value} (was {old_value})", always=True)
                self.instructions[key] = value


def _validate_secure_server(server_url: str) -> str:
    """Enforce TLS for remote connections (allow plain WS only for localhost).
    
    Returns the server_url unchanged if valid; raises SystemExit otherwise.
    """
    if not server_url:
        print("❌ ERROR: Server URL is required")
        sys.exit(1)
    
    if server_url.startswith("wss://"):
        return server_url
    
    # Allow plain WS only for explicit local development
    allowed_plain = ("ws://localhost", "ws://127.0.0.1")
    if any(server_url.startswith(prefix) for prefix in allowed_plain):
        return server_url
    
    print("=" * 60)
    print("❌ ERROR: Insecure WebSocket connection blocked")
    print(f"   Server: {server_url}")
    print("   Plain ws:// is not allowed. Use wss:// (TLS) or localhost for dev.")
    print("   Example: wss://app.clipal.me/ws")
    print("=" * 60)
    sys.exit(1)


class CliPalAgent:
    def __init__(self, token: str, server_url: str = "ws://localhost:8080", debug: bool = False) -> None:
        self.token = token
        # Enforce TLS unless explicitly using localhost for development
        self.server_url = _validate_secure_server(server_url)
        self.debug = debug
        self.websocket = None
        self.master_fd = None
        self.running = True
        
        # Terminal size
        self.rows = 24
        self.cols = 80
        
        # Monitoring
        self.monitoring_enabled = PSUTIL_AVAILABLE
        self.monitoring_interval = 60  # Send metrics every 60 seconds
        
        # Metrics collection counter (for Phase 2 query stats - collect every 5 cycles)
        self.metrics_cycle_count = 0
        
        # Optimization cycle counter (for EXPLAIN/schema collection - every 10 minutes = 10 cycles) - TESTING MODE
        self.optimization_cycle_count = 0
        
        # Disk monitoring
        self.last_disk_io = None
        self.last_disk_io_time = 0
        
        # Network monitoring
        self.last_net_io = None
        self.last_net_io_time = 0
        
        # Background tasks
        self.monitoring_task = None
        
        # MySQL monitoring - Load from config file with fallback to env vars
        config = load_config()
        self.mysql_enabled = config.get('mysql_enabled', False)
        self.mysql_host = config.get('mysql_host', 'localhost')
        self.mysql_user = config.get('mysql_user')
        self.mysql_password = config.get('mysql_password')
        self.mysql_port = config.get('mysql_port', 3306)
        self.mysql_monitor = None
        
        if self.mysql_enabled and MYSQL_AVAILABLE and self.mysql_user and self.mysql_password:
            self.mysql_monitor = MySQLMonitor(
                host=self.mysql_host,
                port=self.mysql_port,
                user=self.mysql_user,
                password=self.mysql_password,
                debug=self.debug,
                slow_threshold_ms=config.get('mysql_slow_threshold_ms', 200)
            )
        
        # Initialize REST API client for metrics (independent of WebSocket)
        self.api_client = MetricsAPIClient(server_url, token, debug)
        
    def log(self, message: str) -> None:
        """Log with timestamp"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}", flush=True)
        
    def debug_log(self, message: str) -> None:
        """Debug logging"""
        if self.debug:
            self.log(f"DEBUG: {message}")
    
    async def connect(self):
        """Main connection loop with auto-reconnect"""
        while self.running:
            try:
                self.log(f"Connecting to {self.server_url}...")
                uri = f"{self.server_url}?token={self.token}&agent_version={VERSION}"
                
                async with websockets.connect(
                    uri,
                    ping_interval=20,
                    ping_timeout=10
                ) as websocket:
                    self.websocket = websocket
                    self.log("✅ Connected to CLI Pal service")
                    
                    # Send initial handshake
                    await self.send_message({
                        'type': 'agent_hello',
                        'version': VERSION,
                        'hostname': os.uname().nodename,
                        'platform': sys.platform
                    })
                    
                    
                    # Send initial metrics
                    if self.monitoring_enabled:
                        self.log("📊 System monitoring enabled")
                        try:
                            await self.send_metrics()
                        except Exception as e:
                            self.log(f"⚠️  Error sending initial metrics: {e}")
                            import traceback
                            self.log(f"Traceback: {traceback.format_exc()}")
                        # Start monitoring loop in background
                        self.monitoring_task = asyncio.create_task(self.monitoring_loop())
                    else:
                        self.log("⚠️  System monitoring DISABLED - psutil not available")
                    
                    # MySQL monitoring status
                    if self.mysql_monitor:
                        self.log(f"📊 MySQL monitoring enabled (slow threshold: {self.mysql_monitor.slow_threshold_ms}ms)")
                        mysql_metrics = self.mysql_monitor.get_metrics()
                        if mysql_metrics and len(mysql_metrics) > 0:
                            self.log(f"  ✅ Connected to MySQL {mysql_metrics.get('mysql_version', 'unknown')}")
                        else:
                            self.log("  ⚠️  MySQL connection failed - check credentials/host/port (CLIPAL_MYSQL_*)")
                    elif self.mysql_enabled and not MYSQL_AVAILABLE:
                        self.log("⚠️  MySQL monitoring DISABLED - mysql-connector-python not available")
                    elif self.mysql_enabled:
                        self.log("⚠️  MySQL monitoring DISABLED - credentials not configured")
                    
                    # Handle messages
                    await self.message_loop()
                    
            except websockets.exceptions.ConnectionClosed:
                self.log("Connection closed by server")
            except Exception as e:
                self.log(f"Connection error: {e}")
            
            # Cancel background tasks
            if self.monitoring_task:
                self.monitoring_task.cancel()
                self.monitoring_task = None
            
            if self.running:
                self.log("Reconnecting in 5 seconds...")
                await asyncio.sleep(5)
    
    async def message_loop(self):
        """Main message handling loop"""
        try:
            async for message in self.websocket:
                try:
                    data = json.loads(message)
                    await self.handle_message(data)
                except json.JSONDecodeError:
                    self.log(f"Invalid JSON received: {message}")
                except Exception as e:
                    self.log(f"Error handling message: {e}")
        except Exception as e:
            self.debug_log(f"Message loop error: {e}")
    
    async def handle_message(self, data):
        """Handle incoming messages from server"""
        msg_type = data.get('type')
        
        if msg_type == 'start_shell':
            await self.start_shell(data.get('cols', 80), data.get('rows', 24))
        elif msg_type == 'command':
            await self.write_to_shell(data.get('data', ''))
        elif msg_type == 'resize':
            await self.resize_terminal(data.get('cols', 80), data.get('rows', 24))
        elif msg_type == 'ping':
            await self.send_message({'type': 'pong'})
        else:
            self.debug_log(f"Unknown message type: {msg_type}")
    
    async def start_shell(self, cols, rows):
        """Start a PTY shell with mandatory authentication
        
        Security: This method ALWAYS requires login authentication.
        There is no way to bypass authentication - no parameters, no flags.
        
        Args:
            cols: Terminal columns
            rows: Terminal rows
        """
        if self.master_fd is not None:
            self.log("Shell already running")
            return
        
        self.cols = cols
        self.rows = rows
        
        self.log(f"Starting authenticated shell ({cols}x{rows})...")
        
        # Fork a PTY
        pid, self.master_fd = pty.fork()
        
        if pid == 0:  # Child process
            # Set up environment
            os.environ['TERM'] = 'xterm-256color'
            os.environ['COLORTERM'] = 'truecolor'
            
            # SECURITY: Always start login program - requires username/password
            # Try common login paths (varies by Linux distribution)
            login_paths = ['/bin/login', '/usr/bin/login']
            login_found = False
            
            for login_path in login_paths:
                if os.path.exists(login_path):
                    try:
                        # Start login program
                        # login will prompt for username, then password
                        # After successful auth, it starts the user's shell
                        os.execv(login_path, [login_path])
                        login_found = True
                        break
                    except Exception as e:
                        # Log to stderr since we're in child process
                        print(f"Failed to start {login_path}: {e}", file=sys.stderr)
                        continue
            
            if not login_found:
                # Fallback: if login doesn't exist, use su
                # This still requires password
                print("⚠️  /bin/login not found, falling back to su", file=sys.stderr)
                if os.path.exists('/bin/su'):
                    os.execv('/bin/su', ['/bin/su', '-'])
                else:
                    # Last resort: Exit with error - do NOT start unauthenticated shell
                    print("❌ SECURITY ERROR: No authentication method available", file=sys.stderr)
                    print("❌ Cannot start shell without authentication", file=sys.stderr)
                    sys.exit(1)
        else:  # Parent process
            # Set terminal size
            self.set_terminal_size(self.master_fd, rows, cols)
            
            # Make fd non-blocking
            flags = fcntl.fcntl(self.master_fd, fcntl.F_GETFL)
            fcntl.fcntl(self.master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)
            
            # Start reading from shell
            asyncio.create_task(self.read_from_shell())
            
            self.log("✅ Login prompt started - authentication required")
    
    async def read_from_shell(self):
        """Read output from shell and send to server"""
        loop = asyncio.get_event_loop()
        
        while self.master_fd is not None and self.running:
            try:
                # Wait for data to be available
                readable, _, _ = select.select([self.master_fd], [], [], 0.1)
                
                if readable:
                    data = os.read(self.master_fd, 8192)
                    if data:
                        # Send to server
                        await self.send_message({
                            'type': 'output',
                            'data': data.decode('utf-8', errors='replace')
                        })
                    else:
                        # EOF - shell closed
                        self.log("Shell closed")
                        self.master_fd = None
                        break
                else:
                    # No data available, yield control
                    await asyncio.sleep(0.01)
                    
            except OSError as e:
                if e.errno == 5:  # EIO - process exited
                    self.log("Shell process exited")
                    self.master_fd = None
                    break
                else:
                    self.log(f"Error reading from shell: {e}")
                    await asyncio.sleep(0.1)
            except Exception as e:
                self.log(f"Unexpected error reading shell: {e}")
                break
    
    async def write_to_shell(self, data):
        """Write command to shell"""
        if self.master_fd is None:
            self.log("No shell running")
            return
        
        try:
            os.write(self.master_fd, data.encode('utf-8'))
        except Exception as e:
            self.log(f"Error writing to shell: {e}")
    
    async def resize_terminal(self, cols, rows):
        """Resize the terminal"""
        if self.master_fd is None:
            return
        
        self.cols = cols
        self.rows = rows
        self.set_terminal_size(self.master_fd, rows, cols)
        self.debug_log(f"Terminal resized to {cols}x{rows}")
    
    def set_terminal_size(self, fd, rows, cols):
        """Set PTY terminal size"""
        try:
            size = struct.pack('HHHH', rows, cols, 0, 0)
            fcntl.ioctl(fd, termios.TIOCSWINSZ, size)
        except Exception as e:
            self.log(f"Error setting terminal size: {e}")
    
    async def send_message(self, data):
        """Send JSON message to server"""
        if self.websocket:
            try:
                # Custom encoder to handle Decimal and datetime objects from MySQL
                class MySQLEncoder(json.JSONEncoder):
                    def default(self, obj):
                        if hasattr(obj, 'to_eng_string'):  # Check for Decimal-like objects
                            return float(obj)
                        if hasattr(obj, 'isoformat'):  # Handle datetime/date objects
                            return obj.isoformat()
                        if isinstance(obj, bytes):  # Handle bytes objects
                            return obj.decode('utf-8', errors='replace')
                        return super(MySQLEncoder, self).default(obj)
                
                await self.websocket.send(json.dumps(data, cls=MySQLEncoder))
            except Exception as e:
                self.log(f"Error sending message: {e}")  # Always log errors, not just debug
    
    def get_system_info(self):
        """Collect system information (OS, version, architecture, hostname, IP address)"""
        try:
            info = {
                'os_platform': platform.system().lower() or 'unknown',
                'os_version': self._get_os_version() or 'unknown',
                'architecture': platform.machine() or 'unknown',
                'hostname': (os.uname().nodename if hasattr(os, 'uname') else platform.node()) or 'unknown',
                'ip_address': self._get_ip_address() or 'unknown'
            }
            self.debug_log(f"Collected system info: OS={info['os_platform']}, Arch={info['architecture']}, Host={info['hostname']}, IP={info['ip_address']}")
            return info
        except Exception as e:
            self.log(f"Error collecting system info: {e}")
            return {
                'os_platform': sys.platform or 'unknown',
                'os_version': 'unknown',
                'architecture': 'unknown',
                'hostname': 'unknown',
                'ip_address': 'unknown'
            }
    
    def _get_ip_address(self):
        """Get the server's primary IP address"""
        try:
            # Method 1: Try to get IP by connecting to external address
            # This gets the IP that would be used for outbound connections
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                # Connect to a public DNS server (doesn't actually send data)
                s.connect(('8.8.8.8', 80))
                ip = s.getsockname()[0]
                s.close()
                return ip
            except Exception:
                s.close()
                raise
            
        except Exception:
            try:
                # Method 2: Get hostname and resolve it
                hostname = socket.gethostname()
                ip = socket.gethostbyname(hostname)
                # Filter out localhost
                if ip != '127.0.0.1' and not ip.startswith('127.'):
                    return ip
            except Exception:
                pass
            
            try:
                # Method 3: Try to get all IPs and pick the first non-loopback IPv4
                hostname = socket.gethostname()
                ip_list = socket.gethostbyname_ex(hostname)[2]
                for ip in ip_list:
                    if not ip.startswith('127.') and '.' in ip:
                        return ip
            except Exception:
                pass
            
            return None
    
    def _get_os_version(self):
        """Get OS version information"""
        try:
            if sys.platform.startswith('linux'):
                # Try to get Linux distribution info
                try:
                    import distro
                    return f"{distro.name()} {distro.version()}"
                except ImportError:
                    # Fallback to reading /etc/os-release
                    try:
                        with open('/etc/os-release', 'r') as f:
                            for line in f:
                                if line.startswith('PRETTY_NAME='):
                                    return line.split('=', 1)[1].strip().strip('"')
                    except:
                        pass
                return platform.release()
            elif sys.platform == 'darwin':
                return f"macOS {platform.mac_ver()[0]}"
            elif sys.platform.startswith('win'):
                return f"Windows {platform.release()}"
            else:
                return platform.release()
        except Exception:
            return platform.release()
    
    def get_failed_logins(self, max_entries: int = 100) -> list:
        """Fetch recent failed login attempts from system logs"""
        failed_logins = []
        
        if not sys.platform.startswith('linux'):
            self.debug_log("Failed logins: Not on Linux, skipping")
            return failed_logins
        
        log_files = [
            '/var/log/auth.log',
            '/var/log/secure',
            '/var/log/mail.log',
            '/var/log/maillog',
            '/var/log/mysql/error.log',
            '/var/log/mysqld.log',
            '/var/log/mariadb/mariadb.log',
        ]
        
        self.debug_log(f"Failed logins: Checking log files: {log_files}")
        
        patterns = [
            # SSH
            ('sshd', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)')),
            ('sshd', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)')),
            
            # Generic PAM
            ('pam', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*authentication failure.*user=(?P<user>\S+).*rhost=(?P<ip>[\d.]+)')),
            
            # vsftpd
            ('vsftpd', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*vsftpd.*FAIL LOGIN: Client "(?P<ip>[\d.]+)"')),
            
            # ProFTPD
            ('proftpd', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*proftpd.*\[(?P<ip>[\d.]+)\].*USER (?P<user>\S+): no such user found')),
            ('proftpd', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*proftpd.*\[(?P<ip>[\d.]+)\].*USER (?P<user>\S+): .*Incorrect password')),
            
            # Pure-FTPd
            ('pure-ftpd', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*pure-ftpd.*\(?(?P<user>\S+)@(?P<ip>[\d.]+)\)?.*Authentication failed')),

            # Dovecot
            ('dovecot', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*dovecot.*Aborted login.*user=<(?P<user>\S+)>.*rip=(?P<ip>[\d.]+)')),
            
            # Exim
            ('exim', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*exim.*authenticator failed for .* \[(?P<ip>[\d.]+)\].*')),

            # Postfix (SASL)
            ('postfix', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*postfix.*warning:.*\[(?P<ip>[\d.]+)\].*SASL.*authentication failed')),

            # MySQL / MariaDB
            # 2024-05-20T10:00:00.123456Z 123 [Note] Access denied for user 'root'@'1.2.3.4'
            ('mysql', re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z).*Access denied for user \'(?P<user>[^\']+)\'@\'(?P<ip>[\d.]+)\'')),
        ]
        
        try:
            for log_file in log_files:
                if not os.path.exists(log_file):
                    self.debug_log(f"Failed logins: {log_file} does not exist")
                    continue
                
                self.debug_log(f"Failed logins: Processing {log_file}")
                
                try:
                    # Use tail to get only the last 1000 lines (avoids loading massive logs)
                    # Use subprocess arguments compatible with Python 3.6+
                    cmd = ['tail', '-n', '1000', log_file]
                    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True, errors='replace')
                    
                    if result.returncode != 0:
                        self.debug_log(f"Failed logins: tail failed for {log_file}: {result.stderr}")
                        continue
                        
                    lines = result.stdout.splitlines()
                    self.debug_log(f"Failed logins: Read {len(lines)} lines from {log_file}")
                    
                    match_count = 0
                    for line in reversed(lines):
                        for service_name, pattern in patterns:
                            match = pattern.search(line)
                            if match:
                                match_count += 1
                                group_dict = match.groupdict()
                                timestamp_str = group_dict.get('timestamp')
                                username = group_dict.get('user', 'unknown')
                                ip_address = group_dict.get('ip', 'unknown')
                                
                                try:
                                    # Fallback service name from pattern
                                    service = service_name

                                    # Attempt to parse timestamp
                                    # Format 1: Syslog (Dec  7 10:00:00)
                                    # Format 2: ISO 8601 (2024-05-20T10:00:00.123456Z)
                                    
                                    attempt_time = None
                                    
                                    # Try Syslog format first
                                    try:
                                        current_year = datetime.now().year
                                        timestamp_with_year = f"{current_year} {timestamp_str}"
                                        attempt_time = datetime.strptime(timestamp_with_year, "%Y %b %d %H:%M:%S")
                                    except ValueError:
                                        pass
                                    
                                    # Try ISO format (MySQL) if Syslog failed
                                    if not attempt_time:
                                        try:
                                            # Clean up timestamp (remove Z, handle T)
                                            # 2024-05-20T10:00:00.123456Z -> 2024-05-20 10:00:00.123456
                                            ts_clean = timestamp_str.replace('T', ' ').replace('Z', '')
                                            attempt_time = datetime.strptime(ts_clean, "%Y-%m-%d %H:%M:%S.%f")
                                        except ValueError:
                                            pass
                                            
                                    if not attempt_time:
                                        raise ValueError(f"Unknown timestamp format: {timestamp_str}")

                                    
                                    failed_logins.append({
                                        'service': service,
                                        'username': username,
                                        'source_ip': ip_address,
                                        'attempt_time': attempt_time.isoformat()
                                    })
                                except Exception as e:
                                    self.debug_log(f"Failed logins: Error parsing timestamp '{timestamp_str}': {e}")
                                    # Fallback: Use current time to avoid losing data
                                    failed_logins.append({
                                        'service': service,
                                        'username': username,
                                        'source_ip': ip_address,
                                        'attempt_time': datetime.now().isoformat(),
                                        'timestamp_raw': timestamp_str,
                                        'parse_error': str(e)
                                    })
                                
                                if len(failed_logins) >= max_entries:
                                    self.debug_log(f"Failed logins: Reached max entries ({max_entries})")
                                    return failed_logins
                                break
                    
                    self.debug_log(f"Failed logins: Found {match_count} matches in {log_file}")
                        
                except PermissionError:
                    self.debug_log(f"No permission to read {log_file} - run agent with sudo for failed login tracking")
                    continue
                except Exception as e:
                    self.debug_log(f"Failed logins: Error reading {log_file}: {e}")
                    continue
        
        except Exception as e:
            self.log(f"Error fetching failed logins: {e}")
        
        self.debug_log(f"Failed logins: Returning {len(failed_logins)} total entries")
        return failed_logins
    
    def get_system_metrics(self) -> dict:
        """Collect current system metrics"""
        if not self.monitoring_enabled:
            return self.get_system_info()
        
        try:
            # CPU usage (non-blocking to avoid signal handler conflicts)
            cpu_percent = psutil.cpu_percent(interval=0) or 0.0
            
            # RAM usage
            ram = psutil.virtual_memory()
            ram_total_mb = ram.total / (1024 * 1024)  # Convert to MB
            ram_used_mb = ram.used / (1024 * 1024)
            ram_percent = ram.percent
            
            # Disk usage (Root partition)
            disk = psutil.disk_usage('/')
            disk_total_gb = disk.total / (1024 * 1024 * 1024)
            disk_used_gb = disk.used / (1024 * 1024 * 1024)
            disk_percent = disk.percent
            
            current_time = time.time()
            disk_io = psutil.disk_io_counters()
            
            iops_read = 0
            iops_write = 0
            
            if disk_io and self.last_disk_io and self.last_disk_io_time > 0:
                time_delta = current_time - self.last_disk_io_time
                if time_delta > 0:
                    iops_read = (disk_io.read_count - self.last_disk_io.read_count) / time_delta
                    iops_write = (disk_io.write_count - self.last_disk_io.write_count) / time_delta
            
            if disk_io:
                self.last_disk_io = disk_io
                self.last_disk_io_time = current_time
            
            net_io = psutil.net_io_counters()
            net_rx_kbps = 0
            net_tx_kbps = 0
            
            if net_io and self.last_net_io and self.last_net_io_time > 0:
                time_delta = current_time - self.last_net_io_time
                if time_delta > 0:
                    net_rx_kbps = (net_io.bytes_recv - self.last_net_io.bytes_recv) / 1024 / time_delta
                    net_tx_kbps = (net_io.bytes_sent - self.last_net_io.bytes_sent) / 1024 / time_delta
            
            if net_io:
                self.last_net_io = net_io
                self.last_net_io_time = current_time
            
            system_info = self.get_system_info()
            
            return {
                'cpu_usage': round(cpu_percent, 2),
                'ram_usage': round(ram_percent, 2),
                'ram_total_mb': int(ram_total_mb),
                'ram_used_mb': int(ram_used_mb),
                'disk_usage': round(disk_percent, 2),
                'disk_total_gb': round(disk_total_gb, 2),
                'disk_used_gb': round(disk_used_gb, 2),
                'iops_read': round(iops_read, 2),
                'iops_write': round(iops_write, 2),
                'net_rx_kbps': round(net_rx_kbps, 2),
                'net_tx_kbps': round(net_tx_kbps, 2),
                **system_info
            }
        except Exception as e:
            self.log(f"Error collecting system metrics: {e}")
            return self.get_system_info()
    
    async def send_metrics(self):
        """Send system metrics via REST API
        
        Metrics are sent via HTTP POST, independent of WebSocket connection.
        Server instructions in the response adjust collection intervals/features.
        """
        metrics = self.get_system_metrics()
        if not metrics:
            return
        
        # Increment metrics cycle counter
        self.metrics_cycle_count += 1
        
        # Fetch failed logins and include in metrics
        try:
            self.debug_log("Attempting to fetch failed logins...")
            failed_logins = self.get_failed_logins(max_entries=50)
            if failed_logins:
                metrics['failed_logins'] = failed_logins
                self.log(f"📛 Collected {len(failed_logins)} failed login attempts")
            else:
                self.debug_log("No failed logins found in system logs")
        except Exception as e:
            self.log(f"Error collecting failed logins: {e}")
        
        # Fetch MySQL metrics and include if available
        if self.mysql_monitor:
            try:
                self.debug_log("Collecting MySQL metrics...")
                mysql_metrics = self.mysql_monitor.get_metrics()
                if mysql_metrics:
                    # Extract deadlock info for separate handling
                    deadlock_info = mysql_metrics.pop('deadlock', None)
                    
                    metrics['mysql'] = mysql_metrics
                    self.debug_log(f"MySQL metrics collected: {len(mysql_metrics)} items")
                    
                    # Send deadlock via dedicated endpoint if detected
                    if deadlock_info:
                        try:
                            loop = asyncio.get_event_loop()
                            success = await loop.run_in_executor(
                                None, 
                                self.api_client.send_deadlock, 
                                deadlock_info
                            )
                            if success:
                                self.log(f"🔴 Sent deadlock event to API (fingerprint: {deadlock_info.get('query_pair_fingerprint', 'N/A')[:8]}...)")
                            else:
                                self.log("⚠️ Failed to send deadlock event via REST API")
                        except Exception as e:
                            self.log(f"Error sending deadlock event: {e}")
                    
                    # Query stats - use server instructions for interval (default every 5 cycles)
                    query_stats_cycles = self.api_client.instructions.get('query_stats_interval', 300) // 60
                    if self.metrics_cycle_count % query_stats_cycles == 0:
                        if self.api_client.instructions.get('collect_query_stats', True):
                            try:
                                self.debug_log("Collecting query stats from performance_schema...")
                                query_stats = self.mysql_monitor.get_query_stats()
                                if query_stats:
                                    metrics['mysql']['query_stats'] = query_stats
                                    self.log(f"📊 Collected {len(query_stats)} query stats from performance_schema")
                            except Exception as e:
                                self.log(f"Error collecting query stats: {e}")
                else:
                    metrics['mysql'] = {}
                    self.debug_log("MySQL metrics collection returned empty dict")
            except Exception as e:
                self.log(f"Error collecting MySQL metrics: {e}")
                metrics['mysql'] = {}
        
        # Send via REST API (in executor to not block event loop)
        loop = asyncio.get_event_loop()
        try:
            success = await loop.run_in_executor(None, self.api_client.send_metrics, metrics)
            if success:
                self.debug_log("Sent metrics via REST API")
            else:
                self.log("⚠️ Failed to send metrics via REST API")
        except Exception as e:
            self.log(f"Error sending metrics via REST API: {e}")
    
    async def monitoring_loop(self):
        """Periodically send system metrics via REST API
        
        Metrics collection runs independently of WebSocket connection.
        - Metrics: every cycle (60s default, configurable via server instructions)
        - EXPLAIN & Schema: every N cycles (based on server instructions, default 10 min)
        """
        while self.running:
            try:
                await asyncio.sleep(self.monitoring_interval)
                
                # Metrics collection (always runs, independent of WebSocket)
                if self.monitoring_enabled:
                    await self.send_metrics()
                
                # EXPLAIN & Schema collection based on server instructions
                self.optimization_cycle_count += 1
                explains_cycles = self.api_client.instructions.get('explains_interval', 600) // 60
                
                if self.optimization_cycle_count >= explains_cycles:
                    self.optimization_cycle_count = 0
                    
                    if self.mysql_monitor and self.api_client.instructions.get('collect_explains', True):
                        await self.collect_and_send_explains()
                    
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.debug_log(f"Monitoring loop error: {e}")
    
    async def collect_and_send_explains(self):
        """Collect EXPLAIN plans and schema, send via REST API"""
        self.log("🔍 Starting query optimization analysis...")
        
        query_stats = self.mysql_monitor.get_query_stats()
        if not query_stats:
            self.debug_log("No query stats available for EXPLAIN analysis")
            return
        
        explains, tables = self.mysql_monitor.get_query_explains(query_stats)
        
        if explains:
            loop = asyncio.get_event_loop()
            
            # Send EXPLAIN plans via REST API
            try:
                success = await loop.run_in_executor(
                    None, 
                    self.api_client.send_query_explains, 
                    explains
                )
                if success:
                    self.log(f"📊 Sent {len(explains)} EXPLAIN plans via REST API")
                else:
                    self.log("⚠️ Failed to send EXPLAIN plans via REST API")
            except Exception as e:
                self.log(f"Error sending EXPLAIN plans: {e}")
            
            # Send schema for involved tables via REST API
            if tables and self.api_client.instructions.get('collect_schema', True):
                schema_info = self.mysql_monitor.get_targeted_schema_info(tables)
                if schema_info:
                    tables_list = [[s, t] for s, t in tables]
                    try:
                        success = await loop.run_in_executor(
                            None,
                            self.api_client.send_schema_update,
                            schema_info,
                            tables_list
                        )
                        if success:
                            self.log(f"📋 Sent schema for {len(tables)} tables via REST API")
                        else:
                            self.log("⚠️ Failed to send schema via REST API")
                    except Exception as e:
                        self.log(f"Error sending schema: {e}")
        else:
            self.debug_log("No queries suitable for EXPLAIN analysis")
    

    def stop(self):
        """Gracefully stop the agent"""
        self.log("Shutting down...")
        self.running = False
        if self.master_fd:
            os.close(self.master_fd)


def main():
    # Load configuration from file (with fallback to env vars)
    config = load_config()
    
    parser = argparse.ArgumentParser(description='CLI Pal Agent')
    parser.add_argument('--token', help='Agent authentication token', 
                       default=config.get('token'))
    parser.add_argument('--server', help='WebSocket server URL (wss:// required; ws:// only for localhost dev)', 
                       default=config.get('server_url'))
    parser.add_argument('--debug', action='store_true', help='Enable debug logging')
    parser.add_argument('--version', action='version', version=f'CLI Pal Agent v{VERSION}')
    
    args = parser.parse_args()
    
    if not args.token:
        print("❌ ERROR: Token required but not found in config file.")
        print("")
        print(f"Please ensure {CONFIG_FILE} contains:")
        print("  api_key=YOUR_TOKEN_HERE")
        print("")
        print("Or reinstall the agent:")
        print("  curl -sSL https://clipal.me/install.sh | sudo bash -s -- --token=YOUR_TOKEN")
        sys.exit(1)
    
    # Validate secure connection (fails fast on non-TLS unless localhost dev)
    args.server = _validate_secure_server(args.server)
    
    # Create agent
    agent = CliPalAgent(args.token, args.server, args.debug)
    
    # Handle Ctrl+C gracefully
    def signal_handler(sig, frame):
        agent.stop()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Run agent
    try:
        asyncio.run(agent.connect())
    except KeyboardInterrupt:
        agent.stop()


if __name__ == '__main__':
    main()