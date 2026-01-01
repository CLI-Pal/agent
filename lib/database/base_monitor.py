"""
CLI Pal Agent - Database Base Monitor Module

Abstract base class for database monitoring implementations.
Defines the interface all database monitors must implement.
"""

import re
import hashlib
from abc import ABC, abstractmethod
from typing import Optional, Set, Tuple


class DatabaseMonitor(ABC):
    """Abstract base class for database monitoring

    All database monitors must implement these methods.
    """

    def __init__(self, host: str, port: int, user: str, password: str,
                 debug: bool, logger):
        """Initialize database monitor

        Args:
            host: Database host
            port: Database port
            user: Database username
            password: Database password
            debug: Enable debug logging
            logger: Logger instance
        """
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.debug = debug
        self.logger = logger
        self.enabled = False

    @abstractmethod
    def get_metrics(self) -> dict:
        """Collect database metrics

        Returns:
            dict: Database metrics
        """
        pass

    @abstractmethod
    def get_query_stats(self, watched_digests: Optional[Set[str]] = None) -> list:
        """Collect query statistics

        Args:
            watched_digests: Set of query digests to always include

        Returns:
            list: List of query statistics dicts
        """
        pass

    @abstractmethod
    def get_query_explains(self, query_digests: list) -> Tuple[list, set]:
        """Run EXPLAIN on queries and extract table names

        Args:
            query_digests: List of query digest dicts

        Returns:
            Tuple of (explains_list, tables_set)
        """
        pass

    @abstractmethod
    def get_targeted_schema_info(self, tables: set) -> dict:
        """Collect indexes and columns for specified tables

        Args:
            tables: Set of (schema_name, table_name) tuples

        Returns:
            dict: Schema info with 'indexes' and 'columns'
        """
        pass

    def is_valid_query_for_optimization(self, query: str) -> Tuple[bool, str]:
        """Check if query is valid for optimization analysis

        Args:
            query: SQL query string

        Returns:
            tuple: (is_valid: bool, reason: str)
        """
        if not query:
            return False, "Empty query"

        query_upper = query.upper()

        # Check for SQL_NO_CACHE
        has_no_cache = 'SQL_NO_CACHE' in query_upper

        if not has_no_cache:
            return True, ""

        # SQL_NO_CACHE present - check for WHERE clause
        if query_upper.strip().startswith('SELECT'):
            has_where = 'WHERE' in query_upper

            if not has_where:
                query_trimmed = query.rstrip()

                valid_endings = (';', 'LIMIT ?', '`', "'")
                valid_clause_patterns = ['LIMIT ?', 'LIMIT ?, ?', 'ORDER BY ?', 'GROUP BY ?']

                ends_properly = (
                    query_trimmed.endswith(valid_endings) or
                    any(query_trimmed.endswith(pattern) for pattern in valid_clause_patterns)
                )

                if not ends_properly:
                    return False, "SQL_NO_CACHE + no WHERE + appears truncated"
                else:
                    return False, "SQL_NO_CACHE + no WHERE (system query)"
            else:
                return True, ""

        return True, ""

    def normalize_query_for_fingerprint(self, query: str) -> str:
        """Normalize query for fingerprinting - strip literals

        Example:
            'SELECT * FROM users WHERE id = 123'
            becomes:
            'SELECT * FROM USERS WHERE ID = ?'

        Args:
            query: SQL query string

        Returns:
            str: Normalized query
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

    def generate_query_fingerprint(self, query: str) -> str:
        """Generate MD5 fingerprint of normalized query

        Args:
            query: SQL query string

        Returns:
            str: MD5 hash (32 chars)
        """
        normalized = self.normalize_query_for_fingerprint(query)
        return hashlib.md5(normalized.encode()).hexdigest()
