"""
CLI Pal Agent - Database Module

Factory for creating database monitors based on configuration.
"""

from .base_monitor import DatabaseMonitor

# Import available monitors
try:
    from .mysql_monitor import MySQLMonitor
    MYSQL_MONITOR_AVAILABLE = True
except ImportError:
    MYSQL_MONITOR_AVAILABLE = False

# PostgreSQL (future)
# try:
#     from .postgres_monitor import PostgreSQLMonitor
#     POSTGRESQL_MONITOR_AVAILABLE = True
# except ImportError:
#     POSTGRESQL_MONITOR_AVAILABLE = False


class NullMonitor(DatabaseMonitor):
    """No-op monitor when database monitoring is disabled"""

    def __init__(self, logger):
        self.logger = logger
        self.enabled = False

    def get_metrics(self) -> dict:
        return {}

    def get_query_stats(self, watched_digests=None) -> list:
        return []

    def get_query_explains(self, query_digests: list) -> tuple:
        return [], set()

    def get_targeted_schema_info(self, tables: set) -> dict:
        return {}

    def check_for_deadlock(self, current_status: dict) -> dict:
        return None


def create_database_monitor(config: dict, logger):
    """Factory function to create appropriate database monitor

    Database type should be explicitly set in config during installation.
    No auto-detection at runtime - keeps agent simple and reliable.

    Args:
        config: Configuration dict (must include 'db_type' or 'mysql_enabled')
        logger: Logger instance

    Returns:
        DatabaseMonitor: Appropriate monitor or NullMonitor if disabled
    """
    db_type = config.get('db_type', 'none')

    # Legacy support: check mysql_enabled flag
    if db_type == 'none' and config.get('mysql_enabled', False):
        db_type = 'mysql'

    # Create appropriate monitor based on explicit config
    if db_type == 'mysql' and MYSQL_MONITOR_AVAILABLE:
        mysql_user = config.get('mysql_user', '')
        mysql_password = config.get('mysql_password', '')

        if mysql_user and mysql_password:
            logger.info("Creating MySQL monitor", always=True)
            return MySQLMonitor(
                host=config.get('mysql_host', 'localhost'),
                port=config.get('mysql_port', 3306),
                user=mysql_user,
                password=mysql_password,
                debug=config.get('debug', False),
                slow_threshold_ms=config.get('mysql_slow_threshold_ms', 200),
                logger=logger.create_child("MySQL")
            )
        else:
            logger.warn("MySQL credentials not configured - monitoring disabled")
            return NullMonitor(logger)

    # elif db_type == 'postgresql' and POSTGRESQL_MONITOR_AVAILABLE:
    #     return PostgreSQLMonitor(...)

    else:
        # Return null monitor (disabled or invalid type)
        if db_type not in ['none', 'mysql', 'postgresql', '']:
            logger.warn(f"Unknown db_type '{db_type}' - monitoring disabled")
        else:
            logger.info(f"Database monitoring disabled (db_type={db_type})")
        return NullMonitor(logger)
