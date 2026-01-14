"""
CLI Pal Agent - Configuration Module

Handles loading and validation of agent configuration.
"""

import os
import sys

# Default configuration file path
CONFIG_FILE = "/opt/clipal/clipal.conf"


class ConfigError(Exception):
    """Configuration error"""
    pass


def load_config(config_file: str = None) -> dict:
    """Load and validate configuration from file

    Args:
        config_file: Path to config file (defaults to /opt/clipal/clipal.conf)

    Returns:
        dict: Configuration with all keys and defaults applied

    Raises:
        ConfigError: If config is invalid or missing required fields
    """
    config_path = config_file or CONFIG_FILE

    if not os.path.exists(config_path):
        print(f"Error: Configuration file not found: {config_path}")
        print()
        print("The config file is required to run the agent.")
        print("Please install the agent using:")
        print("  curl -sSL https://clipal.me/install.sh | sudo bash -s -- --token=YOUR_TOKEN")
        sys.exit(1)

    config = _parse_config_file(config_path)
    config = _apply_defaults(config)
    _validate_config(config)

    print(f"Loaded configuration from {config_path}")
    return config


def _parse_config_file(filepath: str) -> dict:
    """Parse key=value config file

    Args:
        filepath: Path to config file

    Returns:
        dict: Raw configuration values
    """
    config = {}

    try:
        with open(filepath, 'r') as f:
            for line in f:
                line = line.strip()
                # Skip comments and empty lines
                if not line or line.startswith('#'):
                    continue
                # Parse key=value
                if '=' in line:
                    key, value = line.split('=', 1)
                    config[key.strip()] = value.strip()
    except Exception as e:
        print(f"Error: Could not read config file {filepath}: {e}")
        print("Please check file permissions and format")
        sys.exit(1)

    return config


def _apply_defaults(config: dict) -> dict:
    """Apply default values for optional settings

    Args:
        config: Raw configuration from file

    Returns:
        dict: Configuration with defaults applied
    """
    return {
        # Agent connection
        'token': config.get('api_key', ''),
        'server_url': config.get('server_url', 'wss://app.clipal.me/ws'),
        'debug': config.get('debug', 'false').lower() == 'true',

        # Database type (explicit setting from install)
        'db_type': config.get('db_type', 'none'),

        # MySQL settings
        'mysql_enabled': config.get('mysql_enabled', 'false').lower() == 'true',
        'mysql_host': config.get('mysql_host', 'localhost'),
        'mysql_port': int(config.get('mysql_port', '3306')),
        'mysql_user': config.get('mysql_user', ''),
        'mysql_password': config.get('mysql_password', ''),
        'mysql_cnf_file': config.get('mysql_cnf_file', ''),
        'mysql_slow_threshold_ms': int(config.get('mysql_slow_threshold_ms', '200')),

        # PostgreSQL settings (for future)
        'pg_enabled': config.get('pg_enabled', 'false').lower() == 'true',
        'pg_host': config.get('pg_host', 'localhost'),
        'pg_port': int(config.get('pg_port', '5432')),
        'pg_user': config.get('pg_user', ''),
        'pg_password': config.get('pg_password', ''),
        'pg_database': config.get('pg_database', 'postgres'),
        'pg_slow_threshold_ms': int(config.get('pg_slow_threshold_ms', '200')),

        # PHP-FPM settings (optional)
        # Native FastCGI socket connection (no web server proxy needed)
        'php_enabled': config.get('php_enabled', 'false').lower() == 'true',
        # Socket URI: unix:///var/run/php-fpm.sock or tcp://127.0.0.1:9000
        'php_fpm_socket': config.get('php_fpm_socket', ''),
        'php_fpm_status_path': config.get('php_fpm_status_path', '/status'),
        'php_fpm_slow_log': config.get('php_fpm_slow_log', ''),
        # Multi-pool config: JSON array like:
        # [{"name":"www","socket":"unix:///var/run/php-fpm.sock","status_path":"/status","slow_log":"/var/log/php-fpm/www-slow.log"}]
        'php_fpm_pools': config.get('php_fpm_pools', ''),
        # Legacy HTTP URL (deprecated - triggers migration warning)
        'php_fpm_status_url': config.get('php_fpm_status_url', ''),
    }


def _validate_config(config: dict) -> None:
    """Validate required configuration

    Args:
        config: Configuration dict to validate

    Raises:
        ConfigError: If required fields are missing
    """
    if not config.get('token'):
        raise ConfigError("API token is required in configuration")

    if not config.get('server_url'):
        raise ConfigError("Server URL is required in configuration")


def validate_secure_server(server_url: str) -> str:
    """Enforce TLS for remote connections (allow plain WS only for localhost)

    Args:
        server_url: WebSocket server URL

    Returns:
        The server_url unchanged if valid

    Raises:
        SystemExit: If URL is insecure
    """
    if not server_url:
        print("ERROR: Server URL is required")
        sys.exit(1)

    if server_url.startswith("wss://"):
        return server_url

    # Allow plain WS only for explicit local development
    allowed_plain = ("ws://localhost", "ws://127.0.0.1")
    if any(server_url.startswith(prefix) for prefix in allowed_plain):
        return server_url

    print("=" * 60)
    print("ERROR: Insecure WebSocket connection blocked")
    print(f"   Server: {server_url}")
    print("   Plain ws:// is not allowed. Use wss:// (TLS) or localhost for dev.")
    print("   Example: wss://app.clipal.me/ws")
    print("=" * 60)
    sys.exit(1)
