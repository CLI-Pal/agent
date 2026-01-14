#!/bin/bash
set -e

# CLI Pal Agent Installation Script
# Usage: 
#   MySQL:      curl -sSL https://clipal.me/install.sh | sudo bash -s -- --token=YOUR_TOKEN --mysql-root-password=PASSWORD [--enable-performance-schema]
#   PostgreSQL: curl -sSL https://clipal.me/install.sh | sudo bash -s -- --token=YOUR_TOKEN --pg-superuser-password=PASSWORD
#   PHP-FPM:    curl -sSL https://clipal.me/install.sh | sudo bash -s -- --token=YOUR_TOKEN --enable-php-monitoring
#   No DB:      curl -sSL https://clipal.me/install.sh | sudo bash -s -- --token=YOUR_TOKEN --db-type=none
#   Uninstall:  curl -sSL https://clipal.me/install.sh | sudo bash -s -- uninstall

INSTALL_DIR="/opt/clipal"
BIN_PATH="/usr/local/bin/clipal-agent"
SERVICE_FILE="/etc/systemd/system/clipal-agent.service"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Uninstall function
uninstall_agent() {
    log_info "Uninstalling CLI Pal Agent..."
    
    # Check if running as root
    if [ "$EUID" -ne 0 ]; then 
        log_error "Please run as root (use sudo)"
        exit 1
    fi
    
    # Stop and disable service
    if systemctl is-active --quiet clipal-agent 2>/dev/null; then
        log_info "Stopping service..."
        systemctl stop clipal-agent
    fi
    
    if systemctl is-enabled --quiet clipal-agent 2>/dev/null; then
        log_info "Disabling service..."
        systemctl disable clipal-agent
    fi
    
    # Remove service file
    if [ -f "$SERVICE_FILE" ]; then
        log_info "Removing service file..."
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
    fi
    
    # Remove binary
    if [ -f "$BIN_PATH" ]; then
        log_info "Removing binary..."
        rm -f "$BIN_PATH"
    fi
    
    # Remove installation directory
    if [ -d "$INSTALL_DIR" ]; then
        log_info "Removing installation directory..."
        rm -rf "$INSTALL_DIR"
    fi
    
    log_info "✅ CLI Pal Agent has been completely uninstalled!"
    echo ""
    echo "Removed:"
    echo "  - Agent binary ($BIN_PATH)"
    echo "  - Systemd service ($SERVICE_FILE)"
    echo "  - Installation directory ($INSTALL_DIR)"
    echo "  - Configuration file ($INSTALL_DIR/clipal.conf)"
    echo ""
    echo "Note: The 'clipal' MySQL user was NOT removed."
    echo "To remove it manually, run:"
    echo "  mysql -u root -p -e \"DROP USER IF EXISTS 'clipal'@'localhost';\""
    echo ""
    echo "Thank you for using CLI Pal. We're sorry to see you go!"
    echo "If you experienced any issues, please let us know at hello@clipal.me"
    exit 0
}

# Check for uninstall command (check all arguments, not just $1)
for arg in "$@"; do
    if [ "$arg" = "uninstall" ]; then
        uninstall_agent
    fi
done

# Parse arguments for installation
TOKEN=""
SERVER_URL="${WS_SERVER:-wss://app.clipal.me/ws}"
DB_TYPE=""  # Will be set based on flags or explicit --db-type
MYSQL_ROOT_PASSWORD=""
MYSQL_USER=""
MYSQL_PASSWORD=""
MYSQL_HOST="localhost"
MYSQL_PORT="3306"
ENABLE_PERFORMANCE_SCHEMA="false"
PG_SUPERUSER_PASSWORD=""
PG_USER=""
PG_PASSWORD=""
PG_HOST="localhost"
PG_PORT="5432"
PG_DATABASE="postgres"

# PHP-FPM monitoring
PHP_ENABLED="false"
PHP_FPM_SOCKET=""
PHP_FPM_STATUS_PATH="/status"
PHP_FPM_SLOW_LOG=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --token=*)
            TOKEN="${1#*=}"
            shift
            ;;
        --server=*)
            SERVER_URL="${1#*=}"
            shift
            ;;
        --db-type=*)
            DB_TYPE="${1#*=}"
            shift
            ;;
        --mysql-root-password=*)
            MYSQL_ROOT_PASSWORD="${1#*=}"
            shift
            ;;
        --mysql-user=*)
            MYSQL_USER="${1#*=}"
            shift
            ;;
        --mysql-password=*)
            MYSQL_PASSWORD="${1#*=}"
            shift
            ;;
        --mysql-host=*)
            MYSQL_HOST="${1#*=}"
            shift
            ;;
        --mysql-port=*)
            MYSQL_PORT="${1#*=}"
            shift
            ;;
        --enable-performance-schema)
            ENABLE_PERFORMANCE_SCHEMA="true"
            shift
            ;;
        --pg-superuser-password=*)
            PG_SUPERUSER_PASSWORD="${1#*=}"
            shift
            ;;
        --pg-user=*)
            PG_USER="${1#*=}"
            shift
            ;;
        --pg-password=*)
            PG_PASSWORD="${1#*=}"
            shift
            ;;
        --pg-host=*)
            PG_HOST="${1#*=}"
            shift
            ;;
        --pg-port=*)
            PG_PORT="${1#*=}"
            shift
            ;;
        --pg-database=*)
            PG_DATABASE="${1#*=}"
            shift
            ;;
        --enable-php-monitoring)
            PHP_ENABLED="true"
            shift
            ;;
        --php-socket=*)
            PHP_FPM_SOCKET="${1#*=}"
            shift
            ;;
        --php-status-path=*)
            PHP_FPM_STATUS_PATH="${1#*=}"
            shift
            ;;
        --php-slow-log=*)
            PHP_FPM_SLOW_LOG="${1#*=}"
            shift
            ;;
        --dev)
            INSTALL_DEV="true"
            shift
            ;;
        uninstall)
            # Already handled above
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# Validate --db-type if provided
if [ -n "$DB_TYPE" ] && [ "$DB_TYPE" != "mysql" ] && [ "$DB_TYPE" != "postgresql" ] && [ "$DB_TYPE" != "none" ]; then
    log_error "Invalid --db-type: $DB_TYPE"
    log_error "Valid options: mysql, postgresql, none"
    exit 1
fi

# Infer db_type from credentials if not explicitly set
if [ -z "$DB_TYPE" ]; then
    if [ -n "$MYSQL_ROOT_PASSWORD" ] || [ -n "$MYSQL_USER" ]; then
        DB_TYPE="mysql"
    elif [ -n "$PG_SUPERUSER_PASSWORD" ] || [ -n "$PG_USER" ]; then
        DB_TYPE="postgresql"
    else
        DB_TYPE="none"
    fi
fi

log_info "Database type: $DB_TYPE"

# Validate token (only needed for installation, not uninstall)
if [ -z "$TOKEN" ]; then
    log_error "Token is required!"
    echo "Usage: $0 --token=YOUR_TOKEN [--server=wss://your-server.com/ws] [--dev]"
    exit 1
fi

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    log_error "Please run as root (use sudo)"
    exit 1
fi

# Check for existing installation
if [ -f "$SERVICE_FILE" ] || [ -f "$BIN_PATH" ] || [ -d "$INSTALL_DIR" ]; then
    log_warn "Existing CLI Pal Agent installation detected"
    log_info "This will reinstall and update the agent with new credentials"
    echo ""

    # Stop the service before updating to avoid file lock issues
    if systemctl is-active --quiet clipal-agent 2>/dev/null; then
        log_info "Stopping existing service..."
        systemctl stop clipal-agent
    fi
fi

log_info "Installing CLI Pal Agent..."

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
    VERSION_ID=$VERSION_ID
else
    log_error "Cannot detect OS"
    exit 1
fi

log_info "Detected OS: $OS $VERSION_ID"

# Install dependencies
log_info "Installing dependencies..."

case $OS in
    ubuntu|debian)
        apt-get update -qq
        apt-get install -y python3 python3-pip > /dev/null
        ;;
    centos|rhel|fedora)
        yum install -y python3 python3-pip > /dev/null
        ;;
    *)
        log_warn "Unknown OS. Assuming Python 3 is installed..."
        ;;
esac

# Install Python dependencies
log_info "Installing Python dependencies..."
REQUIRED_PACKAGES="websockets psutil"

# Add MySQL connector if MySQL monitoring is enabled
if [ "$DB_TYPE" = "mysql" ]; then
    REQUIRED_PACKAGES="$REQUIRED_PACKAGES mysql-connector-python"
fi

# Add PostgreSQL connector if PostgreSQL monitoring is enabled
if [ "$DB_TYPE" = "postgresql" ]; then
    REQUIRED_PACKAGES="$REQUIRED_PACKAGES psycopg2-binary"
fi

PIP_ROOT_USER_ACTION=ignore pip3 install $REQUIRED_PACKAGES --quiet || PIP_ROOT_USER_ACTION=ignore python3 -m pip install $REQUIRED_PACKAGES --quiet

# Setup MySQL monitoring user if root password provided
if [ -n "$MYSQL_ROOT_PASSWORD" ]; then
    log_info "Setting up MySQL monitoring..."
    
    # Check if MySQL is accessible
    if ! command -v mysql &> /dev/null; then
        log_warn "MySQL client not found. Skipping MySQL setup."
        log_info "Install MySQL client or use --mysql-user/--mysql-password instead"
    else
        # Verify MySQL root password works before proceeding
        log_info "Verifying MySQL root access..."
        
        # Auto-detect MySQL socket path (varies by distribution)
        MYSQL_SOCKET=""
        COMMON_SOCKETS=(
            "/var/run/mysqld/mysqld.sock"
            "/var/lib/mysql/mysql.sock"
            "/tmp/mysql.sock"
            "/run/mysqld/mysqld.sock"
        )
        
        for sock in "${COMMON_SOCKETS[@]}"; do
            if [ -S "$sock" ]; then
                MYSQL_SOCKET="$sock"
                log_info "Found MySQL socket: $MYSQL_SOCKET"
                break
            fi
        done
        
        # If socket not found, try to detect via mysqladmin
        if [ -z "$MYSQL_SOCKET" ] && command -v mysqladmin &> /dev/null; then
            DETECTED_SOCKET=$(mysqladmin variables 2>/dev/null | grep "socket" | awk '{print $4}')
            if [ -n "$DETECTED_SOCKET" ] && [ -S "$DETECTED_SOCKET" ]; then
                MYSQL_SOCKET="$DETECTED_SOCKET"
                log_info "Detected MySQL socket via mysqladmin: $MYSQL_SOCKET"
            fi
        fi
        
        # Create temporary config file for root connection
        MYSQL_ROOT_CNF=$(mktemp)
        chmod 600 "$MYSQL_ROOT_CNF"
        
        # Build config with socket if found
        echo "[client]" > "$MYSQL_ROOT_CNF"
        echo "user=root" >> "$MYSQL_ROOT_CNF"

        # Safe password handling:
        # 1. Escape backslashes first (replace \ with \\)
        # 2. Escape double quotes (replace " with \")
        # 3. Write as quoted string: password="..."
        ESCAPED_PWD="${MYSQL_ROOT_PASSWORD//\\/\\\\}"
        ESCAPED_PWD="${ESCAPED_PWD//\"/\\\"}"
        echo "password=\"$ESCAPED_PWD\"" >> "$MYSQL_ROOT_CNF"

        echo "host=$MYSQL_HOST" >> "$MYSQL_ROOT_CNF"
        echo "port=$MYSQL_PORT" >> "$MYSQL_ROOT_CNF"
        
        # Add socket path if we found it (only for localhost connections)
        if [ -n "$MYSQL_SOCKET" ] && [ "$MYSQL_HOST" = "localhost" ]; then
            echo "socket=$MYSQL_SOCKET" >> "$MYSQL_ROOT_CNF"
        fi
        
        # Test root connection
        set +e
        ROOT_TEST=$(mysql --defaults-file="$MYSQL_ROOT_CNF" -e "SELECT 1" 2>&1)
        ROOT_EXIT=$?
        set -e
        
        if [ $ROOT_EXIT -ne 0 ]; then
            log_error "Failed to connect to MySQL as root"
            log_error "Error: $ROOT_TEST"
            log_error "Please verify:"
            log_error "  - MySQL is running"
            log_error "  - Root password is correct"
            log_error "  - MySQL is listening on $MYSQL_HOST:$MYSQL_PORT"
            rm -f "$MYSQL_ROOT_CNF"
            exit 1
        fi
        
        log_info "✅ MySQL root connection verified"
        
        # Generate secure random password for clipal user
        # Generate secure alphanumeric password using Python (avoids special char issues)
        MYSQL_PASSWORD=$(python3 -c "import secrets,string; print(''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(32)))")
        MYSQL_USER="clipal"
        
        log_info "Creating MySQL monitoring user '$MYSQL_USER'@'localhost'..."
        
        # Create or update user with comprehensive permissions
        # Use CREATE USER IF NOT EXISTS, then ALTER USER to ensure password is always set correctly
        set +e
        CREATE_OUT=$(mysql --defaults-file="$MYSQL_ROOT_CNF" 2>&1 <<EOF
-- Create monitoring user (if not exists)
CREATE USER IF NOT EXISTS '$MYSQL_USER'@'localhost';

-- Always set/update the password (works even if user exists)
ALTER USER '$MYSQL_USER'@'localhost' IDENTIFIED BY '$MYSQL_PASSWORD';

-- Core monitoring permissions
GRANT PROCESS ON *.* TO '$MYSQL_USER'@'localhost';
GRANT REPLICATION CLIENT ON *.* TO '$MYSQL_USER'@'localhost';
GRANT SHOW VIEW ON *.* TO '$MYSQL_USER'@'localhost';

-- Global SELECT for database structure and statistics
GRANT SELECT ON *.* TO '$MYSQL_USER'@'localhost';

-- Performance Schema access for query optimization
GRANT SELECT ON performance_schema.events_statements_summary_by_digest TO '$MYSQL_USER'@'localhost';
GRANT SELECT ON performance_schema.table_io_waits_summary_by_index_usage TO '$MYSQL_USER'@'localhost';
GRANT SELECT ON performance_schema.file_summary_by_instance TO '$MYSQL_USER'@'localhost';

FLUSH PRIVILEGES;
EOF
)
        CREATE_EXIT=$?
        set -e
        
        if [ $CREATE_EXIT -eq 0 ]; then
            log_info "✅ MySQL monitoring user created successfully"
            
            # Verify the user can actually connect with the generated password
            # Wait a moment for privileges to propagate
            sleep 1
            
            log_info "Verifying MySQL connection..."
            # Create a temporary MySQL config file to avoid shell escaping issues
            MYSQL_CNF=$(mktemp)
            chmod 600 "$MYSQL_CNF"
            cat > "$MYSQL_CNF" <<CNFEOF
[client]
user=$MYSQL_USER
password=$MYSQL_PASSWORD
host=$MYSQL_HOST
port=$MYSQL_PORT
CNFEOF
            
            # Add socket path if we found it (only for localhost connections)
            if [ -n "$MYSQL_SOCKET" ] && [ "$MYSQL_HOST" = "localhost" ]; then
                echo "socket=$MYSQL_SOCKET" >> "$MYSQL_CNF"
            fi
            
            # Test connection using the config file (disable set -e to prevent silent exit)
            set +e
            VERIFY_OUT=$(mysql --defaults-file="$MYSQL_CNF" -e "SELECT 1" 2>&1)
            VERIFY_EXIT=$?
            set -e
            
            if [ $VERIFY_EXIT -eq 0 ]; then
                log_info "✅ MySQL connection verified successfully"
            else
                log_warn "⚠️  Warning: Could not verify MySQL connection with generated password"
                log_warn "   Error: $VERIFY_OUT"
                log_warn "   The agent will still attempt to connect - check logs after installation"
            fi
            rm -f "$MYSQL_CNF"
            
            log_info "Checking for MySQL 8.0+ features..."
            
            # Try to grant SYSTEM_VARIABLES_ADMIN for MySQL 8.0+ (will fail gracefully on 5.x)
            # We temporarily disable set -e to ensure this doesn't crash the script on MariaDB/Old MySQL
            set +e
            GRANT_OUT=$(mysql --defaults-file="$MYSQL_ROOT_CNF" 2>&1 <<EOFSQL
GRANT SYSTEM_VARIABLES_ADMIN ON *.* TO '$MYSQL_USER'@'localhost';
FLUSH PRIVILEGES;
EOFSQL
)
            MYSQL_EXIT_CODE=$?
            set -e
            
            if [ $MYSQL_EXIT_CODE -eq 0 ]; then
                log_info "✅ MySQL 8.0+ permissions granted"
            else
                # Check if it was a permission error or syntax error (version mismatch)
                if [[ "$GRANT_OUT" == *"syntax"* ]] || [[ "$GRANT_OUT" == *"You have an error"* ]]; then
                     log_info "ℹ️  MySQL 5.x/MariaDB detected (skipping 8.0+ permissions)"
                else
                     log_warn "ℹ️  Could not grant MySQL 8.0+ permissions: $GRANT_OUT"
                fi
            fi
            
        else
            log_error "Failed to create MySQL user"
            log_error "Error: $CREATE_OUT"
            log_error "Please check your MySQL root password or create the user manually"
            log_info "Manual setup: https://clipal.me/downloads/setup-mysql.sql"
            MYSQL_USER=""
            MYSQL_PASSWORD=""
            # Clean up root config file
            rm -f "$MYSQL_ROOT_CNF"
        fi
        
        # Enable performance_schema if requested
        if [ "$ENABLE_PERFORMANCE_SCHEMA" = "true" ] && [ -n "$MYSQL_ROOT_CNF" ]; then
            log_info "Enabling MySQL performance_schema..."
            
            # Detect MySQL/MariaDB service
            if systemctl is-active --quiet mariadb; then
                DB_SERVICE="mariadb"
                DB_NAME="MariaDB"
            elif systemctl is-active --quiet mysql; then
                DB_SERVICE="mysql"
                DB_NAME="MySQL"
            else
                log_warn "Could not detect MySQL/MariaDB service - skipping performance_schema"
                DB_SERVICE=""
            fi
            
            if [ -n "$DB_SERVICE" ]; then
                # Detect MySQL config file (using same logic as enable-performance-schema.sh)
                DETECTED_CONFIGS=$(mysqld --help --verbose 2>/dev/null | grep -A 1 "Default options are read from" | tail -n 1)
                
                MYSQL_CNF_FILE=""
                if [ -n "$DETECTED_CONFIGS" ]; then
                    # Parse and select best writable file in /etc
                    for config_path in $DETECTED_CONFIGS; do
                        if [ -f "$config_path" ] && [ -w "$config_path" ] && [[ "$config_path" == /etc/* ]]; then
                            MYSQL_CNF_FILE="$config_path"
                            break
                        fi
                    done
                    
                    # Fallback to conf.d directory if no writable file found
                    if [ -z "$MYSQL_CNF_FILE" ]; then
                        for dir in "/etc/mysql/mariadb.conf.d" "/etc/mysql/mysql.conf.d" "/etc/mysql/conf.d" "/etc/my.cnf.d"; do
                            if [ -d "$dir" ] && [ -w "$dir" ]; then
                                MYSQL_CNF_FILE="$dir/99-clipal.cnf"
                                log_info "Creating new config file: $MYSQL_CNF_FILE"
                                break
                            fi
                        done
                    fi
                fi
                
                if [ -z "$MYSQL_CNF_FILE" ]; then
                    log_warn "Could not detect MySQL config file - skipping performance_schema"
                    log_info "You can enable it manually later with: bash enable-performance-schema.sh"
                else
                    log_info "Detected MySQL config: $MYSQL_CNF_FILE"
                    
                    # Check if already enabled
                    CURRENT_PS=$(mysql --defaults-file="$MYSQL_ROOT_CNF" -Nse "SELECT @@performance_schema" 2>/dev/null || echo "0")
                    
                    # Check current values
                    CURRENT_PS_DIGEST=$(mysql --defaults-file="$MYSQL_ROOT_CNF" -Nse "SELECT @@performance_schema_max_digest_length" 2>/dev/null || echo "1024")
                    CURRENT_PS_SQL=$(mysql --defaults-file="$MYSQL_ROOT_CNF" -Nse "SELECT @@performance_schema_max_sql_text_length" 2>/dev/null || echo "1024")
                    CURRENT_GLOBAL_DIGEST=$(mysql --defaults-file="$MYSQL_ROOT_CNF" -Nse "SELECT @@max_digest_length" 2>/dev/null || echo "1024")

                    if [ "$CURRENT_PS" = "1" ]; then
                        log_info "✅ Performance schema already enabled"
                        
                        # Check if limits need to be increased
                        if [ "$CURRENT_PS_DIGEST" -lt 8096 ] || [ "$CURRENT_PS_SQL" -lt 8096 ] || [ "$CURRENT_GLOBAL_DIGEST" -lt 8096 ]; then
                            log_info "Updating Performance Schema limits to 8096..."
                            
                            # Backup existing config file
                            if [ -f "$MYSQL_CNF_FILE" ]; then
                                cp "$MYSQL_CNF_FILE" "${MYSQL_CNF_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
                            fi
                            
                            # Helper to update or add a variable
                            update_mysql_var() {
                                local var_name=$1
                                local var_val=$2
                                local conf_file=$3
                                
                                if grep -q "^$var_name" "$conf_file" 2>/dev/null; then
                                    # Update existing setting
                                    sed -i "s/^$var_name.*/$var_name = $var_val/" "$conf_file"
                                else
                                    # Add new setting to [mysqld] section
                                    if grep -q "^\[mysqld\]" "$conf_file" 2>/dev/null; then
                                        sed -i "/^\[mysqld\]/a $var_name = $var_val" "$conf_file"
                                    else
                                        # No [mysqld] found (unlikely if valid config), append to end
                                        echo "" >> "$conf_file"
                                        echo "[mysqld]" >> "$conf_file"
                                        echo "$var_name = $var_val" >> "$conf_file"
                                    fi
                                fi
                            }

                            update_mysql_var "performance_schema_max_digest_length" "8096" "$MYSQL_CNF_FILE"
                            update_mysql_var "performance_schema_max_sql_text_length" "8096" "$MYSQL_CNF_FILE"
                            update_mysql_var "max_digest_length" "8096" "$MYSQL_CNF_FILE"
                            
                            # Restart MySQL to apply changes
                            log_warn "⚠️  Restarting $DB_NAME to apply Performance Schema limit settings..."
                            systemctl restart $DB_SERVICE
                            sleep 3
                            
                            # Verify it worked
                            VERIFY_DIGEST=$(mysql --defaults-file="$MYSQL_ROOT_CNF" -Nse "SELECT @@performance_schema_max_digest_length" 2>/dev/null || echo "1024")
                            if [ "$VERIFY_DIGEST" = "8096" ]; then
                                log_info "✅ performance_schema settings updated successfully!"
                            else
                                log_warn "⚠️  Settings may not be updated - check MySQL error log"
                            fi
                        else
                            log_info "✅ Performance Schema limits are already sufficient"
                        fi
                    else
                        # Backup existing config file
                        if [ -f "$MYSQL_CNF_FILE" ]; then
                            cp "$MYSQL_CNF_FILE" "${MYSQL_CNF_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
                            
                            # Comment out any existing performance_schema settings to avoid conflicts
                            # (prevents "last value wins" issues if we insert before existing settings)
                            sed -i 's/^\s*performance[-_]schema/#&/' "$MYSQL_CNF_FILE"
                        fi
                        
                        # Add performance_schema configuration
                        # Create temp file for config content
                        PERF_CNF_TEMP=$(mktemp)
                        cat > "$PERF_CNF_TEMP" <<PERFEOF

# Added by CLI Pal installer
performance_schema = ON
performance-schema-consumer-events-statements-history = ON
performance-schema-consumer-events-statements-current = ON
performance_schema_events_statements_history_size = 500
performance_schema_max_digest_length = 8096
performance_schema_max_sql_text_length = 8096
max_digest_length = 8096
PERFEOF

                        if grep -q "^\[mysqld\]" "$MYSQL_CNF_FILE" 2>/dev/null; then
                            # Insert after [mysqld] line using 'r' command which is safer for multiline
                            sed -i "/^\[mysqld\]/r $PERF_CNF_TEMP" "$MYSQL_CNF_FILE"
                        else
                            # Append to end
                            echo "" >> "$MYSQL_CNF_FILE"
                            echo "[mysqld]" >> "$MYSQL_CNF_FILE"
                            cat "$PERF_CNF_TEMP" >> "$MYSQL_CNF_FILE"
                        fi
                        rm -f "$PERF_CNF_TEMP"
                        
                        # Restart MySQL to apply changes
                        log_warn "⚠️  Restarting $DB_NAME to enable performance_schema..."
                        systemctl restart $DB_SERVICE
                        sleep 3
                        
                        # Verify it worked
                        FINAL_PS=$(mysql --defaults-file="$MYSQL_ROOT_CNF" -Nse "SELECT @@performance_schema" 2>/dev/null || echo "0")
                        if [ "$FINAL_PS" = "1" ]; then
                            log_info "✅ Performance schema enabled successfully!"
                        else
                            log_warn "⚠️  Performance schema may not be enabled - check MySQL error log"
                        fi
                    fi
                fi
            fi
        fi
        
        # Clean up root config file and clear root password from memory
        rm -f "$MYSQL_ROOT_CNF"
        unset MYSQL_ROOT_PASSWORD
    fi
elif [ -n "$MYSQL_USER" ] && [ -n "$MYSQL_PASSWORD" ]; then
    log_info "Using provided MySQL credentials for monitoring"
fi

# ==========================================
# PostgreSQL Setup
# ==========================================
if [ "$DB_TYPE" = "postgresql" ]; then
    if [ -n "$PG_SUPERUSER_PASSWORD" ]; then
        log_info "Setting up PostgreSQL monitoring..."
        
        # Check if psql is available
        if ! command -v psql &> /dev/null; then
            log_warn "PostgreSQL client (psql) not found. Skipping PostgreSQL setup."
            log_info "Install PostgreSQL client or use --pg-user/--pg-password instead"
        else
            # Create temporary pgpass file for authentication
            PGPASS_FILE=$(mktemp)
            chmod 600 "$PGPASS_FILE"
            echo "$PG_HOST:$PG_PORT:*:postgres:$PG_SUPERUSER_PASSWORD" > "$PGPASS_FILE"
            export PGPASSFILE="$PGPASS_FILE"
            
            # Test connection
            log_info "Verifying PostgreSQL superuser access..."
            set +e
            PG_TEST=$(psql -h "$PG_HOST" -p "$PG_PORT" -U postgres -d postgres -c "SELECT 1" 2>&1)
            PG_EXIT=$?
            set -e
            
            if [ $PG_EXIT -ne 0 ]; then
                log_error "Failed to connect to PostgreSQL as superuser"
                log_error "Error: $PG_TEST"
                log_error "Please verify:"
                log_error "  - PostgreSQL is running"
                log_error "  - Superuser password is correct"
                log_error "  - PostgreSQL is listening on $PG_HOST:$PG_PORT"
                rm -f "$PGPASS_FILE"
                exit 1
            fi
            
            log_info "✅ PostgreSQL superuser connection verified"
            
            # Generate secure random password for clipal user
            PG_PASSWORD=$(python3 -c "import secrets,string; print(''.join(secrets.choice(string.ascii_letters + string.digits) for i in range(32)))")
            PG_USER="clipal"
            
            log_info "Creating PostgreSQL monitoring user '$PG_USER'..."
            
            # Create monitoring user with appropriate permissions
            set +e
            PG_CREATE=$(psql -h "$PG_HOST" -p "$PG_PORT" -U postgres -d postgres 2>&1 <<PGSQL
-- Create monitoring user (if not exists)
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$PG_USER') THEN
        CREATE USER $PG_USER WITH PASSWORD '$PG_PASSWORD';
    ELSE
        ALTER USER $PG_USER WITH PASSWORD '$PG_PASSWORD';
    END IF;
END
\$\$;

-- Grant monitoring permissions
GRANT pg_monitor TO $PG_USER;
GRANT CONNECT ON DATABASE postgres TO $PG_USER;
PGSQL
)
            PG_CREATE_EXIT=$?
            set -e
            
            if [ $PG_CREATE_EXIT -eq 0 ]; then
                log_info "✅ PostgreSQL monitoring user created successfully"
                
                # Verify the user can connect
                sleep 1
                echo "$PG_HOST:$PG_PORT:*:$PG_USER:$PG_PASSWORD" > "$PGPASS_FILE"
                
                set +e
                PG_VERIFY=$(psql -h "$PG_HOST" -p "$PG_PORT" -U "$PG_USER" -d postgres -c "SELECT 1" 2>&1)
                PG_VERIFY_EXIT=$?
                set -e
                
                if [ $PG_VERIFY_EXIT -eq 0 ]; then
                    log_info "✅ PostgreSQL connection verified successfully"
                else
                    log_warn "⚠️  Warning: Could not verify PostgreSQL connection with generated password"
                    log_warn "   Error: $PG_VERIFY"
                fi
                
                # Configure pg_stat_statements in postgresql.conf
                log_info "Checking pg_stat_statements configuration..."
                PG_CONF_FILE=$(psql -h "$PG_HOST" -p "$PG_PORT" -U postgres -d postgres -t -c "SHOW config_file" 2>/dev/null | xargs)
                
                if [ -f "$PG_CONF_FILE" ] && [ -w "$PG_CONF_FILE" ]; then
                    # Check if pg_stat_statements is already in shared_preload_libraries
                    if ! grep -q "shared_preload_libraries.*pg_stat_statements" "$PG_CONF_FILE" 2>/dev/null; then
                        log_info "Enabling pg_stat_statements in $PG_CONF_FILE..."
                        # Backup config file
                        cp "$PG_CONF_FILE" "${PG_CONF_FILE}.backup.$(date +%Y%m%d_%H%M%S)"
                        
                        # Add/update shared_preload_libraries
                        if grep -q "^shared_preload_libraries" "$PG_CONF_FILE"; then
                            # Append to existing line
                            sed -i "s/^shared_preload_libraries = '\(.*\)'/shared_preload_libraries = '\1,pg_stat_statements'/" "$PG_CONF_FILE"
                        else
                            # Add new line
                            echo "" >> "$PG_CONF_FILE"
                            echo "# CLI Pal: Enable query statistics" >> "$PG_CONF_FILE"
                            echo "shared_preload_libraries = 'pg_stat_statements'" >> "$PG_CONF_FILE"
                        fi
                        
                        # Add pg_stat_statements configuration
                        if ! grep -q "^pg_stat_statements" "$PG_CONF_FILE"; then
                            echo "pg_stat_statements.track = all" >> "$PG_CONF_FILE"
                            echo "pg_stat_statements.max = 10000" >> "$PG_CONF_FILE"
                        fi
                        
                        log_warn "⚠️  Restarting PostgreSQL to enable pg_stat_statements..."
                        if systemctl restart postgresql 2>/dev/null || systemctl restart postgresql-* 2>/dev/null; then
                            sleep 3
                            log_info "✅ PostgreSQL restarted successfully"
                        else
                            log_warn "⚠️  Could not restart PostgreSQL automatically"
                            log_warn "   Please restart manually: sudo systemctl restart postgresql"
                        fi
                    else
                        log_info "✅ pg_stat_statements already configured"
                    fi
                    
                    # Now try to create the extension
                    sleep 2
                    set +e
                    PG_EXT_CREATE=$(psql -h "$PG_HOST" -p "$PG_PORT" -U postgres -d postgres -c "CREATE EXTENSION IF NOT EXISTS pg_stat_statements;" 2>&1)
                    PG_EXT_EXIT=$?
                    set -e
                    
                    if [ $PG_EXT_EXIT -eq 0 ]; then
                        log_info "✅ pg_stat_statements extension enabled"
                    else
                        log_warn "⚠️  Could not create pg_stat_statements extension"
                        log_warn "   Error: $PG_EXT_CREATE"
                        log_warn "   Query statistics may not be available until PostgreSQL is restarted"
                    fi
                else
                    log_warn "⚠️  Cannot modify PostgreSQL config file (not writable or not found)"
                    log_warn "   Config file: $PG_CONF_FILE"
                    log_warn "   To enable pg_stat_statements manually:"
                    log_warn "     1. Add to postgresql.conf: shared_preload_libraries = 'pg_stat_statements'"
                    log_warn "     2. Restart PostgreSQL"
                    log_warn "     3. Run: CREATE EXTENSION pg_stat_statements;"
                fi
            else
                log_error "Failed to create PostgreSQL user"
                log_error "Error: $PG_CREATE"
                PG_USER=""
                PG_PASSWORD=""
            fi
            
            # Clean up
            rm -f "$PGPASS_FILE"
            unset PGPASSFILE
            unset PG_SUPERUSER_PASSWORD
        fi
    elif [ -n "$PG_USER" ] && [ -n "$PG_PASSWORD" ]; then
        log_info "Using provided PostgreSQL credentials for monitoring"
    else
        log_error "PostgreSQL monitoring requires credentials"
        log_error "Use --pg-superuser-password=PASSWORD or --pg-user/--pg-password"
        exit 1
    fi
fi

# Create installation directory
log_info "Creating installation directory..."
mkdir -p "$INSTALL_DIR"

log_info "Installing agent..."

# Modular agent file list (13 files)
AGENT_FILES=(
    "agent.py"
    "lib/__init__.py"
    "lib/config.py"
    "lib/logger.py"
    "lib/system_metrics.py"
    "lib/api_client.py"
    "lib/websocket_client.py"
    "lib/terminal_handler.py"
    "lib/php_monitor.py"
    "lib/database/__init__.py"
    "lib/database/base_monitor.py"
    "lib/database/mysql_monitor.py"
    "lib/database/postgres_monitor.py"
)

# Download source selection
DOMAIN="${INSTALL_SERVER:-clipal.me}"

if [ "$INSTALL_DEV" = "true" ]; then
    # Dev mode: Download from clipal.me/downloads/agent/
    log_warn "DEV MODE: Downloading modular agent from $DOMAIN/downloads/agent/"
    BASE_URL="https://$DOMAIN/downloads/agent"
else
    # Production: Download from GitHub
    GITHUB_ORG="CLI-Pal"
    GITHUB_REPO="agent"
    BRANCH="${BRANCH:-main}"
    BASE_URL="https://raw.githubusercontent.com/$GITHUB_ORG/$GITHUB_REPO/$BRANCH"
fi

log_info "Download source: $BASE_URL"

# Download each file
DOWNLOAD_FAILED=0
for file in "${AGENT_FILES[@]}"; do
    FILE_PATH="$INSTALL_DIR/$file"
    FILE_URL="$BASE_URL/$file"

    # Create directory for this file if needed
    FILE_DIR="$INSTALL_DIR/$(dirname "$file")"
    mkdir -p "$FILE_DIR"

    log_info "Downloading $file..."
    if ! curl -sSL "$FILE_URL" -o "$FILE_PATH"; then
        log_error "Failed to download $file"
        DOWNLOAD_FAILED=1
        break
    fi

    # Verify file is not empty
    if [ ! -s "$FILE_PATH" ]; then
        log_error "Downloaded file is empty: $file"
        DOWNLOAD_FAILED=1
        break
    fi
done

if [ $DOWNLOAD_FAILED -eq 1 ]; then
    log_error "Agent installation failed"
    exit 1
fi

log_info "All ${#AGENT_FILES[@]} agent files downloaded successfully"

# Create wrapper script
cat > "$BIN_PATH" << 'EOF'
#!/bin/bash
exec python3 /opt/clipal/agent.py "$@"
EOF

chmod +x "$BIN_PATH"

# Create configuration file
log_info "Creating configuration file..."

CONFIG_PATH="$INSTALL_DIR/clipal.conf"

# Preserve existing configuration if present
PRESERVED_PHP_POOLS=""
if [ -f "$CONFIG_PATH" ]; then
    log_info "Backing up existing configuration..."
    cp "$CONFIG_PATH" "${CONFIG_PATH}.bak"
    log_info "✅ Backup saved to ${CONFIG_PATH}.bak"
    
    # Extract php_fpm_pools if present (for multi-pool setups configured manually)
    PRESERVED_PHP_POOLS=$(grep "^php_fpm_pools=" "$CONFIG_PATH" 2>/dev/null | cut -d'=' -f2- || true)
    if [ -n "$PRESERVED_PHP_POOLS" ]; then
        log_info "📋 Preserving existing PHP multi-pool configuration"
    fi
fi

cat > "$CONFIG_PATH" << CONFIG_EOF
# CLI Pal Agent Configuration
# Auto-generated during installation on $(date)
# You can manually edit this file and restart the agent to apply changes

# Agent Connection
api_key=$TOKEN
server_url=$SERVER_URL
CONFIG_EOF

# Add database type
cat >> "$CONFIG_PATH" << DB_TYPE_EOF

# Database Monitoring
# Options: mysql, postgresql, none
db_type=$DB_TYPE
DB_TYPE_EOF

# Add MySQL configuration if enabled
if [ -n "$MYSQL_USER" ] && [ -n "$MYSQL_PASSWORD" ]; then
    cat >> "$CONFIG_PATH" << MYSQL_CONFIG_EOF
mysql_enabled=true
mysql_host=$MYSQL_HOST
mysql_port=$MYSQL_PORT
mysql_user=$MYSQL_USER
mysql_password=$MYSQL_PASSWORD
MYSQL_CONFIG_EOF

    # Add mysql_cnf_file if detected during performance_schema setup
    if [ -n "$MYSQL_CNF_FILE" ]; then
        echo "mysql_cnf_file=$MYSQL_CNF_FILE" >> "$CONFIG_PATH"
    fi
fi

# Add PostgreSQL configuration if enabled
if [ -n "$PG_USER" ] && [ -n "$PG_PASSWORD" ]; then
    cat >> "$CONFIG_PATH" << PG_CONFIG_EOF
pg_enabled=true
pg_host=$PG_HOST
pg_port=$PG_PORT
pg_user=$PG_USER
pg_password=$PG_PASSWORD
pg_database=$PG_DATABASE
PG_CONFIG_EOF
fi

# Add PHP-FPM configuration if enabled
if [ "$PHP_ENABLED" = "true" ]; then
    log_info "Configuring PHP-FPM monitoring (native FastCGI)..."
    
    # Check if we have preserved multi-pool config from previous install
    if [ -n "$PRESERVED_PHP_POOLS" ]; then
        log_info "✅ Using preserved multi-pool configuration"
        # Skip socket detection, use preserved config directly
        cat >> "$CONFIG_PATH" << PHP_PRESERVED_EOF

# PHP-FPM Monitoring (native FastCGI - preserved from previous install)
php_enabled=true
php_fpm_pools=$PRESERVED_PHP_POOLS
php_fpm_status_path=$PHP_FPM_STATUS_PATH
PHP_PRESERVED_EOF
    # Auto-detect PHP-FPM socket if not provided
    elif [ -z "$PHP_FPM_SOCKET" ]; then
        log_info "Searching for PHP-FPM sockets..."
        
        # Common socket paths by distribution/control panel
        COMMON_SOCKETS=(
            # Standard paths
            "/var/run/php-fpm.sock"
            "/var/run/php/php-fpm.sock"
            "/run/php-fpm/www.sock"
            "/run/php/php-fpm.sock"
            # Version-specific (Ubuntu/Debian)
            "/var/run/php/php8.3-fpm.sock"
            "/var/run/php/php8.2-fpm.sock"
            "/var/run/php/php8.1-fpm.sock"
            "/var/run/php/php8.0-fpm.sock"
            "/var/run/php/php7.4-fpm.sock"
            # CentOS/RHEL
            "/var/run/php-fpm/www.sock"
            "/run/php-fpm/www.sock"
            # Webuzo (per-user pools: fpm-USERNAME.sock)
            # Note: Webuzo uses /var/fpm-*.sock, not /var/run/
            # cPanel
            "/opt/cpanel/ea-php74/root/var/run/php-fpm.sock"
            "/opt/cpanel/ea-php80/root/var/run/php-fpm.sock"
            "/opt/cpanel/ea-php81/root/var/run/php-fpm.sock"
            "/opt/cpanel/ea-php82/root/var/run/php-fpm.sock"
            "/opt/cpanel/ea-php83/root/var/run/php-fpm.sock"
            # Plesk
            "/var/run/plesk-php74-fpm.sock"
            "/var/run/plesk-php80-fpm.sock"
            "/var/run/plesk-php81-fpm.sock"
            "/var/run/plesk-php82-fpm.sock"
            "/var/run/plesk-php83-fpm.sock"
        )
        
        # Also try glob patterns
        SOCKET_GLOBS=(
            "/var/run/php*.sock"
            "/var/run/php/*.sock"
            "/run/php-fpm/*.sock"
            "/run/php/*.sock"
            # Webuzo: /usr/local/apps/php82/var/fpm-USERNAME.sock
            "/usr/local/apps/php*/var/*.sock"
            "/usr/local/apps/php*/var/fpm-*.sock"
            "/opt/cpanel/ea-php*/root/var/run/*.sock"
        )
        
        # Check explicit paths first
        for sock in "${COMMON_SOCKETS[@]}"; do
            if [ -S "$sock" ]; then
                PHP_FPM_SOCKET="unix://$sock"
                log_info "✅ Found PHP-FPM socket: $sock"
                break
            fi
        done
        
        # If not found, try glob patterns
        if [ -z "$PHP_FPM_SOCKET" ]; then
            for pattern in "${SOCKET_GLOBS[@]}"; do
                for sock in $pattern; do
                    if [ -S "$sock" ] 2>/dev/null; then
                        PHP_FPM_SOCKET="unix://$sock"
                        log_info "✅ Found PHP-FPM socket: $sock"
                        break 2
                    fi
                done
            done
        fi
        
        # Also check for TCP listeners on port 9000
        if [ -z "$PHP_FPM_SOCKET" ]; then
            if command -v ss &> /dev/null; then
                if ss -tlnp | grep -q ':9000 '; then
                    PHP_FPM_SOCKET="tcp://127.0.0.1:9000"
                    log_info "✅ Found PHP-FPM listening on TCP port 9000"
                fi
            elif command -v netstat &> /dev/null; then
                if netstat -tlnp 2>/dev/null | grep -q ':9000 '; then
                    PHP_FPM_SOCKET="tcp://127.0.0.1:9000"
                    log_info "✅ Found PHP-FPM listening on TCP port 9000"
                fi
            fi
        fi
        
        if [ -z "$PHP_FPM_SOCKET" ]; then
            log_error "❌ Could not find PHP-FPM socket"
            log_error "   Please specify manually: --php-socket=unix:///path/to/php-fpm.sock"
            log_error "   Or for TCP: --php-socket=tcp://127.0.0.1:9000"
            log_info ""
            log_info "   Common socket locations:"
            log_info "     Ubuntu/Debian: /var/run/php/php8.x-fpm.sock"
            log_info "     CentOS/RHEL:   /var/run/php-fpm/www.sock"
            log_info "     Webuzo:        /usr/local/apps/php8x/var/run/php-fpm.sock"
            log_info "     cPanel:        /opt/cpanel/ea-php8x/root/var/run/php-fpm.sock"
            log_info ""
            log_info "   You can find your socket with: find /var/run -name '*.sock' 2>/dev/null | grep php"
            PHP_ENABLED="false"
        fi
    else
        # User provided socket path - add unix:// prefix if needed
        if [[ ! "$PHP_FPM_SOCKET" =~ ^(unix|tcp):// ]]; then
            PHP_FPM_SOCKET="unix://$PHP_FPM_SOCKET"
            log_info "Added unix:// prefix to socket path"
        fi
    fi
    
    # Verify FastCGI connection using Python
    if [ "$PHP_ENABLED" = "true" ] && [ -n "$PHP_FPM_SOCKET" ]; then
        log_info "Verifying PHP-FPM connection via FastCGI..."
        
        # Disable set -e for this block to handle Python errors gracefully
        set +e
        VERIFY_RESULT=$(python3 2>&1 << PYEOF
import socket
import struct
import sys
import json

socket_uri = "$PHP_FPM_SOCKET"
status_path = "$PHP_FPM_STATUS_PATH"

# FastCGI constants
FCGI_BEGIN_REQUEST = 1
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_END_REQUEST = 3
FCGI_RESPONDER = 1

def recv_exact(sock, size):
    """Read exactly 'size' bytes, handling partial reads."""
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError(f"Connection closed after {len(data)}/{size} bytes")
        data += chunk
    return data

def build_record(rtype, content, request_id=1):
    clen = len(content)
    plen = (8 - (clen % 8)) % 8
    header = struct.pack('>BBHHBx', 1, rtype, request_id, clen, plen)
    return header + content + (b'\x00' * plen)

def encode_params(params):
    result = b''
    for k, v in params.items():
        kb, vb = k.encode(), v.encode()
        kl, vl = len(kb), len(vb)
        result += struct.pack('B', kl) if kl < 128 else struct.pack('>I', kl | 0x80000000)
        result += struct.pack('B', vl) if vl < 128 else struct.pack('>I', vl | 0x80000000)
        result += kb + vb
    return result

try:
    # Parse URI
    if socket_uri.startswith('unix://'):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect(socket_uri[7:])
    elif socket_uri.startswith('tcp://'):
        host_port = socket_uri[6:]
        host, port = host_port.rsplit(':', 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5.0)
        sock.connect((host, int(port)))
    else:
        print("ERROR:Invalid socket URI format")
        sys.exit(0)
    
    # Send BEGIN_REQUEST
    sock.sendall(build_record(FCGI_BEGIN_REQUEST, struct.pack('>HB5x', FCGI_RESPONDER, 0)))
    
    # Send PARAMS
    params = {
        'SCRIPT_NAME': status_path,
        'SCRIPT_FILENAME': status_path,
        'REQUEST_METHOD': 'GET',
        'QUERY_STRING': 'json',
        'SERVER_PROTOCOL': 'HTTP/1.1',
    }
    sock.sendall(build_record(FCGI_PARAMS, encode_params(params)))
    sock.sendall(build_record(FCGI_PARAMS, b''))
    sock.sendall(build_record(FCGI_STDIN, b''))
    
    # Read response with robust recv loop (handles partial reads)
    stdout = b''
    while True:
        # Read 8-byte header with exact recv
        header = recv_exact(sock, 8)
        _, rtype, _, clen, plen = struct.unpack('>BBHHBx', header)
        
        # Read content + padding with exact recv
        total = clen + plen
        data = recv_exact(sock, total) if total > 0 else b''
        
        if rtype == FCGI_STDOUT:
            stdout += data[:clen]
        elif rtype == FCGI_END_REQUEST:
            break
    
    sock.close()
    
    response = stdout.decode('utf-8', errors='replace')
    
    if 'File not found' in response or 'Status: 404' in response:
        print("ERROR:Status page not found. Enable pm.status_path in PHP-FPM config")
        sys.exit(0)
    elif 'Access denied' in response:
        print("ERROR:Access denied. Check pm.status_listen in PHP-FPM config")
        sys.exit(0)
    elif '"pool"' in response or '"accepted conn"' in response:
        print("OK")
    else:
        print("WARN:Connected but response unclear - check agent logs after start")
        
except socket.timeout:
    print("ERROR:Connection timeout")
    sys.exit(0)
except ConnectionError as e:
    print(f"ERROR:{e}")
    sys.exit(0)
except OSError as e:
    print(f"ERROR:Cannot connect - {e}")
    sys.exit(0)
except Exception as e:
    print(f"ERROR:{e}")
    sys.exit(0)  # Don't crash installer, just report the error
PYEOF
)
        PYTHON_EXIT=$?
        set -e
        
        # Handle empty result (Python crashed before printing anything)
        if [ -z "$VERIFY_RESULT" ]; then
            if [ $PYTHON_EXIT -ne 0 ]; then
                VERIFY_RESULT="ERROR:Python verification script crashed (exit code $PYTHON_EXIT)"
            else
                VERIFY_RESULT="ERROR:Unknown error during verification"
            fi
        fi
        
        if [[ "$VERIFY_RESULT" == "OK" ]]; then
            log_info "✅ PHP-FPM FastCGI connection verified"
        elif [[ "$VERIFY_RESULT" == WARN:* ]]; then
            log_warn "⚠️  ${VERIFY_RESULT#WARN:}"
        elif [[ "$VERIFY_RESULT" == ERROR:* ]]; then
            log_error "❌ PHP-FPM verification failed: ${VERIFY_RESULT#ERROR:}"
            log_error ""
            log_error "   To enable PHP-FPM status, add to your PHP-FPM pool config:"
            log_error "     pm.status_path = $PHP_FPM_STATUS_PATH"
            log_error ""
            log_error "   Then restart PHP-FPM: systemctl restart php-fpm"
            log_error ""
            PHP_ENABLED="false"
        else
            log_warn "⚠️  Unexpected verification result: $VERIFY_RESULT"
        fi
    fi
    
    # Auto-detect slowlog path if not provided
    if [ "$PHP_ENABLED" = "true" ] && [ -z "$PHP_FPM_SLOW_LOG" ]; then
        COMMON_SLOWLOGS=(
            "/var/log/php-fpm/www-slow.log"
            "/var/log/php8.3-fpm-slow.log"
            "/var/log/php8.2-fpm-slow.log"
            "/var/log/php8.1-fpm-slow.log"
            "/var/log/php8.0-fpm-slow.log"
            "/var/log/php7.4-fpm-slow.log"
            "/var/log/php-fpm/slow.log"
            "/var/log/php-fpm.slow.log"
        )
        
        for log in "${COMMON_SLOWLOGS[@]}"; do
            if [ -f "$log" ] && [ -r "$log" ]; then
                PHP_FPM_SLOW_LOG="$log"
                log_info "✅ Found PHP-FPM slow log: $log"
                break
            fi
        done
        
        if [ -z "$PHP_FPM_SLOW_LOG" ]; then
            log_info "ℹ️  No PHP-FPM slowlog found (optional - only needed for slow request tracing)"
        fi
    fi
    
    # Write PHP config if still enabled AND not using preserved config
    if [ "$PHP_ENABLED" = "true" ] && [ -z "$PRESERVED_PHP_POOLS" ]; then
        cat >> "$CONFIG_PATH" << PHP_CONFIG_EOF

# PHP-FPM Monitoring (native FastCGI - no web server proxy needed)
php_enabled=true
php_fpm_socket=$PHP_FPM_SOCKET
php_fpm_status_path=$PHP_FPM_STATUS_PATH
php_fpm_slow_log=$PHP_FPM_SLOW_LOG
PHP_CONFIG_EOF
    fi
fi

# Set strict permissions on config file (contains secrets)
chmod 600 "$CONFIG_PATH"
chown root:root "$CONFIG_PATH"
log_info "✅ Configuration saved to $CONFIG_PATH"

# Create systemd service (simplified - no longer needs env vars)
log_info "Creating systemd service..."

cat > "$SERVICE_FILE" << EOF
[Unit]
Description=CLI Pal Agent
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
Restart=always
RestartSec=10
User=root
ExecStart=/usr/local/bin/clipal-agent
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and start service
log_info "Starting service..."
systemctl daemon-reload
systemctl enable clipal-agent
systemctl start clipal-agent

# Check status
sleep 2
if systemctl is-active --quiet clipal-agent; then
    log_info "✅ CLI Pal Agent installed and running successfully!"
    echo ""
    
    # Show database monitoring status
    if [ "$DB_TYPE" = "mysql" ] && [ -n "$MYSQL_USER" ]; then
        log_info "📊 MySQL monitoring: ENABLED"
        echo "     User: $MYSQL_USER@$MYSQL_HOST:$MYSQL_PORT"
    elif [ "$DB_TYPE" = "postgresql" ] && [ -n "$PG_USER" ]; then
        log_info "📊 PostgreSQL monitoring: ENABLED"
        echo "     User: $PG_USER@$PG_HOST:$PG_PORT/$PG_DATABASE"
    else
        echo "📊 Database monitoring: DISABLED"
        echo "   To enable MySQL: reinstall with --mysql-root-password=YOUR_ROOT_PASSWORD"
        echo "   To enable PostgreSQL: reinstall with --pg-superuser-password=YOUR_PASSWORD"
    fi
    
    # Show PHP monitoring status
    if [ "$PHP_ENABLED" = "true" ]; then
        log_info "📊 PHP-FPM monitoring: ENABLED (native FastCGI)"
        echo "     Socket: $PHP_FPM_SOCKET"
        echo "     Status path: $PHP_FPM_STATUS_PATH"
        if [ -n "$PHP_FPM_SLOW_LOG" ]; then
            echo "     Slow log: $PHP_FPM_SLOW_LOG"
        fi
    fi
    
    echo ""
    echo "Useful commands:"
    echo "  Status:  systemctl status clipal-agent"
    echo "  Logs:    journalctl -u clipal-agent -f"
    echo "  Stop:    systemctl stop clipal-agent"
    echo "  Start:   systemctl start clipal-agent"
    echo "  Restart: systemctl restart clipal-agent"
else
    log_error "Service failed to start. Check logs with: journalctl -u clipal-agent -n 50"
    exit 1
fi
