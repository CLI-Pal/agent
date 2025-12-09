#!/bin/bash
set -e

# CLI Pal Agent Installation Script
# Usage: 
#   Install:   curl -sSL https://clipal.me/install.sh | sudo bash -s -- --token=YOUR_TOKEN [--server=wss://your-server.com/ws] [--mysql-root-password=PASSWORD] [--enable-performance-schema]
#   Uninstall: curl -sSL https://clipal.me/install.sh | sudo bash -s -- uninstall

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
MYSQL_ROOT_PASSWORD=""
MYSQL_USER=""
MYSQL_PASSWORD=""
MYSQL_HOST="localhost"
MYSQL_PORT="3306"
ENABLE_PERFORMANCE_SCHEMA="false"

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
        uninstall)
            # Already handled above
            shift
            ;;
        *)
            shift
            ;;
    esac
done

# Validate token (only needed for installation, not uninstall)
if [ -z "$TOKEN" ]; then
    log_error "Token is required!"
    echo "Usage: $0 --token=YOUR_TOKEN [--server=wss://your-server.com/ws]"
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
if [ -n "$MYSQL_ROOT_PASSWORD" ] || [ -n "$MYSQL_USER" ]; then
    REQUIRED_PACKAGES="$REQUIRED_PACKAGES mysql-connector-python"
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
        cat > "$MYSQL_ROOT_CNF" <<ROOTCNF
[client]
user=root
password=$MYSQL_ROOT_PASSWORD
host=$MYSQL_HOST
port=$MYSQL_PORT
ROOTCNF
        
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
else
    log_info "MySQL monitoring disabled (no credentials provided)"
    log_info "To enable: reinstall with --mysql-root-password=YOUR_ROOT_PASSWORD"
fi

# Create installation directory
log_info "Creating installation directory..."
mkdir -p "$INSTALL_DIR"

# Download agent (for now, we'll copy it, but in production this would download from your server)
log_info "Installing agent..."

# Download the agent from your server
# Download the agent from the official GitHub repository
GITHUB_ORG="CLI-Pal"
GITHUB_REPO="agent"
BRANCH="${BRANCH:-main}"
AGENT_URL="https://raw.githubusercontent.com/$GITHUB_ORG/$GITHUB_REPO/$BRANCH/agent.py"

# Allow overriding URL for testing/development
if [ -n "$CUSTOM_AGENT_URL" ]; then
    AGENT_URL="$CUSTOM_AGENT_URL"
fi

log_info "Downloading agent from $AGENT_URL..."
curl -sSL "$AGENT_URL" -o "$INSTALL_DIR/agent.py" || {
    log_error "Failed to download agent"
    exit 1
}

# Verify download
if [ ! -s "$INSTALL_DIR/agent.py" ]; then
    log_error "Agent file is empty or missing"
    exit 1
fi

# Create wrapper script
cat > "$BIN_PATH" << 'EOF'
#!/bin/bash
exec python3 /opt/clipal/agent.py "$@"
EOF

chmod +x "$BIN_PATH"

# Create configuration file
log_info "Creating configuration file..."

CONFIG_PATH="$INSTALL_DIR/clipal.conf"
cat > "$CONFIG_PATH" << CONFIG_EOF
# CLI Pal Agent Configuration
# Auto-generated during installation on $(date)
# You can manually edit this file and restart the agent to apply changes

# Agent Connection
api_key=$TOKEN
server_url=$SERVER_URL
CONFIG_EOF

# Add MySQL configuration if enabled
if [ -n "$MYSQL_USER" ] && [ -n "$MYSQL_PASSWORD" ]; then
    cat >> "$CONFIG_PATH" << MYSQL_CONFIG_EOF

# MySQL Monitoring
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
    
    # Show MySQL monitoring status
    if [ -n "$MYSQL_USER" ]; then
        log_info "📊 MySQL monitoring: ENABLED"
        echo "     User: $MYSQL_USER@$MYSQL_HOST:$MYSQL_PORT"
    else
        echo "📊 MySQL monitoring: DISABLED"
        echo "   To enable: reinstall with --mysql-root-password=YOUR_ROOT_PASSWORD"
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
