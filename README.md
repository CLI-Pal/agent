# CLI Pal Agent

The official server monitoring and management agent for the [CLI Pal](https://clipal.me) platform.

This lightweight Python agent runs on your Linux server to collect performance metrics, analyze MySQL queries, and enable secure remote terminal access.

## Features

- **Real-time Monitoring**: Tracks CPU, RAM, Disk usage, and System Load.
- **MySQL Intelligence**:
  - Collects `SHOW GLOBAL STATUS` and variables.
  - Analyzes Slow Queries via Performance Schema.
  - Provides index usage recommendations.
- **Remote Terminal**: Secure, web-based terminal access via WebSocket.
- **Secure Architecture**:
  - Outbound-only connection (no firewall ports to open).
  - Minimal resource footprint.

## Installation

The recommended way to install the agent is using the official installer script, which sets up the systemd service and needed dependencies automatically.

```bash
curl -sSL https://clipal.me/install.sh | sudo bash -s -- --token=YOUR_API_TOKEN
```

### Requirements

- **OS**: Linux (Ubuntu, Debian, CentOS, RHEL, Fedora)
- **Runtime**: Python 3.6+
- **Database** (Optional): MySQL 5.7+, MySQL 8.0+, or MariaDB 10.x

## Manual Verification

Since this agent runs with root privileges, we encourage users to audit the code. You can verify the integrity of the installer and agent:

1. **Review the Installer**:
   The `install.sh` in this repository is the exact script used by `clipal.me/install.sh`.
   
2. **Review the Agent**:
   The `agent.py` file contains all the logic for metrics collection and WebSocket communication.

## Configuration

The agent is configured via `/opt/clipal/clipal.conf`.
Restart the agent after making changes: `systemctl restart clipal-agent`

## Contributing

Issues and Pull Requests are welcome! If you find a bug or want to support a new Linux distribution, please open an issue.

## License

MIT
