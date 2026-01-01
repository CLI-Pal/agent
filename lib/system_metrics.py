"""
CLI Pal Agent - System Metrics Module

Collects system metrics: CPU, RAM, disk, network, failed logins.
"""

import os
import re
import sys
import time
import socket
import platform
import subprocess
from datetime import datetime
from typing import Optional

try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    PSUTIL_AVAILABLE = False
    # Print visible warning at import time (before logger is available)
    print("=" * 60)
    print("⚠️  WARNING: psutil module not installed!")
    print("   System monitoring (CPU/RAM/OS info) is DISABLED")
    print("   To fix: pip3 install psutil")
    print("=" * 60)


class SystemMetrics:
    """System metrics collector using psutil

    Collects CPU, RAM, disk, network metrics and failed login attempts.
    Gracefully handles missing psutil module.
    """

    def __init__(self, logger):
        """Initialize system metrics collector

        Args:
            logger: Logger instance for output
        """
        self.logger = logger
        self.available = PSUTIL_AVAILABLE

        # Rate tracking for disk and network
        self.last_disk_io = None
        self.last_disk_io_time = 0
        self.last_net_io = None
        self.last_net_io_time = 0

        if not self.available:
            self.logger.warn("psutil not available - system metrics disabled")
            self.logger.warn("Install with: pip3 install psutil")

    def get_metrics(self) -> dict:
        """Collect system metrics

        Returns:
            dict: System metrics including CPU, RAM, disk, network
        """
        if not self.available:
            return self._get_basic_info()

        try:
            current_time = time.time()

            # CPU usage (non-blocking)
            cpu_percent = psutil.cpu_percent(interval=0) or 0.0

            # RAM usage
            ram = psutil.virtual_memory()
            ram_total_mb = ram.total / (1024 * 1024)
            ram_used_mb = ram.used / (1024 * 1024)
            ram_percent = ram.percent

            # Disk usage (root partition)
            disk = psutil.disk_usage('/')
            disk_total_gb = disk.total / (1024 * 1024 * 1024)
            disk_used_gb = disk.used / (1024 * 1024 * 1024)
            disk_percent = disk.percent

            # Disk IOPS
            iops_read, iops_write = self._get_disk_iops(current_time)

            # Network rates
            net_rx_kbps, net_tx_kbps = self._get_network_rates(current_time)

            # System info
            system_info = self._get_system_info()

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
            self.logger.error(f"Error collecting system metrics: {e}")
            return self._get_basic_info()

    def _get_disk_iops(self, current_time: float) -> tuple:
        """Calculate disk IOPS since last call

        Args:
            current_time: Current timestamp

        Returns:
            tuple: (read_iops, write_iops)
        """
        iops_read = 0
        iops_write = 0

        try:
            disk_io = psutil.disk_io_counters()

            if disk_io and self.last_disk_io and self.last_disk_io_time > 0:
                time_delta = current_time - self.last_disk_io_time
                if time_delta > 0:
                    iops_read = (disk_io.read_count - self.last_disk_io.read_count) / time_delta
                    iops_write = (disk_io.write_count - self.last_disk_io.write_count) / time_delta

            if disk_io:
                self.last_disk_io = disk_io
                self.last_disk_io_time = current_time
        except Exception:
            pass

        return iops_read, iops_write

    def _get_network_rates(self, current_time: float) -> tuple:
        """Calculate network rates since last call

        Args:
            current_time: Current timestamp

        Returns:
            tuple: (rx_kbps, tx_kbps)
        """
        net_rx_kbps = 0
        net_tx_kbps = 0

        try:
            net_io = psutil.net_io_counters()

            if net_io and self.last_net_io and self.last_net_io_time > 0:
                time_delta = current_time - self.last_net_io_time
                if time_delta > 0:
                    net_rx_kbps = (net_io.bytes_recv - self.last_net_io.bytes_recv) / 1024 / time_delta
                    net_tx_kbps = (net_io.bytes_sent - self.last_net_io.bytes_sent) / 1024 / time_delta

            if net_io:
                self.last_net_io = net_io
                self.last_net_io_time = current_time
        except Exception:
            pass

        return net_rx_kbps, net_tx_kbps

    def _get_basic_info(self) -> dict:
        """Get basic system info without psutil

        Returns:
            dict: Basic system information
        """
        return self._get_system_info()

    def _get_system_info(self) -> dict:
        """Collect system information

        Returns:
            dict: OS, version, architecture, hostname, IP
        """
        try:
            return {
                'os_platform': platform.system().lower() or 'unknown',
                'os_version': self._get_os_version() or 'unknown',
                'architecture': platform.machine() or 'unknown',
                'hostname': (os.uname().nodename if hasattr(os, 'uname') else platform.node()) or 'unknown',
                'ip_address': self._get_ip_address() or 'unknown'
            }
        except Exception:
            return {
                'os_platform': sys.platform or 'unknown',
                'os_version': 'unknown',
                'architecture': 'unknown',
                'hostname': 'unknown',
                'ip_address': 'unknown'
            }

    def _get_ip_address(self) -> Optional[str]:
        """Get the server's primary IP address

        Returns:
            Primary IP address or None
        """
        try:
            # Method 1: Connect to external address
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(('8.8.8.8', 80))
                ip = s.getsockname()[0]
                s.close()
                return ip
            except Exception:
                s.close()
                raise
        except Exception:
            pass

        try:
            # Method 2: Resolve hostname
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if ip != '127.0.0.1' and not ip.startswith('127.'):
                return ip
        except Exception:
            pass

        try:
            # Method 3: Get all IPs
            hostname = socket.gethostname()
            ip_list = socket.gethostbyname_ex(hostname)[2]
            for ip in ip_list:
                if not ip.startswith('127.') and '.' in ip:
                    return ip
        except Exception:
            pass

        return None

    def _get_os_version(self) -> str:
        """Get OS version information

        Returns:
            OS version string
        """
        try:
            if sys.platform.startswith('linux'):
                try:
                    import distro
                    return f"{distro.name()} {distro.version()}"
                except ImportError:
                    try:
                        with open('/etc/os-release', 'r') as f:
                            for line in f:
                                if line.startswith('PRETTY_NAME='):
                                    return line.split('=', 1)[1].strip().strip('"')
                    except Exception:
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
        """Fetch recent failed login attempts from system logs

        Args:
            max_entries: Maximum number of entries to return

        Returns:
            List of failed login dicts
        """
        failed_logins = []

        if not sys.platform.startswith('linux'):
            self.logger.debug("Failed logins: Not on Linux, skipping")
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

        patterns = [
            # SSH
            ('sshd', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+)')),
            ('sshd', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*sshd.*Invalid user (?P<user>\S+) from (?P<ip>[\d.]+)')),
            # Generic PAM
            ('pam', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*authentication failure.*user=(?P<user>\S+).*rhost=(?P<ip>[\d.]+)')),
            # FTP
            ('vsftpd', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*vsftpd.*FAIL LOGIN: Client "(?P<ip>[\d.]+)"')),
            ('proftpd', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*proftpd.*\[(?P<ip>[\d.]+)\].*USER (?P<user>\S+): no such user found')),
            ('proftpd', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*proftpd.*\[(?P<ip>[\d.]+)\].*USER (?P<user>\S+): .*Incorrect password')),
            ('pure-ftpd', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*pure-ftpd.*\(?(?P<user>\S+)@(?P<ip>[\d.]+)\)?.*Authentication failed')),
            # Email
            ('dovecot', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*dovecot.*Aborted login.*user=<(?P<user>\S+)>.*rip=(?P<ip>[\d.]+)')),
            ('exim', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*exim.*authenticator failed for .* \[(?P<ip>[\d.]+)\].*')),
            ('postfix', re.compile(r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+).*postfix.*warning:.*\[(?P<ip>[\d.]+)\].*SASL.*authentication failed')),
            # MySQL
            ('mysql', re.compile(r'(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z).*Access denied for user \'(?P<user>[^\']+)\'@\'(?P<ip>[\d.]+)\'')),
        ]

        try:
            for log_file in log_files:
                if not os.path.exists(log_file):
                    continue

                try:
                    cmd = ['tail', '-n', '1000', log_file]
                    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                          universal_newlines=True, errors='replace')

                    if result.returncode != 0:
                        continue

                    lines = result.stdout.splitlines()

                    for line in reversed(lines):
                        for service_name, pattern in patterns:
                            match = pattern.search(line)
                            if match:
                                group_dict = match.groupdict()
                                timestamp_str = group_dict.get('timestamp')
                                username = group_dict.get('user', 'unknown')
                                ip_address = group_dict.get('ip', 'unknown')

                                attempt_time = self._parse_log_timestamp(timestamp_str)

                                failed_logins.append({
                                    'service': service_name,
                                    'username': username,
                                    'source_ip': ip_address,
                                    'attempt_time': attempt_time.isoformat() if attempt_time else datetime.now().isoformat()
                                })

                                if len(failed_logins) >= max_entries:
                                    return failed_logins
                                break

                except PermissionError:
                    self.logger.debug(f"No permission to read {log_file}")
                except Exception as e:
                    self.logger.debug(f"Error reading {log_file}: {e}")

        except Exception as e:
            self.logger.error(f"Error fetching failed logins: {e}")

        return failed_logins

    def _parse_log_timestamp(self, timestamp_str: str) -> Optional[datetime]:
        """Parse log timestamp

        Args:
            timestamp_str: Timestamp string from log

        Returns:
            datetime object or None
        """
        if not timestamp_str:
            return None

        # Try Syslog format (Dec  7 10:00:00)
        try:
            current_year = datetime.now().year
            timestamp_with_year = f"{current_year} {timestamp_str}"
            return datetime.strptime(timestamp_with_year, "%Y %b %d %H:%M:%S")
        except ValueError:
            pass

        # Try ISO format (MySQL: 2024-05-20T10:00:00.123456Z)
        try:
            ts_clean = timestamp_str.replace('T', ' ').replace('Z', '')
            return datetime.strptime(ts_clean, "%Y-%m-%d %H:%M:%S.%f")
        except ValueError:
            pass

        return None
