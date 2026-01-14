"""
CLI Pal Agent - PHP-FPM Monitor Module

Monitors PHP-FPM status via native FastCGI protocol (no web server proxy needed).

Features:
- Direct FastCGI communication with PHP-FPM sockets
- Supports Unix sockets (unix:///path) and TCP (tcp://host:port)
- Collects real-time metrics from PHP-FPM status page
- Tails slowlog files for stack traces
- Supports single and multi-pool configurations
"""

import json
import os
import socket
import struct
import time
import hashlib
from typing import Optional, Dict, List, Any, Tuple

# =============================================================================
# FastCGI Protocol Implementation
# =============================================================================
# FastCGI protocol spec: https://fastcgi-archives.github.io/FastCGI_Specification.html

# FastCGI record types
FCGI_BEGIN_REQUEST = 1
FCGI_ABORT_REQUEST = 2
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7
FCGI_DATA = 8
FCGI_GET_VALUES = 9
FCGI_GET_VALUES_RESULT = 10
FCGI_UNKNOWN_TYPE = 11

# FastCGI roles
FCGI_RESPONDER = 1
FCGI_AUTHORIZER = 2
FCGI_FILTER = 3

# FastCGI flags
FCGI_KEEP_CONN = 1

# Record header format: version(1) + type(1) + requestId(2) + contentLength(2) + paddingLength(1) + reserved(1)
FCGI_HEADER_FORMAT = '>BBHHBx'
FCGI_HEADER_SIZE = 8


class FastCGIError(Exception):
    """FastCGI protocol or connection error"""
    pass


class FastCGIRecord:
    """Represents a FastCGI record"""
    def __init__(self, record_type: int, content: bytes, request_id: int = 1):
        self.type = record_type
        self.content = content
        self.request_id = request_id


def _build_record(record_type: int, content: bytes, request_id: int = 1) -> bytes:
    """Build a FastCGI record with header and content
    
    Args:
        record_type: FCGI_* type constant
        content: Record payload
        request_id: Request ID (default 1)
    
    Returns:
        Complete record bytes including header
    """
    content_length = len(content)
    # Pad to 8-byte boundary
    padding_length = (8 - (content_length % 8)) % 8
    
    header = struct.pack(
        FCGI_HEADER_FORMAT,
        1,  # version
        record_type,
        request_id,
        content_length,
        padding_length
    )
    
    return header + content + (b'\x00' * padding_length)


def _build_begin_request(role: int = FCGI_RESPONDER, flags: int = 0, request_id: int = 1) -> bytes:
    """Build FCGI_BEGIN_REQUEST record
    
    Args:
        role: FCGI_RESPONDER, FCGI_AUTHORIZER, or FCGI_FILTER
        flags: FCGI_KEEP_CONN or 0
        request_id: Request ID
    
    Returns:
        Complete BEGIN_REQUEST record
    """
    # Body: role(2) + flags(1) + reserved(5)
    body = struct.pack('>HB5x', role, flags)
    return _build_record(FCGI_BEGIN_REQUEST, body, request_id)


def _encode_params(params: Dict[str, str]) -> bytes:
    """Encode name-value pairs for FCGI_PARAMS
    
    FastCGI uses a compact encoding for name-value lengths:
    - If length < 128: single byte
    - Otherwise: 4 bytes with high bit set
    
    Args:
        params: Dictionary of name-value pairs
    
    Returns:
        Encoded params bytes
    """
    result = b''
    for name, value in params.items():
        name_bytes = name.encode('utf-8')
        value_bytes = value.encode('utf-8')
        name_len = len(name_bytes)
        value_len = len(value_bytes)
        
        # Encode name length
        if name_len < 128:
            result += struct.pack('B', name_len)
        else:
            result += struct.pack('>I', name_len | 0x80000000)
        
        # Encode value length
        if value_len < 128:
            result += struct.pack('B', value_len)
        else:
            result += struct.pack('>I', value_len | 0x80000000)
        
        result += name_bytes + value_bytes
    
    return result


def _read_exact(sock: socket.socket, size: int) -> bytes:
    """Read exactly `size` bytes from socket, handling partial reads
    
    Args:
        sock: Connected socket
        size: Number of bytes to read
    
    Returns:
        Exactly `size` bytes
    
    Raises:
        FastCGIError: If connection closed before all bytes read
    """
    data = b''
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise FastCGIError(f"Connection closed after {len(data)}/{size} bytes")
        data += chunk
    return data


def _read_record(sock: socket.socket) -> FastCGIRecord:
    """Read a complete FastCGI record from socket
    
    Handles partial reads and padding.
    
    Args:
        sock: Connected socket
    
    Returns:
        FastCGIRecord with type and content
    
    Raises:
        FastCGIError: If connection error or malformed record
    """
    # Read 8-byte header
    header = _read_exact(sock, FCGI_HEADER_SIZE)
    
    version, record_type, request_id, content_length, padding_length = struct.unpack(
        FCGI_HEADER_FORMAT, header
    )
    
    if version != 1:
        raise FastCGIError(f"Unsupported FastCGI version: {version}")
    
    # Read content + padding
    total_length = content_length + padding_length
    if total_length > 0:
        data = _read_exact(sock, total_length)
        content = data[:content_length]
    else:
        content = b''
    
    return FastCGIRecord(record_type, content, request_id)


def _parse_socket_uri(uri: str) -> Tuple[str, Any]:
    """Parse socket URI into (socket_type, address)
    
    Args:
        uri: Socket URI like 'unix:///var/run/php-fpm.sock' or 'tcp://127.0.0.1:9000'
    
    Returns:
        Tuple of ('unix', '/path/to/socket') or ('tcp', ('host', port))
    
    Raises:
        ValueError: If URI format is invalid
    """
    if uri.startswith('unix://'):
        return ('unix', uri[7:])
    elif uri.startswith('tcp://'):
        host_port = uri[6:]
        if ':' not in host_port:
            raise ValueError(f"TCP socket URI must include port: {uri}")
        host, port_str = host_port.rsplit(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            raise ValueError(f"Invalid port in socket URI: {uri}")
        return ('tcp', (host, port))
    else:
        raise ValueError(f"Invalid socket URI: {uri}. Use unix:// or tcp://")


def fetch_status_via_fastcgi(socket_uri: str, status_path: str = '/status', timeout: float = 5.0) -> Dict:
    """Fetch PHP-FPM status via FastCGI protocol
    
    Args:
        socket_uri: Socket URI (unix:///path or tcp://host:port)
        status_path: PHP-FPM status path (default: /status)
        timeout: Socket timeout in seconds
    
    Returns:
        Parsed JSON status dict
    
    Raises:
        FastCGIError: On connection or protocol errors
        json.JSONDecodeError: If response is not valid JSON
    """
    # Parse URI
    try:
        socket_type, address = _parse_socket_uri(socket_uri)
    except ValueError as e:
        raise FastCGIError(str(e))
    
    # Create and connect socket
    try:
        if socket_type == 'unix':
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(address)
        else:  # tcp
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(address)
    except socket.timeout:
        raise FastCGIError(f"Connection timeout to {socket_uri}")
    except OSError as e:
        raise FastCGIError(f"Cannot connect to {socket_uri}: {e}")
    
    try:
        # Send BEGIN_REQUEST
        sock.sendall(_build_begin_request(FCGI_RESPONDER, 0, 1))
        
        # Send PARAMS
        params = {
            'SCRIPT_NAME': status_path,
            'SCRIPT_FILENAME': status_path,
            'REQUEST_METHOD': 'GET',
            'QUERY_STRING': 'json&full',
            'SERVER_PROTOCOL': 'HTTP/1.1',
            'GATEWAY_INTERFACE': 'CGI/1.1',
            'SERVER_SOFTWARE': 'clipal-agent',
        }
        params_data = _encode_params(params)
        sock.sendall(_build_record(FCGI_PARAMS, params_data, 1))
        sock.sendall(_build_record(FCGI_PARAMS, b'', 1))  # Empty PARAMS to signal end
        
        # Send empty STDIN
        sock.sendall(_build_record(FCGI_STDIN, b'', 1))
        
        # Read response records
        stdout_data = b''
        stderr_data = b''
        
        while True:
            record = _read_record(sock)
            
            if record.type == FCGI_STDOUT:
                stdout_data += record.content
            elif record.type == FCGI_STDERR:
                stderr_data += record.content
            elif record.type == FCGI_END_REQUEST:
                break
            # Ignore other record types
        
    finally:
        sock.close()
    
    # Log stderr if any (but don't fail)
    if stderr_data:
        # Note: We can't access logger here, caller should handle
        pass
    
    # Parse HTTP-style response
    # PHP-FPM returns: "Status: 200 OK\r\nContent-Type: ...\r\n\r\n{json}"
    if not stdout_data:
        raise FastCGIError("Empty response from PHP-FPM")
    
    # Split headers and body
    response_text = stdout_data.decode('utf-8', errors='replace')
    
    if '\r\n\r\n' in response_text:
        headers_part, body = response_text.split('\r\n\r\n', 1)
    elif '\n\n' in response_text:
        headers_part, body = response_text.split('\n\n', 1)
    else:
        # No headers, assume entire response is body
        body = response_text
    
    # Check for error status in headers
    if 'Status: 404' in response_text or 'File not found' in response_text:
        raise FastCGIError(f"Status page not found. Ensure pm.status_path = {status_path} is enabled in PHP-FPM config")
    
    if 'Access denied' in response_text:
        raise FastCGIError("Access denied. Check pm.status_listen in PHP-FPM config")
    
    # Parse JSON body
    body = body.strip()
    if not body:
        raise FastCGIError("Empty status body from PHP-FPM")
    
    return json.loads(body)


# =============================================================================
# PHP-FPM Monitor Class
# =============================================================================

class PHPMonitor:
    """PHP-FPM monitoring class

    Collects metrics from PHP-FPM status page via FastCGI and monitors slowlog files.
    """

    def __init__(self, config: dict, logger):
        """Initialize PHP-FPM monitor

        Args:
            config: Configuration dict with php_* settings
            logger: Logger instance
        """
        self.config = config
        self.logger = logger
        self._available = False
        self._pools = []
        self._legacy_config_warned = False

        # Parse pool configuration
        self._init_pools()

        # Track slowlog file positions for tailing
        # Format: {log_path: {'pos': int, 'last_access': float}}
        self._slowlog_positions = {}
        
        # Max entries to prevent unbounded growth (cleanup stale entries)
        self._max_slowlog_entries = 100

        # Check availability
        self._check_availability()

    def _init_pools(self):
        """Initialize pool configurations from config
        
        Supports three config formats:
        1. Multi-pool JSON: php_fpm_pools=[{...}, {...}]
        2. Single pool with socket: php_fpm_socket=unix:///path
        3. Legacy HTTP URL (deprecated): php_fpm_status_url=http://...
        """
        pools_json = self.config.get('php_fpm_pools', '')

        if pools_json:
            # Multi-pool configuration
            try:
                pools = json.loads(pools_json)
                # Validate each pool has required fields
                for pool in pools:
                    if 'socket' not in pool:
                        self.logger.error(f"PHP-FPM: Pool '{pool.get('name', 'unnamed')}' missing 'socket' field")
                        continue
                    # Default status_path if not specified
                    if 'status_path' not in pool:
                        pool['status_path'] = '/status'
                    self._pools.append(pool)
                
                if self._pools:
                    self.logger.info(f"PHP-FPM: Configured {len(self._pools)} pools")
            except json.JSONDecodeError as e:
                self.logger.error(f"PHP-FPM: Invalid pools JSON config: {e}")
                self._pools = []
        else:
            # Single pool configuration
            socket_uri = self.config.get('php_fpm_socket', '')
            status_path = self.config.get('php_fpm_status_path', '/status')
            slow_log = self.config.get('php_fpm_slow_log', '')
            
            if socket_uri:
                self._pools = [{
                    'name': 'www',
                    'socket': socket_uri,
                    'status_path': status_path,
                    'slow_log': slow_log
                }]
            else:
                # Check for legacy HTTP URL config
                legacy_url = self.config.get('php_fpm_status_url', '')
                if legacy_url and not self._legacy_config_warned:
                    self.logger.error("=" * 60)
                    self.logger.error("CRITICAL: Legacy PHP configuration detected!")
                    self.logger.error(f"  Found: php_fpm_status_url={legacy_url}")
                    self.logger.error("  The HTTP URL method is no longer supported.")
                    self.logger.error("  Please re-run the installer to configure socket access:")
                    self.logger.error("    curl -sSL https://clipal.me/install.sh | sudo bash -s -- \\")
                    self.logger.error("      --token=YOUR_TOKEN --enable-php-monitoring")
                    self.logger.error("=" * 60)
                    self._legacy_config_warned = True
                    # Don't set _pools - PHP monitoring will be disabled

    def _check_availability(self):
        """Check if PHP-FPM is accessible via FastCGI"""
        if not self._pools:
            self.logger.warn("PHP-FPM: No pools configured")
            self._available = False
            return

        # Check all pools and log their status
        accessible_count = 0
        for pool in self._pools:
            try:
                status = self._fetch_status(pool['socket'], pool.get('status_path', '/status'))
                if status:
                    self.logger.info(f"PHP-FPM: Pool '{pool['name']}' is accessible via FastCGI")
                    accessible_count += 1
                else:
                    self.logger.warn(f"PHP-FPM: Pool '{pool['name']}' returned empty status")
            except FastCGIError as e:
                self.logger.warn(f"PHP-FPM: Pool '{pool['name']}' not accessible: {e}")
            except Exception as e:
                self.logger.warn(f"PHP-FPM: Pool '{pool['name']}' error: {e}")

        if accessible_count > 0:
            self._available = True
        else:
            self.logger.warn("PHP-FPM: No pools accessible, monitoring disabled")

    def is_available(self) -> bool:
        """Check if PHP-FPM monitoring is available

        Returns:
            True if at least one pool is accessible
        """
        return self._available

    def _fetch_status(self, socket_uri: str, status_path: str = '/status', timeout: int = 5) -> Optional[Dict]:
        """Fetch PHP-FPM status via FastCGI

        Args:
            socket_uri: Socket URI (unix:// or tcp://)
            status_path: PHP-FPM status path
            timeout: Request timeout in seconds

        Returns:
            Status dict or None if failed
        """
        try:
            return fetch_status_via_fastcgi(socket_uri, status_path, timeout)
        except FastCGIError as e:
            self.logger.warn(f"PHP-FPM FastCGI error: {e}")
            return None
        except json.JSONDecodeError as e:
            self.logger.warn(f"PHP-FPM status JSON parse error: {e}")
            return None

    def collect_metrics(self) -> Dict[str, Any]:
        """Collect PHP-FPM metrics from all configured pools

        Returns:
            Dict with pool metrics:
            {
                'pools': [
                    {
                        'name': 'www',
                        'pool': 'www',
                        'start_time': 1234567890,
                        'accepted_conn': 12345,
                        'listen_queue': 0,
                        'active_processes': 5,
                        'idle_processes': 3,
                        'total_processes': 8,
                        'max_active_processes': 10,
                        'max_children_reached': 0,
                        'slow_requests': 0
                    },
                    ...
                ],
                'collected_at': 1234567890
            }
        """
        if not self._available:
            return {}

        result = {
            'pools': [],
            'collected_at': int(time.time())
        }

        for pool_config in self._pools:
            status = self._fetch_status(pool_config['socket'], pool_config.get('status_path', '/status'))
            if status:
                # Add our config name for reference
                status['config_name'] = pool_config['name']
                result['pools'].append(status)
            else:
                # Pool temporarily unavailable, log but continue
                self.logger.debug(f"PHP-FPM: Pool '{pool_config['name']}' status unavailable")

        return result

    def collect_slow_traces(self) -> List[Dict[str, Any]]:
        """Collect new slow request traces from all pool slowlogs

        Returns:
            List of slow trace dicts:
            [
                {
                    'pool_name': 'www',
                    'occurred_at': '2025-12-13 10:23:15',
                    'script': '/var/www/html/index.php',
                    'raw_trace': '...',
                    'trace_hash': 'abc123...'
                },
                ...
            ]
        """
        if not self._available:
            return []

        traces = []

        for pool_config in self._pools:
            slow_log = pool_config.get('slow_log', '')
            if not slow_log:
                continue

            pool_traces = self._tail_slowlog(pool_config['name'], slow_log)
            traces.extend(pool_traces)

        return traces

    def _tail_slowlog(self, pool_name: str, log_path: str) -> List[Dict[str, Any]]:
        """Tail a slowlog file for new entries

        Args:
            pool_name: Name of the pool
            log_path: Path to slowlog file

        Returns:
            List of new slow trace dicts
        """
        traces = []

        if not os.path.exists(log_path):
            self.logger.debug(f"PHP-FPM: Slowlog not found: {log_path}")
            return traces

        try:
            # Check if we can read the file
            if not os.access(log_path, os.R_OK):
                self.logger.warn(f"PHP-FPM: Cannot read slowlog: {log_path}")
                return traces

            # Get current file size
            file_size = os.path.getsize(log_path)

            # Get last known position
            pos_entry = self._slowlog_positions.get(log_path, {'pos': 0, 'last_access': 0})
            last_pos = pos_entry.get('pos', 0) if isinstance(pos_entry, dict) else pos_entry

            # Handle log rotation (file got smaller)
            if file_size < last_pos:
                self.logger.info(f"PHP-FPM: Slowlog rotated: {log_path}")
                last_pos = 0

            # Nothing new to read
            if file_size == last_pos:
                return traces

            # Limit read size to prevent memory explosion (1MB max per cycle)
            max_read_size = 1024 * 1024  # 1MB
            bytes_to_read = min(file_size - last_pos, max_read_size)
            
            if file_size - last_pos > max_read_size:
                self.logger.warn(f"PHP-FPM: Slowlog {log_path} has {file_size - last_pos} bytes pending, reading only {max_read_size}")

            # Read new content with size limit
            with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                f.seek(last_pos)
                content = f.read(bytes_to_read)
                new_pos = f.tell()

            # Update position with timestamp for cleanup
            self._slowlog_positions[log_path] = {'pos': new_pos, 'last_access': time.time()}
            
            # Cleanup stale entries (not accessed in 24 hours)
            self._cleanup_stale_positions()

            # Parse the slowlog content
            traces = self._parse_slowlog(pool_name, content)

        except Exception as e:
            self.logger.error(f"PHP-FPM: Error reading slowlog {log_path}: {e}")

        return traces

    def _parse_slowlog(self, config_pool_name: str, content: str) -> List[Dict[str, Any]]:
        """Parse PHP-FPM slowlog content

        Slowlog format:
        [13-Dec-2025 10:23:15]  [pool www] pid 12345
        script_filename = /var/www/html/index.php
        [0x00007f...] sleep() /var/www/html/slow.php:10
        ...

        Args:
            config_pool_name: Fallback pool name from config
            content: Raw slowlog content

        Returns:
            List of parsed trace dicts
        """
        traces = []
        current_trace = None
        
        # Limit lines per trace to prevent memory issues
        max_trace_lines = 200

        for line in content.split('\n'):
            line = line.rstrip()
            
            # Skip lines that look like binary garbage (high ratio of non-printable chars)
            if line and not self._is_valid_log_line(line):
                continue

            # Start of a new trace entry
            if line.startswith('[') and '[pool ' in line and ' pid ' in line:
                # Save previous trace if exists
                if current_trace and (current_trace.get('lines') or current_trace.get('raw_trace')):
                    traces.append(self._finalize_trace(current_trace))

                # Parse header: [13-Dec-2025 10:23:15]  [pool www] pid 12345
                # Extract actual pool name from the header
                parsed_pool_name = self._parse_slowlog_pool_name(line) or config_pool_name
                
                current_trace = {
                    'pool_name': parsed_pool_name,
                    'occurred_at': self._parse_slowlog_timestamp(line),
                    'script': '',
                    'raw_trace': '',
                    'lines': []
                }

            elif current_trace is not None:
                # script_filename line
                if line.startswith('script_filename = '):
                    # Validate script path (no newlines, reasonable length)
                    script_path = line[18:].strip()
                    if len(script_path) < 512 and '\n' not in script_path:
                        current_trace['script'] = script_path
                # Stack trace line or other content
                elif line.strip() and len(current_trace['lines']) < max_trace_lines:
                    current_trace['lines'].append(line)

        # Don't forget the last trace
        if current_trace and (current_trace.get('lines') or current_trace.get('raw_trace')):
            traces.append(self._finalize_trace(current_trace))

        return traces

    def _parse_slowlog_timestamp(self, header_line: str) -> str:
        """Parse timestamp from slowlog header

        Args:
            header_line: Line like "[13-Dec-2025 10:23:15]  [pool www] pid 12345"

        Returns:
            Formatted timestamp string or empty string
        """
        try:
            # Extract timestamp between first [ and ]
            start = header_line.find('[') + 1
            end = header_line.find(']')
            if start > 0 and end > start:
                ts_str = header_line[start:end]
                # Convert "13-Dec-2025 10:23:15" to "2025-12-13 10:23:15"
                # For now, return as-is since it's human readable
                # Could parse with datetime if strict format needed
                return ts_str
        except Exception:
            pass
        return ''

    def _parse_slowlog_pool_name(self, header_line: str) -> str:
        """Parse pool name from slowlog header

        Args:
            header_line: Line like "[13-Dec-2025 10:23:15]  [pool www] pid 12345"

        Returns:
            Pool name or empty string if not found
        """
        try:
            # Extract pool name from "[pool xxx]"
            pool_start = header_line.find('[pool ')
            if pool_start >= 0:
                pool_start += 6  # Length of "[pool "
                pool_end = header_line.find(']', pool_start)
                if pool_end > pool_start:
                    return header_line[pool_start:pool_end].strip()
        except Exception:
            pass
        return ''

    def _finalize_trace(self, trace: Dict) -> Dict[str, Any]:
        """Finalize a trace entry with hash

        Args:
            trace: Trace dict with 'lines' list

        Returns:
            Finalized trace dict
        """
        # Build raw trace from lines
        trace['raw_trace'] = '\n'.join(trace.get('lines', []))

        # Generate hash for deduplication
        hash_input = f"{trace['script']}:{trace['raw_trace']}"
        trace['trace_hash'] = hashlib.md5(hash_input.encode('utf-8')).hexdigest()

        # Remove temporary 'lines' field
        trace.pop('lines', None)

        # Handle empty traces
        if not trace['raw_trace']:
            trace['raw_trace'] = '(no trace captured)'

        return trace
    
    def _is_valid_log_line(self, line: str) -> bool:
        """Check if a log line looks valid (not binary garbage)
        
        Detect binary garbage that could crash the parser.
        
        Args:
            line: Line from slowlog
            
        Returns:
            True if line appears to be valid text
        """
        if not line:
            return True  # Empty lines are fine
            
        # Count non-printable characters (excluding common whitespace)
        non_printable = sum(1 for c in line if ord(c) < 32 and c not in '\t\r\n')
        
        # If more than 10% non-printable, it's probably garbage
        if non_printable / len(line) > 0.1:
            return False
            
        # Check for null bytes (definite binary indicator)
        if '\x00' in line:
            return False
            
        return True
    
    def _cleanup_stale_positions(self) -> None:
        """Clean up stale slowlog position entries to prevent memory growth
        
        Removes entries not accessed in 24 hours, and enforces max entry limit.
        """
        if len(self._slowlog_positions) <= self._max_slowlog_entries:
            return
            
        current_time = time.time()
        stale_threshold = 24 * 60 * 60  # 24 hours
        
        # Find stale entries
        stale_paths = [
            path for path, entry in self._slowlog_positions.items()
            if isinstance(entry, dict) and current_time - entry.get('last_access', 0) > stale_threshold
        ]
        
        # Remove stale entries
        for path in stale_paths:
            del self._slowlog_positions[path]
            self.logger.debug(f"PHP-FPM: Cleaned up stale slowlog position for {path}")
        
        # If still over limit, remove oldest entries
        if len(self._slowlog_positions) > self._max_slowlog_entries:
            # Sort by last_access, remove oldest
            sorted_entries = sorted(
                self._slowlog_positions.items(),
                key=lambda x: x[1].get('last_access', 0) if isinstance(x[1], dict) else 0
            )
            to_remove = len(self._slowlog_positions) - self._max_slowlog_entries
            for path, _ in sorted_entries[:to_remove]:
                del self._slowlog_positions[path]
                self.logger.debug(f"PHP-FPM: Evicted slowlog position for {path} (limit reached)")
