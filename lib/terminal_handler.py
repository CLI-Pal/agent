"""
CLI Pal Agent - Terminal Handler Module

PTY terminal management for shell sessions.
SECURITY: Always requires login authentication - no bypass.
"""

import os
import sys
import pty
import select
import struct
import fcntl
import termios
import asyncio
from typing import Optional


class TerminalHandler:
    """PTY terminal management

    Security: ALWAYS requires login authentication.
    No bypass - shell only starts after successful login.
    """

    def __init__(self, websocket_client, logger):
        """Initialize terminal handler

        Args:
            websocket_client: WebSocket client for sending output
            logger: Logger instance
        """
        self.ws = websocket_client
        self.logger = logger
        self.master_fd: Optional[int] = None
        self.rows = 24
        self.cols = 80
        self.running = True

    async def start_shell(self, cols: int, rows: int) -> None:
        """Start authenticated shell session

        Args:
            cols: Terminal columns
            rows: Terminal rows
        """
        if self.master_fd is not None:
            self.logger.warn("Shell already running")
            return

        self.cols = cols
        self.rows = rows

        self.logger.info(f"Starting authenticated shell ({cols}x{rows})...", always=True)

        # Fork a PTY
        pid, self.master_fd = pty.fork()

        if pid == 0:  # Child process
            # Set up environment
            os.environ['TERM'] = 'xterm-256color'
            os.environ['COLORTERM'] = 'truecolor'

            # SECURITY: Always start login program - requires username/password
            login_paths = ['/bin/login', '/usr/bin/login']
            login_found = False

            for login_path in login_paths:
                if os.path.exists(login_path):
                    try:
                        os.execv(login_path, [login_path])
                        login_found = True
                        break
                    except Exception as e:
                        print(f"Failed to start {login_path}: {e}", file=sys.stderr)
                        continue

            if not login_found:
                # Fallback: use su (still requires password)
                print("Warning: /bin/login not found, falling back to su", file=sys.stderr)
                if os.path.exists('/bin/su'):
                    os.execv('/bin/su', ['/bin/su', '-'])
                else:
                    # Exit with error - do NOT start unauthenticated shell
                    print("SECURITY ERROR: No authentication method available", file=sys.stderr)
                    print("Cannot start shell without authentication", file=sys.stderr)
                    sys.exit(1)

        else:  # Parent process
            # Set terminal size
            self._set_terminal_size(self.master_fd, rows, cols)

            # Make fd non-blocking
            flags = fcntl.fcntl(self.master_fd, fcntl.F_GETFL)
            fcntl.fcntl(self.master_fd, fcntl.F_SETFL, flags | os.O_NONBLOCK)

            # Start reading from shell
            asyncio.create_task(self._read_loop())

            self.logger.info("Login prompt started - authentication required", always=True)

    async def _read_loop(self) -> None:
        """Read output from shell and send to WebSocket"""
        while self.master_fd is not None and self.running:
            try:
                readable, _, _ = select.select([self.master_fd], [], [], 0.1)

                if readable:
                    data = os.read(self.master_fd, 8192)
                    if data:
                        await self.ws.send_output(data.decode('utf-8', errors='replace'))
                    else:
                        # EOF - shell closed
                        self.logger.info("Shell closed", always=True)
                        self.master_fd = None
                        break
                else:
                    await asyncio.sleep(0.01)

            except OSError as e:
                if e.errno == 5:  # EIO - process exited
                    self.logger.info("Shell process exited", always=True)
                    self.master_fd = None
                    break
                else:
                    self.logger.error(f"Error reading from shell: {e}")
                    await asyncio.sleep(0.1)
            except Exception as e:
                self.logger.error(f"Unexpected error reading shell: {e}")
                break

    async def write_to_shell(self, data: str) -> None:
        """Write input to shell

        Args:
            data: Input string to write
        """
        if self.master_fd is None:
            self.logger.warn("No shell running")
            return

        try:
            os.write(self.master_fd, data.encode('utf-8'))
        except Exception as e:
            self.logger.error(f"Error writing to shell: {e}")

    async def resize(self, cols: int, rows: int) -> None:
        """Resize terminal

        Args:
            cols: New column count
            rows: New row count
        """
        if self.master_fd is None:
            return

        self.cols = cols
        self.rows = rows
        self._set_terminal_size(self.master_fd, rows, cols)
        self.logger.debug(f"Terminal resized to {cols}x{rows}")

    def _set_terminal_size(self, fd: int, rows: int, cols: int) -> None:
        """Set PTY terminal size

        Args:
            fd: File descriptor
            rows: Row count
            cols: Column count
        """
        try:
            size = struct.pack('HHHH', rows, cols, 0, 0)
            fcntl.ioctl(fd, termios.TIOCSWINSZ, size)
        except Exception as e:
            self.logger.error(f"Error setting terminal size: {e}")

    def close(self) -> None:
        """Close the terminal"""
        self.running = False
        if self.master_fd:
            try:
                os.close(self.master_fd)
            except Exception:
                pass
            self.master_fd = None
