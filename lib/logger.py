"""
CLI Pal Agent - Logger Module

Centralized logging utilities for the agent.
"""

import sys
from datetime import datetime


class Logger:
    """Simple logger for CLI Pal agent

    Provides consistent logging format across all modules.
    Debug messages are suppressed unless debug mode is enabled.
    """

    def __init__(self, debug: bool = False, component: str = "Agent"):
        """Initialize logger

        Args:
            debug: Enable debug logging
            component: Component name for log prefix
        """
        self.debug_enabled = debug
        self.component = component

    def _log(self, level: str, message: str, always: bool = False) -> None:
        """Internal log method

        Args:
            level: Log level (DEBUG, INFO, WARN, ERROR)
            message: Log message
            always: If True, log even when debug is disabled
        """
        if not always and not self.debug_enabled and level == "DEBUG":
            return

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] [{self.component}] {level}: {message}", flush=True)

    def debug(self, message: str) -> None:
        """Debug message (only if debug enabled)"""
        self._log("DEBUG", message)

    def info(self, message: str, always: bool = False) -> None:
        """Info message

        Args:
            message: Log message
            always: If True, log even when debug is disabled
        """
        self._log("INFO", message, always)

    def warn(self, message: str) -> None:
        """Warning message (always logged)"""
        self._log("WARN", message, always=True)

    def error(self, message: str) -> None:
        """Error message (always logged)"""
        self._log("ERROR", message, always=True)

    def create_child(self, component: str) -> 'Logger':
        """Create child logger with different component name

        Args:
            component: Component name for child logger

        Returns:
            New Logger instance with same debug setting
        """
        return Logger(self.debug_enabled, component)


def setup_logger(debug: bool = False, component: str = "Agent") -> Logger:
    """Setup and return root logger

    Args:
        debug: Enable debug logging
        component: Component name for log prefix

    Returns:
        Configured Logger instance
    """
    return Logger(debug=debug, component=component)
