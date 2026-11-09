"""
Shared setup for the agent tests: puts the agent on sys.path and stubs modules
that are missing or POSIX-only, so the tests run anywhere without dependencies.

Works in both repos (same files in each):
    clipal-agent:  python -m unittest discover -s tests -v
    clipal:        python -m unittest discover -s tests/agent -v
"""

import os
import sys
import types


def _find_agent_dir():
    """Agent repo root, or public_html/downloads/agent in the clipal repo"""
    here = os.path.dirname(os.path.abspath(__file__))
    for candidate in (os.path.join(here, '..'),
                      os.path.join(here, '..', '..', 'public_html', 'downloads', 'agent')):
        if os.path.isfile(os.path.join(candidate, 'agent.py')):
            return os.path.abspath(candidate)
    raise RuntimeError('agent.py not found relative to ' + here)


AGENT_DIR = _find_agent_dir()
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)


def _stub_missing_modules():
    try:
        import mysql.connector  # noqa: F401
    except ImportError:
        connector = types.ModuleType('mysql.connector')

        class Error(Exception):
            def __init__(self, msg='', errno=None):
                super().__init__(msg)
                self.msg = msg
                self.errno = errno

        def connect(**kwargs):
            raise Error('no MySQL server in tests', 2003)

        connector.Error = Error
        connector.connect = connect
        mysql_pkg = types.ModuleType('mysql')
        mysql_pkg.connector = connector
        sys.modules['mysql'] = mysql_pkg
        sys.modules['mysql.connector'] = connector

    # agent.py imports these at module level (system metrics, terminal, websocket);
    # the tests use fakes instead
    for name in ('psutil', 'websockets', 'pty', 'fcntl', 'termios'):
        try:
            __import__(name)
        except ImportError:
            sys.modules[name] = types.ModuleType(name)


_stub_missing_modules()


class FakeLogger:
    def __init__(self):
        self.records = []

    def debug(self, message):
        self.records.append(('debug', message))

    def info(self, message, always=False):
        self.records.append(('info', message))

    def warn(self, message):
        self.records.append(('warn', message))

    def error(self, message):
        self.records.append(('error', message))

    def create_child(self, component):
        return self

    def messages(self, level):
        return [m for lvl, m in self.records if lvl == level]
