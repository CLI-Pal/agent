"""
Tests for agent deadlock detection (lib/database/mysql_monitor.py) and delivery (agent.py).

No MySQL server or third-party packages are needed (see agent_test_support).
"""

import asyncio
import hashlib
import unittest

from agent_test_support import FakeLogger

from lib.database.mysql_monitor import MySQLMonitor  # noqa: E402
import agent as agent_module  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def innodb_status(deadlock_time='2026-11-09 10:12:13', thread_a=41, thread_b=42):
    """SHOW ENGINE INNODB STATUS text (MariaDB 10.11 layout) with one deadlock"""
    return (
        "=====================================\n"
        "2026-11-09 10:15:02 0x7f8a3c1fe700 INNODB MONITOR OUTPUT\n"
        "=====================================\n"
        "Per second averages calculated from the last 12 seconds\n"
        "-----------------\n"
        "BACKGROUND THREAD\n"
        "-----------------\n"
        "srv_master_thread loops: 1 srv_active, 0 srv_shutdown, 100 srv_idle\n"
        "------------------------\n"
        "LATEST DETECTED DEADLOCK\n"
        "------------------------\n"
        f"{deadlock_time} 0x7f8a3c0c1700\n"
        "*** (1) TRANSACTION:\n"
        "TRANSACTION 1234, ACTIVE 2 sec starting index read\n"
        "mysql tables in use 1, locked 1\n"
        "LOCK WAIT 3 lock struct(s), heap size 1128, 2 row lock(s)\n"
        f"MariaDB thread id {thread_a}, OS thread handle 140233, query id 900 localhost app Updating\n"
        "UPDATE accounts SET balance = balance - 10 WHERE id = 1\n"
        "*** WAITING FOR THIS LOCK TO BE GRANTED:\n"
        "RECORD LOCKS space id 5 page no 3 n bits 72 index PRIMARY of table `shop`.`accounts` "
        "trx id 1234 lock_mode X locks rec but not gap waiting\n"
        "*** (2) TRANSACTION:\n"
        "TRANSACTION 1235, ACTIVE 1 sec starting index read\n"
        "mysql tables in use 1, locked 1\n"
        "3 lock struct(s), heap size 1128, 2 row lock(s)\n"
        f"MariaDB thread id {thread_b}, OS thread handle 140234, query id 901 localhost app Updating\n"
        "UPDATE accounts SET balance = balance + 10 WHERE id = 2\n"
        "*** WAITING FOR THIS LOCK TO BE GRANTED:\n"
        "RECORD LOCKS space id 5 page no 3 n bits 72 index PRIMARY of table `shop`.`accounts` "
        "trx id 1235 lock_mode X locks rec but not gap waiting\n"
        "*** WE ROLL BACK TRANSACTION (2)\n"
        "------------\n"
        "TRANSACTIONS\n"
        "------------\n"
        "Trx id counter 1240\n"
    )


DEADLOCK_A = innodb_status('2026-07-29 21:00:00', 41, 42)
DEADLOCK_B = innodb_status('2026-11-09 10:12:13', 77, 78)


def section_hash(innodb_text):
    monitor = MySQLMonitor(user='u', password='p', logger=FakeLogger())
    section = monitor._extract_deadlock_section(innodb_text)
    return hashlib.md5(section.encode()).hexdigest()[:16]


HASH_A = section_hash(DEADLOCK_A)
HASH_B = section_hash(DEADLOCK_B)


def status(deadlocks, uptime):
    return {'Innodb_deadlocks': str(deadlocks), 'Uptime': str(uptime)}


def make_monitor(innodb=None):
    """MySQLMonitor whose INNODB STATUS read returns monitor.innodb (or raises it)"""
    logger = FakeLogger()
    monitor = MySQLMonitor(user='agent', password='secret', logger=logger)
    monitor.innodb = innodb
    monitor.fetches = 0

    def fake_fetch():
        monitor.fetches += 1
        if isinstance(monitor.innodb, Exception):
            raise monitor.innodb
        return monitor.innodb

    monitor._fetch_innodb_status = fake_fetch
    return monitor, logger


def pending_hashes(monitor):
    return [d['section_hash'] for d in monitor.get_pending_deadlocks()]


# ---------------------------------------------------------------------------
# Counter / reset handling
# ---------------------------------------------------------------------------

class DeadlockCounterTests(unittest.TestCase):

    def test_first_sample_with_zero_counter_only_takes_baseline(self):
        monitor, _ = make_monitor(DEADLOCK_A)
        self.assertIsNone(monitor.check_for_deadlock(status(0, 100)))
        self.assertEqual(monitor.fetches, 0)
        self.assertEqual(monitor.get_pending_deadlocks(), [])

    def test_counter_increase_queues_parsed_deadlock(self):
        monitor, logger = make_monitor(DEADLOCK_A)
        monitor.check_for_deadlock(status(0, 100))
        info = monitor.check_for_deadlock(status(1, 160))

        self.assertEqual(info['section_hash'], HASH_A)
        self.assertEqual(len(info['transactions']), 2)
        self.assertEqual(info['tables_involved'], 'shop.accounts')
        self.assertEqual(pending_hashes(monitor), [HASH_A])
        self.assertTrue(any('Deadlock detected' in m for m in logger.messages('warn')))

    def test_first_sample_with_nonzero_counter_checks_innodb_status(self):
        # Agent (re)start: the latest deadlock may never have been reported
        monitor, _ = make_monitor(DEADLOCK_A)
        monitor.check_for_deadlock(status(116, 8836422))
        self.assertEqual(monitor.fetches, 1)
        self.assertEqual(pending_hashes(monitor), [HASH_A])

    def test_deadlocks_after_db_restart_are_detected(self):
        # The reported bug: baseline 200, MariaDB restarts, counter climbs from 0.
        # The old code stayed silent until the counter passed 200 again.
        monitor, _ = make_monitor(DEADLOCK_A)
        monitor.check_for_deadlock(status(200, 9000000))
        monitor.mark_deadlock_reported(HASH_A)

        monitor.check_for_deadlock(status(0, 30))       # MariaDB restarted
        monitor.innodb = DEADLOCK_B
        info = monitor.check_for_deadlock(status(1, 90))

        self.assertIsNotNone(info)
        self.assertEqual(pending_hashes(monitor), [HASH_B])

    def test_restart_with_counter_already_above_zero_checks_innodb_status(self):
        monitor, logger = make_monitor(DEADLOCK_A)
        monitor.check_for_deadlock(status(200, 9000000))
        monitor.mark_deadlock_reported(HASH_A)

        monitor.innodb = DEADLOCK_B
        info = monitor.check_for_deadlock(status(116, 8836422))  # restart missed between samples

        self.assertEqual(info['section_hash'], HASH_B)
        self.assertTrue(any('reset' in m for m in logger.messages('warn')))

    def test_uptime_going_down_is_a_reset_even_if_counter_did_not_drop(self):
        monitor, _ = make_monitor(DEADLOCK_A)
        monitor.check_for_deadlock(status(3, 9000000))
        monitor.mark_deadlock_reported(HASH_A)

        monitor.innodb = DEADLOCK_B
        info = monitor.check_for_deadlock(status(3, 120))  # restarted, 3 new deadlocks since

        self.assertEqual(info['section_hash'], HASH_B)

    def test_restart_without_new_deadlocks_skips_innodb_status(self):
        monitor, _ = make_monitor(DEADLOCK_A)
        monitor.check_for_deadlock(status(5, 9000000))
        monitor.mark_deadlock_reported(HASH_A)
        fetches = monitor.fetches

        monitor.check_for_deadlock(status(0, 30))
        monitor.check_for_deadlock(status(0, 90))

        self.assertEqual(monitor.fetches, fetches)

    def test_already_reported_deadlock_is_not_queued_again(self):
        monitor, _ = make_monitor(DEADLOCK_A)
        monitor.check_for_deadlock(status(1, 100))
        monitor.mark_deadlock_reported(HASH_A)

        monitor.check_for_deadlock(status(0, 30))
        monitor.check_for_deadlock(status(1, 90))   # INNODB STATUS still shows A

        self.assertEqual(monitor.get_pending_deadlocks(), [])

    def test_missing_counter_is_ignored(self):
        monitor, _ = make_monitor(DEADLOCK_A)
        self.assertIsNone(monitor.check_for_deadlock({'Uptime': '100'}))
        self.assertIsNone(monitor.last_deadlock_count)
        self.assertEqual(monitor.fetches, 0)


# ---------------------------------------------------------------------------
# Delivery bookkeeping
# ---------------------------------------------------------------------------

class PendingDeadlockTests(unittest.TestCase):

    def test_deadlock_stays_pending_until_marked_reported(self):
        monitor, _ = make_monitor(DEADLOCK_A)
        monitor.check_for_deadlock(status(0, 100))
        monitor.check_for_deadlock(status(1, 160))

        # The POST failed: nothing was marked, later cycles keep it queued
        monitor.check_for_deadlock(status(1, 220))
        monitor._reset_deadlock_baseline()
        monitor.check_for_deadlock(status(1, 280))   # re-reads A, must not duplicate it
        self.assertEqual(pending_hashes(monitor), [HASH_A])

        monitor.mark_deadlock_reported(HASH_A)
        self.assertEqual(monitor.get_pending_deadlocks(), [])
        self.assertEqual(monitor.last_deadlock_hash, HASH_A)

    def test_pending_queue_is_bounded_and_drops_oldest(self):
        monitor, _ = make_monitor()
        monitor.check_for_deadlock(status(0, 100))
        limit = MySQLMonitor.MAX_PENDING_DEADLOCKS
        hashes = []
        for i in range(limit + 3):
            monitor.innodb = innodb_status(f'2026-11-09 10:{i:02d}:00')
            hashes.append(monitor.check_for_deadlock(status(i + 1, 160 + i))['section_hash'])

        self.assertEqual(pending_hashes(monitor), hashes[-limit:])

    def test_failed_innodb_status_read_is_retried_next_cycle(self):
        monitor, _ = make_monitor(RuntimeError('MySQL went away'))
        monitor.check_for_deadlock(status(0, 100))
        self.assertIsNone(monitor.check_for_deadlock(status(1, 160)))   # read fails
        self.assertIsNone(monitor.check_for_deadlock(status(1, 220)))   # retried, fails

        monitor.innodb = DEADLOCK_A
        info = monitor.check_for_deadlock(status(1, 280))              # retried, works

        self.assertEqual(monitor.fetches, 3)
        self.assertEqual(info['section_hash'], HASH_A)

    def test_innodb_status_read_gives_up_after_repeated_failures(self):
        monitor, _ = make_monitor(RuntimeError('Access denied; you need the PROCESS privilege'))
        limit = MySQLMonitor.MAX_DEADLOCK_CHECK_FAILURES
        monitor.check_for_deadlock(status(0, 100))
        for i in range(limit + 3):
            monitor.check_for_deadlock(status(1, 160 + 60 * i))
        self.assertEqual(monitor.fetches, limit)

        monitor.check_for_deadlock(status(2, 1000))   # next deadlock re-arms the check
        self.assertEqual(monitor.fetches, limit + 1)


# ---------------------------------------------------------------------------
# get_metrics() with a fake MySQL connection
# ---------------------------------------------------------------------------

class FakeServer:
    def __init__(self):
        self.up = True
        self.status = {'Innodb_deadlocks': '0', 'Uptime': '100', 'Threads_connected': '3'}
        self.innodb = ''
        self.innodb_reads = 0
        self.fail_size_query = False


class FakeCursor:
    def __init__(self, server):
        self.server = server
        self.rows = []

    def execute(self, sql, params=None):
        query = ' '.join(sql.split()).upper()
        if query.startswith('SHOW GLOBAL STATUS'):
            self.rows = [{'Variable_name': k, 'Value': v} for k, v in self.server.status.items()]
        elif query.startswith('SELECT VERSION()'):
            self.rows = [{'version': '10.11.5-MariaDB'}]
        elif query.startswith('SHOW GLOBAL VARIABLES'):
            self.rows = [{'Variable_name': 'max_connections', 'Value': '151'},
                         {'Variable_name': 'innodb_buffer_pool_size', 'Value': '134217728'}]
        elif 'AS SIZE_MB' in query:
            if self.server.fail_size_query:
                raise RuntimeError('information_schema query timed out')
            self.rows = [{'size_mb': 12.5}]
        elif 'AS TABLE_COUNT' in query:
            self.rows = [{'table_count': 3}]
        elif query.startswith('SHOW ENGINE INNODB STATUS'):
            self.server.innodb_reads += 1
            self.rows = [{'Type': 'InnoDB', 'Name': '', 'Status': self.server.innodb}]
        else:
            raise AssertionError('unexpected query: ' + sql)

    def fetchall(self):
        return list(self.rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def close(self):
        pass


class FakeConnection:
    def __init__(self, server):
        self.server = server
        self.open = True

    def cursor(self, dictionary=False):
        return FakeCursor(self.server)

    def is_connected(self):
        return self.open

    def close(self):
        self.open = False


class GetMetricsTests(unittest.TestCase):

    def make(self):
        server = FakeServer()
        monitor = MySQLMonitor(user='agent', password='secret', logger=FakeLogger())
        monitor._connect = lambda: FakeConnection(server) if server.up else None
        return server, monitor

    def test_deadlock_is_queued_not_returned_in_metrics(self):
        server, monitor = self.make()
        monitor.get_metrics()
        server.status.update(Innodb_deadlocks='1', Uptime='160')
        server.innodb = DEADLOCK_A

        metrics = monitor.get_metrics()

        self.assertNotIn('deadlock', metrics)
        self.assertEqual(metrics['status']['Innodb_deadlocks'], '1')
        self.assertEqual(pending_hashes(monitor), [HASH_A])

    def test_restart_with_failed_sample_in_between(self):
        server, monitor = self.make()
        server.status.update(Innodb_deadlocks='200', Uptime='9000000')
        server.innodb = DEADLOCK_A
        monitor.get_metrics()                       # agent start, latest deadlock queued
        monitor.mark_deadlock_reported(HASH_A)

        server.up = False                           # MariaDB restarting
        self.assertEqual(monitor.get_metrics(), {})
        self.assertIsNone(monitor.last_deadlock_count)

        server.up = True
        server.status.update(Innodb_deadlocks='0', Uptime='40')
        server.innodb = ''
        monitor.get_metrics()
        self.assertEqual(monitor.get_pending_deadlocks(), [])

        server.status.update(Innodb_deadlocks='1', Uptime='100')
        server.innodb = DEADLOCK_B
        monitor.get_metrics()
        self.assertEqual(pending_hashes(monitor), [HASH_B])

    def test_failure_after_the_deadlock_check_keeps_the_baseline(self):
        server, monitor = self.make()
        server.status.update(Innodb_deadlocks='3', Uptime='1000')
        server.innodb = DEADLOCK_A
        monitor.get_metrics()
        monitor.mark_deadlock_reported(HASH_A)
        reads = server.innodb_reads

        server.fail_size_query = True               # later query fails every cycle
        for uptime in ('1060', '1120', '1180'):
            server.status['Uptime'] = uptime
            monitor.get_metrics()

        self.assertEqual(monitor.last_deadlock_count, 3)
        self.assertEqual(server.innodb_reads, reads)   # no needless re-checks

        server.status.update(Innodb_deadlocks='4', Uptime='1240')
        server.innodb = DEADLOCK_B
        monitor.get_metrics()
        self.assertEqual(pending_hashes(monitor), [HASH_B])


# ---------------------------------------------------------------------------
# agent.py: deliver, then mark as reported
# ---------------------------------------------------------------------------

class FakeApiClient:
    def __init__(self, deadlock_results=None):
        self.instructions = {'query_stats_interval': 300}
        self.deadlock_results = list(deadlock_results or [])
        self.sent_deadlocks = []
        self.sent_metrics = []

    def send_deadlock(self, deadlock_info):
        self.sent_deadlocks.append(deadlock_info['section_hash'])
        return self.deadlock_results.pop(0) if self.deadlock_results else True

    def send_metrics(self, metrics):
        self.sent_metrics.append(metrics)
        return True


class FakeSystemMetrics:
    available = True

    def get_metrics(self):
        return {'cpu_usage': 1.0}

    def get_failed_logins(self, max_entries=50):
        return []


def make_agent(monitor, deadlock_results=None):
    agent = agent_module.CliPalAgent.__new__(agent_module.CliPalAgent)
    agent.logger = FakeLogger()
    agent.database_monitor = monitor
    agent.api_client = FakeApiClient(deadlock_results)
    agent.system_metrics = FakeSystemMetrics()
    agent.php_monitor = None
    agent.metrics_cycle_count = 0
    return agent


def monitor_with_pending(*innodb_texts):
    monitor, _ = make_monitor()
    monitor.check_for_deadlock(status(0, 100))
    for i, text in enumerate(innodb_texts):
        monitor.innodb = text
        monitor.check_for_deadlock(status(i + 1, 160 + i))
    return monitor


class FlushPendingDeadlocksTests(unittest.TestCase):

    def test_failed_send_keeps_deadlock_for_next_cycle(self):
        monitor = monitor_with_pending(DEADLOCK_A)
        agent = make_agent(monitor, deadlock_results=[False, True])

        asyncio.run(agent._flush_pending_deadlocks())
        self.assertEqual(pending_hashes(monitor), [HASH_A])
        self.assertIsNone(monitor.last_deadlock_hash)

        asyncio.run(agent._flush_pending_deadlocks())
        self.assertEqual(monitor.get_pending_deadlocks(), [])
        self.assertEqual(monitor.last_deadlock_hash, HASH_A)
        self.assertEqual(agent.api_client.sent_deadlocks, [HASH_A, HASH_A])

    def test_stops_at_first_failure_and_keeps_order(self):
        monitor = monitor_with_pending(DEADLOCK_A, DEADLOCK_B)
        agent = make_agent(monitor, deadlock_results=[True, False])

        asyncio.run(agent._flush_pending_deadlocks())
        self.assertEqual(pending_hashes(monitor), [HASH_B])

        asyncio.run(agent._flush_pending_deadlocks())
        self.assertEqual(agent.api_client.sent_deadlocks, [HASH_A, HASH_B, HASH_B])
        self.assertEqual(monitor.get_pending_deadlocks(), [])

    def test_send_metrics_retries_pending_deadlock_while_mysql_is_down(self):
        monitor = monitor_with_pending(DEADLOCK_A)
        monitor._connect = lambda: None              # this cycle's DB collection fails
        agent = make_agent(monitor, deadlock_results=[True])

        asyncio.run(agent._send_metrics())

        self.assertEqual(agent.api_client.sent_deadlocks, [HASH_A])
        self.assertEqual(monitor.get_pending_deadlocks(), [])
        self.assertNotIn('mysql', agent.api_client.sent_metrics[0])


if __name__ == '__main__':
    unittest.main()
