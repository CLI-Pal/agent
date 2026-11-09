"""
Tests for upload behaviour: retry policy, Retry-After, too-soon answers and gzip
(lib/api_client.py), and schema change tracking (agent.py).

No server or third-party packages are needed (see agent_test_support).
"""

import asyncio
import email.message
import gzip
import io
import json
import unittest
import urllib.error
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from unittest import mock

from agent_test_support import FakeLogger

import lib.api_client as api_client_module  # noqa: E402
from lib.api_client import MetricsAPIClient  # noqa: E402
import agent as agent_module  # noqa: E402


# ---------------------------------------------------------------------------
# Fake transport
# ---------------------------------------------------------------------------

class FakeResponse:
    def __init__(self, body=None, status=200):
        self.status = status
        self._body = json.dumps({'success': True} if body is None else body).encode()

    def read(self):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def http_error(code, retry_after=None):
    headers = email.message.Message()
    if retry_after is not None:
        headers['Retry-After'] = str(retry_after)
    return urllib.error.HTTPError('https://app.example/api', code, 'error', headers, io.BytesIO(b''))


READ_TIMEOUT = TimeoutError('The read operation timed out')
WRITE_TIMEOUT = urllib.error.URLError(TimeoutError('The write operation timed out'))


class Transport:
    """Replaces urlopen with scripted outcomes and records requests and sleeps"""

    def __init__(self, *outcomes):
        self.outcomes = list(outcomes)
        self.requests = []
        self.sleeps = []
        self.now = 1000.0

    def urlopen(self, req, timeout=None):
        self.requests.append(req)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds

    def monotonic(self):
        return self.now

    def body(self, index):
        req = self.requests[index]
        data = req.data
        if req.get_header('Content-encoding') == 'gzip':
            data = gzip.decompress(data)
        return json.loads(data)


class ClientTestCase(unittest.TestCase):

    def setUp(self):
        self.logger = FakeLogger()
        self.client = MetricsAPIClient('wss://app.example/ws', 'token', '0.1.3', self.logger)

    def run_with(self, transport, call, *args):
        with mock.patch.object(api_client_module.urllib.request, 'urlopen', transport.urlopen), \
                mock.patch.object(api_client_module.time, 'sleep', transport.sleep), \
                mock.patch.object(api_client_module.time, 'monotonic', transport.monotonic):
            return call(*args)


# ---------------------------------------------------------------------------
# Retry policy
# ---------------------------------------------------------------------------

class RetryPolicyTests(ClientTestCase):

    def test_metrics_read_timeout_is_not_retried(self):
        # The reported pattern: retrying this is what produced the 429s
        t = Transport(READ_TIMEOUT)
        self.assertFalse(self.run_with(t, self.client.send_metrics, {'cpu': 1}))
        self.assertEqual(len(t.requests), 1)
        self.assertEqual(t.sleeps, [])
        self.assertTrue(any('not retrying' in m for m in self.logger.messages('warn')))
        self.assertEqual(self.logger.messages('error'), [])

    def test_schema_read_timeout_is_not_retried(self):
        t = Transport(READ_TIMEOUT)
        self.assertFalse(self.run_with(t, self.client.send_schema_update, {'columns': []}, []))
        self.assertEqual(len(t.requests), 1)

    def test_deadlock_read_timeout_is_retried(self):
        t = Transport(READ_TIMEOUT, FakeResponse({'success': True, 'stored': True}))
        self.assertTrue(self.run_with(t, self.client.send_deadlock, {'section_hash': 'abc'}))
        self.assertEqual(len(t.requests), 2)
        self.assertTrue(2.5 <= t.sleeps[0] <= 5.0)

    def test_send_failure_is_retried_with_growing_jittered_backoff(self):
        # Write timeout / connection errors: the server never got the request
        t = Transport(WRITE_TIMEOUT, WRITE_TIMEOUT, FakeResponse())
        self.assertTrue(self.run_with(t, self.client.send_metrics, {'cpu': 1}))
        self.assertEqual(len(t.requests), 3)
        self.assertTrue(2.5 <= t.sleeps[0] <= 5.0)
        self.assertTrue(5.0 <= t.sleeps[1] <= 10.0)

    def test_gives_up_after_three_attempts(self):
        t = Transport(WRITE_TIMEOUT, WRITE_TIMEOUT, WRITE_TIMEOUT)
        self.assertFalse(self.run_with(t, self.client.send_metrics, {'cpu': 1}))
        self.assertEqual(len(t.requests), 3)
        self.assertIn('Failed to send to /api/v1/metrics after 3 attempts', self.logger.messages('error'))

    def test_server_error_on_metrics_is_not_retried(self):
        t = Transport(http_error(500))
        self.assertFalse(self.run_with(t, self.client.send_metrics, {'cpu': 1}))
        self.assertEqual(len(t.requests), 1)

    def test_server_error_on_deadlock_is_retried(self):
        t = Transport(http_error(500), FakeResponse())
        self.assertTrue(self.run_with(t, self.client.send_deadlock, {'section_hash': 'abc'}))
        self.assertEqual(len(t.requests), 2)

    def test_origin_unreachable_is_retried_for_metrics(self):
        t = Transport(http_error(522), http_error(503), FakeResponse())
        self.assertTrue(self.run_with(t, self.client.send_metrics, {'cpu': 1}))
        self.assertEqual(len(t.requests), 3)

    def test_auth_errors_are_not_retried(self):
        for code in (401, 403, 404):
            t = Transport(http_error(code))
            self.assertFalse(self.run_with(t, self.client.send_deadlock, {'section_hash': 'abc'}))
            self.assertEqual(len(t.requests), 1)

    def test_invalid_json_response_is_not_retried(self):
        response = FakeResponse()
        response._body = b'<html>oops</html>'
        t = Transport(response)
        self.assertFalse(self.run_with(t, self.client.send_metrics, {'cpu': 1}))
        self.assertEqual(len(t.requests), 1)


# ---------------------------------------------------------------------------
# 429, Retry-After and too-soon answers
# ---------------------------------------------------------------------------

class RateLimitTests(ClientTestCase):

    def test_429_is_not_retried_and_retry_after_is_honoured(self):
        t = Transport(http_error(429, retry_after=120), FakeResponse())
        self.assertFalse(self.run_with(t, self.client.send_metrics, {'cpu': 1}))
        self.assertEqual(len(t.requests), 1)
        self.assertEqual(t.sleeps, [])

        t.now += 60
        self.assertFalse(self.run_with(t, self.client.send_metrics, {'cpu': 1}))   # still waiting
        self.assertEqual(len(t.requests), 1)

        t.now += 61
        self.assertTrue(self.run_with(t, self.client.send_metrics, {'cpu': 1}))
        self.assertEqual(len(t.requests), 2)

    def test_429_without_retry_after_waits_a_minute(self):
        t = Transport(http_error(429), FakeResponse())
        self.run_with(t, self.client.send_metrics, {'cpu': 1})
        t.now += 59
        self.run_with(t, self.client.send_metrics, {'cpu': 1})
        self.assertEqual(len(t.requests), 1)
        t.now += 2
        self.assertTrue(self.run_with(t, self.client.send_metrics, {'cpu': 1}))

    def test_429_blocks_only_that_endpoint(self):
        t = Transport(http_error(429, retry_after=300), FakeResponse())
        self.run_with(t, self.client.send_schema_update, {'columns': []}, [])
        self.assertTrue(self.run_with(t, self.client.send_deadlock, {'section_hash': 'abc'}))

    def test_retry_after_http_date(self):
        future = datetime.now(timezone.utc) + timedelta(seconds=90)
        self.assertTrue(85 <= MetricsAPIClient._parse_retry_after(format_datetime(future, usegmt=True)) <= 90)
        self.assertEqual(MetricsAPIClient._parse_retry_after('Wed, 21 Oct 2015 07:28:00 GMT'), 0)
        self.assertEqual(MetricsAPIClient._parse_retry_after('120'), 120)
        self.assertIsNone(MetricsAPIClient._parse_retry_after('soon'))
        self.assertIsNone(MetricsAPIClient._parse_retry_after(None))

    def test_long_retry_after_on_503_does_not_hold_the_loop(self):
        t = Transport(http_error(503, retry_after=600))
        self.assertFalse(self.run_with(t, self.client.send_metrics, {'cpu': 1}))
        self.assertEqual(t.sleeps, [])

    def test_too_soon_answer_is_not_an_error_and_not_retried(self):
        t = Transport(FakeResponse({'success': True, 'stored': False, 'reason': 'too_soon', 'retry_after': 21}))
        self.assertFalse(self.run_with(t, self.client.send_metrics, {'cpu': 1}))
        self.assertEqual(len(t.requests), 1)
        self.assertEqual(self.logger.messages('error'), [])
        self.assertTrue(any('too soon' in m for m in self.logger.messages('info')))

    def test_duplicate_deadlock_counts_as_delivered(self):
        t = Transport(FakeResponse({'success': True, 'stored': False, 'reason': 'duplicate'}))
        self.assertTrue(self.run_with(t, self.client.send_deadlock, {'section_hash': 'abc'}))


# ---------------------------------------------------------------------------
# gzip
# ---------------------------------------------------------------------------

BIG = {'status': {'Var_%d' % i: str(i) for i in range(500)}}


class GzipTests(ClientTestCase):

    def test_not_compressed_until_server_says_it_accepts_gzip(self):
        t = Transport(FakeResponse())
        self.run_with(t, self.client.send_metrics, BIG)
        self.assertIsNone(t.requests[0].get_header('Content-encoding'))

    def test_large_body_is_gzipped_when_accepted(self):
        t = Transport(FakeResponse({'success': True, 'instructions': {'accepts_gzip': True}}), FakeResponse())
        self.run_with(t, self.client.send_metrics, BIG)
        self.run_with(t, self.client.send_metrics, BIG)
        self.assertEqual(t.requests[1].get_header('Content-encoding'), 'gzip')
        self.assertEqual(t.body(1), BIG)
        self.assertLess(len(t.requests[1].data), len(t.requests[0].data) / 3)

    def test_small_body_is_not_gzipped(self):
        self.client.instructions['accepts_gzip'] = True
        t = Transport(FakeResponse())
        self.run_with(t, self.client.send_deadlock, {'section_hash': 'abc'})
        self.assertIsNone(t.requests[0].get_header('Content-encoding'))

    def test_rejected_gzip_falls_back_to_plain_and_stays_off(self):
        self.client.instructions['accepts_gzip'] = True
        t = Transport(http_error(400), FakeResponse())
        self.assertTrue(self.run_with(t, self.client.send_metrics, BIG))
        self.assertEqual(t.requests[1].get_header('Content-encoding'), None)
        self.assertEqual(t.body(1), BIG)
        self.assertFalse(self.client.instructions['accepts_gzip'])
        self.assertEqual(t.sleeps, [])

    def test_instructions_without_gzip_flag_turn_it_off(self):
        self.client.instructions['accepts_gzip'] = True
        t = Transport(FakeResponse({'success': True, 'instructions': {'metrics_interval': 60}}))
        self.run_with(t, self.client.send_metrics, {'cpu': 1})
        self.assertFalse(self.client.instructions['accepts_gzip'])


# ---------------------------------------------------------------------------
# Schema change tracking
# ---------------------------------------------------------------------------

def column(table, name, position=1, schema='shop'):
    return {'TABLE_SCHEMA': schema, 'TABLE_NAME': table, 'COLUMN_NAME': name, 'ORDINAL_POSITION': position,
            'DATA_TYPE': 'int', 'COLUMN_TYPE': 'int(11)', 'COLUMN_KEY': '', 'IS_NULLABLE': 'NO'}


def index(table, name, column_name, cardinality=10, schema='shop'):
    return {'TABLE_SCHEMA': schema, 'TABLE_NAME': table, 'INDEX_NAME': name, 'NON_UNIQUE': 1,
            'SEQ_IN_INDEX': 1, 'COLUMN_NAME': column_name, 'COLLATION': 'A',
            'CARDINALITY': cardinality, 'INDEX_TYPE': 'BTREE'}


TABLES = {('shop', 'orders'), ('shop', 'users')}


def schema(orders_cardinality=10, extra_index=False):
    indexes = [index('orders', 'PRIMARY', 'id', orders_cardinality), index('users', 'PRIMARY', 'id')]
    if extra_index:
        indexes.append(index('orders', 'idx_user', 'user_id'))
    return {'columns': [column('orders', 'id'), column('orders', 'user_id', 2), column('users', 'id')],
            'indexes': indexes}


class SchemaUploadTrackerTests(unittest.TestCase):

    def setUp(self):
        self.tracker = agent_module.SchemaUploadTracker()

    def test_first_upload_sends_everything(self):
        upload = self.tracker.prepare(schema(), TABLES)
        self.assertEqual(upload['tables'], [['shop', 'orders'], ['shop', 'users']])
        self.assertEqual(len(upload['schema_info']['columns']), 3)
        self.assertEqual(len(upload['schema_info']['indexes']), 2)
        self.assertTrue(upload['full'])

    def test_unchanged_schema_is_not_uploaded_again(self):
        self.tracker.mark_uploaded(self.tracker.prepare(schema(), TABLES))
        self.assertIsNone(self.tracker.prepare(schema(), TABLES))

    def test_cardinality_changes_are_ignored(self):
        self.tracker.mark_uploaded(self.tracker.prepare(schema(), TABLES))
        self.assertIsNone(self.tracker.prepare(schema(orders_cardinality=99999), TABLES))

    def test_only_the_changed_table_is_uploaded(self):
        self.tracker.mark_uploaded(self.tracker.prepare(schema(), TABLES))
        upload = self.tracker.prepare(schema(extra_index=True), TABLES)
        self.assertEqual(upload['tables'], [['shop', 'orders']])
        self.assertEqual({r['TABLE_NAME'] for r in upload['schema_info']['columns']}, {'orders'})
        self.assertEqual(len(upload['schema_info']['indexes']), 2)
        self.assertFalse(upload['full'])

    def test_failed_upload_is_sent_again(self):
        self.tracker.prepare(schema(), TABLES)        # never marked as uploaded
        self.assertIsNotNone(self.tracker.prepare(schema(), TABLES))

    def test_tables_without_columns_are_skipped(self):
        upload = self.tracker.prepare(schema(), TABLES | {('shop', 'dropped')})
        self.assertNotIn(['shop', 'dropped'], upload['tables'])

    def test_bytes_table_names_are_matched(self):
        info = schema()
        for row in info['columns'] + info['indexes']:
            row['TABLE_SCHEMA'] = row['TABLE_SCHEMA'].encode()
            row['TABLE_NAME'] = bytearray(row['TABLE_NAME'].encode())
        self.assertEqual(len(self.tracker.prepare(info, TABLES)['tables']), 2)

    def test_everything_is_uploaded_again_once_a_day(self):
        clock = [1000.0]
        with mock.patch.object(agent_module.time, 'monotonic', lambda: clock[0]):
            self.tracker.mark_uploaded(self.tracker.prepare(schema(), TABLES))
            clock[0] += 23 * 3600
            self.assertIsNone(self.tracker.prepare(schema(), TABLES))
            clock[0] += 2 * 3600
            upload = self.tracker.prepare(schema(), TABLES)
            self.assertTrue(upload['full'])
            self.assertEqual(len(upload['tables']), 2)


class FakeMonitor:
    enabled = True

    def __init__(self):
        self.schema = schema()

    def get_query_stats(self, watched_digests=None):
        return [{'DIGEST': 'd1'}]

    def get_query_explains(self, query_stats):
        return [{'digest': 'd1'}], set(TABLES)

    def get_targeted_schema_info(self, tables):
        return self.schema


class FakeApi:
    def __init__(self, schema_results):
        self.instructions = {'collect_schema': True}
        self.schema_results = list(schema_results)
        self.schema_uploads = []

    def send_query_explains(self, explains):
        return True

    def send_schema_update(self, schema_info, tables, changed_only=False):
        self.schema_uploads.append((tables, changed_only))
        return self.schema_results.pop(0)


class CollectAndSendExplainsTests(unittest.TestCase):

    def make_agent(self, schema_results):
        agent = agent_module.CliPalAgent.__new__(agent_module.CliPalAgent)
        agent.logger = FakeLogger()
        agent.database_monitor = FakeMonitor()
        agent.api_client = FakeApi(schema_results)
        agent.schema_tracker = agent_module.SchemaUploadTracker()
        return agent

    def test_schema_is_uploaded_once_then_only_on_change(self):
        agent = self.make_agent([True, True])
        for _ in range(3):
            asyncio.run(agent._collect_and_send_explains())
        agent.database_monitor.schema = schema(extra_index=True)
        asyncio.run(agent._collect_and_send_explains())

        self.assertEqual(agent.api_client.schema_uploads, [
            ([['shop', 'orders'], ['shop', 'users']], True),
            ([['shop', 'orders']], True),
        ])

    def test_failed_schema_upload_is_retried_next_cycle(self):
        agent = self.make_agent([False, True])
        asyncio.run(agent._collect_and_send_explains())
        asyncio.run(agent._collect_and_send_explains())
        asyncio.run(agent._collect_and_send_explains())
        self.assertEqual(len(agent.api_client.schema_uploads), 2)


if __name__ == '__main__':
    unittest.main()
