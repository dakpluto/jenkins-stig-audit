"""Active evidence must correlate SQL outcomes with this run's server records."""
import copy
import csv
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from test_postgres_stig import pg, hardened, SETTINGS, by_id

SCRIPT = Path(__file__).resolve().parents[1] / 'roles/postgres_stig_audit/files/active_probe.py'
SPEC = importlib.util.spec_from_file_location('active_probe', SCRIPT)
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)


def event(name='insert', denied=False):
    return dict(name=name, marker='stig_token_' + name, application='stig_token_' + name,
                session=dict(pid=123, role='stig_audit', database='appdb'), client='expected', denied=denied,
                audit_class='WRITE', command='INSERT',
                sql='/*stig_token_%s*/ INSERT INTO s.allowed VALUES (1);' % name)


def record(e, **changes):
    audit = io.StringIO()
    csv.writer(audit).writerow(['SESSION', '2', '1', e['audit_class'], e['command'], 'TABLE', 's.allowed',
                              e['sql'], '<not logged>'])
    r = dict(pid='123', user='stig_audit', database='appdb', application=e['application'], code='00000',
             severity='LOG', time='2026-10-20 12:00:00 UTC', session='abc',
             message='AUDIT: ' + audit.getvalue().strip(), statement='', raw='matching log', source='/logs/db.log')
    r.update(changes)
    return r


class CorrelationTests(unittest.TestCase):
    def test_success_requires_actual_statement_command_class_and_client_outcome(self):
        e = event()
        r = record(e)
        self.assertEqual(probe.correlate(e, [r], True)['state'], 'verified')
        for field, value in [('pid', '124'), ('user', 'someone'), ('database', 'other'),
                             ('application', 'old_run'), ('code', '42501'), ('message', 'AUDIT: unrelated')]:
            with self.subTest(field=field):
                self.assertEqual(probe.correlate(e, [dict(r, **{field: value})], True)['state'], 'missing_log')
        r['message'] = r['message'].replace('INSERT INTO', 'old_token INSERT INTO').replace(e['marker'], 'old_token')
        self.assertEqual(probe.correlate(e, [r], True)['state'], 'missing_log')
        e['client'] = 'unexpected'  # An attempted/rolled-back statement alone proves nothing.
        self.assertEqual(probe.correlate(e, [record(e)], True)['state'], 'incomplete')

    def test_completion_select_cannot_substitute_for_the_actual_read(self):
        e = event('read')
        e.update(audit_class='READ', command='SELECT', sql='/*%s*/ SELECT marker FROM s.allowed;' % e['marker'])
        done = dict(e, sql="SELECT 'STIG_DONE:%s';" % e['marker'])
        self.assertEqual(probe.correlate(e, [record(done)], True)['state'], 'missing_log')

    def test_denial_needs_matching_statement_and_error(self):
        e = event('denied_read', True)
        error = record(e, severity='ERROR', code='42501', message='permission denied', raw='error')
        statement = record(e, severity='STATEMENT', message=e['sql'], raw='sql')
        self.assertEqual(probe.correlate(e, [error], True)['state'], 'missing_log')
        self.assertEqual(probe.correlate(e, [statement], True)['state'], 'missing_log')
        self.assertEqual(probe.correlate(e, [error, statement], True)['state'], 'verified')
        error['pid'] = '999'
        self.assertEqual(probe.correlate(e, [error, statement], True)['state'], 'missing_log')
        # Structured logs contain the error and SQL in one record.
        error.update(pid='123', statement=statement['message'])
        self.assertEqual(probe.correlate(e, [error], True)['state'], 'verified')

    def test_missing_logs_are_not_failures_when_collection_is_incomplete(self):
        self.assertEqual(probe.correlate(event(), [], False)['state'], 'incomplete')
        self.assertEqual(probe.correlate(event(), [], True)['state'], 'missing_log')

    def test_connection_logs_require_real_session_and_timestamp(self):
        for name, message in [('connect', 'connection authorized: user=stig_audit database=appdb'),
                              ('disconnect', 'disconnection: session time: 0:00:01')]:
            e = event(name)
            r = record(e, message=message)
            self.assertEqual(probe.correlate(e, [r], True)['state'], 'verified')
            r['time'] = ''
            self.assertEqual(probe.correlate(e, [r], True)['state'], 'missing_log')


class LogParsingTests(unittest.TestCase):
    def test_json_and_csv_fields_include_identity_statement_and_sqlstate(self):
        r = dict(timestamp='now', user='stig_audit', dbname='appdb', pid=123, application_name='test',
                 state_code='42501', error_severity='ERROR', message='permission denied',
                 statement='SELECT secret', session_id='session')
        rows, errors = probe.parse_records(json.dumps(r), 'jsonlog')
        self.assertFalse(errors)
        self.assertEqual((rows[0]['code'], rows[0]['statement']), ('42501', 'SELECT secret'))
        fields = [''] * 26
        for index, value in {0: 'now', 1: 'stig_audit', 2: 'appdb', 3: '123', 5: 'session',
                             11: 'ERROR', 12: '42501', 13: 'permission denied',
                             19: 'SELECT\nsecret', 22: 'test'}.items():
            fields[index] = value
        rows, errors = probe.parse_records(probe.next_csv_line(fields), 'csvlog')
        self.assertFalse(errors)
        self.assertEqual(rows[0]['statement'], 'SELECT\nsecret')

    def test_text_prefix_with_sqlstate_and_multiline_limit(self):
        prefix = '< %m %u %d [%p] %a %e: > '
        text = '< 2026-10-20 12:00:00 UTC stig_audit appdb [123] run1 42501: > ERROR:  permission denied'
        rows, errors = probe.parse_records(text, 'stderr', prefix)
        self.assertFalse(errors)
        self.assertEqual(rows[0]['pid'], '123')
        self.assertEqual(rows[0]['user'], 'stig_audit')
        self.assertEqual(rows[0]['database'], 'appdb')
        self.assertEqual(rows[0]['application'], 'run1')
        self.assertEqual(rows[0]['code'], '42501')
        self.assertTrue(probe.parse_records(text + '\ncontinuation', 'stderr', prefix)[1])
        self.assertTrue(probe.parse_records(text, 'stderr', '%m ')[1])

    def test_log_offsets_rotation_and_byte_limit(self):
        with tempfile.TemporaryDirectory() as temp:
            p = Path(temp) / 'current.json'
            p.write_text('{"pid":999,"message":"old"}\n')
            reader = probe.LogReader({'jsonlog': str(p)}, temp, '', 4096)
            with p.open('a') as f:
                f.write('{"pid":123,"message":"new"}\n')
            rows, complete, errors = reader.read()
            self.assertTrue(complete, errors)
            self.assertEqual([r['pid'] for r in rows], ['123'])
            # A new rotated filename is read from its beginning.
            (Path(temp) / 'next.json').write_text('{"pid":124,"message":"rotated"}\n')
            rows, complete, errors = reader.read()
            self.assertTrue(complete, errors)
            self.assertEqual({r['pid'] for r in rows}, {'123', '124'})
            reader.max_bytes = 1
            self.assertFalse(reader.read()[1])


class RunnerLifecycleTests(unittest.TestCase):
    def test_complete_run_correlates_appended_logs_and_cleans_fixtures(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / 'server.json'
            path.touch()
            def backend(argv, sql):
                if 'STIG_INFO:' in sql:
                    info = dict(role_ok=True, database_ok=True, postmaster='100', pgdata=temp, prefix='',
                                sources={'jsonlog': str(path)})
                    return dict(rc=0, stdout='STIG_INFO:' + json.dumps(info), stderr='')
                if 'STIG_CLEAN:' in sql:
                    return dict(rc=0, stdout='STIG_CLEAN:true', stderr='')
                if 'CREATE SCHEMA' in sql:
                    return dict(rc=0, stdout='', stderr='')
                app = next(v.split('=', 1)[1] for v in argv if v.startswith('PGAPPNAME='))
                identity = dict(pid=123, role='stig_audit', session_user='stig_audit', database='appdb',
                                postmaster='100', application=app)
                base = dict(timestamp='2026-10-20 12:00:00 UTC', pid=123, user='stig_audit', dbname='appdb',
                            application_name=app, state_code='00000', error_severity='LOG')
                output = 'STIG_META:' + json.dumps(identity) + '\n'
                if 'STIG_DONE:' not in sql:
                    with path.open('a') as f:
                        for msg in ('connection authorized: user=stig_audit database=appdb',
                                    'disconnection: session time: 0:00:01'):
                            f.write(json.dumps(dict(base, message=msg)) + '\n')
                    return dict(rc=0, stdout=output, stderr='')
                token, name = app[len('stig_'):].split('_', 1)
                _, cls, command, statement, expected = next(c for c in probe.tests('s', token) if c[0] == name)
                actual = sql.split('\n')[1]
                if name.startswith('denied_'):
                    row = dict(base, state_code='42501', error_severity='ERROR', message='permission denied',
                               statement=actual)
                    rc, err = 3, 'ERROR:  42501: permission denied'
                else:
                    e = event(name)
                    e.update(marker=app, audit_class=cls, command=command, sql=actual)
                    msg = record(e)['message']
                    row = dict(base, message=msg)
                    output += expected + '\nSTIG_DONE:' + app + '\n'
                    rc, err = 0, ''
                with path.open('a') as f:
                    f.write(json.dumps(row) + '\n')
                return dict(rc=rc, stdout=output, stderr=err)
            with patch.object(probe, 'execute', backend):
                result = probe.run(dict(database='appdb', role='stig_audit', admin=['psql'], test=['psql'], log_wait=0))
            self.assertEqual(result['cleanup'], 'cleaned')
            self.assertFalse(result['errors'])
            self.assertEqual(len(result['events']), 14)
            self.assertEqual({e['state'] for e in result['events']}, {'verified'})

    def fake_execute(self, argv, sql):
        self.commands.append(sql)
        if 'STIG_INFO:' in sql:
            info = dict(role_ok=True, database_ok=True, postmaster='100', pgdata='/not-used', prefix='', sources={})
            return dict(rc=0, stdout='STIG_INFO:' + json.dumps(info), stderr='')
        if 'STIG_CLEAN:' in sql:
            return dict(rc=0, stdout='STIG_CLEAN:true\n', stderr='')
        if 'CREATE SCHEMA' in sql:
            return dict(rc=1 if self.setup_failure else 0, stdout='', stderr='setup failure' if self.setup_failure else '')
        application = next((v.split('=', 1)[1] for v in argv if v.startswith('PGAPPNAME=')), '')
        identity = dict(pid=123, role='stig_audit', session_user='stig_audit', database='appdb',
                        postmaster='100', application=application)
        if 'STIG_DONE:' not in sql:
            return dict(rc=0, stdout='STIG_META:' + json.dumps(identity), stderr='')
        raise RuntimeError('simulated execution failure')

    def test_cleanup_is_attempted_on_setup_and_probe_failures(self):
        for fail_setup in (True, False):
            self.commands, self.setup_failure = [], fail_setup
            with patch.object(probe, 'execute', self.fake_execute):
                result = probe.run(dict(database='appdb', role='stig_audit', admin=['psql'], test=['psql'], log_wait=0))
            self.assertEqual(result['cleanup'], 'cleaned')
            self.assertTrue(result['errors'])
            cleanup = next(sql for sql in self.commands if 'STIG_CLEAN:' in sql)
            self.assertIn("obj_description(oid,'pg_namespace')", cleanup)
            self.assertIn(result['run'], cleanup)
            # The PL/pgSQL block needs its own terminator inside the dollar quotes.
            self.assertIn('END; $probe$;', cleanup)

    def test_cleanup_failure_is_reported_with_its_database_error(self):
        self.commands, self.setup_failure = [], False
        def backend(argv, sql):
            if 'STIG_CLEAN:' in sql:
                return dict(rc=3, stdout='', stderr='ERROR: permission denied for schema')
            return self.fake_execute(argv, sql)
        with patch.object(probe, 'execute', backend):
            result = probe.run(dict(database='appdb', role='stig_audit', admin=['psql'], test=['psql'], log_wait=0))
        self.assertEqual(result['cleanup'], 'failed')
        self.assertIn('permission denied', result['cleanup_transcript']['stderr'])
        self.assertTrue(any('Cleanup failed' in error for error in result['errors']))

    def test_preflight_does_not_modify_a_privileged_or_missing_account(self):
        self.commands = []
        def reject(argv, sql):
            self.commands.append(sql)
            return dict(rc=0, stdout='STIG_INFO:' + json.dumps(dict(role_ok=False, database_ok=True)), stderr='')
        with patch.object(probe, 'execute', reject):
            result = probe.run(dict(database='appdb', role='stig_audit', admin=['psql'], test=['psql']))
        self.assertEqual(len(self.commands), 1)
        self.assertEqual(result['cleanup'], 'not_needed')


class ActiveEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.ev = hardened()
        self.settings = dict(SETTINGS, active_verify=True)
        names = set().union(*map(set, pg.ACTIVE_CASES.values()))
        self.snapshot = dict(version=1, db='postgres', role='stig_audit', run='unique', schema='_stig_probe_unique',
                             cleanup='cleaned', errors=[], events=[dict(name=n, state='verified', client='expected',
                             logs=['actual record'], log_files=['/logs/db.log'], transcript={}) for n in names])
        self.ev['active'] = [self.snapshot]

    def result(self):
        return by_id(pg.postgres_stig_evaluate(self.ev, self.settings))

    def test_active_evidence_is_required_when_enabled(self):
        self.assertEqual(self.result()['CD16-00-001400']['status'], pg.NF)
        self.ev['active'] = []
        self.assertEqual(self.result()['CD16-00-001400']['status'], pg.NR)
        self.settings['active_verify'] = False
        self.assertEqual(self.result()['CD16-00-001400']['status'], pg.NF)

    def test_matching_logs_failure_and_cleanup_results_affect_status(self):
        e = next(e for e in self.snapshot['events'] if e['name'] == 'denied_write')
        e['state'] = 'missing_log'
        self.assertEqual(self.result()['CD16-00-001400']['status'], pg.OPEN)
        e['state'] = 'incomplete'
        self.assertEqual(self.result()['CD16-00-001400']['status'], pg.NR)
        e['state'] = 'verified'
        self.snapshot['cleanup'] = 'failed'
        self.assertEqual(self.result()['CD16-00-001400']['status'], pg.NR)

    def test_active_success_cannot_override_failed_configuration(self):
        sql = json.loads(self.ev['sql'])
        sql['settings']['pgaudit.log']['setting'] = 'none'
        self.ev['sql'] = json.dumps(sql)
        self.assertEqual(self.result()['CD16-00-001400']['status'], pg.OPEN)

    def test_all_assessed_databases_need_evidence_and_templates_are_passive(self):
        sql = json.loads(self.ev['sql'])
        sql['databases'] += [dict(name='appdb', connect=True, template=False),
                             dict(name='template1', connect=True, template=True)]
        self.ev['sql'] = json.dumps(sql)
        self.assertEqual(self.result()['CD16-00-001400']['status'], pg.NR)
        other = copy.deepcopy(self.snapshot)
        other['db'] = 'appdb'
        self.ev['active'].append(other)
        self.assertEqual(self.result()['CD16-00-001400']['status'], pg.NF)

    def test_unimplemented_role_tests_keep_manual_test_note(self):
        r = self.result()['CD16-00-009800']
        self.assertIn('performs a test action', r['comments'])
        self.assertEqual(self.result()['CD16-00-000500']['status'], pg.NR)


if __name__ == '__main__':
    unittest.main()
