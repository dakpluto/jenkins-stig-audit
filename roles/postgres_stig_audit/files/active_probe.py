#!/usr/bin/env python3
"""Opt-in PostgreSQL probes. Standard library only; invoked on the target as root.

Admin access prepares synthetic fixtures. Each probe uses a real restricted login.
No logging/authentication setting is altered. Only matching log records are exported.
"""
import csv
import io
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time
import uuid


def execute(argv, sql):
    proc = subprocess.Popen(argv + ['-f', '-'], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, universal_newlines=True, encoding='utf-8', errors='replace',
                            start_new_session=os.name == 'posix')
    try:
        out, err = proc.communicate(sql, timeout=15)
    except subprocess.TimeoutExpired:
        if os.name == 'posix':
            os.killpg(proc.pid, signal.SIGKILL)
        else:
            proc.kill()
        out, err = proc.communicate()
        return dict(rc=-1, stdout=out, stderr=err + '\nProbe command timed out.')
    return dict(rc=proc.returncode, stdout=out, stderr=err)


def tagged_json(output, tag):
    for line in output.splitlines():
        if line.startswith(tag):
            return json.loads(line[len(tag):])
    return None


def prefix_regex(prefix):
    """Parse session text prefixes; PID is mandatory for reliable correlation."""
    if '%p' not in prefix:
        return None
    timestamp = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\.\d+)?(?: [A-Za-z0-9_+:/-]+)?'
    fields = {'p': ('pid', r'\d+'), 'u': ('user', '.*?'), 'd': ('database', '.*?'),
              'a': ('application', '.*?'), 'e': ('code', '[A-Z0-9]{5}'),
              'm': ('time', timestamp), 't': ('time', timestamp), 'n': ('time', r'\d+(?:\.\d+)?'),
              'c': ('session', r'[0-9a-f]+\.[0-9a-f]+')}
    parts, used, i = [], set(), 0
    while i < len(prefix):
        if prefix[i] == '%' and i + 1 < len(prefix):
            code = prefix[i + 1]
            if code == '%':
                parts.append('%')
            elif code == 'q':
                pass  # Only session backends are relevant here.
            else:
                name, pattern = fields.get(code, ('', '.*?'))
                if name and name not in used:
                    parts.append('(?P<%s>%s)' % (name, pattern))
                    used.add(name)
                else:
                    parts.append(pattern)
            i += 2
        else:
            parts.append(re.escape(prefix[i]))
            i += 1
    return re.compile('^' + ''.join(parts) +
                      r'(?P<severity>DEBUG[1-5]?|INFO|NOTICE|LOG|ERROR|FATAL|PANIC|WARNING|STATEMENT|DETAIL|CONTEXT|HINT):\s+(?P<message>.*)$')


def parse_records(text, kind, prefix=''):
    """Normalize csvlog/jsonlog or a supported text prefix into individual records."""
    records, errors = [], []
    if kind == 'jsonlog':
        for line in text.splitlines():
            if not line.strip():
                continue
            try:
                r = json.loads(line)
                records.append(dict(pid=str(r.get('pid', '')), user=r.get('user', ''),
                                    database=r.get('dbname', ''), application=r.get('application_name', ''),
                                    code=r.get('state_code', ''), severity=r.get('error_severity', ''),
                                    time=r.get('timestamp', ''), session=r.get('session_id', ''),
                                    message=r.get('message', ''), statement=r.get('statement', ''), raw=line))
            except (ValueError, AttributeError):
                errors.append('Incomplete or invalid JSON log record.')
    elif kind == 'csvlog':
        try:
            for r in csv.reader(io.StringIO(text), strict=True):
                if len(r) < 23:
                    errors.append('Incomplete CSV log record.')
                    continue
                records.append(dict(time=r[0], user=r[1], database=r[2], pid=r[3], session=r[5],
                                    severity=r[11], code=r[12], message=r[13], statement=r[19],
                                    application=r[22], raw=next_csv_line(r)))
        except csv.Error:
            errors.append('Incomplete or invalid CSV log record.')
    else:
        rx = prefix_regex(prefix)
        if rx is None:
            return [], ['Text log_line_prefix must contain %p; CSV/JSON logs are also supported.']
        for line in text.splitlines():
            m = rx.match(line)
            if not m:
                # Multiline/unrecognized text cannot establish a complete log scan.
                if line.strip():
                    errors.append('Unrecognized text log record or continuation line.')
                continue
            r = m.groupdict()
            r['raw'], r['statement'] = line, ''
            if not r.get('code'):
                code = re.match(r'([A-Z0-9]{5}):\s+', r['message'])
                if code:
                    r['code'] = code.group(1)
            records.append(r)
    return records, sorted(set(errors))


def next_csv_line(row):
    out = io.StringIO()
    csv.writer(out).writerow(row)
    return out.getvalue().rstrip('\r\n')


def correlate(event, records, complete):
    """An AUDIT keyword, old record, or another session never satisfies a probe."""
    meta = event.get('session') or {}
    if not meta or event.get('client') != 'expected':
        return dict(state='incomplete', reason='Expected SQL outcome and session identity were not established.', logs=[])
    matching = []
    for r in records:
        if str(r.get('pid')) != str(meta['pid']):
            continue
        if r.get('user') and r['user'] != meta['role']:
            continue
        if r.get('database') and r['database'] != meta['database']:
            continue
        if r.get('application') and r['application'] != event['application']:
            continue
        matching.append(r)
    marker = event['marker']
    def target_statement(sql):
        # Completion/metadata SELECTs also mention the token. Only the exact
        # tagged target SQL may prove the operation was audited.
        return '/*%s*/' % marker in sql and sql.strip().rstrip(';').strip() == \
            event.get('sql', '').strip().rstrip(';').strip()
    if event['name'] in ('connect', 'disconnect'):
        start = 'connection authorized:' if event['name'] == 'connect' else 'disconnection:'
        for r in matching:
            if r.get('message', '').startswith(start) and r.get('code') == '00000' and r.get('time'):
                return dict(state='verified', reason='Real login session log record with timestamp.', logs=[r['raw']],
                            log_files=[r.get('source', '')])
    elif event['denied']:
        statements = [r for r in matching if target_statement(r.get('statement', '')) or
                      (r.get('severity') == 'STATEMENT' and target_statement(r.get('message', '')))]
        failures = [r for r in matching if r.get('severity') == 'ERROR' and r.get('code') == '42501']
        if statements and failures:
            logs = {r['raw'] for r in statements + failures}
            return dict(state='verified', reason='SQLSTATE 42501 denial and its statement are present.', logs=sorted(logs),
                        log_files=sorted({r.get('source', '') for r in statements + failures}))
    else:
        for r in matching:
            msg = r.get('message', '')
            if 'AUDIT: ' not in msg:
                continue
            try:
                fields = next(csv.reader([msg.split('AUDIT: ', 1)[1]]))
            except (csv.Error, StopIteration):
                continue
            if len(fields) >= 8 and fields[3] == event['audit_class'] and fields[4] == event['command'] and \
                    target_statement(fields[7]) and r.get('code') == '00000':
                return dict(state='verified', reason='Successful client result and corresponding pgAudit record.',
                            logs=[r['raw']], log_files=[r.get('source', '')])
    if not complete:
        return dict(state='incomplete', reason='Log source is unavailable, incomplete, or lacks SQLSTATE.', logs=[])
    return dict(state='missing_log', reason='Expected correlated log record was not found before the deadline.', logs=[])


class LogReader:
    def __init__(self, sources, pgdata, prefix, max_bytes):
        # Choose one complete local destination, preferring structured output.
        self.kind = next((k for k in ('jsonlog', 'csvlog', 'stderr') if sources.get(k)), '')
        self.errors, self.offsets = [], {}
        self.prefix, self.max_bytes = prefix, max_bytes
        self.path = Path(sources[self.kind]) if self.kind else None
        if self.path is not None and not self.path.is_absolute():
            self.path = Path(pgdata) / self.path
        if self.path is None:
            self.errors.append('No local collector log file; syslog/journal-only verification is not supported.')
            return
        if self.kind == 'stderr' and (prefix_regex(prefix) is None or '%e' not in prefix):
            self.errors.append('Text logs need %p and %e in log_line_prefix for active outcome verification.')
        try:
            for p in self.files():
                st = p.stat()
                self.offsets[(st.st_dev, st.st_ino)] = st.st_size
        except OSError as exc:
            self.errors.append('Cannot snapshot local log files: %s' % exc)

    def files(self):
        suffix = self.path.suffix
        files = [p for p in self.path.parent.iterdir() if p.is_file() and p.suffix == suffix]
        if len(files) > 200:
            raise OSError('More than 200 candidate log files; reduce the log directory scope.')
        return files

    def read(self):
        records, errors, remaining = [], list(self.errors), self.max_bytes
        if self.path is None:
            return records, False, errors
        try:
            for p in sorted(self.files()):
                st = p.stat()
                offset = self.offsets.get((st.st_dev, st.st_ino), 0)
                if st.st_size < offset:
                    errors.append('A log file was truncated during verification.')
                    offset = 0
                if st.st_size - offset > remaining:
                    errors.append('Log collection exceeded max_bytes; evidence is incomplete.')
                    continue
                with p.open('rb') as f:
                    f.seek(offset)
                    data = f.read(remaining + 1)
                if len(data) > remaining:
                    errors.append('Log collection exceeded max_bytes; evidence is incomplete.')
                    continue
                remaining -= len(data)
                rows, parse_errors = parse_records(data.decode('utf-8', errors='replace'), self.kind, self.prefix)
                for r in rows:
                    r['source'] = str(p)
                records += rows
                errors += parse_errors
        except OSError as exc:
            errors.append('Cannot read local logs: %s' % exc)
        # Text without outcome codes is never treated as a complete log source.
        complete = not errors
        return records, complete, sorted(set(errors))


def tests(schema, token):
    return [
        ('read', 'READ', 'SELECT', "SELECT marker FROM %s.allowed WHERE id=1" % schema, token),
        ('catalog_read', 'READ', 'SELECT', "SELECT '%s' FROM information_schema.table_privileges LIMIT 1" % token, token),
        ('insert', 'WRITE', 'INSERT', "INSERT INTO %s.allowed VALUES (2, '%s')" % (schema, token), 'INSERT 0 1'),
        ('update', 'WRITE', 'UPDATE', "UPDATE %s.allowed SET marker='%s' WHERE id=1" % (schema, token), 'UPDATE 1'),
        ('delete', 'WRITE', 'DELETE', "DELETE FROM %s.allowed WHERE id=2" % schema, 'DELETE 1'),
        ('create', 'DDL', 'CREATE TABLE', "CREATE TABLE %s.created(id integer)" % schema, 'CREATE TABLE'),
        ('alter', 'DDL', 'ALTER TABLE', "ALTER TABLE %s.created ADD COLUMN verified boolean" % schema, 'ALTER TABLE'),
        ('drop', 'DDL', 'DROP TABLE', "DROP TABLE %s.created" % schema, 'DROP TABLE'),
        ('denied_read', '', '', "SELECT * FROM %s.protected" % schema, '42501'),
        ('denied_write', '', '', "UPDATE %s.protected SET id=2" % schema, '42501'),
        ('denied_ddl', '', '', "ALTER TABLE %s.protected ADD COLUMN forbidden integer" % schema, '42501'),
        ('denied_permissions', '', '', "SELECT rolname, rolsuper FROM pg_catalog.pg_authid", '42501'),
    ]


def run(config):
    database, role = config['database'], config['role']
    if not isinstance(database, str) or not database or not re.fullmatch(r'[a-z_][a-z0-9_]{0,62}', role):
        raise ValueError('Invalid database or restricted role name.')
    token = uuid.uuid4().hex[:16]
    schema = '_stig_probe_' + token
    quoted_role = '"' + role + '"'
    result = dict(version=1, db=database, role=role, run=token, schema=schema, events=[], errors=[], cleanup='not_needed')
    admin = config['admin'] + ['-d', database]
    preflight = execute(admin, """SELECT 'STIG_INFO:' || json_build_object(
      'role_ok', EXISTS (SELECT 1 FROM pg_roles r WHERE rolname='%s' AND rolcanlogin
        AND NOT (rolsuper OR rolcreaterole OR rolcreatedb OR rolreplication OR rolbypassrls)
        AND NOT EXISTS (SELECT 1 FROM pg_auth_members m WHERE m.member=r.oid)),
      'database_ok', (SELECT NOT datistemplate AND datallowconn FROM pg_database WHERE datname=current_database()),
      'postmaster', extract(epoch FROM pg_postmaster_start_time())::text,
      'pgdata', current_setting('data_directory'), 'prefix', current_setting('log_line_prefix'),
      'sources', json_build_object('jsonlog', pg_current_logfile('jsonlog'),
        'csvlog', pg_current_logfile('csvlog'), 'stderr', pg_current_logfile('stderr')))::text;""" % role)
    result['preflight'] = preflight
    info = tagged_json(preflight['stdout'], 'STIG_INFO:')
    if preflight['rc'] or not info or not info['role_ok'] or not info['database_ok']:
        result['errors'].append('Preflight failed: require a restricted LOGIN without memberships and a non-template database.')
        return result
    logs = LogReader(info['sources'], info['pgdata'], info['prefix'], config.get('max_bytes', 8388608))
    # Validate the real login before any mutation; do not accept SET ROLE as login evidence.
    login_sql = "SELECT 'STIG_META:' || json_build_object('pid',pg_backend_pid(), 'role',current_user, " \
        "'session_user',session_user, 'database',current_database(), " \
        "'postmaster',extract(epoch FROM pg_postmaster_start_time())::text," \
        "'application',current_setting('application_name'))::text;"
    login_application = 'stig_' + token + '_session'
    login = execute(['env', 'PGAPPNAME=' + login_application] + config['test'] + ['-d', database], login_sql)
    result['login'] = login
    identity = tagged_json(login['stdout'], 'STIG_META:')
    if login['rc'] or not identity or identity['role'] != role or identity['session_user'] != role or \
            identity['database'] != database or identity['postmaster'] != info['postmaster'] or \
            identity['application'] != login_application:
        result['errors'].append('Real login failed or reached a different role/database/instance; check the libpq service and HBA.')
        return result
    for name in ('connect', 'disconnect'):
        result['events'].append(dict(name=name, marker=login_application, application=login_application,
                                     session=identity, client='expected', denied=False,
                                     sql=login_sql, transcript=login))
    setup_sql = """BEGIN;
      CREATE SCHEMA %s;
      COMMENT ON SCHEMA %s IS '%s';
      REVOKE ALL ON SCHEMA %s FROM PUBLIC;
      GRANT USAGE, CREATE ON SCHEMA %s TO %s;
      CREATE TABLE %s.allowed(id integer PRIMARY KEY, marker text);
      CREATE TABLE %s.protected(id integer);
      REVOKE ALL ON %s.allowed, %s.protected FROM PUBLIC, %s;
      GRANT SELECT, INSERT, UPDATE, DELETE ON %s.allowed TO %s;
      INSERT INTO %s.allowed VALUES (1, '%s');
      INSERT INTO %s.protected VALUES (1);
      COMMIT;""" % (schema, schema, token, schema, schema, quoted_role, schema, schema,
                      schema, schema, quoted_role, schema, quoted_role, schema, token, schema)
    # Cleanup checks the ownership marker so a preexisting schema cannot be dropped.
    cleanup_sql = """DO $probe$ BEGIN
      IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='%s'
                 AND obj_description(oid,'pg_namespace')='%s') THEN
        EXECUTE 'DROP SCHEMA %s CASCADE';
      END IF;
      END $probe$;
      SELECT 'STIG_CLEAN:' || (NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname='%s'))::text;
      """ % (schema, token, schema, schema)
    try:
        result['cleanup'] = 'pending'
        setup = execute(admin, setup_sql)
        result['setup'] = setup
        if setup['rc']:
            result['errors'].append('Fixture setup failed; no tests were accepted as evidence.')
            return result
        for name, audit_class, command, sql, expected in tests(schema, token):
            marker = 'stig_' + token + '_' + name
            application = 'stig_' + token + '_' + name
            statement = '/*%s*/ %s;' % (marker, sql)
            transcript = login_sql + '\n' + statement + "\nSELECT 'STIG_DONE:%s';" % marker
            # env is an argument to runuser, not a shell; no user text is executed as shell code.
            argv = ['env', 'PGAPPNAME=' + application] + config['test'] + ['-d', database]
            outcome = execute(argv, transcript)
            session = tagged_json(outcome['stdout'], 'STIG_META:')
            identity_ok = session and session['role'] == role and session['session_user'] == role and \
                session['database'] == database and session['postmaster'] == info['postmaster'] and \
                session['application'] == application
            denied = name.startswith('denied_')
            if denied:
                expected_outcome = outcome['rc'] > 0 and re.search(r'ERROR:\s+42501:', outcome['stderr'])
            else:
                expected_outcome = outcome['rc'] == 0 and expected in outcome['stdout'].splitlines() and \
                    'STIG_DONE:' + marker in outcome['stdout'].splitlines()
            event = dict(name=name, marker=marker, application=application, denied=denied,
                         audit_class=audit_class, command=command, sql=statement, session=session,
                         transcript=outcome, client='expected' if expected_outcome and identity_ok else 'unexpected')
            result['events'].append(event)
        deadline = time.monotonic() + min(60, max(0, config.get('log_wait', 10)))
        while True:
            records, complete, errors = logs.read()
            for event in result['events']:
                event.update(correlate(event, records, complete))
            if all(e['state'] == 'verified' for e in result['events']) or time.monotonic() >= deadline:
                result['log_errors'] = errors
                result['log_source'] = dict(kind=logs.kind, path=str(logs.path), complete=complete)
                break
            time.sleep(0.5)
    except Exception as exc:
        result['errors'].append('Probe execution failed: %s' % exc)
    finally:
        try:
            cleanup = execute(admin, cleanup_sql)
            result['cleanup_transcript'] = cleanup
            result['cleanup'] = 'cleaned' if cleanup['rc'] == 0 and 'STIG_CLEAN:true' in cleanup['stdout'].splitlines() else 'failed'
        except Exception as exc:
            result['cleanup'] = 'failed'
            result['errors'].append('Cleanup execution error: %s' % exc)
        if result['cleanup'] != 'cleaned':
            result['errors'].append('Cleanup failed: review the recorded schema name and remove only that marked fixture.')
    return result


def main():
    config = {}
    try:
        config = json.load(sys.stdin)
        result = run(config)
    except Exception as exc:
        result = dict(version=1, db=config.get('database', ''), role=config.get('role', ''),
                      errors=['Active runner failed: %s' % exc], events=[], cleanup='unknown')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
