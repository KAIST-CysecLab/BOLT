"""Offline smoke tests for DB script ordering and failure propagation.

Run with: python3 scripts/test_db_scripts.py
All executions use copied scripts and fake Docker/BOLT programs under /tmp.
"""

import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import unittest


REPOSITORY = Path(__file__).resolve().parents[1]
FAKE_PROGRAM = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
program = pathlib.Path(sys.argv[0]).name
with open(os.environ['TEST_DB_LOG'], 'a') as log:
    log.write(json.dumps({'program': program, 'args': args, 'cwd': os.getcwd()}) + '\n')
phase = args[0] if args else ''
if program == 'docker' and phase == 'compose':
    phase = args[1]
if program == 'docker' and phase == os.environ.get('TEST_FAIL_PHASE'):
    sys.exit(71)
if program == 'fake-bolt' and '--download-db-only' in args and os.environ.get('TEST_FAIL_UPDATE'):
    sys.exit(72)
if program == 'fetch-bin-sbom-data.sh' and os.environ.get('TEST_FAIL_FETCH'):
    sys.exit(73)
if program == 'docker' and args[:2] == ['compose', 'config'] and os.environ.get('TEST_COMPOSE_NAME'):
    print('name: ' + os.environ['TEST_COMPOSE_NAME'])
if program == 'docker' and args[:2] == ['volume', 'ls']:
    print(os.environ.get('TEST_VOLUMES', ''), end='')
if program == 'docker' and args[:1] == ['ps']:
    print(os.environ.get('TEST_CONTAINERS', ''), end='')
'''


class DatabaseScriptsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='bolt-db-script-test-', dir='/tmp')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'checkout with spaces'
        self.root.mkdir()
        self.fakebin = Path(self.temp.name) / 'bin'
        self.fakebin.mkdir()
        self.log = Path(self.temp.name) / 'commands.jsonl'
        for filename in ('init.sh', 'update-db.sh', 'fetch-db-dump.sh'):
            shutil.copy2(REPOSITORY / filename, self.root / filename)
        for target in (self.fakebin / 'docker', self.fakebin / 'fake-bolt', self.root / 'fetch-bin-sbom-data.sh'):
            target.write_text(FAKE_PROGRAM)
            target.chmod(0o755)
        entrypoint = (REPOSITORY / 'docker/bolt-entrypoint.sh').read_text()
        # Preserve production's fixed executable path; substitute it only in this
        # isolated fixture so no real installation or container is needed.
        (self.root / 'entrypoint.sh').write_text(entrypoint.replace('/usr/local/bin/bolt', str(self.fakebin / 'fake-bolt')))
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith(('BOLT_', 'MYSQL_', 'TRIVY_', 'TEST_FAIL_', 'INSTALL_BIN_SBOM'))}
        # init.sh requires a Docker socket; a bound Unix socket passes its check
        # without a daemon.
        self.sock_path = Path(self.temp.name) / 'docker.sock'
        self.sock = socket.socket(socket.AF_UNIX)
        self.sock.bind(str(self.sock_path))
        self.addCleanup(self.sock.close)
        self.env.update(PATH=str(self.fakebin) + os.pathsep + os.environ['PATH'], TEST_DB_LOG=str(self.log),
                        BOLT_DOCKER_SOCK=str(self.sock_path))

    def run_script(self, name, *args, extra_env=None):
        env = dict(self.env, **(extra_env or {}))
        return subprocess.run(['bash', str(self.root / name), *args], env=env,
                              cwd=self.temp.name, text=True, capture_output=True, timeout=10)

    def events(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def test_update_waits_and_preserves_arguments_and_existing_dump(self):
        (self.root / 'bolt_db.sql').write_text('old dump must not be imported or removed')
        dsn = 'user:p a$$@tcp(db.example:3307)/custom_db'
        result = self.run_script('update-db.sh', '--timeout', '45m', extra_env={'BOLT_MYSQL_DSN': dsn})
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events()
        self.assertEqual(events[0]['args'], ['compose', 'up', '-d', '--wait', '--wait-timeout', '120', 'mysql'])
        self.assertEqual(events[1]['args'], ['compose', 'run', '--rm', 'bolt', 'image',
                         '--download-db-only', '--timeout', '30m', '--mysql-dsn', dsn,
                         '--db-repository', 'ghcr.io/aquasecurity/trivy-db:2', '--timeout', '45m'])
        self.assertTrue(all(event['cwd'] == str(self.root) for event in events))
        self.assertTrue((self.root / '.cache').is_dir())
        self.assertEqual((self.root / 'bolt_db.sql').read_text(), 'old dump must not be imported or removed')

    def test_update_leaves_the_dsn_to_compose_by_default(self):
        result = self.run_script('update-db.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.events()[1]['args'], ['compose', 'run', '--rm', 'bolt', 'image',
                         '--download-db-only', '--timeout', '30m',
                         '--db-repository', 'ghcr.io/aquasecurity/trivy-db:2'])

    def test_update_propagates_health_and_update_failures(self):
        for phase, count in [('up', 1), ('run', 2)]:
            with self.subTest(phase=phase):
                self.log.unlink(missing_ok=True)
                result = self.run_script('update-db.sh', extra_env={'TEST_FAIL_PHASE': phase})
                self.assertEqual(result.returncode, 71)
                self.assertEqual(len(self.events()), count)

    def env_file(self):
        lines = (self.root / '.env').read_text().splitlines()
        return dict(line.split('=', 1) for line in lines)

    def test_init_installs_bin_sbom_by_default_and_builds_before_update(self):
        result = self.run_script('init.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events()
        self.assertEqual([event['program'] for event in events],
                         ['docker', 'fetch-bin-sbom-data.sh', 'docker', 'docker', 'docker'])
        self.assertEqual(events[0]['args'], ['compose', 'config'])
        self.assertIn('INSTALL_BIN_SBOM=true', events[2]['args'])
        self.assertEqual(events[2]['args'][0], 'build')
        self.assertEqual(events[3]['args'][:2], ['compose', 'up'])
        self.assertIn('--download-db-only', events[4]['args'])
        self.assertNotIn('--mysql-dsn', events[4]['args'])

    def test_init_generates_mysql_passwords_once_and_keeps_them(self):
        result = self.run_script('init.sh', extra_env={'INSTALL_BIN_SBOM': 'false'})
        self.assertEqual(result.returncode, 0, result.stderr)
        first = self.env_file()
        for key in ('MYSQL_PASSWORD', 'MYSQL_ROOT_PASSWORD'):
            self.assertRegex(first[key], r'^[0-9a-f]{48}$')
        self.assertNotEqual(first['MYSQL_PASSWORD'], first['MYSQL_ROOT_PASSWORD'])
        self.assertEqual(first['SOCK_GID'], str(self.sock_path.stat().st_gid))
        self.assertEqual((self.root / '.env').stat().st_mode & 0o777, 0o600)
        self.log.unlink()
        result = self.run_script('init.sh', extra_env={'INSTALL_BIN_SBOM': 'false'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.env_file(), first)
        # Kept credentials need no check for a volume made with other ones.
        self.assertNotIn(['compose', 'config'], [event['args'] for event in self.events()])

    def test_init_stops_without_a_docker_socket(self):
        for missing in (self.root / 'no-such.sock', self.root):  # absent, and not a socket
            with self.subTest(path=missing.name):
                result = self.run_script('init.sh', extra_env={'BOLT_DOCKER_SOCK': str(missing)})
                self.assertEqual(result.returncode, 1)
                self.assertIn('no Docker socket', result.stderr)
                # Nothing else runs, and no .env with a made-up socket group is written.
                self.assertEqual(self.events(), [])
                self.assertFalse((self.root / '.env').exists())

    def test_init_refuses_an_existing_volume_it_cannot_open(self):
        result = self.run_script('init.sh', extra_env={
            'TEST_COMPOSE_NAME': 'bolt', 'TEST_VOLUMES': 'bolt_mysql_data', 'TEST_CONTAINERS': 'abc123'})
        self.assertEqual(result.returncode, 1)
        self.assertIn('docker rm -f abc123', result.stderr)
        self.assertIn('docker volume rm bolt_mysql_data', result.stderr)
        self.assertEqual([event['args'][:2] for event in self.events()],
                         [['compose', 'config'], ['volume', 'ls'], ['ps', '-aq']])
        # Leaving .env unwritten keeps the next run on this check until the volume is gone.
        self.assertFalse((self.root / '.env').exists())

    def test_init_stops_after_build_or_optional_data_failure(self):
        result = self.run_script('init.sh', extra_env={'INSTALL_BIN_SBOM': 'false', 'TEST_FAIL_PHASE': 'build'})
        self.assertEqual(result.returncode, 71)
        self.assertEqual([event['args'][:2] for event in self.events()], [['compose', 'config'], ['build', '-f']])
        self.assertIn('INSTALL_BIN_SBOM=false', self.events()[1]['args'])
        self.log.unlink()
        result = self.run_script('init.sh', extra_env={'TEST_FAIL_FETCH': '1'})
        self.assertEqual(result.returncode, 73)
        self.assertEqual([event['program'] for event in self.events()], ['fetch-bin-sbom-data.sh'])

    def test_deprecated_fetch_runs_updater_even_when_dump_exists(self):
        (self.root / 'bolt_db.sql').write_text('already exists')
        result = self.run_script('fetch-db-dump.sh', '--quiet')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('deprecated', result.stderr)
        self.assertEqual(self.events()[-1]['args'][-1], '--quiet')
        self.assertIn('--download-db-only', self.events()[-1]['args'])

    def test_entrypoint_preserves_normal_invocation(self):
        result = self.run_script('entrypoint.sh', 'image', 'target with spaces', '--skip-db-update')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual([event['args'] for event in self.events()], [['image', 'target with spaces', '--skip-db-update']])

    def test_legacy_entrypoint_uses_official_update_without_sql(self):
        env = {'BOLT_INIT_DB': '1', 'MYSQL_HOST': 'mysql', 'MYSQL_USER': 'olduser',
               'MYSQL_PASSWORD': 'p a$$', 'MYSQL_DATABASE': 'bolt_db', 'BOLT_DB_SQL': '/does/not/exist.sql'}
        result = self.run_script('entrypoint.sh', 'image', 'target', extra_env=env)
        self.assertEqual(result.returncode, 0, result.stderr)
        events = self.events()
        self.assertEqual(len(events), 2)
        self.assertIn('--download-db-only', events[0]['args'])
        self.assertIn('olduser:p a$$@tcp(mysql:3306)/bolt_db', events[0]['args'])
        self.assertIn('ghcr.io/aquasecurity/trivy-db:2', events[0]['args'])
        self.assertEqual(events[1]['args'], ['image', 'target'])

    def test_legacy_entrypoint_stops_after_update_failure(self):
        result = self.run_script('entrypoint.sh', 'image', 'target', extra_env={
            'BOLT_INIT_DB': '1', 'BOLT_MYSQL_DSN': 'user:pass@tcp(mysql:3306)/bolt_db', 'TEST_FAIL_UPDATE': '1'})
        self.assertEqual(result.returncode, 72)
        self.assertEqual(len(self.events()), 1)


if __name__ == '__main__':
    unittest.main()
