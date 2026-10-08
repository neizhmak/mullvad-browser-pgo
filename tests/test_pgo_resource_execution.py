#!/usr/bin/env python3
"""Native execution/renderer mechanics fixtures, NOT live Firefox/cache/PGO proof."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
WRAPPER = ROOT / "scripts/run-pgo-resource-limited.py"
RENDERER = ROOT / "scripts/render-pgo-resource-metadata.pl"
SPEC = importlib.util.spec_from_file_location("pgo_resource_execution", WRAPPER)
EXECUTION = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(EXECUTION)


class PolicyExecutionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="pgo-resource-exec-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.upstream = self.base / "upstream"
        self.upstream.mkdir()
        self.path = self.base / "policy.json"
        self.before = os.sched_getaffinity(0)
        if len(self.before) < 2:
            self.skipTest("requires two currently allowed CPU members")
        self.environment = dict(os.environ)
        for key in EXECUTION.CPU_ENV:
            self.environment.pop(key, None)
        self.environment.update({"GITHUB_SHA": "a" * 40, "GITHUB_RUN_ID": "37000001",
                                 "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "generate",
                                 "UPSTREAM": str(self.upstream), "PYTHONDONTWRITEBYTECODE": "1"})
        self.policy = {"schema": 1, "kind": "pgo-generation-resource-policy", "verified": True,
                       "target": "pgo-generate", "binding": {
                           key: self.environment[value] for key, value in EXECUTION.BINDING_ENV.items()},
                       "upstream_lock": EXECUTION.EXPECTED_LOCK.copy(),
                       "rbm_commit": EXECUTION.EXPECTED_RBM,
                       "parent_affinity": sorted(self.before),
                       "selected_affinity": sorted(self.before)[:2], "expected_num_procs": 2,
                       "rust_identity_sha256": EXECUTION.EXPECTED_RUST,
                       "node_identity_sha256": EXECUTION.EXPECTED_NODE}
        self.write()

    def tearDown(self):
        self.assertEqual(os.sched_getaffinity(0), self.before, "test parent mask changed")

    def write(self, policy=None):
        self.path.write_text(json.dumps(self.policy if policy is None else policy))

    def command(self, code="print('command-started')", arguments=()):
        return [sys.executable, str(WRAPPER), "--policy", str(self.path), "--",
                sys.executable, "-c", code, *arguments]

    def run_child(self, code="print('command-started')", arguments=(), **options):
        return subprocess.run(self.command(code, arguments), cwd=self.base,
                              env=self.environment, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, timeout=5, **options)

    def rejected(self, policy=None):
        if policy is not None:
            self.write(policy)
        marker = self.base / "started"
        result = self.run_child(f"from pathlib import Path; Path({str(marker)!r}).touch()")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(marker.exists())
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"secret-private", result.stderr)
        return result

    def test_exact_four_cpu_policy_execution(self):
        if len(self.before) < 4:
            self.skipTest("requires four currently allowed CPU members")
        policy = self.policy.copy()
        policy["selected_affinity"] = sorted(self.before)[:4]
        policy["expected_num_procs"] = 4
        self.write(policy)
        code = "import json, os; print(json.dumps(sorted(os.sched_getaffinity(0))))"
        process = subprocess.Popen(self.command(code), cwd=self.base,
                                   env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0, error)
        self.assertEqual(json.loads(output), sorted(self.before)[:4])

    def test_exact_two_cpu_argv_cwd_environment_pid_and_group(self):
        self.environment["UNCHANGED_VALUE"] = "spaces 'quotes' snowman-\u2603"
        arguments = ["--", "spaces here", "'quoted'", "$(not-a-shell)", "unicode-\u2603"]
        code = ("import json, os, sys; print(json.dumps({'args':sys.argv[1:],'cwd':os.getcwd(),"
                "'value':os.environ['UNCHANGED_VALUE'],'cpus':sorted(os.sched_getaffinity(0)),"
                "'group':os.getpgrp(),'pid':os.getpid()}))")
        process = subprocess.Popen(self.command(code, arguments), cwd=self.base,
                                   env=self.environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output, error = process.communicate(timeout=5)
        self.assertEqual(process.returncode, 0, error)
        data = json.loads(output)
        self.assertEqual(data["args"], arguments)
        self.assertEqual(data["cwd"], str(self.base))
        self.assertEqual(data["value"], self.environment["UNCHANGED_VALUE"])
        self.assertEqual(data["cpus"], sorted(self.before)[:2])
        self.assertEqual(data["pid"], process.pid, "wrapper forked rather than exec")
        self.assertEqual(data["group"], os.getpgrp(), "wrapper created a process group")

    def test_unrelated_environment_is_preserved_not_printed_by_wrapper(self):
        self.environment["PRIVATE_VALUE"] = "secret-private-value"
        code = "import os; assert os.environ['PRIVATE_VALUE']=='secret-private-value'; print('ok')"
        result = self.run_child(code)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, b"ok\n", b""))

    def test_native_exit_23_is_not_wrapped(self):
        result = self.run_child("import sys; sys.exit(23)")
        self.assertEqual(result.returncode, 23)
        self.assertEqual(result.stdout + result.stderr, b"")

    def test_native_sigterm_is_not_intercepted(self):
        result = self.run_child("import os, signal; os.kill(os.getpid(),signal.SIGTERM)")
        self.assertEqual(result.returncode, -signal.SIGTERM)

    def test_stdio_preserved(self):
        result = self.run_child("import os; os.write(1,b'out'); os.write(2,b'err')")
        self.assertEqual((result.stdout, result.stderr), (b"out", b"err"))

    def test_inherited_fd_preserved(self):
        reader, writer = os.pipe()
        try:
            result = self.run_child(f"import os; os.write({writer}, b'inherited-fd')", pass_fds=(writer,))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(os.read(reader, 100), b"inherited-fd")
        finally:
            os.close(reader)
            os.close(writer)

    def test_policy_reader_fds_are_closed(self):
        before = len(os.listdir('/proc/self/fd'))
        EXECUTION.read_policy(self.path)
        self.assertEqual(len(os.listdir('/proc/self/fd')), before)

    def test_policy_exact_keys_missing_each_rejected(self):
        for key in self.policy:
            with self.subTest(key=key):
                candidate = copy.deepcopy(self.policy)
                del candidate[key]
                self.rejected(candidate)

    def test_unexpected_private_policy_key_rejected(self):
        candidate = self.policy | {"secret-private-key": "secret-private-value"}
        self.rejected(candidate)

    def test_unexpected_binding_private_key_rejected(self):
        candidate = copy.deepcopy(self.policy)
        candidate["binding"]["secret-private-key"] = "secret-private-value"
        self.rejected(candidate)

    def test_binding_missing_each_key_rejected(self):
        for key in self.policy["binding"]:
            with self.subTest(key=key):
                candidate = copy.deepcopy(self.policy)
                del candidate["binding"][key]
                self.rejected(candidate)

    def test_stale_each_execution_binding_rejected(self):
        for key in self.policy["binding"]:
            with self.subTest(key=key):
                candidate = copy.deepcopy(self.policy)
                candidate["binding"][key] = "secret-private-stale"
                self.rejected(candidate)

    def test_missing_each_environment_binding_rejected(self):
        for key, name in EXECUTION.BINDING_ENV.items():
            with self.subTest(key=key):
                old = self.environment.pop(name)
                self.rejected()
                self.environment[name] = old

    def test_unverified_and_boolean_schema_rejected(self):
        for key, value in (("verified", False), ("verified", 1), ("schema", True),
                           ("schema", 2), ("expected_num_procs", True), ("expected_num_procs", 1)):
            with self.subTest(key=key, value=value):
                self.rejected(self.policy | {key: value})

    def test_wrong_kind_and_target_rejected(self):
        self.rejected(self.policy | {"kind": "other"})
        self.rejected(self.policy | {"target": "pgo-use"})

    def test_wrong_rbm_or_cache_identity_rejected(self):
        for key in ("rbm_commit", "rust_identity_sha256", "node_identity_sha256"):
            with self.subTest(key=key):
                self.rejected(self.policy | {key: "0" * len(self.policy[key])})

    def test_each_wrong_upstream_lock_field_rejected(self):
        for key in self.policy["upstream_lock"]:
            with self.subTest(key=key):
                candidate = copy.deepcopy(self.policy)
                candidate["upstream_lock"][key] = "wrong"
                self.rejected(candidate)

    def test_extra_upstream_lock_key_rejected(self):
        candidate = copy.deepcopy(self.policy)
        candidate["upstream_lock"]["extra"] = "secret-private"
        self.rejected(candidate)

    def test_selected_one_or_three_not_two_rejected(self):
        for selected in (sorted(self.before)[:1], sorted(self.before)[:2] + [1048576]):
            self.rejected(self.policy | {"selected_affinity": selected})

    def test_boolean_float_negative_duplicate_unsorted_cpus_rejected(self):
        cpus = self.policy["selected_affinity"]
        for value in ([True, cpus[1]], [1.0, cpus[1]], [-1, cpus[1]],
                      [cpus[0], cpus[0]], list(reversed(cpus)), [cpus[0], 1048577]):
            with self.subTest(value=value):
                self.rejected(self.policy | {"selected_affinity": value})

    def test_parent_current_affinity_mismatch_rejected(self):
        self.rejected(self.policy | {"parent_affinity": sorted(self.before) + [1048576]})

    def test_selected_outside_parent_rejected(self):
        self.rejected(self.policy | {"selected_affinity": [1048575, 1048576]})

    def test_non_array_and_huge_affinity_rejected(self):
        for value in ({"cpu": 1}, [], list(range(5000))):
            self.rejected(self.policy | {"parent_affinity": value})

    def test_float_nan_infinity_rejected_at_json_reader(self):
        for value in ('1.0', 'NaN', 'Infinity', '-Infinity'):
            with self.subTest(value=value):
                self.path.write_text(json.dumps(self.policy).replace('"schema": 1', '"schema": ' + value))
                self.rejected()

    def test_huge_integer_rejected_at_json_reader(self):
        self.path.write_text(json.dumps(self.policy).replace('"schema": 1', '"schema": ' + '9' * 3000))
        self.rejected()

    def test_duplicate_top_or_nested_key_rejected(self):
        raw = json.dumps(self.policy)
        for text in (raw.replace('"schema": 1', '"schema": 1, "schema": 1'),
                     raw.replace('"head":', '"head": "a", "head":')):
            self.path.write_text(text)
            self.rejected()

    def test_non_utf8_and_trailing_garbage_rejected(self):
        for data in (b'\xff', json.dumps(self.policy).encode() + b' extra', b'[]', b'null'):
            self.path.write_bytes(data)
            self.rejected()

    def test_huge_file_empty_file_and_deep_json_rejected(self):
        for data in (b'x' * 70000, b'', b'[' * 1500 + b']' * 1500):
            self.path.write_bytes(data)
            self.rejected()

    def test_policy_symlink_rejected(self):
        target = self.base / "target.json"
        self.path.rename(target)
        self.path.symlink_to(target)
        self.rejected()

    def test_policy_parent_symlink_rejected(self):
        actual = self.base / "actual"
        actual.mkdir()
        moved = actual / "policy.json"
        self.path.rename(moved)
        linked = self.base / "linked"
        linked.symlink_to(actual, target_is_directory=True)
        self.path = linked / "policy.json"
        self.rejected()

    def test_policy_hardlink_rejected(self):
        os.link(self.path, self.base / "other-link")
        self.rejected()

    def test_policy_fifo_fails_without_blocking(self):
        self.path.unlink()
        os.mkfifo(self.path)
        self.rejected()

    def test_policy_directory_rejected(self):
        self.path.unlink()
        self.path.mkdir()
        self.rejected()

    def test_wrong_policy_owner_rejected(self):
        with patch.object(EXECUTION.os, 'getuid', return_value=-1):
            with self.assertRaises(EXECUTION.Rejected):
                EXECUTION.read_policy(self.path)

    def test_upstream_symlink_rejected(self):
        self.upstream.rmdir()
        target = self.base / "source-target"
        target.mkdir()
        self.upstream.symlink_to(target, target_is_directory=True)
        self.rejected()

    def test_lossy_or_control_upstream_binding_rejected(self):
        for value in (str(self.upstream) + '/', str(self.upstream) + '/..',
                      str(self.upstream) + '\n', '.', '/'):
            candidate = copy.deepcopy(self.policy)
            candidate['binding']['upstream'] = value
            self.environment['UPSTREAM'] = value
            self.rejected(candidate)

    def test_noncanonical_binding_ids_rejected(self):
        for key, value in (('head', 'A' * 40), ('run', '01'), ('run', '0'),
                           ('attempt', True), ('job', 'space job'), ('job', 'x\n'),
                           ('job', 'invalid!')):
            candidate = copy.deepcopy(self.policy)
            candidate['binding'][key] = value
            self.environment[EXECUTION.BINDING_ENV[key]] = str(value)
            self.rejected(candidate)

    def test_lone_surrogate_in_policy_rejected_before_exec(self):
        candidate = copy.deepcopy(self.policy)
        candidate['binding']['upstream'] = '\ud800'
        self.rejected(candidate)

    def test_cpu_environment_presence_rejected_without_dump(self):
        for key in EXECUTION.CPU_ENV:
            self.environment[key] = 'secret-private-cpu'
            self.rejected()
            del self.environment[key]

    def test_argument_errors_do_not_echo_private_args(self):
        for arguments in (["--unknown", "secret-private", "--policy", str(self.path)],
                          ["--policy", str(self.path), "secret-private"],
                          ["--policy", str(self.path), "--"]):
            result = subprocess.run([sys.executable, str(WRAPPER), *arguments], cwd=self.base,
                                    env=self.environment, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b'secret-private', result.stdout + result.stderr)

    def test_missing_exec_returns_127_without_argv_dump(self):
        command = [sys.executable, str(WRAPPER), '--policy', str(self.path), '--',
                   str(self.base / 'secret-private-missing-command')]
        result = subprocess.run(command, env=self.environment, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 127)
        self.assertNotIn(b'secret-private', result.stdout + result.stderr)

    def test_nonexecutable_returns_126(self):
        target = self.base / 'nonexecutable'
        target.write_text('not executable')
        result = subprocess.run([sys.executable, str(WRAPPER), '--policy', str(self.path), '--',
                                 str(target)], env=self.environment, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 126)

    def test_affinity_set_failure_never_execs(self):
        with patch.object(EXECUTION.os, 'sched_setaffinity', side_effect=OSError):
            with patch.object(EXECUTION.os, 'execvpe') as execute:
                with patch.object(sys, 'argv', ['wrapper', '--policy', str(self.path), '--', 'command']):
                    with patch.dict(os.environ, self.environment, clear=True):
                        self.assertEqual(EXECUTION.main(), 2)
                execute.assert_not_called()


FAKE_RBM = r'''
package RBM;
use strict;
use warnings;
use JSON::PP;
our $config;
our $fixture;
sub load_config {
    my ($file) = @_;
    open my $handle, '<', $file or die 'private fixture error';
    local $/; $fixture = decode_json(<$handle>); close $handle;
    $config = {run => {}, opt => {}, step => 'rbm_init'};
}
sub set_default_env { $ENV{TZ} = 'UTC'; $ENV{LC_ALL} = 'C'; }
sub load_system_config { }
sub load_local_config { }
sub load_modules_config { }
sub valid_project { die 'private project' unless $_[0] eq 'firefox'; }
sub check_context {
    die 'private context' unless $config->{step} eq 'build'
      && join(',', @{$config->{run}{target}}) eq 'alpha,mullvadbrowser-windows-x86_64,pgo-generate';
}
sub marker { open(my $out, '>', $fixture->{marker}); print {$out} 'side-effect'; close $out; }
sub project_config {
    my ($project, $key, $options) = @_;
    check_context();
    if ($key eq 'num_procs') {
        return $options->{num_procs} if $options && $options->{num_procs};
        open(my $fh, '<', '/proc/self/status'); my $allowed;
        while (<$fh>) { $allowed=$1 if /^Cpus_allowed_list:\s*(\S+)/; } close $fh;
        my $total=0;
        for (split /,/, $allowed) { my ($a,$b)=split /-/; $b //= $a; $total += $b-$a+1; }
        return $fixture->{bad_num} // $total;
    }
    return [{filename=>'mozconfig',content=>'configured-content-sentinel'}] if $key eq 'input_files';
    if ($key eq 'content') {
        die 'private unconfigured content' unless $options->{filename} eq 'mozconfig'
             && $options->{content} eq 'configured-content-sentinel' && $options->{pkg_type} eq 'build';
        die 'secret-private-render-error' if $fixture->{render_failure};
        return 'mk_add_options MOZ_PARALLEL_BUILD=' . project_config($project,'num_procs',$options) . "\n"
             . 'configured exact fixture content' . "\n";
    }
    if ($key eq 'build') {
        my $operation = $fixture->{operation} // '';
        git_clone_fetch_chdir('firefox', {}) if $operation eq 'git';
        hg_clone_fetch_chdir('firefox', {}) if $operation eq 'hg';
        urlget('firefox', {}) if $operation eq 'url';
        build_pkg('firefox', {}) if $operation eq 'build';
        build_run('firefox', {}) if $operation eq 'build_run';
        input_files('link','firefox',{}) if $operation eq 'link';
        input_files('copy','firefox',{}) if $operation eq 'copy';
        input_files('getfnames','firefox',{}) if $operation eq 'metadata';
        die 'private pkg context' unless $options->{pkg_type} eq 'build';
        return "#!/bin/sh\n./mach configure --enable-profile-generate=cross\n./mach build --verbose\n";
    }
    return 'git_clones' if $key eq 'git_clone_dir';
    die 'secret-private-unknown-key';
}
sub rbm_path { return $fixture->{root} . '/' . $_[0]; }
sub git_need_fetch { return $fixture->{need_fetch} // 0; }
sub git_clone_fetch_chdir { marker(); return; }
sub hg_clone_fetch_chdir { marker(); }
sub urlget { marker(); }
sub build_pkg { marker(); }
sub build_run { marker(); }
sub input_files { return {}; }
sub recursive_copy {
    my ($from, $name, $destination, $action) = @_;
    die 'private primitive' unless $action eq 'link' && $name eq 'staged';
    link($from, "$destination/$name") or die 'private hardlink';
    return ($name);
}
1;
'''


class ResourceRendererFixtureTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='pgo-render-native-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.upstream = self.base / 'upstream'
        self.output = self.base / 'rendered'
        (self.upstream / 'rbm/lib').mkdir(parents=True)
        (self.upstream / 'rbm/lib/RBM.pm').write_text(FAKE_RBM)
        self.marker = self.base / 'side-effect'
        self.fixture = {'root': str(self.upstream), 'marker': str(self.marker)}
        self.write()
        self.before = os.sched_getaffinity(0)
        self.environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')

    def write(self):
        (self.upstream / 'rbm.conf').write_text(json.dumps(self.fixture))

    def execute(self, cpus=None, output=None, arguments=None):
        command = ['perl', str(RENDERER), '--upstream', str(self.upstream),
                   '--output-directory', str(output or self.output)]
        if arguments is not None:
            command = ['perl', str(RENDERER), *arguments]
        if cpus:
            command = ['taskset', '--cpu-list', ','.join(map(str, cpus)), *command]
        return subprocess.run(command, cwd=self.base, env=self.environment,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)

    def rejected(self):
        result = self.execute()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn(b'secret-private', result.stdout + result.stderr)
        self.assertFalse((self.output / 'metadata.json').exists())
        self.assertFalse(self.marker.exists(), 'forbidden original side effect was invoked')
        return result

    def tearDown(self):
        self.assertEqual(os.sched_getaffinity(0), self.before)

    def test_actual_host_atomic_probe_and_fixed_metadata_shape(self):
        result = self.execute()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout + result.stderr, b'')
        metadata = json.loads((self.output / 'metadata.json').read_text())
        self.assertEqual(set(metadata), {'schema','num_procs','logical_cpu_count','affinity',
                        'path_tiny_version','path_tiny_source_sha256','atomic_spew_hardlink_verified'})
        self.assertEqual(metadata['schema'], 1)
        self.assertEqual(metadata['num_procs'], len(self.before))
        self.assertEqual(metadata['affinity'], sorted(self.before))
        self.assertTrue(metadata['atomic_spew_hardlink_verified'])
        self.assertRegex(metadata['path_tiny_version'], r'^\d+\.\d+')
        self.assertRegex((self.output / 'path-tiny-source.sha256').read_text(), r'^[0-9a-f]{64}\n$')
        evidence = json.loads((self.output / 'atomic-spew-hardlink.json').read_text())
        self.assertEqual(evidence['operational_bytes'], (self.output / 'mozconfig.operational').stat().st_size)
        self.assertGreater(evidence['normalized_bytes'], 32)
        self.assertTrue(evidence['hardlink_same_inode_before'])
        self.assertTrue(evidence['atomic_inode_replaced'])
        self.assertTrue(evidence['staged_operational_bytes_preserved'])
        self.assertEqual(metadata['path_tiny_source_sha256'], (self.output / 'path-tiny-source.sha256').read_text().strip())
        self.assertEqual(evidence['staged_after_sha256'], hashlib.sha256((self.output / 'mozconfig.operational').read_bytes()).hexdigest())
        self.assertEqual(list(self.output.glob('path-tiny-*')), [self.output / 'path-tiny-source.sha256'])

    def test_renderer_uses_configured_input_not_existing_normalized_file(self):
        old = self.upstream / 'out/firefox/mozconfig'
        old.parent.mkdir(parents=True)
        old.write_text('mk_add_options MOZ_PARALLEL_BUILD=999\nstatic-not-operational\n')
        cpus = sorted(self.before)[:2]
        if len(cpus)<2: self.skipTest('needs two currently allowed CPUs')
        result = self.execute(cpus=cpus)
        self.assertEqual(result.returncode,0,result.stderr)
        rendered = (self.output / 'mozconfig.operational').read_text()
        self.assertIn('MOZ_PARALLEL_BUILD=2',rendered)
        self.assertIn('configured exact fixture content',rendered)
        self.assertNotIn('static-not-operational',rendered)
        self.assertIn('MOZ_PARALLEL_BUILD=999',old.read_text())

    def test_renderer_outputs_actual_fixture_build_not_flag_fixture_in_script(self):
        result = self.execute()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual((self.output / 'firefox-build.operational').read_text(),
                         '#!/bin/sh\n./mach configure --enable-profile-generate=cross\n./mach build --verbose\n')

    def test_atomic_copy_uses_actual_operational_and_normalized_four_bytes(self):
        cpus = sorted(self.before)[:2]
        if len(cpus) < 2:
            self.skipTest('needs two currently allowed CPUs')
        result = self.execute(cpus=cpus)
        self.assertEqual(result.returncode, 0, result.stderr)
        operational = (self.output / 'mozconfig.operational').read_bytes()
        normalized = operational.replace(b'MOZ_PARALLEL_BUILD=2', b'MOZ_PARALLEL_BUILD=4')
        evidence = json.loads((self.output / 'atomic-spew-hardlink.json').read_text())
        self.assertEqual(evidence['staged_after_sha256'], hashlib.sha256(operational).hexdigest())
        self.assertEqual(evidence['original_after_sha256'], hashlib.sha256(normalized).hexdigest())
        self.assertNotEqual(evidence['staged_after_sha256'], evidence['original_after_sha256'])

    def test_one_cpu_metadata_only(self):
        result = self.execute(cpus=sorted(self.before)[:1])
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertEqual(json.loads((self.output / 'metadata.json').read_text())['num_procs'],1)

    def test_render_failure_no_metadata_or_private_error(self):
        self.fixture['render_failure']=True
        self.write()
        self.rejected()

    def test_bad_numeric_count_rejected(self):
        self.fixture['bad_num']='secret-private-count'
        self.write()
        self.rejected()

    def test_url_download_refused_before_original_call(self):
        self.fixture['operation']='url'
        self.write()
        self.rejected()

    def test_build_pkg_refused_before_original_call(self):
        self.fixture['operation']='build'
        self.write()
        self.rejected()

    def test_build_run_refused_before_original_call(self):
        self.fixture['operation']='build_run'
        self.write()
        self.rejected()

    def test_generic_link_or_copy_refused(self):
        for operation in ('link','copy'):
            self.fixture['operation']=operation
            self.write()
            self.rejected()

    def test_hg_fetch_refused(self):
        self.fixture['operation']='hg'
        self.write()
        self.rejected()

    def test_cold_git_clone_refused_before_original_call(self):
        self.fixture['operation']='git'
        self.write()
        self.rejected()
        self.assertFalse((self.upstream / 'git_clones').exists())

    def test_warm_git_needed_fetch_refused_before_original_call(self):
        (self.upstream / 'git_clones/firefox').mkdir(parents=True)
        self.fixture.update(operation='git',need_fetch=True)
        self.write()
        self.rejected()

    def test_warm_git_no_fetch_uses_original_metadata_api(self):
        (self.upstream / 'git_clones/firefox').mkdir(parents=True)
        self.fixture['operation']='git'
        self.write()
        result=self.execute()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(self.marker.exists(), 'valid warm native method was not called')

    def test_metadata_input_operation_allowed(self):
        self.fixture['operation']='metadata'
        self.write()
        result=self.execute()
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertFalse(self.marker.exists())

    def test_output_inside_upstream_rejected_without_creation(self):
        unsafe=self.upstream / 'new-output'
        result=self.execute(output=unsafe)
        self.assertNotEqual(result.returncode,0)
        self.assertFalse(unsafe.exists())

    def test_output_symlink_rejected(self):
        target=self.base / 'target'
        target.mkdir()
        self.output.symlink_to(target,target_is_directory=True)
        result=self.execute()
        self.assertNotEqual(result.returncode,0)
        self.assertEqual(list(target.iterdir()),[])

    def test_existing_metadata_rejected(self):
        self.output.mkdir()
        (self.output / 'metadata.json').write_text('untrusted')
        result=self.execute()
        self.assertNotEqual(result.returncode,0)
        self.assertEqual((self.output / 'metadata.json').read_text(),'untrusted')

    def test_renderer_arguments_reject_private_values_without_dump(self):
        result=self.execute(arguments=['--unknown','secret-private-value'])
        self.assertEqual(result.returncode,2)
        self.assertNotIn(b'secret-private',result.stdout+result.stderr)

    def test_inplace_path_tiny_implementation_fails_actual_probe(self):
        source = self.upstream / 'rbm/lib/Path/Tiny.pm'
        source.parent.mkdir(parents=True)
        source.write_text('package Path::Tiny; use strict; our $VERSION="0.144"; '
                          'sub path {bless {p=>$_[0]},"Path::Tiny";} '
                          'use overload \'""\'=>sub {$_[0]{p}},fallback=>1; '
                          'sub spew_utf8 {my($s,$v)=@_;open(my$f,">",$s->{p})or die;print $f $v;close$f;} '
                          'sub slurp_raw {my$s=shift;open(my$f,"<",$s->{p})or die;local$/;<$f>;} 1;')
        self.rejected()


AUTHORITY_ARTIFACT = (ROOT.parent / 'mullvad-browser-pgo-review' /
                      'resource-rbm-authority-real-pilot/artifact-source-controller')


@unittest.skipUnless((AUTHORITY_ARTIFACT / 'probe.json').is_file(),
                     'optional saved authentic865 native-renderer fixture unavailable')
class PinnedRbmRendererMechanicsTests(unittest.TestCase):
    """Actual865 code with a tiny test recipe, NOT live Firefox/cache/PGO proof."""
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='pgo-actual-rbm-fixture-')
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.upstream = self.base / 'upstream'
        self.output = self.base / 'rendered'
        (self.upstream / 'rbm/lib/RBM').mkdir(parents=True)
        data = json.loads((AUTHORITY_ARTIFACT / 'probe.json').read_text())
        self.assertEqual(data['rbm']['commit'], EXECUTION.EXPECTED_RBM)
        for source in data['sources']:
            if source['source'].startswith('rbm/lib/'):
                content = (AUTHORITY_ARTIFACT / source['artifact']).read_bytes()
                self.assertEqual(hashlib.sha256(content).hexdigest(), source['sha256'])
                destination = self.upstream / source['source']
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(content)
        (self.upstream / 'projects/firefox').mkdir(parents=True)
        (self.upstream / 'rbm.conf').write_text(
            'output_dir: "out/[% project %]"\n'
            'targets:\n  alpha: {}\n  mullvadbrowser-windows-x86_64: {}\n  pgo-generate: {}\n')
        (self.upstream / 'projects/firefox/config').write_text(
            'version: native-fixture\nfilename: native-fixture-output\n'
            'input_files:\n  - filename: mozconfig\n'
            '    content: \'[% INCLUDE "mozconfig.in" %]\'\n    refresh_input: 1\n')
        (self.upstream / 'projects/firefox/mozconfig.in').write_text(
            'mk_add_options MOZ_PARALLEL_BUILD=[% c("num_procs") %]\n'
            'actual-rbm-native-fixture-not-browser-proof\n')
        (self.upstream / 'projects/firefox/build').write_text(
            '#!/bin/sh\n./mach configure --enable-profile-generate=cross\n'
            './mach build --verbose\n')
        self.environment = dict(os.environ, PYTHONDONTWRITEBYTECODE='1')
        for key in EXECUTION.CPU_ENV:
            self.environment.pop(key, None)
        self.before = os.sched_getaffinity(0)

    def tearDown(self):
        self.assertEqual(os.sched_getaffinity(0), self.before)

    def execute(self, cpus):
        command = ['taskset', '--cpu-list', ','.join(map(str, cpus)), 'perl', str(RENDERER),
                   '--upstream', str(self.upstream), '--output-directory', str(self.output)]
        return subprocess.run(command, cwd=self.base, env=self.environment,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10)

    def test_real_pinned_recursive_copy_with_actual_loaded_host_atomic_content(self):
        cpus = sorted(self.before)[:2]
        if len(cpus) < 2:
            self.skipTest('requires two currently allowed CPU members')
        result = self.execute(cpus)
        self.assertEqual(result.returncode, 0, result.stderr)
        metadata = json.loads((self.output / 'metadata.json').read_text())
        self.assertEqual(metadata['num_procs'], 2)
        self.assertEqual(metadata['affinity'], cpus)
        self.assertTrue(metadata['atomic_spew_hardlink_verified'])
        self.assertRegex(metadata['path_tiny_source_sha256'], r'^[0-9a-f]{64}$')
        content = (self.output / 'mozconfig.operational').read_bytes()
        self.assertIn(b'MOZ_PARALLEL_BUILD=2', content)
        normalized = content.replace(b'MOZ_PARALLEL_BUILD=2', b'MOZ_PARALLEL_BUILD=4')
        evidence = json.loads((self.output / 'atomic-spew-hardlink.json').read_text())
        self.assertEqual(evidence['staged_after_sha256'], hashlib.sha256(content).hexdigest())
        self.assertEqual(evidence['original_after_sha256'], hashlib.sha256(normalized).hexdigest())
        self.assertTrue(evidence['atomic_inode_replaced'])
        self.assertFalse((self.upstream / 'git_clones').exists())
        self.assertFalse((self.upstream / 'out').exists())

    def test_real_pinned_cold_git_is_refused_without_clone(self):
        config = self.upstream / 'projects/firefox/config'
        config.write_text(config.read_text() +
                          'git_url: https://private-invalid.example/never-clone\n'
                          'git_hash: missing-ref\n')
        (self.upstream / 'projects/firefox/mozconfig.in').write_text(
            'mk_add_options MOZ_PARALLEL_BUILD=[% c("num_procs") %]\n'
            'source=[% c("var/git_commit") %]\n')
        config.write_text(config.read_text() +
                          'var:\n  git_commit: \'[% exec("git rev-parse missing-ref", {exec_noco => 1}) %]\'\n')
        result = self.execute(sorted(self.before)[:1])
        self.assertEqual(result.returncode, 1)
        self.assertFalse((self.upstream / 'git_clones').exists())
        self.assertFalse((self.output / 'metadata.json').exists())
        self.assertNotIn(b'private-invalid', result.stderr)


if __name__ == '__main__':
    unittest.main()
