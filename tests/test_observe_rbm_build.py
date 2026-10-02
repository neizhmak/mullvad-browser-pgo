#!/usr/bin/env python3
"""Native CLI fixtures for observation only, not an RBM/browser validation."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts/observe-rbm-build.py"
PROJECTS = ("firefox-windows-x86_64.log", "node-windows-x86_64.log")


class ObserveRbmBuildTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="rbm-observe-test-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name).resolve()
        self.upstream = self.base / "upstream"
        self.upstream.mkdir()
        self.projects = self.upstream / "logs"
        self.projects.mkdir()
        self.log = self.base / "build.log"
        self.resources = self.base / "resources.jsonl"
        self.environment = os.environ | {"PYTHONDONTWRITEBYTECODE": "1"}

    def cli(self, source="print('native child', flush=True)", arguments=(),
            log=None, resources=None, interval="0.05"):
        command = [sys.executable, str(HELPER), "--upstream", str(self.upstream),
                   "--log", str(log or self.log), "--resource-log", str(resources or self.resources)]
        if interval is not None:
            command += ["--interval", interval]
        return command + ["--", sys.executable, "-c", source, *arguments]

    def execute(self, source="print('native child', flush=True)", **options):
        result = subprocess.run(self.cli(source, **options), cwd=ROOT, env=self.environment,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=8)
        return result

    def records(self):
        return [json.loads(line) for line in self.resources.read_text().splitlines()]

    def console_records(self, output, prefix):
        records = []
        for line in output.splitlines():
            position = line.find(prefix)
            if position >= 0:
                records.append(json.loads(line[position + len(prefix):]))
        return records

    def rejected(self, **options):
        marker = self.base / "child-launched"
        result = self.execute(f"from pathlib import Path; Path({str(marker)!r}).touch()", **options)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(marker.exists(), "unsafe destination launched a child")
        return result

    def test_exact_argv_cwd_environment_and_combined_log(self):
        arguments = ["with spaces", "'quoted'", "--upstream", "semi;colon", "$(false)", "snowman-\u2603"]
        self.environment["RBM_OBSERVE_FIXTURE"] = "inherited value"
        self.environment["RBM_OBSERVE_UNPRINTED_SECRET"] = "secret-not-for-console-853975"
        source = ("import json, os, sys; "
                  "data={'argv':sys.argv[1:],'cwd':os.getcwd(),"
                  "'env':os.environ['RBM_OBSERVE_FIXTURE']}; "
                  "os.write(1, ('CHILD '+json.dumps(data)+'\\n').encode()); "
                  "os.write(2,b'child stderr\\n')")
        result = self.execute(source, arguments=arguments)
        expected = ("CHILD " + json.dumps({"argv": arguments, "cwd": str(self.upstream),
                                          "env": "inherited value"}) + "\nchild stderr\n").encode()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(self.log.read_bytes(), expected)
        self.assertIn(expected, result.stdout)
        self.assertNotIn(self.environment["RBM_OBSERVE_UNPRINTED_SECRET"].encode(), result.stdout)
        self.assertNotIn(self.environment["RBM_OBSERVE_UNPRINTED_SECRET"], self.resources.read_text())

    def test_exit_23_is_preserved(self):
        result = self.execute("import os, sys; os.write(2,b'fixture error\\n'); sys.exit(23)")
        self.assertEqual(result.returncode, 23)
        self.assertEqual(self.log.read_bytes(), b"fixture error\n")
        self.assertEqual(self.records()[-1]["exit_code"], 23)

    def test_binary_stdout_and_large_stdout_are_not_reencoded_or_lost(self):
        payload = b"\x00\xff\r\n" + b"abcdef" * 60000 + b"END\n"
        source = "import os; data=b'\\x00\\xff\\r\\n'+b'abcdef'*60000+b'END\\n'; os.write(1,data)"
        result = self.execute(source)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.log.read_bytes(), payload)
        # Resource records can be interleaved, but child byte order is unchanged.
        output = result.stdout
        for line in self.resources.read_bytes().splitlines(keepends=True):
            output = output.replace(b"[rbm-resource] " + line, b"")
        self.assertEqual(output, payload)

    def test_default_interval_and_final_resource_fields(self):
        result = self.execute(interval=None)
        self.assertEqual(result.returncode, 0)
        records = self.records()
        self.assertEqual([record["reason"] for record in records], ["start", "exit"])
        self.assertEqual(self.console_records(result.stdout, b"[rbm-resource] "), records)
        self.assertEqual(records[-1]["child_returncode"], 0)
        self.assertIsNone(records[-1]["observed_supervisor_signal"])
        for record in records:
            self.assertEqual(record["cpu"]["logical"], os.cpu_count())
            if hasattr(os, "sched_getaffinity"):
                self.assertEqual(record["cpu"]["affinity"], len(os.sched_getaffinity(0)))
            for label in ("upstream", "log"):
                self.assertGreater(record["disks"][label]["total_bytes"], 0)
                self.assertGreaterEqual(record["disks"][label]["free_bytes"], 0)
                if hasattr(os, "statvfs"):
                    self.assertGreaterEqual(record["disks"][label]["total_inodes"], 0)
                    self.assertGreaterEqual(record["disks"][label]["free_inodes"], 0)
            if sys.platform.startswith("linux"):
                for key in ("MemTotal", "MemAvailable", "SwapTotal", "SwapFree"):
                    self.assertIsInstance(record["meminfo_kib"][key], int)
                if record.get("oom_kill") is not None:
                    self.assertIsInstance(record["oom_kill"], int)
                if "cgroup_v2" in record:
                    self.assertTrue(set(record["cgroup_v2"]).issubset(
                        {"memory.current", "memory.max", "memory.events"}))

    def test_existing_diagnostics_append_and_native_tree_remains_unchanged(self):
        self.log.write_bytes(b"existing diagnostics\n")
        self.resources.write_text('{"existing":true}\n')
        for name in PROJECTS:
            (self.projects / name).write_bytes((name + " unchanged source\n").encode())
        instrumentation = self.upstream / "instrumentation.profraw"
        instrumentation.write_bytes(b"fixture profile never changed by observation")
        before = {str(path.relative_to(self.upstream)): path.read_bytes()
                  for path in self.upstream.rglob("*") if path.is_file()}
        result = self.execute()
        self.assertEqual(result.returncode, 0)
        after = {str(path.relative_to(self.upstream)): path.read_bytes()
                 for path in self.upstream.rglob("*") if path.is_file()}
        self.assertEqual(after, before)
        self.assertEqual(self.log.read_bytes(), b"existing diagnostics\nnative child\n")
        self.assertEqual(self.records()[0], {"existing": True})
        self.assertEqual(self.records()[-1]["reason"], "exit")

    def test_live_project_tails_are_bounded_and_resource_records_are_live(self):
        firefox = self.projects / PROJECTS[0]
        node = self.projects / PROJECTS[1]
        firefox.write_bytes(b"OLD-SECRET-PREFIX\n" + b"a" * 180000 + b"LATEST-PRESTART\n")
        node.write_bytes(b"NODE-PRESTART\n")
        source = ("import os, threading; "
                  f"f=open({str(firefox)!r},'ab'); f.write(b'\\nerror: native compiler fixture\\n'); f.close(); "
                  f"f=open({str(node)!r},'ab'); f.write(b'NODE-LIVE\\n'); f.close(); "
                  "threading.Event().wait(0.8); print('CHILD-DONE',flush=True)")
        process = subprocess.Popen(self.cli(source), cwd=ROOT, env=self.environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        lines = []
        seen_project = threading.Event()
        seen_interval = threading.Event()

        def read_console():
            for line in process.stdout:
                lines.append(line)
                if b"error: native compiler fixture" in line:
                    seen_project.set()
                if b'"reason":"interval"' in line:
                    seen_interval.set()

        reader = threading.Thread(target=read_console)
        reader.start()
        try:
            self.assertTrue(seen_project.wait(3), "live compiler tail was not surfaced")
            self.assertTrue(seen_interval.wait(3), "live resource record was not printed")
            self.assertIsNone(process.poll(), "diagnostics appeared only after child exit")
            self.assertEqual(process.wait(timeout=5), 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            reader.join(timeout=5)
            process.stdout.close()
            stderr = process.stderr.read()
            process.stderr.close()
        self.assertFalse(reader.is_alive())
        self.assertEqual(stderr, b"")
        output = b"".join(lines)
        tails = self.console_records(output, b"[rbm-project] ")
        self.assertTrue(tails)
        self.assertEqual({record["project"] for record in tails}, set(PROJECTS))
        for record in tails:
            self.assertLessEqual(record["bytes"], 8192)
            self.assertEqual(record["end"] - record["start"], record["bytes"])
        self.assertNotIn(b"OLD-SECRET-PREFIX", output)
        self.assertIn(b"LATEST-PRESTART", output)
        self.assertEqual(sum(record["text"].count("native compiler fixture") for record in tails), 1)
        self.assertTrue(any(record["reason"] == "interval" for record in self.records()))
        self.assertEqual(self.records()[-1]["reason"], "exit")
        self.assertEqual(self.log.read_bytes(), b"CHILD-DONE\n")
        self.assertTrue(firefox.read_bytes().endswith(b"error: native compiler fixture\n"))

    def test_project_workflow_command_markers_are_escaped_only_on_console(self):
        payload = (b"::error::v2 project fixture\n"
                   b"##[error]legacy project fixture\n"
                   b"##[set-output name=fixture]legacy-value\n")
        target = self.projects / PROJECTS[0]
        target.write_bytes(payload)
        result = self.execute()
        self.assertEqual(result.returncode, 0)
        project_lines = [line for line in result.stdout.splitlines()
                         if line.startswith(b"[rbm-project] ")]
        self.assertEqual(len(project_lines), 1)
        self.assertNotIn(b"##[", project_lines[0])
        self.assertIn(b"\\u0023\\u0023[error]", project_lines[0])
        record = json.loads(project_lines[0][len(b"[rbm-project] "):])
        self.assertEqual(record["text"].encode(), payload)
        self.assertEqual(record["bytes"], len(payload))
        self.assertEqual(target.read_bytes(), payload)
        self.assertEqual(self.log.read_bytes(), b"native child\n")

    def test_truncated_and_replaced_project_logs_are_followed(self):
        target = self.projects / PROJECTS[0]
        target.write_bytes(b"original project fixture\n")
        source = ("from pathlib import Path; import threading; "
                  f"p=Path({str(target)!r}); "
                  "threading.Event().wait(.12); p.write_bytes(b'truncated fixture\\n'); "
                  "threading.Event().wait(.12); q=p.with_suffix('.new'); "
                  "q.write_bytes(b'replacement fixture\\n'); q.replace(p); "
                  "threading.Event().wait(.12)")
        result = self.execute(source)
        self.assertEqual(result.returncode, 0)
        self.assertIn(b"original project fixture", result.stdout)
        self.assertIn(b"truncated fixture", result.stdout)
        self.assertIn(b"replacement fixture", result.stdout)
        self.assertEqual(target.read_bytes(), b"replacement fixture\n")

    def test_missing_destination_parent_is_rejected_before_launch(self):
        for keyword in ("log", "resources"):
            with self.subTest(keyword=keyword):
                self.rejected(**{keyword: self.base / "absent" / "output.log"})

    def test_same_destination_is_rejected_before_launch(self):
        self.rejected(resources=self.log)

    def test_native_project_log_destination_is_rejected_before_launch(self):
        native = self.projects / PROJECTS[0]
        native.write_bytes(b"never truncate native log\n")
        for keyword in ("log", "resources"):
            with self.subTest(keyword=keyword):
                self.rejected(**{keyword: native})
                self.assertEqual(native.read_bytes(), b"never truncate native log\n")

    def test_dotdot_destination_is_rejected_before_launch(self):
        self.rejected(log=self.projects / ".." / "overwrite.log")

    def test_symlink_destinations_and_parent_links_are_rejected_before_launch(self):
        target = self.base / "target.log"
        target.write_bytes(b"must remain unchanged\n")
        link = self.base / "linked-output.log"
        parent = self.base / "linked-parent"
        try:
            link.symlink_to(target)
            parent.symlink_to(self.base, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"native symlink creation unavailable: {type(error).__name__}")
        for keyword in ("log", "resources"):
            for path in (link, parent / "new.log"):
                with self.subTest(keyword=keyword, path=path.name):
                    self.rejected(**{keyword: path})
        self.assertEqual(target.read_bytes(), b"must remain unchanged\n")
        self.assertFalse((self.base / "new.log").exists())

    def test_directory_destinations_are_rejected_before_launch(self):
        for keyword in ("log", "resources"):
            with self.subTest(keyword=keyword):
                self.rejected(**{keyword: self.base})

    @unittest.skipUnless(os.name == "posix", "native POSIX FIFO safety")
    def test_fifo_destinations_are_rejected_without_blocking(self):
        fifo = self.base / "output.fifo"
        os.mkfifo(fifo)
        for keyword in ("log", "resources"):
            with self.subTest(keyword=keyword):
                self.rejected(**{keyword: fifo})

    def test_hardlinked_destinations_are_rejected_before_launch(self):
        target = self.projects / PROJECTS[0]
        target.write_bytes(b"native log cannot be overwritten via hardlink\n")
        linked = self.base / "linked.log"
        try:
            os.link(target, linked)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"native hardlink creation unavailable: {type(error).__name__}")
        self.rejected(log=linked)
        self.assertEqual(target.read_bytes(), b"native log cannot be overwritten via hardlink\n")

    def test_project_symlink_does_not_leak_and_is_diagnostic_only(self):
        target = self.base / "private.txt"
        target.write_bytes(b"private-project-symlink-marker-982\n")
        try:
            (self.projects / PROJECTS[0]).symlink_to(target)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"native symlink creation unavailable: {type(error).__name__}")
        result = self.execute()
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(target.read_bytes().strip(), result.stdout)
        self.assertEqual(target.read_bytes(), b"private-project-symlink-marker-982\n")
        self.assertEqual(self.records()[-1]["exit_code"], 0)

    def test_project_directory_symlink_does_not_leak(self):
        outside = self.base / "private-directory"
        outside.mkdir()
        (outside / PROJECTS[0]).write_bytes(b"private-directory-marker-712\n")
        self.projects.rmdir()
        try:
            self.projects.symlink_to(outside, target_is_directory=True)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"native symlink creation unavailable: {type(error).__name__}")
        result = self.execute()
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(b"private-directory-marker-712", result.stdout)

    @unittest.skipUnless(os.name == "posix", "native POSIX nonregular project logs")
    def test_project_fifo_is_diagnostic_only_and_not_opened_blocking(self):
        os.mkfifo(self.projects / PROJECTS[0])
        result = self.execute()
        self.assertEqual(result.returncode, 0)
        self.assertEqual(self.records()[-1]["exit_code"], 0)
        self.assertEqual(self.log.read_bytes(), b"native child\n")

    def test_invalid_interval_missing_command_or_missing_log_are_prelaunch_errors(self):
        for interval in ("0", "-1", "nan", "inf"):
            with self.subTest(interval=interval):
                self.rejected(interval=interval)
        for command in (self.cli()[:self.cli().index("--")],
                        [sys.executable, str(HELPER), "--upstream", str(self.upstream),
                         "--", sys.executable, "-c", "print('must not start')"]):
            result = subprocess.run(command, cwd=ROOT, env=self.environment,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
            self.assertEqual(result.returncode, 2)
            self.assertNotIn(b"must not start", result.stdout)

    def test_resource_stat_failure_during_build_does_not_change_native_success(self):
        diagnostics = self.base / "diagnostics"
        diagnostics.mkdir()
        moved = self.base / "moved-diagnostics"
        source = ("import os, threading; "
                  f"os.rename({str(diagnostics)!r},{str(moved)!r}); "
                  "threading.Event().wait(.15); print('native success',flush=True)")
        result = self.execute(source, log=diagnostics / "build.log",
                              resources=diagnostics / "resources.jsonl")
        self.assertEqual(result.returncode, 0)
        self.assertEqual((moved / "build.log").read_bytes(), b"native success\n")
        records = [json.loads(line) for line in (moved / "resources.jsonl").read_text().splitlines()]
        self.assertEqual(records[-1]["exit_code"], 0)
        self.assertTrue(any(any(error.startswith("disk_log:") for error in record.get("errors", []))
                            for record in records))
        self.assertEqual(self.console_records(result.stdout, b"[rbm-resource] "), records)

    def test_project_hardlink_is_not_read_or_modified(self):
        target = self.base / "private-hardlink.txt"
        target.write_bytes(b"private-hardlink-marker-831\n")
        try:
            os.link(target, self.projects / PROJECTS[0])
        except (OSError, NotImplementedError) as error:
            self.skipTest(f"native hardlink creation unavailable: {type(error).__name__}")
        result = self.execute()
        self.assertEqual(result.returncode, 0)
        self.assertNotIn(b"private-hardlink-marker-831", result.stdout)
        self.assertEqual(target.read_bytes(), b"private-hardlink-marker-831\n")

    def test_launch_failure_is_not_success(self):
        command = self.cli()
        command = command[:command.index("--") + 1] + [str(self.base / "missing-executable")]
        result = subprocess.run(command, cwd=ROOT, env=self.environment,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 127)
        self.assertEqual(self.records()[-1]["reason"], "launch-error")

    @unittest.skipUnless(os.name == "posix", "native POSIX negative-signal exit mapping")
    def test_native_child_signal_maps_to_143(self):
        result = self.execute("import os, signal; os.kill(os.getpid(),signal.SIGTERM)")
        self.assertEqual(result.returncode, 143)
        self.assertEqual(self.records()[-1]["child_returncode"], -signal.SIGTERM)
        self.assertEqual(self.records()[-1]["exit_code"], 143)
        self.assertIsNone(self.records()[-1]["observed_supervisor_signal"])

    @unittest.skipUnless(os.name == "posix", "native POSIX inherited stdout cleanup")
    def test_successful_leader_does_not_leave_descendant_or_pipe_running(self):
        source = ("import os, subprocess, sys; "
                  "p=subprocess.Popen([sys.executable,'-c',"
                  "'import threading; threading.Event().wait(60)']); "
                  "print('DESCENDANT '+str(p.pid),flush=True)")
        started = time.monotonic()
        result = self.execute(source)
        self.assertEqual(result.returncode, 0)
        self.assertLess(time.monotonic() - started, 4.5)
        self.assertEqual(self.records()[-1]["child_returncode"], 0)
        self.assertIsNone(self.records()[-1]["observed_supervisor_signal"])
        pid = int(self.log.read_text().split()[1])
        if sys.platform.startswith("linux"):
            proc_stat = Path(f"/proc/{pid}/stat")
            if proc_stat.exists():
                self.assertEqual(proc_stat.read_text().rsplit(")", 1)[1].split()[0], "Z")

    @unittest.skipUnless(os.name == "posix", "native POSIX escaped-session pipe drain")
    def test_escaped_session_retaining_stdout_has_bounded_drain_without_signal(self):
        pid_file = self.base / "escaped-fixture.pid"
        source = ("from pathlib import Path; import subprocess, sys; "
                  "p=subprocess.Popen([sys.executable,'-c',"
                  "'import threading; threading.Event().wait(10)'],start_new_session=True); "
                  f"Path({str(pid_file)!r}).write_text(str(p.pid)); "
                  "print('ESCAPED '+str(p.pid),flush=True)")
        started = time.monotonic()
        try:
            result = self.execute(source)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertLess(time.monotonic() - started, 4.5)
            self.assertEqual(self.records()[-1]["reason"], "exit")
            self.assertEqual(self.records()[-1]["child_returncode"], 0)
            self.assertEqual(self.records()[-1]["exit_code"], 0)
            self.assertIsNone(self.records()[-1]["observed_supervisor_signal"])
            pid = int(pid_file.read_text())
            self.assertEqual(self.log.read_bytes(), f"ESCAPED {pid}\n".encode())
            # The helper must not adopt or signal this different session.
            os.kill(pid, 0)
            if sys.platform.startswith("linux"):
                state = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()[0]
                self.assertNotEqual(state, "Z", "observer killed an escaped-session fixture")
            self.assertEqual(self.console_records(result.stdout, b"[rbm-resource] "), self.records())
        finally:
            # Test-only cleanup of the exact PID the fixture wrote, even on failure.
            # The fixture also has its own finite 10-second fallback lifetime.
            if pid_file.exists():
                try:
                    os.kill(int(pid_file.read_text()), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    @unittest.skipUnless(os.name == "posix", "native POSIX graceful signal forwarding")
    def test_sigint_flushes_snapshot_before_child_handler_and_final_output(self):
        source = ("import signal, sys, threading; "
                  "signal.signal(signal.SIGINT, lambda *args: "
                  "(print('HANDLED-INT',flush=True),sys.exit(0))); "
                  "print('READY-INT',flush=True); threading.Event().wait(60)")
        process = subprocess.Popen(self.cli(source), cwd=ROOT, env=self.environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        lines = []
        ready = threading.Event()

        def read_console():
            for line in process.stdout:
                lines.append(line)
                if line.startswith(b"READY-INT"):
                    ready.set()

        reader = threading.Thread(target=read_console)
        reader.start()
        try:
            self.assertTrue(ready.wait(3))
            process.send_signal(signal.SIGINT)
            self.assertEqual(process.wait(timeout=5), 130)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            reader.join(timeout=5)
            process.stdout.close()
            stderr = process.stderr.read()
            process.stderr.close()
        self.assertFalse(reader.is_alive())
        self.assertEqual(stderr, b"")
        output = b"".join(lines)
        self.assertLess(output.index(b'"observed_supervisor_signal":"SIGINT"'),
                        output.index(b"HANDLED-INT"))
        self.assertEqual(self.log.read_bytes(), b"READY-INT\nHANDLED-INT\n")
        self.assertEqual(self.records()[-1]["child_returncode"], 0)
        self.assertEqual(self.records()[-1]["exit_code"], 130)
        self.assertEqual(self.records()[-1]["observed_supervisor_signal"], "SIGINT")

    @unittest.skipUnless(sys.platform.startswith("linux"), "native Linux process-group cleanup")
    def test_sigterm_snapshot_then_group_cleanup_and_final_143(self):
        grandchild = ("import os, signal, sys, threading; "
                      "signal.signal(signal.SIGTERM,signal.SIG_IGN); "
                      "os.write(int(sys.argv[1]),b'1'); "
                      "os.close(int(sys.argv[1])); threading.Event().wait(60)")
        source = ("import os, subprocess, sys, threading; r,w=os.pipe(); "
                  f"p=subprocess.Popen([sys.executable,'-c',{grandchild!r},str(w)],pass_fds=(w,)); "
                  "os.close(w); os.read(r,1); os.close(r); "
                  "print('READY '+str(os.getpid())+' '+str(p.pid),flush=True); "
                  "threading.Event().wait(60)")
        process = subprocess.Popen(self.cli(source), cwd=ROOT, env=self.environment,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        lines = []
        ready = threading.Event()
        pids = []
        states_before_fixture_cleanup = []

        def read_console():
            for line in process.stdout:
                lines.append(line)
                if line.startswith(b"READY "):
                    pids.extend(int(value) for value in line.split()[1:])
                    ready.set()

        reader = threading.Thread(target=read_console)
        reader.start()
        try:
            self.assertTrue(ready.wait(3), "native group fixture did not start")
            started = time.monotonic()
            process.send_signal(signal.SIGTERM)
            self.assertEqual(process.wait(timeout=5), 143)
            self.assertLess(time.monotonic() - started, 4.5)
            for pid in pids:
                proc_stat = Path(f"/proc/{pid}/stat")
                states_before_fixture_cleanup.append(
                    proc_stat.read_text().rsplit(")", 1)[1].split()[0] if proc_stat.exists() else None)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            for pid in pids:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            reader.join(timeout=5)
            process.stdout.close()
            stderr = process.stderr.read()
            process.stderr.close()
        self.assertFalse(reader.is_alive())
        self.assertEqual(stderr, b"")
        records = self.records()
        signals = [record for record in records if record["reason"] == "signal"]
        self.assertEqual([record["signal"] for record in signals], ["SIGTERM"])
        self.assertEqual(records[-1]["reason"], "exit")
        self.assertEqual(records[-1]["exit_code"], 143)
        self.assertEqual(records[-1]["observed_supervisor_signal"], "SIGTERM")
        self.assertEqual(signals[0]["observed_supervisor_signal"], "SIGTERM")
        self.assertIsNone(signals[0]["child_returncode"])
        self.assertIn(b'"signal":"SIGTERM"', b"".join(lines))
        self.assertEqual(self.log.read_bytes(), f"READY {pids[0]} {pids[1]}\n".encode())
        self.assertEqual(len(states_before_fixture_cleanup), 2)
        # Check before the test's safety cleanup, so that cleanup cannot mask a bug.
        # A killed orphan can be a zombie until the host init reaps it.
        self.assertTrue(all(state in (None, "Z") for state in states_before_fixture_cleanup),
                        states_before_fixture_cleanup)


if __name__ == "__main__":
    unittest.main()
