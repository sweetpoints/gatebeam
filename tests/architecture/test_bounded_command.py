"""Behavioral tests for the verification command deadline (Python 3 prerequisite)."""
import importlib.util
import os
import pathlib
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

RUNNER = pathlib.Path(__file__).resolve().parents[2] / "scripts" / "bounded-command.py"


def running(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    if sys.platform.startswith("linux"):
        try:
            # A child adopted by PID1 can remain a zombie until its next reap;
            # it has terminated and cannot execute any more commands.
            state = pathlib.Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()
            return bool(state) and state[0] != "Z"
        except (FileNotFoundError, ProcessLookupError):
            return False
    return True


class BoundedCommandTests(unittest.TestCase):
    def test_proc_read_race_after_pid_probe_is_terminated(self):
        with patch.object(sys, "platform", "linux"), patch.object(os, "kill"), patch.object(
            pathlib.Path, "read_text", side_effect=ProcessLookupError(3, "No such process")
        ):
            self.assertFalse(running(12345))

    def test_proc_permission_error_is_not_reported_as_termination(self):
        with patch.object(sys, "platform", "linux"), patch.object(os, "kill"), patch.object(
            pathlib.Path, "read_text", side_effect=PermissionError(13, "Permission denied")
        ):
            with self.assertRaises(PermissionError):
                running(12345)

    def test_propagates_nonzero_exit(self):
        result = subprocess.run(
            [sys.executable, str(RUNNER), "5", sys.executable, "-c", "raise SystemExit(23)"],
            timeout=10,
        )
        self.assertEqual(result.returncode, 23)

    def test_deadline_applies_even_before_child_starts(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = pathlib.Path(directory) / "not-started"
            command = f"import time,pathlib; time.sleep(30); pathlib.Path({str(marker)!r}).touch()"
            result = subprocess.run(
                [sys.executable, str(RUNNER), "0.5", sys.executable, "-c", command],
                timeout=5,
            )
            self.assertEqual(result.returncode, 124)
            self.assertFalse(marker.exists())

    def test_deadline_terminates_child_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            ready = pathlib.Path(directory) / "child-ready"
            child = (
                "import pathlib,time,os; "
                f"pathlib.Path({str(ready)!r}).write_text(str(os.getpid())); "
                "time.sleep(30)"
            )
            # Deliberately take longer than the watchdog to boot the fixture.
            # Startup is not what this test measures: it must exercise the kill
            # path with a genuinely running descendant, even on a busy worker.
            parent = (
                "import subprocess,sys,time; time.sleep(0.75); "
                f"subprocess.Popen([sys.executable,'-c',{child!r}]); "
                "time.sleep(30)"
            )
            spec = importlib.util.spec_from_file_location("bounded_command", RUNNER)
            runner = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(runner)
            real_popen = subprocess.Popen
            process = None
            child_pid = None

            def launch(command, **options):
                nonlocal process, child_pid
                # Assert before starting: a broken session flag must never
                # place this test's process group in the watchdog's kill path.
                self.assertTrue(options.get("start_new_session"))
                process = real_popen(command, **options)
                self.assertEqual(os.getpgid(process.pid), process.pid)
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    if ready.exists():
                        text = ready.read_text().strip()
                        if text:
                            child_pid = int(text)
                            self.assertTrue(running(child_pid))
                            return process
                    self.assertIsNone(process.poll(), "fixture exited before readiness")
                    time.sleep(0.01)
                self.fail("owned child fixture did not become ready")

            try:
                with patch.object(sys, "argv", [str(RUNNER), "0.5", sys.executable, "-c", parent]), patch.object(
                    runner.subprocess, "Popen", side_effect=launch
                ):
                    code = runner.main()
                self.assertEqual(code, 124)
                self.assertIsNotNone(child_pid)
                deadline = time.monotonic() + 2
                while running(child_pid) and time.monotonic() < deadline:
                    time.sleep(0.01)
                self.assertFalse(running(child_pid), "child survived parent deadline")
            finally:
                if process is not None:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
