"""Database crash evidence must survive cleanup without exposing SQL or secrets."""
import importlib.util
import pathlib
import subprocess
import sys
import unittest

SCRIPT = pathlib.Path(__file__).resolve().with_name("db-fixture-diagnostics.py")
spec = importlib.util.spec_from_file_location("db_fixture_diagnostics", SCRIPT)
diagnostics = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnostics)


class DatabaseFixtureDiagnosticsTests(unittest.TestCase):
    def test_counts_known_crash_causes_without_log_payloads(self):
        result = diagnostics.classify([
            "PANIC: write failed: No space left on device token=private-value\n",
            "server process terminated by signal 9\n",
            "out of memory: private-value\n",
        ])
        self.assertEqual(result, {
            "memory_exhausted": 1, "process_signaled": 1,
            "server_panic": 1, "storage_exhausted": 1,
        })
        self.assertNotIn("private-value", str(result))

    def test_sql_detail_and_context_cannot_inject_failure_classes(self):
        self.assertEqual(diagnostics.classify([
            "STATEMENT: SELECT 'PANIC: No space left on device'\n",
            "DETAIL: out of memory\n",
            "CONTEXT: database system was interrupted\n",
        ]), {})

    def test_cli_never_echoes_unknown_server_messages(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT)], input="FATAL: secret-credential\n",
            text=True, capture_output=True, timeout=5,
        )
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "fixture_database_log_classes={}\n")
        self.assertEqual(result.stderr, "")


if __name__ == "__main__":
    unittest.main()
