"""The public acceptance workflow runs the full suite on both GitHub-hosted architectures."""
from pathlib import Path
import unittest


class WorkflowTests(unittest.TestCase):
    def test_both_native_linux_platforms_execute_full_acceptance(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/acceptance.yml').read_text()
        for required in (
            'pull_request:', 'branches: [main]', 'contents: read',
            'arch: amd64', 'runner: ubuntu-24.04',
            'arch: arm64', 'runner: ubuntu-24.04-arm',
            'GATEBEAM_ACCEPTANCE_EXECUTION: native',
            'sh scripts/check-system.sh full', 'validate_receipt(result, manifest',
        ):
            self.assertIn(required, workflow)
        for unwanted in ('pull_request_target:', 'upload-artifact', 'download-artifact', 'packages: write'):
            self.assertNotIn(unwanted, workflow)

    def test_host_can_access_bind_mounts_owned_by_fixture_container_users(self):
        workflow = (Path(__file__).resolve().parents[1] / '.github/workflows/acceptance.yml').read_text()
        start = workflow.index('name: Run all twenty gates against local images')
        end = workflow.index('name: Verify complete same-commit acceptance', start)
        acceptance = workflow[start:end]
        self.assertIn('sudo --non-interactive', acceptance)
        self.assertIn('GIT_CONFIG_KEY_0=safe.directory', acceptance)
        self.assertIn('GIT_CONFIG_VALUE_0="$PWD"', acceptance)
        self.assertIn('sh scripts/check-system.sh full', acceptance)


if __name__ == '__main__':
    unittest.main()
