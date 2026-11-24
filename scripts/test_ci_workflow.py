"""The public acceptance workflow runs the full suite on both GitHub-hosted architectures."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]


class WorkflowTests(unittest.TestCase):
    def test_both_native_linux_platforms_execute_full_acceptance(self):
        workflow = (ROOT / '.github/workflows/acceptance.yml').read_text()
        normal = workflow[:workflow.index('  release_amd64:')]
        action = (ROOT / '.github/actions/native-acceptance/action.yml').read_text()
        for required in (
            'pull_request:', 'branches: [main]', 'contents: read',
            'arch: amd64', 'runner: ubuntu-24.04',
            'arch: arm64', 'runner: ubuntu-24.04-arm',
            'GATEBEAM_ACCEPTANCE_EXECUTION: native',
            'name: Full acceptance / ${{ matrix.arch }}',
            'uses: ./.github/actions/native-acceptance', 'scripts/public_release.py verify',
        ):
            self.assertIn(required, normal)
        self.assertIn('sh scripts/check-system.sh full', action)
        self.assertNotIn('packages: write', normal)

    def test_release_jobs_require_an_explicit_main_version_and_share_native_acceptance(self):
        workflow = (ROOT / '.github/workflows/acceptance.yml').read_text()
        platform = (ROOT / '.github/workflows/release-platform.yml').read_text()
        self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/main'", workflow)
        self.assertIn("if: github.event_name == 'push' && github.ref == 'refs/heads/main'", platform)
        self.assertEqual(workflow.count("if: needs.release_plan.outputs.version != ''"), 2)
        self.assertIn('needs: [release_plan, release_amd64, release_arm64]', workflow)
        self.assertIn('uses: ./.github/actions/native-acceptance', platform)
        self.assertLess(platform.index('scripts/public_release.py verify'), platform.index('scripts/public_release.py stage'))
        for unwanted in ('pull_request_target:', 'upload-artifact', 'download-artifact'):
            self.assertNotIn(unwanted, workflow + platform)

    def test_host_can_access_bind_mounts_owned_by_fixture_container_users(self):
        action = (ROOT / '.github/actions/native-acceptance/action.yml').read_text()
        start = action.index('name: Run all twenty gates against local images')
        acceptance = action[start:]
        self.assertIn('sudo --non-interactive', acceptance)
        self.assertIn('GIT_CONFIG_KEY_0=safe.directory', acceptance)
        self.assertIn('GIT_CONFIG_VALUE_0="$PWD"', acceptance)
        self.assertIn('sh scripts/check-system.sh full', acceptance)


if __name__ == '__main__':
    unittest.main()
