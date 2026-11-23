"""The diagnostic run must collect every stage without authorizing publication."""
from contextlib import redirect_stdout
import io
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('check-system.py')


class SystemRunnerTests(unittest.TestCase):
    def execute(self, keep_going, failed_stage, execution="native", route_evidence=True, group="full"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            script = root / 'scripts/check-system.py'
            script.parent.mkdir()
            script.write_text(SCRIPT.read_text())
            calls = []

            def stage(command, **options):
                calls.append(command)
                if command[-2:] == ['scripts/check-pki.sh','public-client'] and route_evidence:
                    output = root / '.work/system-acceptance/tls-performance.json'
                    output.write_text(json.dumps({'execution':'software-emulated-vm','policy':'software-functional-v1','performance_certification':'not-certified','routes':400,'verified':72,'elapsed_seconds':5.01,'budget_seconds':5,'target_met':False,'functional_verified':400,'functional_batches':50,'full_business_verified':False,'full_failed':True,'full_routes':[{'site_id':'site-'+str(i//8),'host':'host-'+str(i),'sni':'host-'+str(i),'route':'/','outcome':'verified' if i<72 else 'degraded','reason':'' if i<72 else 'verification_budget_exhausted'} for i in range(400)]}))
                return 23 if len(calls) == failed_stage else 0

            def source(command, **options):
                if command[0]=='docker':
                    from ci import ROLES
                    return json.dumps([{'RepoTags':['gatebeam-'+r+':local'],'Id':'sha256:'+str(i)*64,'Architecture':'amd64','Os':'linux'} for i,r in enumerate(ROLES,1)])
                return 'a' * 40 + '\n' if command[-1] == 'HEAD' else ''

            code = 0
            with redirect_stdout(io.StringIO()), patch.dict(os.environ, {'GATEBEAM_ACCEPTANCE_KEEP_GOING': str(int(keep_going)), 'GATEBEAM_ACCEPTANCE_EXECUTION': execution,'GATEBEAM_ACCEPTANCE_GROUP':group,'GATEBEAM_CI_RUN_ID':'42','GATEBEAM_CI_RUN_ATTEMPT':'1','GATEBEAM_TARGET_ARCH':'amd64'}), patch(
                'subprocess.call', side_effect=stage
            ), patch('subprocess.check_output', side_effect=source):
                try:
                    runpy.run_path(str(script), run_name='__main__')
                except SystemExit as error:
                    code = error.code
            receipt = json.loads((root / '.work/system-acceptance/results.json').read_text())
            return code, calls, receipt

    def test_diagnostic_failure_executes_all_twenty_but_remains_incomplete(self):
        code, calls, receipt = self.execute(True, 2)
        self.assertNotEqual(code, 0)
        self.assertEqual(len(calls), 20)
        self.assertEqual([r['name'] for r in receipt['stages']], receipt['required_stages'])
        self.assertEqual(receipt['stages'][1]['exit_code'], 23)
        self.assertFalse(receipt['complete'])

    def test_emulated_receipt_records_each_effective_aggregate_budget(self):
        code, calls, receipt = self.execute(True, 2, 'software-emulated-vm')
        self.assertNotEqual(code, 0)
        self.assertEqual(len(calls), 20)
        self.assertEqual(receipt['execution'], 'software-emulated-vm')
        self.assertEqual(receipt['aggregate_budget_factor'], 12)
        for command, stage in zip(calls, receipt['stages']):
            self.assertEqual(stage['budget_seconds'], stage['base_budget_seconds'] * 12)
            self.assertEqual(float(command[2]), stage['budget_seconds'])
        self.assertFalse(receipt['complete'])

    def test_missing_route_measurement_fails_the_functional_gate(self):
        code, calls, receipt = self.execute(True, None, 'software-emulated-vm', route_evidence=False)
        self.assertNotEqual(code, 0)
        self.assertEqual(len(calls), 20)
        self.assertEqual(receipt['stages'][4]['exit_code'], 1)
        self.assertFalse(receipt['complete'])

    def test_named_groups_cannot_claim_complete_twenty_or_rebuild_images(self):
        for group,count in [('core',3),('security',5),('runtime',2),('web',3),('data',6)]:
            code,calls,receipt=self.execute(True,None,'software-emulated-vm',group=group)
            self.assertEqual(code,0)
            self.assertEqual(len(calls),count)
            self.assertFalse(receipt['complete'])
            self.assertTrue(receipt['group_complete'])
            self.assertEqual(receipt['group'],group)
            self.assertEqual(receipt['ci_context']['run_id'],'42')
            self.assertEqual(len(receipt['required_stages']),20)
            self.assertNotIn('fixed-images',[stage['name'] for stage in receipt['stages']])
            self.assertFalse(any('scripts/build-system.sh' in call for call in calls))

    def test_normal_failure_still_stops_at_first_failed_stage(self):
        code, calls, receipt = self.execute(False, 2)
        self.assertEqual(code, 23)
        self.assertEqual(len(calls), 2)
        self.assertFalse(receipt['complete'])

    def test_all_stages_must_succeed_for_complete_receipt(self):
        for diagnostic in (False, True):
            code, calls, receipt = self.execute(diagnostic, None)
            self.assertEqual(code, 0)
            self.assertEqual(len(calls), 20)
            self.assertTrue(receipt['complete'])

    def test_emulated_success_is_functional_acceptance_without_native_performance_claim(self):
        code, _, receipt = self.execute(True, None, 'software-emulated-vm')
        self.assertEqual(code, 0)
        self.assertEqual(receipt['acceptance_policy'], 'software-functional-v1')
        self.assertEqual(receipt['performance_certification'], 'not-certified')



if __name__ == '__main__':
    unittest.main()
