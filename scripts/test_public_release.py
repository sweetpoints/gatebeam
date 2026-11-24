import json
import unittest
from unittest.mock import Mock
from unittest.mock import patch

import public_release
from ci import ARCHES, ROLES
from public_release import release_version, registry_tag, verification_state, validate_index


class PublicReleaseTests(unittest.TestCase):
    def test_release_requires_an_explicit_increase_in_precedence(self):
        self.assertIsNone(release_version('0.1.0', '0.1.0'))
        self.assertEqual(release_version('0.1.0-rc.9', '0.1.0-rc.10+build.001'), '0.1.0-rc.10+build.001')
        self.assertEqual(release_version('0.1.0-rc.10', '0.1.0'), '0.1.0')
        for before, after in [('1.10.0', '1.9.0'), ('1.0.0', '1.0.0-rc.1'), ('1.0.0+one', '1.0.0+two')]:
            with self.subTest(before=before, after=after), self.assertRaises(ValueError):
                release_version(before, after)

    def test_registry_tags_preserve_unique_version_identity(self):
        self.assertEqual(registry_tag('1.2.3-rc.1'), '1.2.3-rc.1')
        self.assertEqual(registry_tag('1.2.3-rc.1+build.001'), '1.2.3-rc.1_build.001')
        self.assertLessEqual(len(registry_tag('1.2.3+' + 140 * 'a')), 128)
        self.assertNotEqual(registry_tag('1.2.3+' + 140 * 'a'), registry_tag('1.2.3+' + 140 * 'b'))

    def test_both_platforms_must_finish_the_receipt_step(self):
        def job(arch, conclusion, status='in_progress'):
            return {'name': f'Release {arch} / Verify and stage', 'status': status, 'steps': [
                {'name': 'Verify complete same-commit acceptance', 'status': 'completed' if conclusion else 'in_progress', 'conclusion': conclusion}
            ]}

        amd64 = job('amd64', 'success')
        self.assertFalse(verification_state([amd64]))
        self.assertFalse(verification_state([amd64, job('arm64', None)]))
        self.assertTrue(verification_state([amd64, job('arm64', 'success')]))
        with self.assertRaises(ValueError):
            verification_state([amd64, job('arm64', 'failure', 'completed')])
        with self.assertRaises(ValueError):
            verification_state([amd64, amd64, job('arm64', 'success')])

    def test_index_rejects_conflicting_content_and_platforms(self):
        digest = lambda suffix: 'sha256:' + suffix * 64
        children = {'amd64': digest('a'), 'arm64': digest('b')}
        sha = '1234567890' * 4
        index = {'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json',
                 'annotations': {'org.opencontainers.image.version': '0.2.0', 'org.opencontainers.image.revision': sha},
                 'manifests': [{'digest': value, 'platform': {'os': 'linux', 'architecture': arch}} for arch, value in children.items()]}
        validate_index(index, children, '0.2.0', sha)
        with self.assertRaises(ValueError):
            validate_index(index, children, '0.2.0', 'f' * 40)
        index['manifests'][1]['digest'] = digest('c')
        with self.assertRaises(ValueError):
            validate_index(index, children, '0.2.0', sha)

    def test_peer_failure_prevents_upload(self):
        with (patch.object(public_release, 'release_context', return_value=('owner/gatebeam', '0.2.0', 'a' * 40)),
              patch.object(public_release, 'verified_images'),
              patch.object(public_release, 'await_full_acceptance', side_effect=ValueError('peer failed')),
              patch.object(public_release, 'command') as command):
            with self.assertRaisesRegex(ValueError, 'peer failed'):
                public_release.stage()
            command.assert_not_called()

    def test_conflicting_version_ref_prevents_all_index_writes(self):
        env = {'DOCKER_CONFIG': '/absent'}
        for arch in ARCHES:
            env['DIGESTS_' + arch.upper()] = json.dumps({role: 'sha256:' + 'a' * 64 for role in ROLES})
        with (patch.dict('os.environ', env),
              patch.object(public_release, 'release_context', return_value=('owner/gatebeam', '0.2.0', 'a' * 40)),
              patch.object(public_release, 'inspect_index', side_effect=[None] * (len(ROLES) - 1) + [b'{}']),
              patch.object(public_release, 'command') as command):
            with self.assertRaisesRegex(ValueError, 'cannot be overwritten'):
                public_release.publish()
            command.assert_not_called()

    def test_existing_matching_indexes_remain_untouched(self):
        version, sha = '0.2.0', 'a' * 40
        children = {'amd64': 'sha256:' + 'a' * 64, 'arm64': 'sha256:' + 'b' * 64}
        env = {'DOCKER_CONFIG': '/absent'}
        for arch, digest in children.items():
            env['DIGESTS_' + arch.upper()] = json.dumps(dict.fromkeys(ROLES, digest))
        index = json.dumps({'schemaVersion': 2, 'mediaType': 'application/vnd.oci.image.index.v1+json',
                            'annotations': public_release.image_labels('owner/gatebeam', version, sha),
                            'manifests': [{'digest': digest, 'platform': {'os': 'linux', 'architecture': arch}}
                                          for arch, digest in children.items()]}).encode()
        inspect_index = Mock(return_value=index)
        with (patch.dict('os.environ', env),
              patch.object(public_release, 'release_context', return_value=('owner/gatebeam', version, sha)),
              patch.object(public_release, 'inspect_index', inspect_index),
              patch.object(public_release, 'command') as command,
              patch('builtins.print')):
            public_release.publish()
            command.assert_not_called()
        anonymous_reads = [call.args for call in inspect_index.call_args_list if len(call.args) == 1]
        self.assertEqual(len(anonymous_reads), len(ROLES))
