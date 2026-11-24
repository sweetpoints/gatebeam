"""Publish previously verified, native Gatebeam images from a protected push."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import urllib.request

from acceptance_phases import snapshot_images
from ci import ARCHES, DIGEST, ROLES, ROOT, head, load, validate_receipt
from ci_oci import inspect_oci
from product_version import read_version, SEMVER

VERIFY_STEP = 'Verify complete same-commit acceptance'
VERSION_LABEL = 'org.opencontainers.image.version'
REVISION_LABEL = 'org.opencontainers.image.revision'
SOURCE_LABEL = 'org.opencontainers.image.source'


def semver_order(version):
    if SEMVER.fullmatch(version.encode('ascii')) is None:
        raise ValueError('expected SemVer 2.0.0')
    core, dash, suffix = version.split('+', 1)[0].partition('-')

    def number(part):
        return len(part), part

    identifiers = tuple((0, number(part)) if part.isdigit() else (1, part)
                        for part in suffix.split('.')) if dash else ()
    return tuple(map(number, core.split('.'))), not dash, identifiers


def release_version(before, after):
    old, new = semver_order(before), semver_order(after)
    if before == after:
        return None
    if new <= old:
        raise ValueError('new VERSION must increase SemVer precedence')
    return after


def registry_tag(version):
    semver_order(version)
    label = version.replace('+', '_')
    if len(label) > 128:
        return 'version-sha256-' + hashlib.sha256(version.encode()).hexdigest()
    return label


def command(*args, **kwargs):
    return subprocess.run(args, cwd=ROOT, capture_output=True, check=True, timeout=900, **kwargs).stdout


def plan():
    after = head()
    before = os.environ['PUSH_BEFORE']
    if not re.fullmatch(r'[a-f0-9]{40}', before) or before == '0' * 40:
        raise ValueError('a previous main commit is required')
    command('git', 'merge-base', '--is-ancestor', before, after)
    old = command('git', 'show', before + ':VERSION').removesuffix(b'\n').decode('ascii')
    version = release_version(old, read_version())
    if version is not None:
        output(version=version, tag=registry_tag(version))


def verified_images():
    sha = head()
    arch = os.environ['GATEBEAM_TARGET_ARCH']
    version = read_version()
    result = load(ROOT / '.work/system-acceptance/results.json')
    manifest = load(ROOT / '.work/artifacts/manifest.json')
    if result.get('execution') != 'native' or manifest.get('product_version') != version:
        raise ValueError('native acceptance and exact product version required')
    validate_receipt(result, manifest, sha, arch)
    tested = {}
    for image in snapshot_images():
        tag = f"gatebeam-{image['role']}:local"
        built = next(row for row in manifest['artifacts'] if tag in row['RepoTags'])
        if image['Id'] != built['Id']:
            raise ValueError(f'acceptance image changed: {tag}')
        tested[image['role']] = image['Id']
    return tested


def verification_state(jobs):
    verified = 0
    for arch in ARCHES:
        matching = [job for job in jobs if job['name'] == f'Release {arch} / Verify and stage']
        if len(matching) > 1:
            raise ValueError(f'ambiguous release job for {arch}')
        if not matching:
            continue
        job = matching[0]
        checks = [step for step in job.get('steps', []) if step['name'] == VERIFY_STEP]
        if job['status'] == 'completed' and job.get('conclusion') != 'success':
            raise ValueError(f'{arch} release acceptance failed')
        if len(checks) != 1 or checks[0]['status'] != 'completed':
            continue
        if checks[0]['conclusion'] != 'success':
            raise ValueError(f'{arch} failed to verify complete acceptance')
        verified += 1
    return verified == len(ARCHES)


def await_full_acceptance(repository):
    run, attempt = (os.environ[name] for name in ('GITHUB_RUN_ID', 'GITHUB_RUN_ATTEMPT'))
    if not all(re.fullmatch(r'[1-9][0-9]*', part) for part in (run, attempt)):
        raise ValueError('expected a GitHub run and attempt')
    url = f'https://api.github.com/repos/{repository}/actions/runs/{run}/attempts/{attempt}/jobs?per_page=100'
    request = urllib.request.Request(url, headers={
        'Authorization': 'Bearer ' + os.environ['GH_TOKEN'],
        'Accept': 'application/vnd.github+json',
    })
    cutoff = time.monotonic() + 3600
    while time.monotonic() < cutoff:
        with urllib.request.urlopen(request, timeout=15) as response:
            if verification_state(json.load(response)['jobs']):
                return
        time.sleep(15)
    raise TimeoutError('both native acceptance jobs must verify in the same attempt')


def output(**values):
    with open(os.environ['GITHUB_OUTPUT'], 'a') as stream:
        for name, value in values.items():
            stream.write(f'{name}={value}\n')


def release_context():
    repository = os.environ['GITHUB_REPOSITORY']
    version = os.environ['RELEASE_VERSION']
    if (os.environ.get('GITHUB_EVENT_NAME') != 'push' or os.environ.get('GITHUB_REF') != 'refs/heads/main'
            or not re.fullmatch(r'[a-zA-Z0-9-]+/[a-zA-Z0-9_.-]+', repository)
            or read_version() != version or registry_tag(version) != os.environ.get('RELEASE_TAG')):
        raise ValueError('expected the declared release on a push to main')
    return repository, version, head()


def registry_repository(repository, role):
    return f'ghcr.io/{repository.lower()}-{role}'


def image_labels(repository, version, sha):
    return {VERSION_LABEL: version, REVISION_LABEL: sha, SOURCE_LABEL: 'https://github.com/' + repository}


def stage():
    repository, version, sha = release_context()
    tested = verified_images()
    await_full_acceptance(repository)
    authfile = str(Path(os.environ['DOCKER_CONFIG']) / 'config.json')
    arch = os.environ['GATEBEAM_TARGET_ARCH']
    digests = {}
    for role in ROLES:
        with tempfile.TemporaryDirectory(prefix='gatebeam-tested-') as folder:
            archive = Path(folder) / 'tested.tar'
            command('docker', 'image', 'save', '--output', str(archive), 'gatebeam-' + role + ':local')
            image = inspect_oci(archive, arch, expected_labels=image_labels(repository, version, sha))
            # Docker's containerd and classic stores report different image identifiers.
            if tested[role] not in (image['manifest_digest'], image['config_digest']):
                raise ValueError(f'exported {role} identity differs from the tested image')
            # Classic Docker exports uncompressed layers. Encode them for the
            # registry locally and require the tested config digest (including
            # the uncompressed layer digests) to survive the copy.
            compressed = Path(folder) / 'registry.tar'
            source = f'oci-archive:{compressed}:tested'
            command('skopeo', 'copy', '--format', 'oci', f'oci-archive:{archive}', source)
            shipping = inspect_oci(compressed, arch, expected_labels=image_labels(repository, version, sha))
            digest, config = shipping['manifest_digest'], shipping['config_digest']
            if config != image['config_digest']:
                raise ValueError(f'registry encoding changed the tested {role} image config')
            target = registry_repository(repository, role) + '@' + digest
            command('skopeo', 'copy', '--preserve-digests', '--dest-authfile', authfile, source, 'docker://' + target)
            remote = command('skopeo', 'inspect', '--raw', '--authfile', authfile, 'docker://' + target)
            if json.loads(remote)['config']['digest'] != config:
                raise ValueError(f'GHCR returned a different {role} image config')
            digests[role] = digest
    output(images=json.dumps(digests, separators=(',', ':')))


def validate_index(index, children, version, sha):
    annotations = index.get('annotations', {})
    manifests = index.get('manifests', [])
    expected = {(arch, digest) for arch, digest in children.items()}
    actual = {(m['platform']['architecture'], m['digest']) for m in manifests if m['platform']['os'] == 'linux'}
    if (index.get('schemaVersion') != 2 or index.get('mediaType') != 'application/vnd.oci.image.index.v1+json'
            or annotations.get(VERSION_LABEL) != version or annotations.get(REVISION_LABEL) != sha
            or len(manifests) != len(expected) or actual != expected):
        raise ValueError('existing index does not match this release and cannot be overwritten')


def inspect_index(reference, authfile=None):
    credentials = ['--authfile', authfile] if authfile is not None else ['--no-creds']
    try:
        return command('skopeo', 'inspect', '--raw', *credentials, 'docker://' + reference)
    except subprocess.CalledProcessError as error:
        reason = error.stderr.decode(errors='replace').lower()
        if 'manifest unknown' in reason:
            return None
        raise


def publish():
    repository, version, sha = release_context()
    by_arch = {arch: json.loads(os.environ['DIGESTS_' + arch.upper()]) for arch in ARCHES}
    for images in by_arch.values():
        if set(images) != set(ROLES) or not all(DIGEST.fullmatch(digest) for digest in images.values()):
            raise ValueError('all five tested platform image digests are required')
    authfile = str(Path(os.environ['DOCKER_CONFIG']) / 'config.json')
    release = []
    for role in ROLES:
        name = registry_repository(repository, role)
        tag = name + ':' + registry_tag(version)
        children = {arch: by_arch[arch][role] for arch in ARCHES}
        existing = inspect_index(tag, authfile)
        if existing is not None:
            validate_index(json.loads(existing), children, version, sha)
        release.append((name, tag, children, existing is not None))
    for name, tag, children, exists in release:
        # Check again before a write. The final job is serialized for each version.
        current = inspect_index(tag, authfile)
        if current is not None:
            validate_index(json.loads(current), children, version, sha)
        elif exists:
            raise ValueError(f'existing release tag disappeared: {tag}')
        else:
            labels = image_labels(repository, version, sha)
            args = ['docker', 'buildx', 'imagetools', 'create', '--tag', tag]
            for key, value in labels.items():
                args += ['--annotation', f'index:{key}={value}']
            command(*args, *(name + '@' + children[arch] for arch in ARCHES))
        written = inspect_index(tag, authfile)
        if written is None:
            raise ValueError(f'GHCR did not return the published version: {tag}')
        validate_index(json.loads(written), children, version, sha)
    for _, tag, children, _ in release:
        try:
            raw = inspect_index(tag)
            if raw is None:
                raise ValueError('version tag unavailable anonymously')
            validate_index(json.loads(raw), children, version, sha)
        except (ValueError, subprocess.CalledProcessError) as error:
            raise ValueError(f'{tag} must support anonymous pulls. Set first-time GHCR packages to Public.') from error
        print(f'{tag} -> sha256:{hashlib.sha256(raw).hexdigest()}')


if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('plan', 'verify', 'stage', 'publish'))
    operations = {'plan': plan, 'verify': verified_images, 'stage': stage, 'publish': publish}
    try:
        operations[parser.parse_args().operation]()
    except subprocess.CalledProcessError as error:
        sys.exit(error.stderr.decode(errors='replace').strip() or str(error))
    except (OSError, ValueError) as error:
        sys.exit(str(error))
