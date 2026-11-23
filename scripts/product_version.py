"""Read the explicitly declared Gatebeam version using SemVer 2.0.0 grammar."""

from pathlib import Path
import re
import sys


NUMBER = rb'(?:0|[1-9][0-9]*)'
PRERELEASE_ID = rb'(?:' + NUMBER + rb'|[0-9]*[A-Za-z-][0-9A-Za-z-]*)'
BUILD_ID = rb'[0-9A-Za-z-]+'
SEMVER = re.compile(
    rb'\.'.join((NUMBER, NUMBER, NUMBER))
    + rb'(?:-' + PRERELEASE_ID + rb'(?:\.' + PRERELEASE_ID + rb')*)?'
    + rb'(?:\+' + BUILD_ID + rb'(?:\.' + BUILD_ID + rb')*)?'
)
VERSION_FILE = Path(__file__).resolve().parents[1] / 'VERSION'


def read_version(path: Path = VERSION_FILE) -> str:
    value = path.read_bytes().removesuffix(b'\n')
    if SEMVER.fullmatch(value) is None:
        raise ValueError(f'{path.name} must contain exactly one SemVer 2.0.0 version')
    return value.decode('ascii')


if __name__ == '__main__':
    try:
        print(read_version())
    except (OSError, ValueError) as error:
        sys.exit(str(error))
