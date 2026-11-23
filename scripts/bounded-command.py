#!/usr/bin/env python3
"""Run a command under a wall-clock deadline. Requires Python 3 on macOS/Linux.

Usage: python3 scripts/bounded-command.py SECONDS COMMAND [ARG ...]
Timeout kills the complete command process group and returns 124. Normal exits
preserve the child's status; signal exits use the conventional 128 + signal.
"""
import argparse
import math
import os
import signal
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("seconds", type=float)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if not math.isfinite(args.seconds) or args.seconds <= 0 or not args.command:
        parser.error("a positive finite deadline and command are required")
    try:
        process = subprocess.Popen(args.command, start_new_session=True)
    except OSError:
        print("bounded command could not start", file=sys.stderr)
        return 127
    try:
        status = process.wait(timeout=args.seconds)
    except (subprocess.TimeoutExpired, KeyboardInterrupt) as error:
        # Kill the entire session's process group, including subprocesses left
        # running by the immediate child. No unbounded graceful-shutdown wait.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
        if isinstance(error, KeyboardInterrupt):
            return 130
        print("bounded command exceeded deadline", file=sys.stderr)
        return 124
    return status if status >= 0 else 128 - status


if __name__ == "__main__":
    sys.exit(main())
