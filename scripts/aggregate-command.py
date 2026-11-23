#!/usr/bin/env python3
"""Bound an explicitly marked aggregate CI command, preserving test deadlines."""
import argparse
import os
from pathlib import Path
import sys
from acceptance_budget import aggregate, command_arguments

def main():
 p=argparse.ArgumentParser(description=__doc__)
 p.add_argument('--test-package',action='store_true')
 p.add_argument('seconds',type=float)
 p.add_argument('command',nargs=argparse.REMAINDER)
 a=p.parse_args()
 if not a.command:p.error('command required')
 try:
  seconds=aggregate(a.seconds)
  command=command_arguments(a.command,a.test_package)
 except (ValueError,IndexError) as e:p.error(str(e))
 print(f'Aggregate CI watchdog: base={a.seconds:g}s effective={seconds:g}s execution={os.environ.get("GATEBEAM_ACCEPTANCE_EXECUTION","native")}',file=sys.stderr,flush=True)
 os.execv(sys.executable,[sys.executable,str(Path(__file__).with_name('bounded-command.py')),str(seconds),*command])

if __name__=='__main__':main()
