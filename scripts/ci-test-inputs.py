#!/usr/bin/env python3
"""Reuse the source-bound programs/assets already built for this CI target."""
import argparse
import os
from pathlib import Path
import shutil
from acceptance_phases import ci_context
from ci import ROOT,head
from ci_artifacts import PROGRAMS,ALIASES,test_inputs

if __name__=='__main__':
 parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--arch',required=True,choices=['amd64','arm64']);parser.add_argument('--web',action='store_true');parser.add_argument('--program',action='append',choices=PROGRAMS);parser.add_argument('--alias',action='append',choices=ALIASES);args=parser.parse_args()
 test_inputs(Path(os.environ['GATEBEAM_CI_BUILD_INPUT']),ci_context(head(),args.arch),os.environ['GATEBEAM_CI_BUILD_BUNDLE_SHA256'],ROOT/'.work/build',web=args.web,names=args.program or PROGRAMS,aliases=args.alias or ())
 if args.web:
  destination=ROOT/'web/dist'
  if destination.exists():shutil.rmtree(destination)
  shutil.copytree(ROOT/'.work/build/web-dist',destination)
