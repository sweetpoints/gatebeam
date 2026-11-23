"""Explicit aggregate-suite budgets; functional deadlines never use this policy."""
import math
import os

EMULATED = 'software-emulated-vm'
FACTOR = 12

def aggregate(seconds, execution=None):
 seconds=float(seconds)
 if not math.isfinite(seconds) or seconds<=0:
  raise ValueError('positive finite aggregate budget required')
 execution=os.environ.get('GATEBEAM_ACCEPTANCE_EXECUTION','native') if execution is None else execution
 if execution not in ('native',EMULATED):
  raise ValueError('unknown acceptance execution profile')
 return seconds*(FACTOR if execution==EMULATED else 1)

def duration(value):
 # These owned scripts use seconds, not arbitrary user-supplied Go durations.
 if not value.endswith('s'):
  raise ValueError('aggregate package timeout must use seconds')
 return f'{aggregate(float(value[:-1])):g}s'

def command_arguments(command, test_package=False):
 command=list(command)
 # Only go test's whole-package watchdog is adapted. Arguments following
 # -args belong to the application tests and retain their original values.
 start=0
 if command and command[0]=='env':
  start=1
  while start<len(command) and '=' in command[start]:start+=1
 go_test=len(command)>start+1 and os.path.basename(command[start])=='go' and command[start+1]=='test'
 if go_test:
  i=start+2
  while i<len(command) and command[i]!='-args':
   if command[i]=='-timeout':
    command[i+1]=duration(command[i+1]);i+=1
   elif command[i].startswith('-timeout='):
    command[i]='-timeout='+duration(command[i].split('=',1)[1])
   i+=1
 if test_package:
  # Explicit opt-in only for a container running an entire Go test package.
  # Single capacity scenarios do not invoke this wrapper.
  command=[('-test.timeout='+duration(x.split('=',1)[1])) if x.startswith('-test.timeout=') else x for x in command]
 return command

if __name__=='__main__':
 import argparse
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('seconds',type=float)
 args=parser.parse_args()
 try:print(f'{aggregate(args.seconds):g}')
 except ValueError as error:parser.error(str(error))
