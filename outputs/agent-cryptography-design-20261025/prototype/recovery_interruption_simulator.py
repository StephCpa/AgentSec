"""Recovery interruption composition for existing restricted simulators.

An interrupted recovery is a logical stutter, including after its local commit.
No witness head, replica contents or actual storage outcome enters this wrapper.
The environment must still declare successful recovery before resuming business.
"""
from copy import deepcopy
from public_trace_adapter import require

RECOVERY_CUTS=('after_recovery_delete','before_recovery_commit','after_recovery_commit')
REPEATED_CUTS=RECOVERY_CUTS+RECOVERY_CUTS


class RecoveryInterruptionSimulator:
    def __init__(self,base):self.base=base
    def __getattr__(self,name):return getattr(self.base,name)

    def target(self):
        pending=self.base.needs_recovery
        require(bool(pending),'RECOVERY_NOT_PENDING')
        return pending if type(pending) is tuple else ('sender','')

    def emit(self,command):
        require(type(command) is dict,'COMMAND_SCOPE')
        if command.get('kind')!='RECOVERY_CUT':return self.base.emit(command)
        require(set(command)=={'kind','at','side','operation','cut'},'RECOVERY_CUT_SCOPE')
        require(type(command['cut']) is str and command['cut'] in RECOVERY_CUTS,'RECOVERY_CUT_SCOPE')
        require((command['side'],command['operation'])==self.target(),'RECOVERY_TARGET')
        require(type(command['at']) is int and self.state.now<=command['at']<2**62,'PUBLIC_CLOCK')
        # Even after_recovery_commit is not a business transaction. Keep the
        # logical state, pending exact retry and all mechanism resources intact.
        self.state.now=command['at']
        event={k:command[k] for k in ('at','side','operation')};event['kind']='RECOVERY_UNAVAILABLE'
        self.records.append(event);return deepcopy(event)

    def generate(self,commands):
        for command in commands:self.emit(command)
        return deepcopy(self.records)
