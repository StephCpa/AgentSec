"""Lossless common event vocabulary for the restricted trace experiments.

This is a syntax/causality boundary, not a replacement state machine or proof.
Environment cuts and packet-loss causes are retained for reproducibility but
excluded from caller_view. Completed local calls do not imply a fresh replica
or a new durable commit. Wire bytes are preserved, not authenticated here.
"""
from copy import deepcopy
import re

SCHEMA = 'agentsec-observation-event-v1'
ENVIRONMENT = frozenset(('cut', 'loss', 'challenge_coin'))

# Endpoint names describe the call, independently of its injected failure.
COMMANDS = {
    'PUBLIC': ('gateway.handle_public', 'request peer challenge_coin'),
    'PUBLIC_CUT': ('gateway.handle_public', 'request peer challenge_coin cut'),
    'TICK': ('scheduler.advance', 'tick'),
    'TICK_CUT': ('scheduler.advance', 'tick cut'),
    'TICK_RETRY': ('scheduler.advance', 'tick'),
    'SEND': ('delivery.exchange', 'operation delivery_kind challenge loss'),
    'RECEIVE_CUT': ('delivery.exchange', 'operation delivery_kind challenge cut'),
    'CONFIRM': ('sender.confirm', 'operation'),
    'CONFIRM_CUT': ('sender.confirm', 'operation cut'),
    'RECOVER': ('replica.restore', ''),
    'DELIVERY_RECOVER': ('replica.restore', 'side operation'),
    'RECOVERY_CUT': ('replica.restore', 'side operation cut'),
    'PREPARE_RECOVER': ('replica.restore', 'operation'),
    'RETIRE_RECOVER': ('replica.restore', 'side route'),
    'PREPARE': ('sender.prepare', 'operation delivery_kind'),
    'PREPARE_CUT': ('sender.prepare', 'operation delivery_kind cut'),
    'RETIRE_PREPARE': ('sender.prepare_retirement', 'route target'),
    'RETIRE_PREPARE_CUT': ('sender.prepare_retirement', 'route target cut'),
    'RETIRE_SEND': ('retention.exchange', 'route base target challenge loss'),
    'RETIRE_SEND_CUT': ('retention.exchange', 'route base target challenge cut'),
    'RETIRE_CONFIRM': ('sender.confirm_retirement', 'route'),
    'RETIRE_CONFIRM_CUT': ('sender.confirm_retirement', 'route cut'),
    'RETENTION_QUERY': ('recipient.query', 'route query_kind seq challenge'),
    'DELIVERY_REPLAY': ('delivery.exchange', 'operation'),
}
CALLERS = {
    'gateway.handle_public': 'public_client', 'scheduler.advance': 'trusted_scheduler',
    'delivery.exchange': 'delivery_controller', 'sender.confirm': 'delivery_controller',
    'sender.prepare': 'delivery_controller', 'replica.restore': 'recovery_operator',
    'sender.prepare_retirement': 'retention_controller', 'retention.exchange': 'retention_controller',
    'sender.confirm_retirement': 'retention_controller', 'recipient.query': 'retention_controller',
}
ALLOWED = {
    'PUBLIC': ('PUBLIC', 'PUBLIC_UNAVAILABLE'),
    'PUBLIC_CUT': ('PUBLIC_UNAVAILABLE',),
    'TICK': ('TICK', 'TICK_UNAVAILABLE'),
    'TICK_CUT': ('TICK_UNAVAILABLE',), 'TICK_RETRY': ('TICK_RETRY',),
    'SEND': ('DELIVERY', 'DELIVERY_REJECTED'),
    'RECEIVE_CUT': ('DELIVERY_UNAVAILABLE',),
    'CONFIRM': ('CONFIRM',), 'CONFIRM_CUT': ('CONFIRM_UNAVAILABLE',),
    'RECOVER': ('RECOVER',), 'DELIVERY_RECOVER': ('DELIVERY_RECOVER',),
    'RECOVERY_CUT': ('RECOVERY_UNAVAILABLE',),
    'PREPARE_RECOVER': ('PREPARE_RECOVER',), 'RETIRE_RECOVER': ('RETIRE_RECOVER',),
    'PREPARE': ('PREPARATION', 'PREPARATION_REJECTED'),
    'PREPARE_CUT': ('PREPARATION_UNAVAILABLE',),
    'RETIRE_PREPARE': ('RETIRE_PREPARATION', 'RETIRE_PREPARATION_REJECTED'),
    'RETIRE_PREPARE_CUT': ('RETIRE_PREPARATION_UNAVAILABLE',),
    'RETIRE_SEND': ('RETIRE_DELIVERY',),
    'RETIRE_SEND_CUT': ('RETIRE_DELIVERY_UNAVAILABLE',),
    'RETIRE_CONFIRM': ('RETIRE_CONFIRMATION',),
    'RETIRE_CONFIRM_CUT': ('RETIRE_CONFIRM_UNAVAILABLE',),
    'RETENTION_QUERY': ('RETENTION_QUERY', 'RETENTION_UNAVAILABLE'),
    'DELIVERY_REPLAY': ('DELIVERY_REPLAY',),
}

# Event fields whose values must equal their invocation parameters.
BOUND = {
    'TICK': 'tick', 'TICK_UNAVAILABLE': 'tick', 'TICK_RETRY': 'tick',
    'PUBLIC': 'request peer', 'PUBLIC_UNAVAILABLE': 'request peer',
    'DELIVERY_RECOVER': 'side operation', 'RECOVERY_UNAVAILABLE': 'side operation',
    'PREPARE_RECOVER': 'operation', 'RETIRE_RECOVER': 'side route',
    'PREPARATION': 'operation delivery_kind',
    'PREPARATION_REJECTED': 'operation delivery_kind',
    'PREPARATION_UNAVAILABLE': 'operation delivery_kind',
    'RETIRE_PREPARATION': 'route target', 'RETIRE_PREPARATION_REJECTED': 'route target',
    'RETIRE_PREPARATION_UNAVAILABLE': 'route target',
    'RETIRE_DELIVERY': 'route', 'RETIRE_DELIVERY_UNAVAILABLE': 'route',
    'RETIRE_CONFIRMATION': 'route', 'RETIRE_CONFIRM_UNAVAILABLE': 'route',
    'RETENTION_QUERY': 'route', 'RETENTION_UNAVAILABLE': 'route',
    'DELIVERY_REPLAY': 'operation',
}
WIRE_INPUT = frozenset(('PUBLIC', 'PUBLIC_UNAVAILABLE', 'DELIVERY', 'DELIVERY_REJECTED',
    'DELIVERY_UNAVAILABLE', 'CONFIRM', 'CONFIRM_UNAVAILABLE', 'RETIRE_DELIVERY',
    'RETIRE_DELIVERY_UNAVAILABLE', 'RETIRE_CONFIRMATION', 'RETIRE_CONFIRM_UNAVAILABLE',
    'RETENTION_QUERY', 'RETENTION_UNAVAILABLE', 'DELIVERY_REPLAY'))
CONFIRMATIONS = frozenset(('CONFIRM', 'CONFIRM_UNAVAILABLE', 'RETIRE_CONFIRMATION', 'RETIRE_CONFIRM_UNAVAILABLE'))
COMPLETE = frozenset(('TICK', 'TICK_RETRY', 'RECOVER', 'DELIVERY_RECOVER', 'PREPARE_RECOVER', 'RETIRE_RECOVER',
                      'CONFIRM', 'RETIRE_CONFIRMATION'))
BODY = frozenset(('PREPARATION', 'RETIRE_PREPARATION'))
DENIED = frozenset(('PREPARATION_REJECTED', 'RETIRE_PREPARATION_REJECTED', 'DELIVERY_REJECTED'))
QUERY = frozenset(('RETENTION_QUERY', 'DELIVERY_REPLAY'))
REPLY = frozenset(('PUBLIC', 'DELIVERY', 'RETIRE_DELIVERY'))
LOSS_MARKERS = {'packet': 'PACKET_LOST', 'ack': 'ACK_LOST'}


class EventError(ValueError):
    pass


def require(value, message):
    if not value:
        raise EventError(message)


def _hex(value, field, empty=False):
    require(type(value) is str and (empty or bool(value)) and len(value) % 2 == 0 and
            re.fullmatch('[0-9a-f]*', value) is not None, 'invalid hex: ' + field)


def _command(command):
    require(type(command) is dict and type(command.get('kind')) is str and command['kind'] in COMMANDS,
            'unknown command')
    endpoint, fields = COMMANDS[command['kind']]
    require(set(command) == {'kind', 'at'} | set(fields.split()), 'command fields')
    require(type(command['at']) is int and 0 <= command['at'] < 2**62, 'clock')
    for name in fields.split():
        value = command[name]
        if name in ('tick', 'base', 'target', 'seq'):
            minimum = 1 if name in ('tick', 'target') else 0
            require(type(value) is int and minimum <= value < 2**64, 'integer: ' + name)
        elif name in ('request', 'peer', 'challenge', 'challenge_coin'):
            _hex(value, name, empty=name == 'challenge_coin')
            if name in ('challenge', 'challenge_coin'):
                require(len(value) == 64 or (name == 'challenge_coin' and not value), 'coin length')
        else:
            require(type(value) is str and (bool(value) or
                    (name == 'operation' and command['kind'] == 'RECOVERY_CUT')), 'text: ' + name)
    if 'side' in command:
        require(command['side'] in ('sender', 'receiver'), 'side')
    if 'delivery_kind' in command:
        require(command['delivery_kind'] in ('DELIVERY', 'TERMINAL'), 'delivery kind')
    if 'query_kind' in command:
        require(command['query_kind'] in ('FINAL', 'RETIRED', 'CHECKPOINT'), 'query kind')
    if 'loss' in command:
        permitted = ('none', 'ack') if command['kind'] == 'RETIRE_SEND' else ('none', 'packet', 'ack')
        require(command['loss'] in permitted, 'loss kind')
    return endpoint


def normalize(command, event):
    """Validate a command/event pair; never use observations to generate a reply."""
    endpoint = _command(command)
    require(type(event) is dict and type(event.get('kind')) is str and
            event['kind'] in ALLOWED[command['kind']], 'command/event kind mismatch')
    kind = event['kind']
    require(type(event.get('at')) is int and event['at'] == command['at'], 'event clock mismatch')
    fields = {'kind', 'at'} | set(BOUND.get(kind, '').split())
    for name in BOUND.get(kind, '').split():
        require(name in event and type(event[name]) is type(command[name]) and event[name] == command[name],
                'invocation binding: ' + name)
    wire = {}
    if kind in WIRE_INPUT:
        fields.add('request'); _hex(event.get('request'), 'request')
        wire['request'] = event['request']
    if kind.startswith('PUBLIC'):
        wire['peer'] = event['peer']
    if kind in CONFIRMATIONS:
        # Legacy response is a previously obtained receipt supplied as INPUT.
        fields.add('response'); _hex(event.get('response'), 'receipt input')
        wire['receipt'] = event['response']
    if kind.endswith('_UNAVAILABLE'):
        if 'error' in event:
            require(command['kind'] in ('PUBLIC', 'TICK', 'RETENTION_QUERY') and
                    event['error'] == 'WITNESS_RECOVERY_REQUIRED', 'availability error')
            fields.add('error'); outcome = dict(kind='exception', code=event['error'])
        else:
            require(command['kind'].endswith('_CUT'), 'missing availability error')
            outcome = dict(kind='no_return')
    elif kind in COMPLETE:
        outcome = dict(kind='completed')
    elif kind in BODY:
        fields.add('body'); _hex(event.get('body'), 'body')
        outcome = dict(kind='returned_bytes', value=event['body'])
    elif kind in DENIED or (kind in QUERY and 'reason' in event):
        fields.add('reason')
        require(type(event.get('reason')) is str and re.fullmatch('[A-Z][A-Z0-9_]*', event['reason']), 'denial code')
        outcome = dict(kind='business_exception', code=event['reason'])
    elif kind in REPLY | QUERY:
        fields.add('response'); value = event.get('response')
        if kind in ('DELIVERY', 'RETIRE_DELIVERY') and command.get('loss') != 'none':
            require(value == LOSS_MARKERS[command['loss']], 'loss marker mismatch')
            outcome = dict(kind='no_return')
        else:
            _hex(value, 'response'); outcome = dict(kind='returned_bytes', value=value)
    else:
        raise EventError('unclassified event')
    require(set(event) == fields, 'event fields')
    return dict(schema=SCHEMA, at=command['at'], source=dict(command_kind=command['kind'], event_kind=kind),
                call=dict(endpoint=endpoint, caller=CALLERS[endpoint], parameters={k: deepcopy(v) for k, v in command.items()
                    if k not in ENVIRONMENT | {'kind', 'at', 'request', 'peer'}}, wire=wire),
                outcome=outcome, environment={k: command[k] for k in command if k in ENVIRONMENT})


def to_legacy(normalized):
    """Invert a canonical event; reject altered metadata or ambiguous fields."""
    try:
        n = normalized; source = n['source']; call = n['call']; outcome = n['outcome']; kind = source['event_kind']
        command = dict(call['parameters'], **n['environment'])
        command.update(kind=source['command_kind'], at=n['at'])
        wire = call['wire']
        if command['kind'] in ('PUBLIC', 'PUBLIC_CUT'):
            command.update(request=wire['request'], peer=wire['peer'])
        event = dict(kind=kind, at=n['at'])
        for name in BOUND.get(kind, '').split():
            event[name] = command[name]
        if kind in WIRE_INPUT:
            event['request'] = wire['request']
        if kind in CONFIRMATIONS:
            event['response'] = wire['receipt']
        if outcome['kind'] == 'exception':
            event['error'] = outcome['code']
        elif outcome['kind'] == 'business_exception':
            event['reason'] = outcome['code']
        elif outcome['kind'] == 'returned_bytes':
            event['body' if kind in BODY else 'response'] = outcome['value']
        elif kind in ('DELIVERY', 'RETIRE_DELIVERY'):
            event['response'] = LOSS_MARKERS[command['loss']]
        require(normalize(command, event) == n, 'noncanonical event')
        return deepcopy(command), deepcopy(event)
    except (KeyError, TypeError, AttributeError) as exc:
        raise EventError('malformed canonical event') from exc


def caller_view(normalized):
    """The calling role's local API view, NOT a global/network attacker view.

at is the experiment's declared public clock. Roles/route authorization still
need a deployment policy. No cut, packet-vs-ACK loss, or source tag is exposed.
"""
    to_legacy(normalized)
    return deepcopy({k: normalized[k] for k in ('at', 'call', 'outcome')})


class EventStream:
    """Check time ordering and that confirmation inputs were actually returned.

Each instance starts with empty observation history. Existing-state fixtures
must first supply their observation prefix; state cannot be inferred from cuts.
"""
    def __init__(self):
        self.now = 0
        self.receipts = set()
        self.count = 0

    def append(self, command, event):
        normalized = normalize(command, event)
        require(command['at'] >= self.now, 'clock regression')
        if event['kind'] in CONFIRMATIONS:
            require((event['request'], event['response']) in self.receipts, 'unobserved receipt input')
        if event['kind'] in ('DELIVERY', 'DELIVERY_REPLAY', 'RETIRE_DELIVERY', 'RETENTION_QUERY') and normalized['outcome']['kind'] == 'returned_bytes':
            self.receipts.add((event['request'], event['response']))
        self.now = command['at']; self.count += 1
        return normalized
