"""Bounded pages reconstructing historical facts against a pinned checkpoint.

Internal privileged archive API, not a public Agent endpoint or result delivery.
Pages are untrusted and unsigned: a verifier releases the selected canonical
fact only after hashing the entire prefix from genesis to an independently
supplied authenticated receiver checkpoint. No result plaintext is exported.
An old signed checkpoint proves history only, not current receiver freshness.
"""
from ledger import Rejected
from wire import encode,decode
from retention_sender import u64,number
import retention_wire as r

PROFILE='mixed-retention-archive-v2'
MAX_FACTS=16
PAGE_FIELDS={'profile','context_hash','checkpoint_hash','first','base_root','facts'}


def checkpoint_binding(request,ack,context):
    checkpoint=r.parse_checkpoint(ack,request,context)
    digest=r.sha(encode(['retention-archive-checkpoint',2,request,ack]))
    return checkpoint,digest


def parse_page(raw,context,checkpoint_hash):
    obj=decode(r.frame(raw))
    if type(obj) is not dict or set(obj)!=PAGE_FIELDS or obj.get('profile')!=PROFILE:
        raise Rejected('ARCHIVE_SCHEMA')
    if obj['context_hash']!=r.context_hash(context) or obj['checkpoint_hash']!=checkpoint_hash:
        raise Rejected('ARCHIVE_CHECKPOINT_BINDING')
    r.uint(obj['first'],1);r.blob(obj['base_root'])
    if type(obj['facts']) is not list or not 1<=len(obj['facts'])<=MAX_FACTS:
        raise Rejected('ARCHIVE_PAGE_COUNT')
    # Per-fact and sequence validation is performed by the streaming verifier.
    return obj


def archive_page(sender,context_hash,request,ack,first,limit=MAX_FACTS,fault=lambda point:None):
    """Read one immutable archive page under current sender authority fencing.

    No signing key, private operation/result decryption, clock update or CAS.
    The caller must authorize this audit access. Linearization is the final
    authority comparison; the supplied historical checkpoint need not be latest.
    Full-image fencing and prefix scans are intentionally expensive reference
    operations, not scalable random-access storage or availability guarantees.
    """
    r.uint(first,1)
    if type(limit) is not int or not 1<=limit<=MAX_FACTS:raise Rejected('ARCHIVE_PAGE_LIMIT')
    if sender.db.in_transaction:raise Rejected('ARCHIVE_TRANSACTION_ACTIVE')
    sender.db.execute('BEGIN IMMEDIATE')
    try:
        sender.check_storage_profile();sender.check_current_state()
        route,context=sender.route(context_hash)
        checkpoint,binding=checkpoint_binding(request,ack,context)
        floor=checkpoint['floor']
        if not first<=floor<=number(route['retired'])<=number(route['confirmed']):
            raise Rejected('ARCHIVE_UNCONFIRMED_CHECKPOINT')
        if checkpoint['high']>number(route['high']):raise Rejected('ARCHIVE_RECEIVER_AHEAD')
        if sender.archive_root(context_hash,floor)!=checkpoint['root']:
            raise Rejected('ARCHIVE_ROOT_MISMATCH')
        base=sender.archive_root(context_hash,first-1)
        fault('after_archive_roots')
        rows=sender.db.execute('SELECT * FROM v2_outbox WHERE context_hash=? AND seq>=? AND seq<=? ORDER BY seq LIMIT ?',
            (context_hash,u64(first),u64(floor),limit)).fetchall()
        expected=min(limit,floor-first+1)
        if len(rows)!=expected:raise Rejected('V2_ARCHIVE_GAP')
        facts=[]
        for seq,row in enumerate(rows,first):
            if number(row['seq'])!=seq or row['fact'] is None:raise Rejected('V2_ARCHIVE_GAP')
            raw=sender.open('fact',row)
            if r.parse_fact(raw,context)['seq']!=seq:raise Rejected('V2_ARCHIVE_GAP')
            facts.append(raw)
        raw=r.frame(encode(dict(profile=PROFILE,context_hash=context_hash,checkpoint_hash=binding,
            first=first,base_root=base,facts=facts)))
        fault('before_archive_fence')
        sender.check_current_state()
        # Return only after the read transaction exits; no data is committed.
    finally:sender.db.rollback()
    fault('after_archive_read')
    return raw


class ArchiveVerifier:
    """In-memory, fail-closed verification; restart from genesis after state loss.

    Pages may come from an untrusted store. Context and exact checkpoint request/
    reply are supplied separately by the verifier's trusted caller. No partial
    fact is an authenticated result; result() remains unavailable until complete.
    """
    def __init__(self,context,request,ack,target):
        self.context=decode(encode(r.validate_context(context)))
        self.checkpoint,self.binding=checkpoint_binding(request,ack,self.context)
        r.uint(target,1)
        if target>self.checkpoint['floor']:raise Rejected('ARCHIVE_TARGET_NOT_RETIRED')
        self.target=target;self.next=1;self.root=r.genesis(self.context)
        self._fact=None;self.complete=False

    def accept(self,raw):
        if self.complete:raise Rejected('ARCHIVE_ALREADY_COMPLETE')
        obj=parse_page(raw,self.context,self.binding)
        if obj['first']!=self.next or obj['base_root']!=self.root:raise Rejected('ARCHIVE_CURSOR')
        end=self.next+len(obj['facts'])-1
        if end>self.checkpoint['floor']:raise Rejected('ARCHIVE_PAST_CHECKPOINT')
        root=self.root;selected=self._fact
        # Stage all changes locally: a rejected page never advances the cursor.
        for seq,fact in enumerate(obj['facts'],self.next):
            root=r.extend_prefix(root,fact,self.context,seq)
            if seq==self.target:selected=fact
        complete=end==self.checkpoint['floor']
        if complete and root!=self.checkpoint['root']:raise Rejected('ARCHIVE_ROOT_MISMATCH')
        self.root=root;self.next=end+1;self._fact=selected;self.complete=complete
        return {'processed_prefix_length':end,'checkpoint_floor':self.checkpoint['floor'],'complete':complete}

    def result(self):
        if not self.complete:raise Rejected('ARCHIVE_INCOMPLETE')
        # Immutable canonical fact bytes, never a fresh ACCEPTED/CLOSED event.
        return self._fact
