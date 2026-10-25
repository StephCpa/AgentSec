"""Field encryption for the synthetic delegated count service.

Keys and a deployment identifier are supplied by trusted bootstrap, outside the
database. No KMS, online rotation, memory erasure, whole-database authentication,
rollback prevention, or physical timing guarantee is implemented. Fresh DB only.
"""
import hashlib
import hmac
import secrets
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from delegated_ledger import DelegatedLedger, Rejected
from scheduled_ledger import SCHEDULE_OVERHEAD
from wire import encode


MAGIC=b'ACV1'
VERSION=1
MAX_PLAINTEXT=65536
FIELDS=('count_value','alive0','alive1','g0','g1')


class StateVault:
    """Single-key-version, memory-only key holder; not a remote decrypt API."""
    def __init__(self, master_key, deployment_id):
        if type(master_key) is not bytes or len(master_key)!=32:
            raise Rejected('INVALID_STORAGE_KEY')
        if type(deployment_id) is not bytes or len(deployment_id)!=16:
            raise Rejected('INVALID_DEPLOYMENT_ID')
        self.deployment_id=deployment_id
        def derive(purpose):
            return HKDF(algorithm=hashes.SHA256(),length=32,salt=deployment_id,
                        info=encode(['agent-state-vault',VERSION,purpose])).derive(master_key)
        self._aead=AESGCMSIV(derive('encryption'))
        self._binding_key=derive('result-binding')
        self.key_check=hmac.new(derive('database-key-check'),
                               encode(['database-key-check',VERSION,deployment_id]),hashlib.sha256).hexdigest()

    def context(self, kind, identity):
        # Identities are public service-validated IDs, not caller-selected AAD.
        return encode(['agent-state-vault',VERSION,self.deployment_id,kind,list(identity)])

    def seal(self, kind, identity, plaintext):
        if type(plaintext) is not bytes or len(plaintext)>MAX_PLAINTEXT:
            raise Rejected('INVALID_SECRET_RECORD')
        header=MAGIC+VERSION.to_bytes(4,'big')
        nonce=secrets.token_bytes(12)
        return header+nonce+self._aead.encrypt(nonce,plaintext,header+self.context(kind,identity))

    def open(self, kind, identity, envelope):
        if (type(envelope) is not bytes or not 36<=len(envelope)<=MAX_PLAINTEXT+36 or
                envelope[:8]!=MAGIC+VERSION.to_bytes(4,'big')):
            raise Rejected('STORAGE_INTEGRITY')
        try:
            return self._aead.decrypt(envelope[8:20],envelope[20:],
                                      envelope[:8]+self.context(kind,identity))
        except InvalidTag:
            raise Rejected('STORAGE_INTEGRITY') from None

    def bind_result(self, identity, result):
        return 'hmac-v1:'+hmac.new(self._binding_key,
            self.context('result-binding',identity)+result,hashlib.sha256).hexdigest()


class EncryptedLedger(DelegatedLedger):
    storage_profile='delegated-count-aes256-gcm-siv-v1'

    def __init__(self, path, clock=None, *, vault):
        if type(vault) is not StateVault:
            raise Rejected('INVALID_STORAGE_VAULT')
        self.vault=vault
        super().__init__(path,clock=clock)

    def storage_configuration(self):
        return (self.storage_profile,self.vault.key_check)

    def protect_operation_field(self, kind, tenant, oid, digest, value):
        return self.vault.seal(kind,(tenant,oid,digest),value)

    def open_operation_row(self, row):
        op=dict(row)
        identity=(op['tenant'],op['id'],op['digest'])
        for kind,size in (('seed',32),('result',8)):
            if op[kind] is not None:
                op[kind]=self.vault.open(kind,identity,op[kind])
                if len(op[kind])!=size:
                    raise Rejected('STORAGE_INTEGRITY')
        if op['result'] is not None and not hmac.compare_digest(
                self.vault.bind_result(identity,op['result']),op['result_digest'] or ''):
            raise Rejected('STORAGE_INTEGRITY')
        return op

    def result_binding(self, tenant, oid, digest, result):
        return self.vault.bind_result((tenant,oid,digest),result)

    def protect_snapshot(self, tenant, domain_id, snapshot_id, rows):
        # Fixed public capacity => ciphertext length does not expose row values.
        return self.vault.seal('snapshot',(tenant,domain_id,snapshot_id),bytes(rows))

    def open_snapshot(self, tenant, domain_id, snapshot_id, value):
        rows=self.vault.open('snapshot',(tenant,domain_id,snapshot_id),value)
        if len(rows)!=self.domain(tenant,domain_id)['capacity'] or any(x not in (0,1) for x in rows):
            raise Rejected('STORAGE_INTEGRITY')
        return list(rows)

    def private_identity(self, job, pc):
        op=self.db.execute('SELECT digest FROM operations WHERE tenant=? AND id=?',
                           (job['tenant'],job['operation_id'])).fetchone()
        return (job['tenant'],job['operation_id'],op['digest'],job['domain_id'],job['seq'],job['work'],pc)

    def save_private_state(self, job, state, pc):
        data=struct.pack('>I4B',*(state[k] for k in FIELDS))
        envelope=self.vault.seal('job-state',self.private_identity(job,pc),data)
        # Legacy columns keep public defaults; private values never reach SQL.
        self.db.execute('UPDATE jobs SET private_state=? WHERE tenant=? AND operation_id=?',
                        (envelope,job['tenant'],job['operation_id']))

    def load_private_state(self, job):
        if tuple(job[k] for k in FIELDS)!=(0,1,1,0,0):
            raise Rejected('STORAGE_INTEGRITY')
        data=self.vault.open('job-state',self.private_identity(job,job['pc']),job['private_state'])
        if len(data)!=8:
            raise Rejected('STORAGE_INTEGRITY')
        state=dict(zip(FIELDS,struct.unpack('>I4B',data)))
        if (state['count_value']>job['work']-SCHEDULE_OVERHEAD or state['alive0'] not in (0,1) or
                state['alive1'] not in (0,1) or state['g0']>40 or state['g1']>40):
            raise Rejected('STORAGE_INTEGRITY')
        return state

    def audit(self):
        self.check_storage_profile()
        errors=super().audit()
        # Fail closed: an unreadable secret is never interpreted as an empty row,
        # a canceled job, a refundable reservation, or a request for fresh noise.
        for row in self.db.execute('SELECT * FROM snapshots'):
            self.open_snapshot(row['tenant'],row['domain_id'],row['id'],row['rows_json'])
        for job in self.db.execute('SELECT * FROM jobs'):
            self.load_private_state(job)
        return errors
