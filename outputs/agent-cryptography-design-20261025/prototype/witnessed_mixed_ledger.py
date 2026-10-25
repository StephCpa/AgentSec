"""Whole-state witness integration for signed encrypted count/histogram jobs.

The generic witness image captures the mixed catalogs, signatures, ancestor
accounts, ciphertext tapes/checkpoints/results and all scheduler/control state.
The TLS profile requires the existing authenticated adapter, without fallback.
Local rollback detection remains conditional on a linearizable, authenticated,
nonrollback witness. The reference SQLite witness is not production custody.
"""
from witnessed_ledger import WitnessedLedger
from encrypted_mixed_ledger import EncryptedMixedLedger
from witness_transport import TLSWitnessedLedger


class WitnessedMixedLedger(WitnessedLedger,EncryptedMixedLedger):
    storage_profile='witnessed-signed-mixed-v1'


class TLSWitnessedMixedLedger(TLSWitnessedLedger,WitnessedMixedLedger):
    storage_profile='mtls-witnessed-signed-mixed-v1'
