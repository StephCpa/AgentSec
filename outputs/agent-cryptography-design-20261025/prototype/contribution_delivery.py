"""Fresh combined contribution-ingestion and retention-v2 sender profiles.

Cooperative method resolution preserves BOTH schemas and BOTH precommit
recovery audits. No conversion of earlier snapshots or databases is supported.
"""
from contribution_ingestion import ContributionLedger
from retention_sender import RetentionSender
from witness_transport import TLSWitnessedLedger


class ContributionRetentionSender(ContributionLedger, RetentionSender):
    storage_profile = 'witnessed-contribution-retention-v2'


class TLSContributionRetentionSender(TLSWitnessedLedger, ContributionRetentionSender):
    storage_profile = 'mtls-contribution-retention-v2'
