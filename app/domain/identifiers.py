import uuid
from typing import NewType

# Note: These identifiers provide static type-level separation and reduce accidental mixing during development.
# They are not a runtime security boundary.
DocumentID = NewType('DocumentID', uuid.UUID)
RecipientID = NewType('RecipientID', str)
SessionID = NewType('SessionID', uuid.UUID)
FingerprintID = NewType('FingerprintID', str)
ManifestID = NewType('ManifestID', uuid.UUID)
ReceiptID = NewType('ReceiptID', uuid.UUID)
LedgerEntryID = NewType('LedgerEntryID', str)
ValidatorID = NewType('ValidatorID', str)
CertificateID = NewType('CertificateID', str)
