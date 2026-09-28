import hashlib
import time

from app.crypto.kdf import derive_key
from app.crypto.kem import KEMWrapper
from app.crypto.randomness import generate_nonce, generate_session_id_bytes
from app.crypto.secret_split import reconstruct_dek
from app.crypto.signatures import SignatureWrapper
from app.crypto.symmetric import decrypt_document, encrypt_document
from app.crypto.zeroization import zeroize_bytearray
from app.storage.repositories import ThresholdRepository

from .authentication import ChallengeManager
from .envelope import open_request
from .errors import (
    AuthenticationError,
    AuthorizationError,
    ContractViolationError,
    ProtocolError,
)
from .interfaces import (
    AuthorityKEMKeyProvider,
    ControlledPlaintextProcessor,
    DocumentProvider,
    ManifestProvider,
    RecipientKeyProvider,
    ReleaseAuthorizer,
    ShareBProvider,
)
from .models import (
    AuthChallenge,
    AuthorityReleaseStatement,
    EncryptedReleaseEnvelope,
    ReleaseArtifact,
    ReleaseRequest,
)
from .serialization import canonicalize_for_signing
from .states import ProtocolState

STATEMENT_CONTEXT = b"DecryptTrace/AuthorityReleaseStatement/v1"

class ReleaseProtocol:
    def __init__(
        self,
        authorizer: ReleaseAuthorizer,
        manifest_provider: ManifestProvider,
        share_b_provider: ShareBProvider,
        recipient_key_provider: RecipientKeyProvider,
        document_provider: DocumentProvider,
        plaintext_processor: ControlledPlaintextProcessor,
        challenge_manager: "ChallengeManager",
        threshold_repository: "ThresholdRepository",
        authority_secret_key: bytes,
        authority_key_id: str,
        authority_kem_key_provider: AuthorityKEMKeyProvider,
        authority_sig_alg: str = "ML-DSA-65",
    ):
        self.authorizer = authorizer
        self.manifest_provider = manifest_provider
        self.share_b_provider = share_b_provider
        # WARNING: Any implementation used here outside of tests MUST be backed by verified, registered key material.
        self.recipient_key_provider = recipient_key_provider
        self.document_provider = document_provider
        self.plaintext_processor = plaintext_processor
        self.challenge_manager = challenge_manager
        self.threshold_repository = threshold_repository
        self.authority_kem_key_provider = authority_kem_key_provider

        self.authority_secret_key = authority_secret_key
        self.authority_key_id = authority_key_id
        self.authority_sig_alg = authority_sig_alg

        self.state = ProtocolState.CREATED

    def process_sealed_release(
        self,
        envelope: EncryptedReleaseEnvelope,
        challenge: AuthChallenge,
    ) -> tuple[ReleaseArtifact, AuthorityReleaseStatement]:
        """Primary entry point: unwrap the encrypted envelope, then run the release protocol.

        Share A is only materialized inside this method after decryption —
        it never appears in the ``envelope`` object that was received from
        the network.
        """
        try:
            authority_kem_sk = self.authority_kem_key_provider.get_authority_kem_secret_key()
            request = open_request(envelope, authority_kem_sk)
            return self._process(request, challenge)
        except Exception:
            self.state = ProtocolState.FAILED
            raise

    def process_release(self, request: ReleaseRequest, challenge: AuthChallenge) -> tuple[ReleaseArtifact, AuthorityReleaseStatement]:
        """Legacy / test entry point that accepts a plaintext ReleaseRequest.

        WARNING: this method does NOT enforce application-layer confidentiality
        for Share A.  Production code MUST use process_sealed_release().
        """
        try:
            return self._process(request, challenge)
        except Exception:
            self.state = ProtocolState.FAILED
            raise

    def _process(self, request: ReleaseRequest, challenge: AuthChallenge) -> tuple[ReleaseArtifact, AuthorityReleaseStatement]:
        recipient_dsa_pubkey = self.recipient_key_provider.get_recipient_dsa_pubkey(request.recipient_key_id)
        if not recipient_dsa_pubkey:
            raise AuthenticationError("Unknown recipient key id")
        
        self.challenge_manager.verify_request_authentication(request, challenge, recipient_dsa_pubkey, "ML-DSA-65")
        self.state = ProtocolState.AUTHENTICATED
        
        is_authorized = self.authorizer.authorize(
            document_id=request.document_id,
            manifest_id=request.manifest_id,
            recipient_key_id=request.recipient_key_id,
            request_id=request.request_id
        )
        if not is_authorized:
            raise AuthorizationError("Release explicitly denied by authorizer")
            
        self.state = ProtocolState.AUTHORIZED
        
        manifest = self.manifest_provider.get_manifest(request.manifest_id)
        if not manifest:
            raise ContractViolationError("Manifest not found")
        if manifest.document_id != request.document_id:
            raise ContractViolationError("Manifest document ID mismatch")
            
        self.state = ProtocolState.MANIFEST_VERIFIED
        
        try:
            share_a = bytes.fromhex(request.share_a_hex)
        except ValueError:
            raise ContractViolationError("Invalid Share A encoding")
            
        share_b = self.share_b_provider.get_share_b(request.document_id, request.recipient_key_id)
        if not share_b:
            raise ContractViolationError("Share B not found for this document/recipient")
            
        self.state = ProtocolState.SHARES_VALIDATED
        
        dek = reconstruct_dek(share_a, share_b)
        self.state = ProtocolState.DEK_RECONSTRUCTED
        
        doc_data = self.document_provider.get_document_ciphertext(request.document_id)
        if not doc_data:
            zeroize_bytearray(dek)
            raise ContractViolationError("Document ciphertext not found")
        
        orig_ciphertext, orig_nonce, orig_aad = doc_data
        
        try:
            plaintext = decrypt_document(orig_ciphertext, dek, orig_nonce, orig_aad)
        except Exception as e:
            zeroize_bytearray(dek)
            raise ProtocolError("Document decryption failed") from e
            
        zeroize_bytearray(dek)
        
        session_id_bytes = generate_session_id_bytes()
        session_id = session_id_bytes.hex()
        
        cached_thresh = self.threshold_repository.get_threshold(request.document_id)
        processed_plaintext, detection_threshold = self.plaintext_processor.process(
            document_id=request.document_id,
            session_id=session_id,
            recipient_key_id=request.recipient_key_id,
            plaintext=plaintext,
            cached_threshold=cached_thresh
        )
        if cached_thresh is None:
            self.threshold_repository.save_threshold(request.document_id, detection_threshold)
        
        self.state = ProtocolState.PLAINTEXT_PROCESSED
        
        recipient_kem_pubkey = self.recipient_key_provider.get_recipient_kem_pubkey(request.recipient_key_id)
        if not recipient_kem_pubkey:
            raise ContractViolationError("Recipient KEM public key not found")
            
        kem_alg = manifest.kem_algorithm
        kem = KEMWrapper(kem_alg)
        
        encapsulated_key, shared_secret = kem.encapsulate(recipient_kem_pubkey)
        
        hkdf_info = f"DecryptTrace/dek-transport|{request.protocol_version}|{request.document_id}|{request.manifest_id}|{request.recipient_key_id}|{session_id}".encode()
        transport_dek = bytearray(derive_key(shared_secret, None, hkdf_info, 32))
        
        from app.crypto.symmetric import build_canonical_aad

        from .serialization import canonicalize_artifact
        
        artifact_nonce = generate_nonce()
        
        aad_data = {
            "protocol_version": request.protocol_version,
            "document_id": request.document_id,
            "manifest_id": request.manifest_id,
            "recipient_key_id": request.recipient_key_id,
            "session_id": session_id,
            "kem_algorithm": kem_alg,
            "encryption_algorithm": "AES-GCM-256",
            "encryption_version": "1.0"
        }
        artifact_aad = build_canonical_aad(aad_data)
        
        artifact_ciphertext = encrypt_document(processed_plaintext, bytes(transport_dek), artifact_nonce, artifact_aad)
        zeroize_bytearray(transport_dek)
        
        artifact_id = generate_session_id_bytes().hex()
        
        artifact = ReleaseArtifact(
            artifact_id=artifact_id,
            protocol_version=request.protocol_version,
            document_id=request.document_id,
            manifest_id=request.manifest_id,
            recipient_key_id=request.recipient_key_id,
            session_id=session_id,
            processing_status="WATERMARKED",
            kem_algorithm=kem_alg,
            kem_version="1.0",
            kem_ciphertext_hex=encapsulated_key.hex(),
            encryption_algorithm="AES-GCM-256",
            encryption_version="1.0",
            nonce_hex=artifact_nonce.hex(),
            aad_hex=artifact_aad.hex(),
            ciphertext_hex=artifact_ciphertext.hex(),
            artifact_hash_hex=""
        )
        
        canonical_env = canonicalize_artifact(artifact)
        hasher = hashlib.sha256()
        hasher.update(canonical_env)
        artifact_hash = hasher.digest().hex()
        artifact.artifact_hash_hex = artifact_hash
        
        self.state = ProtocolState.ARTIFACT_ENCRYPTED
        
        orig_hasher = hashlib.sha256()
        orig_hasher.update(orig_ciphertext)
        orig_ciphertext_hash = orig_hasher.digest().hex()
        
        man_hasher = hashlib.sha256()
        man_hasher.update(canonicalize_for_signing(manifest))
        source_manifest_hash = man_hasher.digest().hex()
        
        # Derive fingerprint commitment securely (e.g., hash of recipient_key_id + document_id)
        fp_commit_hasher = hashlib.sha256()
        fp_commit_hasher.update(f"fp_commit|{request.document_id}|{request.recipient_key_id}".encode())
        
        statement = AuthorityReleaseStatement(
            protocol_version=request.protocol_version,
            release_id=generate_session_id_bytes().hex(),
            request_id=request.request_id,
            document_id=request.document_id,
            manifest_id=request.manifest_id,
            source_manifest_hash_hex=source_manifest_hash,
            recipient_key_id=request.recipient_key_id,
            session_id=session_id,
            artifact_id=artifact_id,
            artifact_hash_hex=artifact_hash,
            original_ciphertext_hash_hex=orig_ciphertext_hash,
            processing_status="WATERMARKED",
            fingerprint_commitment=fp_commit_hasher.digest().hex(),
            detection_threshold=detection_threshold,
            algorithm_identifiers={
                "kem": kem_alg,
                "signature": self.authority_sig_alg,
                "encryption": "AES-GCM-256"
            },
            authority_key_id=self.authority_key_id,
            creation_timestamp=str(int(time.time())),
            schema_version="1.0"
        )
        
        canonical_stmt = canonicalize_for_signing(statement)
        signer = SignatureWrapper(self.authority_sig_alg)
        signature = signer.sign(canonical_stmt, self.authority_secret_key, STATEMENT_CONTEXT)
        statement.signature_hex = signature.hex()
        
        self.state = ProtocolState.AUTHORITY_STATEMENT_SIGNED
        self.state = ProtocolState.DELIVERED
        
        return artifact, statement
