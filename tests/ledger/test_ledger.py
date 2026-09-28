from app.ledger.core import Ledger, verify_proof


def test_ledger_append_and_proof():
    ledger = Ledger()
    
    # Append elements
    payload1 = {"action": "request", "user": "alice"}
    payload2 = {"action": "authorize", "user": "bob"}
    payload3 = {"action": "release", "user": "charlie"}
    
    ledger.append(payload1)
    entry2 = ledger.append(payload2)
    ledger.append(payload3)
    
    assert len(ledger.entries) == 3
    assert ledger.verify_chain_integrity() is True
    
    # Check inclusion proof for entry 2
    root = ledger.get_root()
    proof = ledger.get_inclusion_proof(1)
    
    leaf_hash = bytes.fromhex(entry2.entry_hash)
    binary_proof = [(bytes.fromhex(h), is_right) for h, is_right in proof]
    binary_root = bytes.fromhex(root)
    
    assert verify_proof(leaf_hash, binary_proof, binary_root) is True
    
def test_ledger_tamper_detection():
    ledger = Ledger()
    ledger.append({"data": "1"})
    ledger.append({"data": "2"})
    ledger.append({"data": "3"})
    
    assert ledger.verify_chain_integrity() is True
    
    # Tamper with payload
    ledger.entries[1].payload = {"data": "tampered"}
    assert ledger.verify_chain_integrity() is False
    
    # Fix payload, tamper with prev_hash
    ledger.entries[1].payload = {"data": "2"}
    ledger.entries[1].prev_hash = "deadbeef"
    assert ledger.verify_chain_integrity() is False
