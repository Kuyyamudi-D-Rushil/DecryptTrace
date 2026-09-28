import hashlib
import json
from typing import Any


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def hash_leaf(data: bytes) -> bytes:
    return sha256(b'\x00' + data)

def hash_node(left: bytes, right: bytes) -> bytes:
    return sha256(b'\x01' + left + right)

class MerkleTree:
    def __init__(self, leaves: list[bytes]):
        self.leaves = leaves
        self.tree: list[list[bytes]] = []
        self._build_tree()

    def _build_tree(self):
        if not self.leaves:
            self.tree = [[]]
            return
        
        current_level = [hash_leaf(leaf) for leaf in self.leaves]
        self.tree.append(current_level)
        
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                if i + 1 < len(current_level):
                    right = current_level[i + 1]
                    next_level.append(hash_node(left, right))
                else:
                    # Duplicate last odd node
                    next_level.append(hash_node(left, left))
            self.tree.append(next_level)
            current_level = next_level

    @property
    def root(self) -> bytes:
        if not self.tree or not self.tree[-1]:
            return sha256(b'')
        return self.tree[-1][0]

    def get_proof(self, index: int) -> list[tuple[bytes, bool]]:
        if index < 0 or index >= len(self.leaves):
            raise ValueError("Index out of bounds")
        
        proof = []
        current_index = index
        for level in self.tree[:-1]:
            is_right = current_index % 2 == 1
            sibling_index = current_index - 1 if is_right else current_index + 1
            
            if sibling_index < len(level):
                sibling_hash = level[sibling_index]
            else:
                sibling_hash = level[current_index] # duplicated odd node
                
            proof.append((sibling_hash, not is_right)) # is_right means the sibling is on the left
            current_index //= 2
            
        return proof

def verify_proof(leaf: bytes, proof: list[tuple[bytes, bool]], root: bytes) -> bool:
    current_hash = hash_leaf(leaf)
    for sibling_hash, is_sibling_right in proof:
        if is_sibling_right:
            current_hash = hash_node(current_hash, sibling_hash)
        else:
            current_hash = hash_node(sibling_hash, current_hash)
    return current_hash == root

class LedgerEntry:
    def __init__(self, seq: int, prev_hash: str, payload_hash: str, payload: dict[str, Any]):
        self.seq = seq
        self.prev_hash = prev_hash
        self.payload_hash = payload_hash
        self.payload = payload
        
        # entry_hash = SHA256(prev_hash + payload_hash)
        self.entry_hash = sha256(prev_hash.encode() + payload_hash.encode()).hex()

class Ledger:
    def __init__(self):
        self.entries: list[LedgerEntry] = []
        self._merkle_tree: MerkleTree | None = None
        
    def append(self, payload: dict[str, Any]) -> LedgerEntry:
        payload_str = json.dumps(payload, sort_keys=True)
        payload_hash = sha256(payload_str.encode()).hex()
        
        prev_hash = self.entries[-1].entry_hash if self.entries else sha256(b'').hex()
        seq = len(self.entries)
        
        entry = LedgerEntry(seq, prev_hash, payload_hash, payload)
        self.entries.append(entry)
        self._merkle_tree = None # Invalidate tree cache
        return entry
        
    def _get_tree(self) -> MerkleTree:
        if self._merkle_tree is None:
            # Leaves are the entry hashes
            leaves = [bytes.fromhex(e.entry_hash) for e in self.entries]
            self._merkle_tree = MerkleTree(leaves)
        return self._merkle_tree
        
    def get_root(self) -> str:
        return self._get_tree().root.hex()
        
    def get_inclusion_proof(self, seq: int) -> list[tuple[str, bool]]:
        tree = self._get_tree()
        proof = tree.get_proof(seq)
        return [(h.hex(), is_right) for h, is_right in proof]
        
    def verify_chain_integrity(self) -> bool:
        prev_hash = sha256(b'').hex()
        for entry in self.entries:
            if entry.prev_hash != prev_hash:
                return False
            expected_payload_hash = sha256(json.dumps(entry.payload, sort_keys=True).encode()).hex()
            if entry.payload_hash != expected_payload_hash:
                return False
            expected_entry_hash = sha256(entry.prev_hash.encode() + entry.payload_hash.encode()).hex()
            if entry.entry_hash != expected_entry_hash:
                return False
            prev_hash = entry.entry_hash
        return True
