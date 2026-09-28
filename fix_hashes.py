import os

files_to_fix = [
    'tests/protocol/test_release.py',
    'tests/protocol/test_envelope.py'
]

for file_path in files_to_fix:
    with open(file_path, 'r') as f:
        c = f.read()
    
    import hashlib
    h = hashlib.sha256(b"mock_ciphertext").hexdigest()
    c = c.replace('ciphertext_hash="mock_hash"', f'ciphertext_hash="{h}"')
    
    h2 = hashlib.sha256(b"sealed_ct").hexdigest()
    c = c.replace('ciphertext_hash="hash_xyz"', f'ciphertext_hash="{h2}"')
    c = c.replace('ciphertext_hash="sealed_doc_hash"', f'ciphertext_hash="{h2}"')
    
    with open(file_path, 'w') as f:
        f.write(c)
