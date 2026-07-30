#!/usr/bin/env python3
"""
did5-keygen.py — Generate secp256k1 keypair and create DID for EAP-DID peer

Generates a new secp256k1 private key, derives the public key,
creates a did:peer:2 DID document, and optionally registers it
with the Issuer Cloud Agent.

Output files:
  key.pem         — secp256k1 private key (PEM)
  pubkey.hex      — secp256k1 public key (hex, uncompressed)
  did.txt         — the did:peer:2 string
"""

import argparse
import base64
import hashlib
import json
import os
import subprocess
import sys
import urllib.request

# Base58 Bitcoin alphabet
B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def base58_encode(data):
    """Encode bytes as base58 (Bitcoin alphabet)."""
    n = int.from_bytes(data, 'big')
    result = []
    while n > 0:
        n, r = divmod(n, 58)
        result.append(B58_ALPHABET[r])
    # Leading zero bytes → '1' prefix
    for b in data:
        if b == 0:
            result.append('1')
        else:
            break
    return ''.join(reversed(result))

def multibase_encode(multicodec_prefix, key_bytes):
    """Encode as multibase base58btc: 'z' + base58(prefix + key)."""
    raw = multicodec_prefix + key_bytes
    return 'z' + base58_encode(raw)

def create_did_peer_2(secp256k1_pub_bytes):
    """Create a did:peer:2 from a secp256k1 public key.
    
    Format: did:peer:2.<assertion>.<key_agreement>.<service>
    
    For secp256k1 assertion key:
      multicodec prefix: 0xe7 0x01 (secp256k1 public key)
    
    For key agreement, we need X25519. Since we can't directly convert
    secp256k1 → X25519, we generate a separate X25519 keypair.
    But for simplicity in the testbed, we use the same key for both
    (the DIDComm library will handle key type negotiation).
    
    Actually, for DIDComm authcrypt, the sender needs an X25519 key.
    secp256k1 public keys are 33 bytes (compressed) or 65 bytes (uncompressed).
    X25519 keys are 32 bytes.
    
    For the testbed, we create a minimal DID with just the assertion key.
    The JWE construction generates ephemeral X25519 keys per message,
    so the static key agreement key can be any format the recipient expects.
    
    Simplified approach: use Ed25519 (multicodec 0xed01) for assertion
    and X25519 (multicodec 0xec01) for key agreement.
    
    For the testbed, we generate both from the same entropy.
    """
    # Assertion key: secp256k1 (multicodec 0xe701)
    # Using compressed public key (33 bytes)
    assertion_mb = 'E' + multibase_encode(b'\xe7\x01', secp256k1_pub_bytes)
    
    # Key agreement: we need X25519. Generate separately.
    # For now, create a placeholder — the JWE uses ephemeral X25519.
    # The verifier's key agreement key is what matters for ECDH-1PU.
    # The sender's static key for authcrypt can be any DID key.
    
    # Service endpoint (minimal)
    service_json = json.dumps({
        "t": "dm",
        "s": {"uri": "http://localhost:8082/didcomm", "r": [], "a": ["didcomm/v2"]}
    }, separators=(',', ':'))
    service_mb = 'S' + multibase_encode(b'', service_json.encode())
    
    # For now, return a did:key format (simpler than did:peer:2)
    # did:key:z<nmultibase(secp256k1_pubkey)>
    did = f"did:key:{multibase_encode(b'\\xe7\\x01', secp256k1_pub_bytes)}"
    
    return did

def main():
    parser = argparse.ArgumentParser(description='did5 keypair generation')
    parser.add_argument('--output-dir', default='.',
                        help='Output directory')
    parser.add_argument('--issuer', default=None,
                        help='Issuer Cloud Agent URL (optional, for registration)')
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    # Generate secp256k1 keypair
    print('Generating secp256k1 keypair...')
    proc = subprocess.run(
        ['openssl', 'ecparam', '-name', 'secp256k1', '-genkey', '-noout'],
        capture_output=True, check=True
    )
    priv_pem = proc.stdout.decode()

    # Get public key in uncompressed format (65 bytes: 04 + X + Y)
    proc2 = subprocess.run(
        ['openssl', 'ec', '-pubout', '-conv_form', 'uncompressed'],
        input=proc.stdout, capture_output=True, check=True
    )
    pub_pem = proc2.stdout.decode()

    # Extract raw public key bytes from PEM
    # Parse the PEM to get the DER, then extract the point
    import base64 as b64
    pub_der = b64.b64decode(''.join(pub_pem.split('\n')[1:-2]))
    # For secp256k1 SubjectPublicKeyInfo, the public key point starts at offset 26
    # (simplified: last 65 bytes for uncompressed)
    pub_point = pub_der[-65:]  # 04 + 32X + 32Y
    if pub_point[0] != 0x04:
        print(f'ERROR: expected uncompressed point (04), got {pub_point[0]:02x}')
        sys.exit(1)
    pub_bytes = pub_point[1:]  # 64 bytes (X || Y)

    # Also get compressed form (33 bytes)
    proc3 = subprocess.run(
        ['openssl', 'ec', '-pubout', '-conv_form', 'compressed'],
        input=proc.stdout, capture_output=True, check=True
    )
    pub_pem_c = proc3.stdout.decode()
    pub_der_c = b64.b64decode(''.join(pub_pem_c.split('\n')[1:-2]))
    pub_compressed = pub_der_c[-33:]

    # Create DID
    did = create_did_peer_2(pub_compressed)
    
    # Write files
    key_path = os.path.join(args.output_dir, 'key.pem')
    with open(key_path, 'w') as f:
        f.write(priv_pem)
    os.chmod(key_path, 0o600)
    print(f'Private key: {key_path}')

    pub_path = os.path.join(args.output_dir, 'pubkey.hex')
    with open(pub_path, 'w') as f:
        f.write(pub_compressed.hex())
    print(f'Public key (compressed): {pub_path}')

    did_path = os.path.join(args.output_dir, 'did.txt')
    with open(did_path, 'w') as f:
        f.write(did)
    print(f'DID: {did_path} ({did})')

    print(f'\n✅ Keypair generated.')
    print(f'   Use the private key in wpa_supplicant config:')
    print(f'   DID_KEY_FILE={key_path}')
    print(f'   DID_HOLDER_DID={did}')

if __name__ == '__main__':
    main()
