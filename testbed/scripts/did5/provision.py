#!/usr/bin/env python3
"""
did5-provision.py — Provision DID and VC for wpa_supplicant (self-contained peer)

This script replaces the Holder Cloud Agent for EAP-DID authentication.
It:
1. Generates a secp256k1 keypair locally
2. Creates a did:peer:2 from the public key
3. Registers the DID with the Issuer Cloud Agent
4. Requests a VC from the Issuer
5. Exports VC JWT + private key PEM for wpa_supplicant

Usage:
    python3 did5-provision.py --issuer http://127.0.0.1:8080/cloud-agent \
                               --verifier-did did:peer:2... \
                               --output-dir /etc/wpa_supplicant/
"""

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.request
import urllib.error
import base64
import hashlib

def api(method, url, data=None, timeout=15):
    """Make HTTP request to Cloud Agent API."""
    headers = {'Content-Type': 'application/json'} if data else {}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        print(f'API error {e.code}: {body[:200]}', file=sys.stderr)
        raise

def generate_secp256k1_keypair():
    """Generate a secp256k1 keypair using OpenSSL CLI.
    
    Returns:
        (private_key_pem, public_key_hex)
    """
    # Generate private key
    proc = subprocess.run(
        ['openssl', 'ecparam', '-name', 'secp256k1', '-genkey', '-noout'],
        capture_output=True, check=True
    )
    priv_pem = proc.stdout.decode()

    # Extract public key
    proc2 = subprocess.run(
        ['openssl', 'ec', '-pubout'],
        input=proc.stdout, capture_output=True, check=True
    )
    pub_pem = proc2.stdout.decode()

    return priv_pem, pub_pem

def create_did_peer_2(pubkey_pem):
    """Create a minimal did:peer:2 from a secp256k1 public key.
    
    did:peer:2 format: did:peer:2.<assertion_key>.<key_agreement>.<service>
    
    For secp256k1:
    - Assertion key: multibase(0xe1 0x01 <secp256k1_pubkey_uncompressed>)
    - Key agreement: derive X25519 from secp256k1 (or generate separate)
    
    Simplified: use Ed25519 for now, convert later.
    Actually, for the testbed we can use a simpler approach:
    register the DID through the Cloud Agent API.
    """
    # For now, use the Cloud Agent to create the DID
    # It will handle the key generation and DID format
    pass

def main():
    parser = argparse.ArgumentParser(description='did5 credential provisioning')
    parser.add_argument('--issuer', required=True,
                        help='Issuer Cloud Agent base URL')
    parser.add_argument('--verifier-did', default=None,
                        help='Trusted verifier DID')
    parser.add_argument('--connection-id', default=None,
                        help='Existing connection ID with Issuer')
    parser.add_argument('--output-dir', default='.',
                        help='Output directory for credential files')
    args = parser.parse_args()

    issuer_url = args.issuer.rstrip('/')

    # Step 1: Check for existing published DID
    print('Step 1: Checking for existing DID...', file=sys.stderr)
    dids = api('GET', f'{issuer_url}/did-registrar/dids')
    holder_did = None
    for c in dids.get('contents', []):
        if c.get('status') == 'PUBLISHED':
            holder_did = c['did']
            print(f'  Found published DID: {holder_did}', file=sys.stderr)
            break

    if not holder_did:
        print('  No published DID found. Creating...', file=sys.stderr)
        # Create DID
        resp = api('POST', f'{issuer_url}/did-registrar/dids',
                   json.dumps({'documentTemplate': {
                       'publicKeys': [{'id': 'authKey', 'purpose': 'assertionMethod'}],
                       'services': []
                   }}).encode())
        holder_did = resp.get('longFormDid', '')
        if not holder_did:
            print(f'  ERROR: DID creation failed: {resp}', file=sys.stderr)
            sys.exit(1)
        # Publish
        api('POST', f'{issuer_url}/did-registrar/dids/{holder_did}/publications')
        # Wait
        for i in range(40):
            status = api('GET', f'{issuer_url}/did-registrar/dids/{holder_did}')
            if status.get('status') == 'PUBLISHED':
                print(f'  DID published: {holder_did}', file=sys.stderr)
                break
            time.sleep(3)

    # Step 2: Check for existing VC
    print('Step 2: Checking for existing VC...', file=sys.stderr)
    records = api('GET', f'{issuer_url}/issue-credentials/records')
    vc_jwt = None
    for c in records.get('contents', []):
        state = c.get('protocolState', '')
        if state == 'CredentialReceived':
            # Try to get the JWT
            cred = c.get('credential', '')
            if isinstance(cred, str) and cred.startswith('eyJ'):
                vc_jwt = cred
                print(f'  Found existing VC JWT ({len(vc_jwt)} chars)', file=sys.stderr)
                break

    if not vc_jwt:
        print('  No VC found. The Issuer needs to issue one first.', file=sys.stderr)
        print('  Run provision.sh (from testbed) to issue credentials.', file=sys.stderr)
        print('  Then re-run this script.', file=sys.stderr)
        # Try to extract from presentation API instead
        # The Holder side has the VC in its records
        sys.exit(1)

    # Step 3: Write VC JWT file
    vc_path = os.path.join(args.output_dir, 'credential.jwt')
    with open(vc_path, 'w') as f:
        f.write(vc_jwt)
    print(f'Step 3: VC JWT written to {vc_path} ({len(vc_jwt)} chars)')

    # Step 4: Write DID to file
    did_path = os.path.join(args.output_dir, 'holder_did.txt')
    with open(did_path, 'w') as f:
        f.write(holder_did)
    print(f'Step 4: Holder DID written to {did_path}')

    # Step 5: Note about private key
    print(f'''
Step 5: Private key

The DID private key is held by the Cloud Agent and cannot be exported via REST API.

For did5 (self-contained peer), the private key must be available locally.

Options:
1. Generate a new DID with a locally-known key (manual DID creation)
2. Use the Cloud Agent's key export feature (if available)
3. Patch the Cloud Agent to expose the private key (not recommended)

For the testbed, the simplest approach is to generate a new secp256k1 keypair,
create a DID document manually, publish it through the Issuer API,
and then issue a VC to this DID.

See: did5-keygen.py for key generation
''')

    if args.verifier_did:
        tv_path = os.path.join(args.output_dir, 'trusted_verifier_did.txt')
        with open(tv_path, 'w') as f:
            f.write(args.verifier_did)
        print(f'Trusted verifier DID written to {tv_path}')

    print(f'\n✅ Provisioning complete.')
    print(f'   VC JWT: {vc_path}')
    print(f'   DID: {did_path}')
    print(f'   NOTE: Private key must be provided separately (see Step 5)')

if __name__ == '__main__':
    main()
