/*
 * EAP-DID: Shared definitions between server and peer
 * Copyright (c) 2024-2026, Caciano Machado
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef EAP_DID_COMMON_H
#define EAP_DID_COMMON_H

/* Flags octet at the start of every EAP-DID payload */
#define EAP_DID_FLAGS_LENGTH_INCLUDED 0x80
#define EAP_DID_FLAGS_MORE_FRAGMENTS 0x40
#define EAP_DID_FLAGS_START 0x20
#define EAP_DID_FLAGS_KEY_CONFIRM 0x10 /* reserved */
#define EAP_DID_VERSION_MASK 0x07

#define EAP_DID_VERSION 1
#define EAP_DID_MAX_VERSION 1

/* Upper bound for a reassembled OOB invitation or presentation (1 MB) */
#define EAP_DID_MAX_FILE_SIZE 1000000

/* Fragment size used when the configuration does not specify one */
#define EAP_DID_DEFAULT_FRAGMENT_SIZE 1300

/* Length of the derived MSK and EMSK */
#define EAP_DID_KEY_LEN 64

/**
 * eap_did_derive_key_cek - Derive keying material from the DIDComm CEK
 * @cek: Content encryption key recovered from the DIDComm JWE
 * @cek_len: Length of @cek in octets
 * @thid: DIDComm thread identifier, used as the HKDF salt
 * @label: HKDF info string, e.g. "EAP-DID-MSK"
 * @out_len: Number of octets to derive
 * Returns: Allocated buffer that the caller must free with os_free(), or
 * %NULL on failure
 *
 * The CEK is the key material both peers share after the DIDComm exchange;
 * it never traverses the EAP channel. The thid does, but it only acts as a
 * salt here.
 *
 * HKDF-SHA256 as RFC 5869 defines it: extract with the thid as salt, expand
 * with @label as info. @out_len is capped at 255 hash lengths.
 */
u8 * eap_did_derive_key_cek(const u8 *cek, size_t cek_len, const char *thid,
			    const char *label, size_t out_len);

/* Room for a DID URL, which for a did:peer:2 runs past a kilobyte */
#define EAP_DID_KID_LEN 1024

/**
 * eap_did_key_id - Build the DID URL naming the key agreement key of a DID
 * @did: did:peer:2 to read
 * @buf: Buffer for the NUL terminated DID URL
 * @buf_len: Capacity of @buf
 *
 * Resolving a did:peer:2 names each key segment "#key-N", numbered from one in
 * the order the segments appear, so the key agreement key is found by counting
 * the key purposes up to the 'E' segment. A DID with no such segment falls
 * back to "#key-1".
 */
void eap_did_key_id(const char *did, char *buf, size_t buf_len);

/* Room for a DID; a did:peer:2 with three key segments runs to a few hundred
 * octets */
#define EAP_DID_DID_LEN 512

/**
 * did_x25519_from_did - Read the key agreement key out of a did:peer:2
 * @did: DID to read, without any fragment
 * @pub: Buffer of 32 octets for the X25519 public key
 * Returns: 0 on success, -1 if the DID carries no usable key
 *
 * A did:peer:2 is a sequence of dot separated segments, each introduced by a
 * purpose code: 'A' assertion, 'E' key agreement, 'V' verification, 'I'
 * capability invocation, 'D' capability delegation and 'S' service. The key
 * agreement material sits in the 'E' segment as multibase base58btc over a
 * multicodec prefixed key. An Ed25519 key found there is converted to its
 * birationally equivalent X25519 key.
 */
int did_x25519_from_did(const char *did, u8 *pub);

/**
 * eap_did_session_id - Build the EAP Session-Id
 * @eap_type: EAP method type octet
 * @thid: DIDComm thread identifier
 * @len: Buffer for the length of the returned identifier
 * Returns: Allocated buffer that the caller must free with os_free(), or
 * %NULL on failure
 *
 * The Session-Id is the method type octet followed by SHA256(thid).
 */
u8 * eap_did_session_id(u8 eap_type, const char *thid, size_t *len);

#endif /* EAP_DID_COMMON_H */
