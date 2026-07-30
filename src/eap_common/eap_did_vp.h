/*
 * EAP-DID: Verifiable Presentation JWT creation
 * Copyright (c) 2024-2026, Caciano Machado
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef EAP_DID_VP_H
#define EAP_DID_VP_H

/*
 * Seconds a presentation stays good for. Long enough to cover an EAP exchange
 * and the clock skew between the parties, short enough that a presentation
 * that leaks is worth little.
 */
#define DID_VP_LIFETIME 300

/*
 * Bounds for the presentation being built. The payload carries the whole
 * credential, the encoding of it is a third larger again, and the signing
 * input is the header and that encoding together. They are stated once and
 * derived from each other so that a payload that fits cannot produce an
 * encoding that does not.
 */
#define DID_VP_PAYLOAD_LEN 6144
#define DID_VP_PAYLOAD_B64_LEN ((DID_VP_PAYLOAD_LEN + 2) / 3 * 4 + 1)
#define DID_VP_HEADER_B64_LEN 1792
#define DID_VP_SIGNING_INPUT_LEN (DID_VP_HEADER_B64_LEN + 1 + \
				  DID_VP_PAYLOAD_B64_LEN)

/* header.payload.signature, which is what did_vp_create() writes */
#define DID_VP_JWT_LEN (DID_VP_SIGNING_INPUT_LEN + 1 + 128)

/**
 * struct did_credential - Holder credential and keys used to build a VP
 * @vc_jwt: Verifiable Credential in JWT form
 * @vc_jwt_len: Length of @vc_jwt
 * @holder_did: Holder DID, did:peer:2 or did:prism form
 * @subject_did: DID the credential was issued to, taken from its "sub" claim
 * @prism_key_id: Name of the authentication key in @subject_did
 * @secp256k1_priv: secp256k1 private key of that authentication key
 * @has_secp256k1: Whether @secp256k1_priv was loaded
 * @ed25519_priv: Ed25519 private key used to sign the VP JWT
 * @has_ed25519: Whether @ed25519_priv was loaded
 * @x25519_priv: X25519 static private key used for JWE authcrypt
 * @x25519_pub: X25519 static public key matching @x25519_priv
 * @has_x25519: Whether the X25519 key pair was loaded
 * @trusted_verifier_did: Expected verifier DID, or an empty string to accept
 *	whichever DID the invitation carries
 */
struct did_credential {
	char vc_jwt[4096];
	size_t vc_jwt_len;
	char holder_did[256];
	char subject_did[1024];
	char prism_key_id[64];
	u8 secp256k1_priv[32];
	int has_secp256k1;
	u8 ed25519_priv[32];
	int has_ed25519;
	u8 x25519_priv[32];
	u8 x25519_pub[32];
	int has_x25519;
	char trusted_verifier_did[256];
};

/**
 * did_vp_create - Build a Verifiable Presentation JWT
 * @cred: Credential and signing key
 * @audience: Verifier DID or domain taken from the invitation
 * @nonce: Challenge taken from the invitation
 * @out: Buffer for the NUL terminated JWT
 * @out_cap: In: capacity of @out; out: length written
 * Returns: 0 on success, -1 on failure
 */
int did_vp_create(const struct did_credential *cred, const char *audience,
		  const char *nonce, char *out, size_t *out_cap);

/**
 * did_credential_load - Read the holder credential and keys from the environment
 * @cred: Buffer to populate
 * Returns: 0 on success, -1 when no credential is configured
 *
 * The credential is taken from DID_CREDENTIAL, or from the file named by
 * DID_CREDENTIAL_FILE, falling back to /etc/wpa_supplicant/credential.jwt.
 *
 * Private keys are read from files only, named by DID_SECP256K1_PRIV_FILE,
 * DID_ED25519_KEY_FILE and DID_X25519_KEY_FILE, and a file any account but the
 * owner can read is refused. They were once accepted in the environment as
 * well, which put them in /proc/<pid>/environ, in every child process and in
 * ps e. All keys are base64url encoded; the X25519 file is JSON with
 * x25519_priv and x25519_pub members.
 */
int did_credential_load(struct did_credential *cred);

#endif /* EAP_DID_VP_H */
