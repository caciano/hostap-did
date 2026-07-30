/*
 * EAP-DID: DIDComm v2 JWE authcrypt and authdecrypt
 * Copyright (c) 2024-2026, Caciano Machado
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef EAP_DID_JWE_H
#define EAP_DID_JWE_H

/* Length of the content encryption key used by A256CBC-HS512 */
#define DID_JWE_CEK_LEN 64

/* Most recipients a JWE is built for: the verifier and the authenticator */
#define DID_JWE_MAX_RECIPIENTS 4

/*
 * Largest plaintext did_jwe_authcrypt() encrypts. The callers' own message
 * bounds are derived from this one so that a message they accept cannot be a
 * message this fails to encode.
 */
#define DID_JWE_MAX_PLAINTEXT 16384

/* Octets base64url takes for @n, NUL included */
#define DID_B64URL_LEN(n) (((n) + 2) / 3 * 4 + 1)

/**
 * struct did_jwe_recipient - One party a JWE is encrypted for
 * @x25519_pub: Recipient X25519 public key (32 octets)
 * @kid: DID URL naming that key
 */
struct did_jwe_recipient {
	const u8 *x25519_pub;
	const char *kid;
};

/**
 * did_jwe_authcrypt - Wrap a plaintext in a DIDComm v2 JWE
 * @recipients: Parties the content encryption key is wrapped for
 * @num_recipients: Number of entries in @recipients, at most
 *	%DID_JWE_MAX_RECIPIENTS
 * @sender_x25519_priv: Sender X25519 static private key (32 octets)
 * @sender_x25519_pub: Sender X25519 static public key (32 octets)
 * @sender_kid: DID URL for the JWE skid header
 * @plaintext: Data to encrypt
 * @pt_len: Length of @plaintext
 * @cek_out: Buffer of %DID_JWE_CEK_LEN octets for the generated CEK
 * @jwe_out: Buffer for the serialized JWE
 * @jwe_out_cap: In: capacity of @jwe_out; out: length written
 * Returns: 0 on success, -1 on failure
 *
 * Uses ECDH-1PU key agreement with AES-256-KeyWrap and A256CBC-HS512 content
 * encryption, which is what the didcomm-jvm stack behind the Identus verifier
 * expects. Every recipient gets its own wrapped copy of the same content
 * encryption key, as a DIDComm message addressed to several parties does.
 */
int did_jwe_authcrypt(const struct did_jwe_recipient *recipients,
		      size_t num_recipients,
		      const u8 *sender_x25519_priv,
		      const u8 *sender_x25519_pub, const char *sender_kid,
		      const u8 *plaintext,
		      size_t pt_len, u8 *cek_out, char *jwe_out,
		      size_t *jwe_out_cap);

/**
 * did_jwe_authdecrypt - Recover the CEK, and optionally the plaintext, from a JWE
 * @recipient_x25519_priv: Recipient X25519 static private key (32 octets)
 * @sender_x25519_pub: Sender X25519 static public key (32 octets)
 * @jwe_json: Serialized JWE produced by did_jwe_authcrypt()
 * @jwe_len: Length of @jwe_json
 * @recipient_kid: DID URL naming our key, to pick our entry out of the
 *	recipient list, or %NULL to take the first entry
 * @cek_out: Buffer of %DID_JWE_CEK_LEN octets for the recovered CEK
 * @pt_out: Buffer for the plaintext, or %NULL to recover the CEK only
 * @pt_out_cap: In: capacity of @pt_out; out: length written. Ignored when
 *	@pt_out is %NULL
 * Returns: 0 on success, -1 on failure, including an authentication tag
 * mismatch when the plaintext was requested
 *
 * The ephemeral public key and the key identifiers are read from the JWE, so
 * only the two static keys have to be supplied. Recovering the CEK locally is
 * what lets the authenticator derive the MSK without contacting the verifier
 * out of band.
 */
int did_jwe_authdecrypt(const u8 *recipient_x25519_priv,
			const u8 *sender_x25519_pub, const char *jwe_json,
			size_t jwe_len, const char *recipient_kid,
			u8 *cek_out, u8 *pt_out, size_t *pt_out_cap);

/**
 * did_jwe_sender_kid - Read the skid header naming the sender key
 * @jwe_json: Serialized JWE
 * @jwe_len: Length of @jwe_json
 * @out: Buffer for the NUL terminated DID URL
 * @out_cap: Capacity of @out
 * Returns: 0 on success, -1 if the header carries no skid
 *
 * ECDH-1PU needs the sender static public key, and the JWE names the key it
 * used rather than carrying it. Reading the skid is what lets a recipient
 * resolve that key instead of having it configured out of band.
 */
int did_jwe_sender_kid(const char *jwe_json, size_t jwe_len, char *out,
		       size_t out_cap);

/**
 * did_b64url_encode - Base64url encode without padding
 * @in: Input data
 * @in_len: Length of @in
 * @out: Buffer for the NUL terminated result
 * @out_cap: In: capacity of @out; out: length written
 * Returns: 0 on success, -1 if @out is too small
 */
int did_b64url_encode(const u8 *in, size_t in_len, char *out,
		      size_t *out_cap);

#endif /* EAP_DID_JWE_H */
