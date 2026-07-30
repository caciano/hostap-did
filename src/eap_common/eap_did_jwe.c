/*
 * EAP-DID: DIDComm v2 JWE authcrypt and authdecrypt
 * Copyright (c) 2024-2026, Caciano Machado
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * ECDH-1PU key agreement with AES-256-KeyWrap and A256CBC-HS512 content
 * encryption, producing a JWE that the didcomm-jvm stack behind the Identus
 * verifier can unpack. Derived from didcomm-jvm v0.3.2; see NOTICE in the
 * swarm repository for the full attribution.
 *
 * References:
 * RFC 7518 (ECDH-1PU, A256KW, A256CBC-HS512), NIST SP 800-56A Rev3 section
 * 5.8.1 (ConcatKDF), RFC 3394 (AES Key Wrap) and the DIDComm v2 specification
 * at https://identity.foundation/didcomm-messaging/spec/
 */

#include "includes.h"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>
#include <openssl/core_names.h>

#include "common.h"
#include "utils/base64.h"
#include "eap_did_common.h"
#include "eap_did_http.h"
#include "eap_did_jwe.h"


/* Base64URL encode (no padding) */

int did_b64url_encode(const u8 *in, size_t in_len,
		      char *out, size_t *out_cap)
{
	static const char alphabet[] =
		"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
	size_t i, j;
	size_t out_len;

	out_len = (in_len + 2) / 3 * 4;
	if (in_len % 3 == 1)
		out_len -= 2;
	else if (in_len % 3 == 2)
		out_len -= 1;

	if (out_len + 1 > *out_cap)
		return -1;

	j = 0;
	for (i = 0; i + 2 < in_len; i += 3) {
		u32 v = ((u32) in[i] << 16) |
			     ((u32) in[i + 1] << 8) |
			     (u32) in[i + 2];
		out[j++] = alphabet[(v >> 18) & 0x3f];
		out[j++] = alphabet[(v >> 12) & 0x3f];
		out[j++] = alphabet[(v >> 6) & 0x3f];
		out[j++] = alphabet[v & 0x3f];
	}
	if (i < in_len) {
		u32 v = (u32) in[i] << 16;
		if (i + 1 < in_len)
			v |= (u32) in[i + 1] << 8;
		out[j++] = alphabet[(v >> 18) & 0x3f];
		out[j++] = alphabet[(v >> 12) & 0x3f];
		if (i + 1 < in_len)
			out[j++] = alphabet[(v >> 6) & 0x3f];
	}
	out[j] = '\0';
	*out_cap = j;
	return 0;
}

/* X25519 ECDH */

static int x25519_ecdh(const u8 *priv_key, const u8 *pub_key,
		       u8 shared_out[32])
{
	EVP_PKEY *pkey = NULL;
	EVP_PKEY *peer = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	size_t shared_len = 32;
	int ret = -1;

	pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
					    priv_key, 32);
	if (!pkey)
		goto out;

	peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
					   pub_key, 32);
	if (!peer)
		goto out;

	ctx = EVP_PKEY_CTX_new(pkey, NULL);
	if (!ctx)
		goto out;

	if (EVP_PKEY_derive_init(ctx) <= 0 ||
	    EVP_PKEY_derive_set_peer(ctx, peer) <= 0 ||
	    EVP_PKEY_derive(ctx, shared_out, &shared_len) <= 0)
		goto out;

	ret = 0;
out:
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(peer);
	EVP_PKEY_free(pkey);
	return ret;
}

static int x25519_generate_keypair(u8 priv_out[32], u8 pub_out[32])
{
	EVP_PKEY *pkey = NULL;
	EVP_PKEY_CTX *ctx = NULL;
	size_t len = 32;
	int ret = -1;

	ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
	if (!ctx)
		goto out;
	if (EVP_PKEY_keygen_init(ctx) <= 0)
		goto out;
	if (EVP_PKEY_keygen(ctx, &pkey) <= 0)
		goto out;

	if (EVP_PKEY_get_raw_private_key(pkey, priv_out, &len) <= 0 || len != 32)
		goto out;
	len = 32;
	if (EVP_PKEY_get_raw_public_key(pkey, pub_out, &len) <= 0 || len != 32)
		goto out;

	ret = 0;
out:
	EVP_PKEY_free(pkey);
	EVP_PKEY_CTX_free(ctx);
	return ret;
}

/* ConcatKDF (NIST SP 800-56A Section 5.8.1) */

static void put_be32(u8 *buf, u32 val)
{
	buf[0] = (val >> 24) & 0xff;
	buf[1] = (val >> 16) & 0xff;
	buf[2] = (val >> 8) & 0xff;
	buf[3] = val & 0xff;
}

/* One length prefixed OtherInfo field: a 32 bit octet count then the data */
static int kdf_update_segment(EVP_MD_CTX *md_ctx, const u8 *data, size_t len)
{
	u8 prefix[4];

	put_be32(prefix, (u32) len);
	if (EVP_DigestUpdate(md_ctx, prefix, 4) != 1)
		return -1;
	if (len && EVP_DigestUpdate(md_ctx, data, len) != 1)
		return -1;

	return 0;
}

/*
 * Derive the key encryption key the way ECDH-1PU in key wrapping mode wants
 * it (draft-madden-jose-ecdh-1pu-04 section 2.3): OtherInfo is the "alg"
 * value, the two agreement party fields, the key length, an empty
 * SuppPrivInfo, and the authentication tag of the content encryption. The tag
 * is what ties the wrapped key to the message, so it has to be computed
 * before this is called.
 */
static int concat_kdf(const u8 *z, size_t z_len,
		      const char *algorithm_id,
		      const u8 *party_u, size_t party_u_len,
		      const u8 *party_v, size_t party_v_len,
		      const u8 *tag, size_t tag_len,
		      u8 *kek_out, size_t kek_len)
{
	u8 supp_pub[4];
	u8 counter_buf[4];
	u32 counter = 1;
	size_t generated = 0;
	EVP_MD_CTX *md_ctx = NULL;

	put_be32(supp_pub, (u32)(kek_len * 8));

	while (generated < kek_len) {
		u8 digest[32];
		size_t copy_len;

		put_be32(counter_buf, counter);

		md_ctx = EVP_MD_CTX_new();
		if (!md_ctx)
			return -1;
		if (EVP_DigestInit_ex(md_ctx, EVP_sha256(), NULL) != 1 ||
		    EVP_DigestUpdate(md_ctx, counter_buf, 4) != 1 ||
		    EVP_DigestUpdate(md_ctx, z, z_len) != 1 ||
		    kdf_update_segment(md_ctx, (const u8 *) algorithm_id,
				       os_strlen(algorithm_id)) ||
		    kdf_update_segment(md_ctx, party_u, party_u_len) ||
		    kdf_update_segment(md_ctx, party_v, party_v_len) ||
		    EVP_DigestUpdate(md_ctx, supp_pub, 4) != 1 ||
		    kdf_update_segment(md_ctx, tag, tag_len)) {
			EVP_MD_CTX_free(md_ctx);
			return -1;
		}
		{
			unsigned int md_len = 32;
			EVP_DigestFinal_ex(md_ctx, digest, &md_len);
		}
		EVP_MD_CTX_free(md_ctx);

		copy_len = kek_len - generated;
		if (copy_len > 32)
			copy_len = 32;
		os_memcpy(kek_out + generated, digest, copy_len);
		generated += copy_len;
		counter++;
	}

	return 0;
}

/* AES-256 Key Wrap (RFC 3394)
 *
 * @wrapped_cap is in/out: the capacity of @wrapped_out on the way in, the
 * number of octets written on the way out. Key Wrap adds eight octets.
 */

static int aes256_keywrap(const u8 *kek, size_t kek_len,
			  const u8 *cek, size_t cek_len,
			  u8 *wrapped_out, size_t *wrapped_cap)
{
	EVP_CIPHER_CTX *ctx = NULL;
	EVP_CIPHER *cipher = NULL;
	int outlen;
	u8 outbuf[80];
	size_t wrapped_len;
	int ret = -1;

	if (cek_len < 16 || cek_len + 8 > sizeof(outbuf) ||
	    cek_len + 8 > *wrapped_cap)
		return -1;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	cipher = EVP_CIPHER_fetch(NULL, "aes-256-wrap", NULL);
	if (!cipher)
		cipher = (EVP_CIPHER *) EVP_aes_256_wrap();
#else
	cipher = (EVP_CIPHER *) EVP_aes_256_wrap();
#endif

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx || !cipher)
		goto out;

	/* RFC 3394 / RFC 7518 (A256KW) default IV = A6A6A6A6A6A6A6A6.
	 * Passing NULL makes OpenSSL apply this default, which is what the
	 * Nimbus/didcomm-jvm recipient (Identus Verifier) expects on unwrap.
	 * A non-default IV would make the wrapped key un-unwrappable by peers. */
	if (EVP_EncryptInit_ex(ctx, cipher, NULL, kek, NULL) <= 0)
		goto out;

	EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

	if (!EVP_EncryptUpdate(ctx, outbuf, &outlen, cek, cek_len) || outlen < 0)
		goto out;
	wrapped_len = (size_t) outlen;

	if (!EVP_EncryptFinal_ex(ctx, outbuf + wrapped_len, &outlen) ||
	    outlen < 0 || wrapped_len + (size_t) outlen > sizeof(outbuf))
		goto out;
	wrapped_len += (size_t) outlen;

	/* The bound is checked before the copy, never after it */
	if (wrapped_len > *wrapped_cap) {
		wpa_printf(MSG_ERROR,
			   "EAP-DID JWE: wrapped key of %zu octets exceeds the %zu octet buffer",
			   wrapped_len, *wrapped_cap);
		goto out;
	}

	os_memcpy(wrapped_out, outbuf, wrapped_len);
	*wrapped_cap = wrapped_len;
	ret = 0;

out:
	EVP_CIPHER_CTX_free(ctx);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (cipher)
		EVP_CIPHER_free(cipher);
#endif
	return ret;
}

/* AES-256 Key Unwrap (RFC 3394) — inverse of aes256_keywrap
 *
 * @cek_cap is in/out: the capacity of @cek_out on the way in, the number of
 * octets written on the way out. @wrapped comes from the recipient entry of a
 * JWE, so an unauthenticated peer chooses its length; the unwrap yields eight
 * octets less than that, and nothing here may write more than the caller can
 * hold.
 */

static int aes256_keyunwrap(const u8 *kek, size_t kek_len,
			    const u8 *wrapped, size_t wrapped_len,
			    u8 *cek_out, size_t *cek_cap)
{
	EVP_CIPHER_CTX *ctx = NULL;
	EVP_CIPHER *cipher = NULL;
	int outlen;
	u8 outbuf[80];
	size_t cek_len;
	int ret = -1;

	(void) kek_len;

	if (wrapped_len < 24 || wrapped_len > sizeof(outbuf) ||
	    wrapped_len - 8 > *cek_cap) {
		wpa_printf(MSG_INFO,
			   "EAP-DID JWE: wrapped key of %zu octets rejected (buffer is %zu)",
			   wrapped_len, *cek_cap);
		return -1;
	}

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	cipher = EVP_CIPHER_fetch(NULL, "aes-256-wrap", NULL);
	if (!cipher)
		cipher = (EVP_CIPHER *) EVP_aes_256_wrap();
#else
	cipher = (EVP_CIPHER *) EVP_aes_256_wrap();
#endif

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx || !cipher)
		goto out;

	/* NULL IV -> RFC 3394 default (A6A6A6A6A6A6A6A6); the wrap integrity
	 * check fails (EVP_DecryptFinal returns 0) if the KEK is wrong. */
	if (EVP_DecryptInit_ex(ctx, cipher, NULL, kek, NULL) <= 0)
		goto out;

	EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

	if (!EVP_DecryptUpdate(ctx, outbuf, &outlen, wrapped,
			       (int) wrapped_len) || outlen < 0)
		goto out;
	cek_len = (size_t) outlen;

	if (!EVP_DecryptFinal_ex(ctx, outbuf + cek_len, &outlen) ||
	    outlen < 0 || cek_len + (size_t) outlen > sizeof(outbuf))
		goto out;
	cek_len += (size_t) outlen;

	/* The bound is checked before the copy, never after it */
	if (cek_len > *cek_cap) {
		wpa_printf(MSG_INFO,
			   "EAP-DID JWE: unwrapped key of %zu octets exceeds the %zu octet buffer",
			   cek_len, *cek_cap);
		goto out;
	}

	os_memcpy(cek_out, outbuf, cek_len);
	*cek_cap = cek_len;
	ret = 0;

out:
	EVP_CIPHER_CTX_free(ctx);
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
	if (cipher)
		EVP_CIPHER_free(cipher);
#endif
	return ret;
}

/*
 * AES-256-CBC + HMAC-SHA512 (A256CBC-HS512 per RFC 7518 §5.2.5)
 *
 * CEK is 64 bytes: mac_key = CEK[0:32], enc_key = CEK[32:64].
 * HMAC input: AAD || IV(16) || ciphertext || uint64_be(aad_len_bits)
 * Tag = first 32 bytes of HMAC-SHA512 output.
 */

static int aescbc_hmac512_encrypt(const u8 cek[DID_JWE_CEK_LEN],
				  const u8 *plaintext, size_t pt_len,
				  const u8 *aad, size_t aad_len,
				  u8 iv[16],
				  u8 *ct_out, size_t *ct_len,
				  u8 tag[32])
{
	const u8 *mac_key = cek;
	const u8 *enc_key = cek + 32;
	EVP_CIPHER_CTX *ctx = NULL;
	int outlen, ret = -1;
	u8 hmac_out[64];
	unsigned int hmac_out_len = sizeof(hmac_out);
	u8 al_buf[8];
	u64 aad_bits;
	u8 *hmac_input = NULL;
	size_t hmac_input_len;

	if (RAND_bytes(iv, 16) != 1)
		return -1;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return -1;
	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, iv) != 1)
		goto out;
	if (EVP_EncryptUpdate(ctx, ct_out, &outlen, plaintext, pt_len) != 1)
		goto out;
	*ct_len = outlen;
	if (EVP_EncryptFinal_ex(ctx, ct_out + outlen, &outlen) != 1)
		goto out;
	*ct_len += outlen;

	aad_bits = (u64) aad_len * 8;
	for (int i = 7; i >= 0; i--) {
		al_buf[i] = (u8)(aad_bits & 0xFF);
		aad_bits >>= 8;
	}

	hmac_input_len = aad_len + 8 + 16 + *ct_len;
	hmac_input = os_malloc(hmac_input_len);
	if (!hmac_input)
		goto out;
	os_memcpy(hmac_input, aad, aad_len);
	os_memcpy(hmac_input + aad_len, iv, 16);
	os_memcpy(hmac_input + aad_len + 16, ct_out, *ct_len);
	os_memcpy(hmac_input + aad_len + 16 + *ct_len, al_buf, 8);

	if (HMAC(EVP_sha512(), mac_key, 32, hmac_input, hmac_input_len,
		 hmac_out, &hmac_out_len) == NULL)
		goto out;

	os_memcpy(tag, hmac_out, 32);
	ret = 0;

out:
	os_free(hmac_input);
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

/*
 * AES-256-CBC + HMAC-SHA512 decrypt/verify (inverse of aescbc_hmac512_encrypt)
 *
 * Verifies the truncated HMAC-SHA512 tag over AAD || IV || ciphertext || al
 * before decrypting. Returns -1 on tag mismatch (constant-time compare).
 */

static int aescbc_hmac512_decrypt(const u8 cek[DID_JWE_CEK_LEN],
				  const u8 *ct, size_t ct_len,
				  const u8 *aad, size_t aad_len,
				  const u8 iv[16],
				  const u8 tag[32],
				  u8 *pt_out, size_t *pt_len)
{
	const u8 *mac_key = cek;
	const u8 *enc_key = cek + 32;
	EVP_CIPHER_CTX *ctx = NULL;
	int outlen, ret = -1;
	u8 hmac_out[64];
	unsigned int hmac_out_len = sizeof(hmac_out);
	u8 al_buf[8];
	u64 aad_bits;
	u8 *hmac_input = NULL;
	size_t hmac_input_len;

	/* 1. Recompute and verify the authentication tag */
	aad_bits = (u64) aad_len * 8;
	for (int i = 7; i >= 0; i--) {
		al_buf[i] = (u8)(aad_bits & 0xFF);
		aad_bits >>= 8;
	}

	hmac_input_len = aad_len + 8 + 16 + ct_len;
	hmac_input = os_malloc(hmac_input_len);
	if (!hmac_input)
		return -1;
	os_memcpy(hmac_input, aad, aad_len);
	os_memcpy(hmac_input + aad_len, iv, 16);
	os_memcpy(hmac_input + aad_len + 16, ct, ct_len);
	os_memcpy(hmac_input + aad_len + 16 + ct_len, al_buf, 8);

	if (HMAC(EVP_sha512(), mac_key, 32, hmac_input, hmac_input_len,
		 hmac_out, &hmac_out_len) == NULL)
		goto out;

	if (os_memcmp_const(hmac_out, tag, 32) != 0) {
		wpa_printf(MSG_INFO, "EAP-DID JWE: auth tag mismatch");
		goto out;
	}

	/* 2. Decrypt AES-256-CBC */
	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		goto out;
	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, enc_key, iv) != 1)
		goto out;
	if (EVP_DecryptUpdate(ctx, pt_out, &outlen, ct, (int) ct_len) != 1)
		goto out;
	*pt_len = outlen;
	if (EVP_DecryptFinal_ex(ctx, pt_out + outlen, &outlen) != 1)
		goto out;
	*pt_len += outlen;
	ret = 0;

out:
	os_free(hmac_input);
	EVP_CIPHER_CTX_free(ctx);
	return ret;
}

/* JWE authcrypt (main entry point) */

/*
 * apv is the SHA-256 over the recipient key identifiers, sorted and joined
 * with a dot, as the DIDComm messaging specification defines it.
 */
static int agreement_party_v(const struct did_jwe_recipient *recipients,
			     size_t num_recipients, u8 apv[32])
{
	const char *sorted[DID_JWE_MAX_RECIPIENTS];
	size_t i, j;
	EVP_MD_CTX *ctx;
	unsigned int len = 32;
	int ret = -1;

	if (num_recipients > DID_JWE_MAX_RECIPIENTS)
		return -1;

	for (i = 0; i < num_recipients; i++)
		sorted[i] = recipients[i].kid ? recipients[i].kid : "";

	for (i = 1; i < num_recipients; i++) {
		const char *key = sorted[i];

		for (j = i; j > 0 && os_strcmp(sorted[j - 1], key) > 0; j--)
			sorted[j] = sorted[j - 1];
		sorted[j] = key;
	}

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		return -1;
	if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1)
		goto out;
	for (i = 0; i < num_recipients; i++) {
		if ((i && EVP_DigestUpdate(ctx, ".", 1) != 1) ||
		    EVP_DigestUpdate(ctx, sorted[i],
				     os_strlen(sorted[i])) != 1)
			goto out;
	}
	if (EVP_DigestFinal_ex(ctx, apv, &len) == 1)
		ret = 0;

out:
	EVP_MD_CTX_free(ctx);

	return ret;
}


int did_jwe_authcrypt(const struct did_jwe_recipient *recipients,
                      size_t num_recipients,
                      const u8 *sender_x25519_priv,
                      const u8 *sender_x25519_pub,
                      const char *sender_kid,
                      const u8 *plaintext, size_t pt_len,
                      u8 *cek_out,
                      char *jwe_out, size_t *jwe_out_cap)
{
	u8 eph_priv[32];
	u8 eph_pub[32];
	u8 z1[32], z2[32], z_concat[64];
	u8 kek[32];
	u8 cek[DID_JWE_CEK_LEN];  /* A256CBC-HS512 takes a 64 octet key */
	u8 iv[16];   /* CBC block size */
	u8 *ciphertext = NULL;
	u8 tag[32];  /* Truncated HMAC-SHA512 */
	u8 apv[32];  /* SHA-256 over the recipient key identifier */

	u8 wrapped_cek[80];
	size_t wrapped_cek_len = 0;

	char eph_pub_b64[64];
	size_t eph_pub_b64_len;
	char protected_b64[4096];
	size_t protected_b64_len;
	char iv_b64[32];
	size_t iv_b64_len;
	char *ct_b64 = NULL;
	size_t ct_b64_len;
	char tag_b64[64];
	size_t tag_b64_len;
	char wrapped_b64[160];
	size_t wrapped_b64_len;

	char protected_json[2048];
	char recipient_hdr[4096];
	int rh_len, plen;
	size_t ct_real_len = 0;
	size_t needed;
	size_t i;

	int ret = -1;

	if (!recipients || num_recipients == 0 ||
	    num_recipients > DID_JWE_MAX_RECIPIENTS) {
		wpa_printf(MSG_ERROR, "EAP-DID JWE: %zu recipients requested",
			   num_recipients);
		return -1;
	}

	if (pt_len > DID_JWE_MAX_PLAINTEXT) {
		wpa_printf(MSG_ERROR,
			   "EAP-DID JWE: plaintext of %zu octets exceeds the %d the method encodes",
			   pt_len, DID_JWE_MAX_PLAINTEXT);
		return -1;
	}

	wpa_printf(MSG_DEBUG,
		   "EAP-DID JWE: authcrypt start (pt_len=%zu, recipients=%zu)",
		   pt_len, num_recipients);

	/* 1. Generate CEK (64 bytes) */
	if (RAND_bytes(cek, DID_JWE_CEK_LEN) != 1) {
		wpa_printf(MSG_ERROR, "EAP-DID JWE: RAND_bytes(cek) failed");
		goto out;
	}

	/* 2. Generate ephemeral X25519 keypair */
	if (x25519_generate_keypair(eph_priv, eph_pub) != 0) {
		wpa_printf(MSG_ERROR, "EAP-DID JWE: ephemeral keypair failed");
		goto out;
	}

	/* 3. Encode ephemeral public key as base64url */
	eph_pub_b64_len = sizeof(eph_pub_b64);
	if (did_b64url_encode(eph_pub, 32, eph_pub_b64, &eph_pub_b64_len) != 0) {
		wpa_printf(MSG_ERROR, "EAP-DID JWE: eph_pub b64url failed");
		goto out;
	}

	/* 4. Build the protected header. apu names the sender key and apv is
	 * the SHA-256 over the recipient key identifiers, as DIDComm requires;
	 * both are fed to the key derivation further down. */
	{
		const char *skid = sender_kid ? sender_kid : "";
		char apu_b64[512], apv_b64[64];
		size_t apu_b64_len = sizeof(apu_b64);
		size_t apv_b64_len = sizeof(apv_b64);

		if (agreement_party_v(recipients, num_recipients, apv) != 0) {
			wpa_printf(MSG_ERROR, "EAP-DID JWE: apv digest failed");
			goto out;
		}
		if (did_b64url_encode((const u8 *) skid, os_strlen(skid),
				      apu_b64, &apu_b64_len) != 0 ||
		    did_b64url_encode(apv, sizeof(apv),
				      apv_b64, &apv_b64_len) != 0) {
			wpa_printf(MSG_ERROR, "EAP-DID JWE: apu/apv b64url failed");
			goto out;
		}
		plen = os_snprintf(protected_json, sizeof(protected_json),
			"{\"typ\":\"application/didcomm-encrypted+json\","
			"\"alg\":\"ECDH-1PU+A256KW\","
			"\"enc\":\"A256CBC-HS512\","
			"\"epk\":{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"%s\"},"
			"\"skid\":\"%s\","
			"\"apu\":\"%s\","
			"\"apv\":\"%s\"}",
			eph_pub_b64, skid, apu_b64, apv_b64);
		if (plen < 0 || (size_t) plen >= sizeof(protected_json))
			goto out;
	}


	/* AAD = base64url(protected_header) */
	protected_b64_len = sizeof(protected_b64);
	if (did_b64url_encode((const u8 *) protected_json, plen,
			      protected_b64, &protected_b64_len) != 0) {
		wpa_printf(MSG_ERROR, "EAP-DID JWE: protected b64url failed");
		goto out;
	}

	/* 5. AES-256-CBC + HMAC-SHA512 encrypt */
	ciphertext = os_malloc(pt_len + 16);
	if (!ciphertext)
		goto out;

	if (aescbc_hmac512_encrypt(cek, plaintext, pt_len,
				   (const u8 *) protected_b64,
				   protected_b64_len,
				   iv, ciphertext, &ct_real_len, tag) != 0) {
		wpa_printf(MSG_ERROR, "EAP-DID JWE: AES-CBC-HS512 encrypt failed");
		goto out;
	}

	/*
	 * 6. One wrapped copy of the content encryption key per recipient. The
	 * protected header and the tag are shared, so only Z changes.
	 */
	rh_len = 0;
	for (i = 0; i < num_recipients; i++) {
		const char *kid = recipients[i].kid ? recipients[i].kid : "";
		int n;

		/* ECDH-1PU: Z = Ze || Zs, the ephemeral secret first */
		if (x25519_ecdh(eph_priv, recipients[i].x25519_pub, z1) != 0 ||
		    x25519_ecdh(sender_x25519_priv, recipients[i].x25519_pub,
				z2) != 0) {
			wpa_printf(MSG_ERROR, "EAP-DID JWE: ECDH failed");
			goto out;
		}
		os_memcpy(z_concat, z1, 32);
		os_memcpy(z_concat + 32, z2, 32);

		/* ConcatKDF over Z and the authentication tag -> KEK */
		if (concat_kdf(z_concat, 64, "ECDH-1PU+A256KW",
			       (const u8 *) (sender_kid ? sender_kid : ""),
			       sender_kid ? os_strlen(sender_kid) : 0,
			       apv, sizeof(apv), tag, sizeof(tag),
			       kek, 32) != 0) {
			wpa_printf(MSG_ERROR, "EAP-DID JWE: ConcatKDF failed");
			goto out;
		}

		wrapped_cek_len = sizeof(wrapped_cek);
		if (aes256_keywrap(kek, 32, cek, DID_JWE_CEK_LEN,
				   wrapped_cek, &wrapped_cek_len) != 0) {
			wpa_printf(MSG_ERROR, "EAP-DID JWE: AES-KeyWrap failed");
			goto out;
		}

		wrapped_b64_len = sizeof(wrapped_b64);
		if (did_b64url_encode(wrapped_cek, wrapped_cek_len,
				      wrapped_b64, &wrapped_b64_len)) {
			wpa_printf(MSG_ERROR,
				   "EAP-DID JWE: wrapped key b64url failed");
			goto out;
		}

		n = os_snprintf(recipient_hdr + rh_len,
				sizeof(recipient_hdr) - rh_len,
				"%s{\"header\":{\"kid\":\"%s\"},"
				"\"encrypted_key\":\"%s\"}",
				i ? "," : "", kid, wrapped_b64);
		if (n < 0 || (size_t) n >= sizeof(recipient_hdr) - rh_len) {
			wpa_printf(MSG_ERROR,
				   "EAP-DID JWE: recipient list too long");
			goto out;
		}
		rh_len += n;
	}

	/*
	 * 7. Base64url encode the shared components. The ciphertext is the
	 * only one that scales with the message, and it is a third larger
	 * again encoded, so it does not go on the stack.
	 */
	iv_b64_len = sizeof(iv_b64);
	tag_b64_len = sizeof(tag_b64);
	ct_b64_len = DID_B64URL_LEN(ct_real_len);

	ct_b64 = os_malloc(ct_b64_len);
	if (!ct_b64) {
		wpa_printf(MSG_ERROR,
			   "EAP-DID JWE: no memory for %zu octets of ciphertext",
			   ct_b64_len);
		goto out;
	}

	if (did_b64url_encode(iv, 16, iv_b64, &iv_b64_len) ||
	    did_b64url_encode(ciphertext, ct_real_len, ct_b64, &ct_b64_len) ||
	    did_b64url_encode(tag, 32, tag_b64, &tag_b64_len)) {
		wpa_printf(MSG_ERROR, "EAP-DID JWE: b64url encode failed");
		goto out;
	}

	/* 8. Assemble JWE JSON */
	needed = os_snprintf(jwe_out, *jwe_out_cap,
		"{"
		"\"protected\":\"%s\","
		"\"recipients\":[%s],"
		"\"iv\":\"%s\","
		"\"ciphertext\":\"%s\","
		"\"tag\":\"%s\""
		"}",
		protected_b64,
		recipient_hdr,
		iv_b64,
		ct_b64,
		tag_b64);

	if (needed >= *jwe_out_cap) {
		wpa_printf(MSG_ERROR, "EAP-DID JWE: output overflow (%zu > %zu)",
			   needed, *jwe_out_cap);
		goto out;
	}
	*jwe_out_cap = needed;

	/* Copy CEK (64 bytes) to caller */
	os_memcpy(cek_out, cek, DID_JWE_CEK_LEN);

	wpa_printf(MSG_DEBUG, "EAP-DID JWE: authcrypt done "
		   "(jwe=%zu bytes, cek=64B)", *jwe_out_cap);
	ret = 0;

out:
	os_free(ciphertext);
	os_free(ct_b64);
	return ret;
}

/*
 * JWE authdecrypt (recipient side) — recover CEK (and optionally plaintext)
 */

/*
 * Find the wrapped key meant for us. A JWE addressed to several parties
 * carries one entry per recipient, each naming the key it was wrapped for, so
 * the entries have to be walked rather than the first one taken.
 */
static int recipient_entry(const char *jwe_json, size_t jwe_len,
			   const char *want_kid, char *kid, size_t kid_len,
			   char *enc_key, size_t enc_key_len)
{
	const char *pos, *end = jwe_json + jwe_len;

	pos = os_strstr(jwe_json, "\"recipients\"");
	if (!pos)
		return -1;

	while (pos < end && *pos != '[') {
		pos++;
	}

	while (pos < end) {
		const char *entry;
		int depth = 0;

		while (pos < end && *pos != '{') {
			if (*pos == ']')
				return -1;
			pos++;
		}
		entry = pos;
		while (pos < end) {
			if (*pos == '{')
				depth++;
			else if (*pos == '}' && --depth == 0)
				break;
			pos++;
		}
		if (pos >= end)
			return -1;
		pos++;

		if (did_json_extract_str(entry, pos - entry, "kid",
					 kid, kid_len) != 0 ||
		    did_json_extract_str(entry, pos - entry, "encrypted_key",
					 enc_key, enc_key_len) != 0)
			continue;

		if (!want_kid || !want_kid[0] || os_strcmp(kid, want_kid) == 0)
			return 0;
	}

	return -1;
}


int did_jwe_sender_kid(const char *jwe_json, size_t jwe_len, char *out,
		       size_t out_cap)
{
	char protected_b64[4096];
	u8 *protected_json;
	size_t protected_json_len = 0;
	int res;

	if (!jwe_json || !out || out_cap == 0)
		return -1;

	if (did_json_extract_str(jwe_json, jwe_len, "protected",
				 protected_b64, sizeof(protected_b64)) != 0)
		return -1;

	protected_json = base64_url_decode(protected_b64,
					   os_strlen(protected_b64),
					   &protected_json_len);
	if (!protected_json)
		return -1;

	res = did_json_extract_str((const char *) protected_json,
				   protected_json_len, "skid", out, out_cap);
	os_free(protected_json);

	return res;
}


int did_jwe_authdecrypt(const u8 *recipient_x25519_priv,
			const u8 *sender_x25519_pub,
			const char *jwe_json, size_t jwe_len,
			const char *recipient_kid,
			u8 *cek_out,
			u8 *pt_out, size_t *pt_out_cap)
{
	/* Matches the encoder: the protected header carries epk, skid and apu,
	 * which for did:peer DID URLs is well past a kilobyte */
	char protected_b64[4096];
	char enc_key_b64[256];
	char our_kid[600];
	char sender_kid[600];
	char epk_x_b64[128];
	char apu_b64[1024];
	char apv_b64[128];
	char cc_tag_b64[128];

	u8 *protected_json = NULL;
	size_t protected_json_len = 0;
	u8 *wrapped_cek = NULL;
	size_t wrapped_cek_len = 0;
	u8 *apu = NULL, *apv = NULL, *cc_tag = NULL;
	size_t apu_len = 0, apv_len = 0, cc_tag_len = 0;
	u8 *eph = NULL;
	u8 eph_pub[32];
	u8 z1[32], z2[32], z_concat[64];
	u8 kek[32];
	u8 cek[DID_JWE_CEK_LEN];
	size_t cek_len = 0;
	int ret = -1;

	if (!recipient_x25519_priv || !sender_x25519_pub || !jwe_json || !cek_out)
		return -1;

	/* 1. Extract top-level JWE fields (protected/AAD, tag) and our own
	 * entry in the recipient list */
	if (did_json_extract_str(jwe_json, jwe_len, "protected",
				 protected_b64, sizeof(protected_b64)) != 0 ||
	    did_json_extract_str(jwe_json, jwe_len, "tag",
				 cc_tag_b64, sizeof(cc_tag_b64)) != 0) {
		wpa_printf(MSG_INFO, "EAP-DID JWE: authdecrypt missing JWE fields");
		goto out;
	}

	if (recipient_entry(jwe_json, jwe_len, recipient_kid,
			    our_kid, sizeof(our_kid),
			    enc_key_b64, sizeof(enc_key_b64)) != 0) {
		wpa_printf(MSG_INFO,
			   "EAP-DID JWE: no wrapped key for %s",
			   recipient_kid && recipient_kid[0] ?
			   recipient_kid : "any recipient");
		goto out;
	}

	/* In key wrapping mode the authentication tag is part of the key
	 * derivation, so it is needed before the key can be unwrapped */
	cc_tag = base64_url_decode(cc_tag_b64, os_strlen(cc_tag_b64),
				  &cc_tag_len);
	if (!cc_tag || cc_tag_len != 32) {
		wpa_printf(MSG_INFO,
			   "EAP-DID JWE: authdecrypt bad tag (len=%zu)",
			   cc_tag_len);
		goto out;
	}

	/* 2. Decode protected header -> JSON, extract skid + epk.x */
	protected_json = base64_url_decode(protected_b64,
					   os_strlen(protected_b64),
					   &protected_json_len);
	if (!protected_json)
		goto out;

	if (did_json_extract_str((const char *) protected_json,
				 protected_json_len, "skid",
				 sender_kid, sizeof(sender_kid)) != 0 ||
	    did_json_extract_str((const char *) protected_json,
				 protected_json_len, "x",
				 epk_x_b64, sizeof(epk_x_b64)) != 0) {
		wpa_printf(MSG_INFO,
			   "EAP-DID JWE: authdecrypt missing protected fields");
		goto out;
	}

	/* The agreement party fields go into the derivation as they stand,
	 * decoded; both are optional and then count as empty */
	if (did_json_extract_str((const char *) protected_json,
				 protected_json_len, "apu",
				 apu_b64, sizeof(apu_b64)) == 0) {
		apu = base64_url_decode(apu_b64, os_strlen(apu_b64), &apu_len);
		if (!apu)
			goto out;
	}
	if (did_json_extract_str((const char *) protected_json,
				 protected_json_len, "apv",
				 apv_b64, sizeof(apv_b64)) == 0) {
		apv = base64_url_decode(apv_b64, os_strlen(apv_b64), &apv_len);
		if (!apv)
			goto out;
	}

	/* 3. Decode ephemeral public key (epk.x, 32 bytes) */
	{
		size_t eph_len = 0;

		eph = base64_url_decode(epk_x_b64, os_strlen(epk_x_b64), &eph_len);
		if (!eph || eph_len != 32) {
			wpa_printf(MSG_INFO,
				   "EAP-DID JWE: bad ephemeral key (len=%zu)",
				   eph_len);
			goto out;
		}
		os_memcpy(eph_pub, eph, 32);
	}

	/* 4. Decode wrapped CEK. A256KW adds eight octets to the key, and
	 * A256CBC-HS512 takes nothing but a DID_JWE_CEK_LEN key, so any other
	 * length is refused here rather than after the unwrap has run. */
	wrapped_cek = base64_url_decode(enc_key_b64, os_strlen(enc_key_b64),
					&wrapped_cek_len);
	if (!wrapped_cek)
		goto out;
	if (wrapped_cek_len != DID_JWE_CEK_LEN + 8) {
		wpa_printf(MSG_INFO,
			   "EAP-DID JWE: authdecrypt bad wrapped key (len=%zu, want %d)",
			   wrapped_cek_len, DID_JWE_CEK_LEN + 8);
		goto out;
	}

	/* 5. ECDH-1PU (recipient side):
	 *      Ze = ECDH(recipient_priv, ephemeral_pub)
	 *      Zs = ECDH(recipient_priv, sender_static_pub)
	 *      Z  = Ze || Zs
	 * This mirrors the sender side (Ze=ECDH(eph_priv,recip_pub),
	 * Zs=ECDH(sender_priv,recip_pub)) and yields the identical Z. */
	if (x25519_ecdh(recipient_x25519_priv, eph_pub, z1) != 0 ||
	    x25519_ecdh(recipient_x25519_priv, sender_x25519_pub, z2) != 0) {
		wpa_printf(MSG_ERROR, "EAP-DID JWE: authdecrypt ECDH failed");
		goto out;
	}
	os_memcpy(z_concat, z1, 32);
	os_memcpy(z_concat + 32, z2, 32);

	/* 6. ConcatKDF -> KEK, over the agreement party fields as they stand
	 * in the protected header and the authentication tag of the message */
	if (concat_kdf(z_concat, 64, "ECDH-1PU+A256KW", apu, apu_len,
		       apv, apv_len, cc_tag, cc_tag_len, kek, 32) != 0) {
		wpa_printf(MSG_ERROR, "EAP-DID JWE: authdecrypt ConcatKDF failed");
		goto out;
	}

	/* 7. AES-KeyUnwrap -> CEK (DID_JWE_CEK_LEN for A256CBC-HS512) */
	cek_len = sizeof(cek);
	if (aes256_keyunwrap(kek, 32, wrapped_cek, wrapped_cek_len,
			     cek, &cek_len) != 0 || cek_len != DID_JWE_CEK_LEN) {
		wpa_printf(MSG_INFO,
			   "EAP-DID JWE: authdecrypt key unwrap failed (len=%zu)",
			   cek_len);
		goto out;
	}

	os_memcpy(cek_out, cek, DID_JWE_CEK_LEN);

	/* 8. Optional: decrypt + authenticate the payload (A256CBC-HS512).
	 * AAD is base64url(protected header) exactly as it appears in the JWE. */
	if (pt_out && pt_out_cap) {
		char iv_b64[64];
		char *ct_b64 = NULL;
		u8 *iv = NULL, *ct = NULL;
		size_t iv_len = 0, ct_len = 0, pt_len = 0;
		int payload_ret = -1;

		ct_b64 = os_malloc(jwe_len);
		if (!ct_b64)
			goto payload_done;

		if (did_json_extract_str(jwe_json, jwe_len, "iv",
					 iv_b64, sizeof(iv_b64)) != 0 ||
		    did_json_extract_str(jwe_json, jwe_len, "ciphertext",
					 ct_b64, jwe_len) != 0) {
			wpa_printf(MSG_INFO,
				   "EAP-DID JWE: authdecrypt missing iv/ct");
			goto payload_done;
		}

		iv = base64_url_decode(iv_b64, os_strlen(iv_b64), &iv_len);
		ct = base64_url_decode(ct_b64, os_strlen(ct_b64), &ct_len);

		/* CBC only ever produces whole blocks, and the plaintext is
		 * shorter than the ciphertext once the padding comes off, so a
		 * whole number of blocks that fits in @pt_out is what makes the
		 * decryption safe to run into the caller's buffer. */
		if (!iv || iv_len != 16 || !ct || ct_len == 0 ||
		    ct_len % 16 != 0) {
			wpa_printf(MSG_INFO,
				   "EAP-DID JWE: authdecrypt bad iv/ct sizes (iv=%zu, ct=%zu)",
				   iv_len, ct_len);
			goto payload_done;
		}
		if (ct_len > *pt_out_cap) {
			wpa_printf(MSG_INFO,
				   "EAP-DID JWE: plaintext buffer too small (%zu octets for %zu)",
				   *pt_out_cap, ct_len);
			goto payload_done;
		}

		if (aescbc_hmac512_decrypt(cek, ct, ct_len,
					   (const u8 *) protected_b64,
					   os_strlen(protected_b64),
					   iv, cc_tag, pt_out, &pt_len) != 0)
			goto payload_done;

		*pt_out_cap = pt_len;
		payload_ret = 0;

	payload_done:
		os_free(ct_b64);
		os_free(iv);
		os_free(ct);
		if (payload_ret != 0)
			goto out;
	}

	wpa_printf(MSG_DEBUG, "EAP-DID JWE: authdecrypt done (cek=64B)");
	ret = 0;

out:
	os_free(protected_json);
	os_free(wrapped_cek);
	os_free(apu);
	os_free(apv);
	os_free(cc_tag);
	os_free(eph);
	return ret;
}
