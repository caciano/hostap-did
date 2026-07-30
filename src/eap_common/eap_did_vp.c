/*
 * EAP-DID: Verifiable Presentation JWT creation
 * Copyright (c) 2024-2026, Caciano Machado
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * Builds and signs the VP JWT with pure EdDSA (Ed25519) on the supplicant
 * itself, so no Holder Cloud Agent is needed at authentication time. Derived
 * from Identus Cloud Agent concepts; see NOTICE in the swarm repository for
 * the full attribution.
 */

#include "includes.h"

#include <sys/stat.h>

#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

#include "common.h"
#include "utils/base64.h"
#include "eap_did_common.h"
#include "eap_did_http.h"
#include "eap_did_vp.h"


/* Base64URL helpers (no padding) */

static int b64url_encode(const u8 *in, size_t in_len,
			 char *out, size_t *out_cap)
{
	char *enc;
	size_t enc_len;

	enc = base64_url_encode(in, in_len, &enc_len);
	if (!enc || enc_len >= *out_cap) {
		free(enc);
		return -1;
	}

	os_memcpy(out, enc, enc_len);
	out[enc_len] = '\0';
	*out_cap = enc_len;
	free(enc);
	return 0;
}

/* Ed25519 sign (EdDSA pure) */

/*
 * Sign a message with an Ed25519 private key (pure EdDSA, no pre-hash).
 *
 * EdDSA (Ed25519) is a one-shot signature: the hashing is internal to the
 * algorithm, so we pass the raw message to EVP_DigestSign().
 *
 * Parameters:
 *   priv_key  : 32-byte raw Ed25519 private key
 *   msg       : message to sign (the "header.payload" JWT signing input)
 *   msg_len   : message length
 *   sig_out   : output buffer for raw 64-byte Ed25519 signature
 * Returns 0 on success, -1 on error.
 */
static int ed25519_sign(const u8 priv_key[32],
                        const char *msg, size_t msg_len,
                        u8 sig_out[64])
{
	EVP_PKEY *pkey = NULL;
	EVP_MD_CTX *ctx = NULL;
	size_t sig_len = 64;
	int ret = -1;

	pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL,
					    priv_key, 32);
	if (!pkey) {
		wpa_printf(MSG_ERROR, "EAP-DID: Ed25519 key load failed");
		goto out;
	}

	ctx = EVP_MD_CTX_new();
	if (!ctx)
		goto out;

	if (EVP_DigestSignInit(ctx, NULL, NULL, NULL, pkey) == 1 &&
	    EVP_DigestSign(ctx, sig_out, &sig_len,
			   (const unsigned char *) msg, msg_len) == 1 &&
	    sig_len == 64)
		ret = 0;

out:
	EVP_MD_CTX_free(ctx);
	EVP_PKEY_free(pkey);
	return ret;
}

/* ES256K sign (ECDSA over secp256k1 with SHA-256) */

/* Build an OpenSSL key from the raw secp256k1 scalar */
static EVP_PKEY * secp256k1_key(const u8 priv[32])
{
	EVP_PKEY *pkey = NULL;
	EC_GROUP *group = NULL;
	EC_POINT *point = NULL;
	BIGNUM *priv_bn = NULL;
	BN_CTX *bn_ctx = NULL;
	u8 pub[65];
	size_t pub_len;
	OSSL_PARAM_BLD *bld = NULL;
	OSSL_PARAM *params = NULL;
	EVP_PKEY_CTX *ctx = NULL;

	group = EC_GROUP_new_by_curve_name(NID_secp256k1);
	priv_bn = BN_bin2bn(priv, 32, NULL);
	bn_ctx = BN_CTX_new();
	if (!group || !priv_bn || !bn_ctx)
		goto out;

	/* The public point is derived here because EVP_PKEY_fromdata()
	 * expects the whole key pair */
	point = EC_POINT_new(group);
	if (!point || !EC_POINT_mul(group, point, priv_bn, NULL, NULL, bn_ctx))
		goto out;
	pub_len = EC_POINT_point2oct(group, point,
				     POINT_CONVERSION_UNCOMPRESSED,
				     pub, sizeof(pub), bn_ctx);
	if (pub_len == 0)
		goto out;

	bld = OSSL_PARAM_BLD_new();
	if (!bld ||
	    !OSSL_PARAM_BLD_push_utf8_string(bld, OSSL_PKEY_PARAM_GROUP_NAME,
					     "secp256k1", 0) ||
	    !OSSL_PARAM_BLD_push_BN(bld, OSSL_PKEY_PARAM_PRIV_KEY, priv_bn) ||
	    !OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
					      pub, pub_len))
		goto out;

	params = OSSL_PARAM_BLD_to_param(bld);
	ctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
	if (!params || !ctx || EVP_PKEY_fromdata_init(ctx) != 1 ||
	    EVP_PKEY_fromdata(ctx, &pkey, EVP_PKEY_KEYPAIR, params) != 1)
		pkey = NULL;

out:
	EVP_PKEY_CTX_free(ctx);
	OSSL_PARAM_free(params);
	OSSL_PARAM_BLD_free(bld);
	EC_POINT_free(point);
	BN_CTX_free(bn_ctx);
	BN_clear_free(priv_bn);
	EC_GROUP_free(group);

	return pkey;
}


/*
 * Sign a message with a secp256k1 private key, SHA-256 digest, and return the
 * signature as JOSE wants it: r and s concatenated, each padded to 32 octets.
 * s is normalised to the lower half of the group order, which some verifiers
 * insist on and none object to.
 */
static int secp256k1_sign(const u8 priv[32], const char *msg, size_t msg_len,
			  u8 sig_out[64])
{
	EVP_PKEY *pkey;
	EVP_MD_CTX *md_ctx = NULL;
	ECDSA_SIG *sig = NULL;
	const BIGNUM *r, *s;
	BIGNUM *order = NULL, *half = NULL, *low_s = NULL;
	u8 *der = NULL;
	const u8 *der_pos;
	size_t der_len = 0;
	int ret = -1;

	pkey = secp256k1_key(priv);
	if (!pkey) {
		wpa_printf(MSG_ERROR, "EAP-DID: secp256k1 key load failed");
		return -1;
	}

	md_ctx = EVP_MD_CTX_new();
	if (!md_ctx)
		goto out;

	if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha256(), NULL, pkey) != 1 ||
	    EVP_DigestSign(md_ctx, NULL, &der_len,
			   (const u8 *) msg, msg_len) != 1)
		goto out;

	der = os_malloc(der_len);
	if (!der ||
	    EVP_DigestSign(md_ctx, der, &der_len, (const u8 *) msg,
			   msg_len) != 1)
		goto out;

	der_pos = der;
	sig = d2i_ECDSA_SIG(NULL, &der_pos, der_len);
	if (!sig)
		goto out;
	ECDSA_SIG_get0(sig, &r, &s);

	order = BN_new();
	half = BN_new();
	low_s = BN_new();
	if (!order || !half || !low_s ||
	    !BN_hex2bn(&order,
		       "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141") ||
	    !BN_rshift1(half, order))
		goto out;

	if (BN_cmp(s, half) > 0) {
		if (!BN_sub(low_s, order, s))
			goto out;
	} else if (!BN_copy(low_s, s)) {
		goto out;
	}

	if (BN_bn2binpad(r, sig_out, 32) != 32 ||
	    BN_bn2binpad(low_s, sig_out + 32, 32) != 32)
		goto out;

	ret = 0;

out:
	BN_free(low_s);
	BN_free(half);
	BN_free(order);
	ECDSA_SIG_free(sig);
	os_free(der);
	EVP_MD_CTX_free(md_ctx);
	EVP_PKEY_free(pkey);

	return ret;
}


/* VP JWT creation */

/*
 * Build the VP JWT.
 *
 * The presentation is issued by the DID the credential was issued to, which
 * is what the verifier resolves to check the signature and what holder
 * binding compares against the "sub" of the credential. For an Identus
 * issued credential that is a did:prism, published or not, whose
 * authentication key is secp256k1, so the presentation is signed ES256K. The
 * did:peer of the DIDComm layer is only used when no such key is configured.
 *
 * Structure:
 *   header: {"kid":"<issuer did>#<key>","typ":"JWT","alg":"ES256K"}
 *   payload: {
 *     "iss": "<issuer did>",
 *     "aud": "<audience>",
 *     "nonce": "<nonce>",
 *     "jti": "<unique identifier>",
 *     "iat": <issued at>,
 *     "exp": <expiry>,
 *     "vp": {
 *       "@context": ["https://www.w3.org/2018/presentations/v1"],
 *       "type": ["VerifiablePresentation"],
 *       "verifiableCredential": ["<vc_jwt>"]
 *     }
 *   }
 *   signature: ES256K(header.payload)
 *
 * The nonce and the audience come from the request, which is what ties the
 * presentation to one authentication. jti and the validity window narrow it
 * further: a verifier that keeps the identifiers it has seen can refuse a
 * second showing outright, and one that does not still only has a few minutes
 * in which the presentation means anything.
 *
 * Output: "header.payload.signature" (base64url-encoded parts)
 */
int did_vp_create(const struct did_credential *cred,
		  const char *audience,
		  const char *nonce,
		  char *out, size_t *out_cap)
{
	/* Identity the presentation is issued under */
	int es256k = cred->has_secp256k1 && cred->subject_did[0];
	const char *iss = es256k ? cred->subject_did : cred->holder_did;

	/* JWT header — dynamic because kid names the signing key */
	char header_json[1280];
	int header_json_len;
	char header_b64[DID_VP_HEADER_B64_LEN];
	size_t header_b64_len = sizeof(header_b64);

	/*
	 * The payload carries the whole credential and the signing input
	 * carries the payload again encoded, so between them they are some
	 * thirty kilobytes. On the heap: this used to be one 34 kB stack
	 * frame, which the main stack survives and a thread stack would not.
	 */
	char *payload = NULL;
	int payload_len;
	char *payload_b64 = NULL;
	size_t payload_b64_len = DID_VP_PAYLOAD_B64_LEN;
	char *signing_input = NULL;
	size_t si_len;
	int res = -1;

	/* Signature */
	u8 sig_raw[64];
	char sig_b64[128];
	size_t sig_b64_len = sizeof(sig_b64);

	/* Identity and validity window of this presentation */
	u8 jti_raw[16];
	char jti[64];
	size_t jti_len = sizeof(jti);
	struct os_time now;

	if (!es256k && !cred->has_ed25519) {
		wpa_printf(MSG_ERROR, "EAP-DID: no key to sign the VP with");
		return -1;
	}

	payload = os_malloc(DID_VP_PAYLOAD_LEN);
	payload_b64 = os_malloc(DID_VP_PAYLOAD_B64_LEN);
	signing_input = os_malloc(DID_VP_SIGNING_INPUT_LEN);
	if (!payload || !payload_b64 || !signing_input) {
		wpa_printf(MSG_ERROR, "EAP-DID: no memory to build the VP");
		goto out;
	}

	/* Build header JSON naming the key that signs it */
	if (es256k)
		header_json_len = os_snprintf(header_json,
			sizeof(header_json),
			"{\"kid\":\"%s#%s\",\"typ\":\"JWT\",\"alg\":\"ES256K\"}",
			cred->subject_did,
			cred->prism_key_id[0] ? cred->prism_key_id : "authKey");
	else
		header_json_len = os_snprintf(header_json,
			sizeof(header_json),
			"{\"kid\":\"%s\",\"typ\":\"JWT\",\"alg\":\"EdDSA\"}",
			cred->holder_did);
	if (header_json_len < 0 ||
	    (size_t) header_json_len >= sizeof(header_json)) {
		wpa_printf(MSG_ERROR, "EAP-DID: VP header too large");
		goto out;
	}

	/* Encode header */
	if (b64url_encode((const u8 *) header_json,
			  header_json_len,
			  header_b64, &header_b64_len) != 0) {
		wpa_printf(MSG_ERROR, "EAP-DID: VP header b64url failed");
		goto out;
	}

	if (os_get_random(jti_raw, sizeof(jti_raw)) < 0 ||
	    b64url_encode(jti_raw, sizeof(jti_raw), jti, &jti_len) != 0) {
		wpa_printf(MSG_ERROR, "EAP-DID: Could not build the VP jti");
		goto out;
	}
	os_get_time(&now);

	/* Build payload JSON */
	payload_len = os_snprintf(payload, DID_VP_PAYLOAD_LEN,
		"{"
		"\"iss\":\"%s\","
		"\"aud\":\"%s\","
		"\"nonce\":\"%s\","
		"\"jti\":\"urn:uuid:%s\","
		"\"iat\":%ld,"
		"\"exp\":%ld,"
		"\"vp\":{"
		"\"@context\":[\"https://www.w3.org/2018/presentations/v1\"],"
		"\"type\":[\"VerifiablePresentation\"],"
		"\"verifiableCredential\":[\"%s\"]"
		"}"
		"}",
		iss,
		audience ? audience : "domain.com",
		nonce ? nonce : "",
		jti,
		(long) now.sec,
		(long) now.sec + DID_VP_LIFETIME,
		cred->vc_jwt);

	if (payload_len < 0 || (size_t) payload_len >= DID_VP_PAYLOAD_LEN) {
		wpa_printf(MSG_ERROR, "EAP-DID: VP payload too large (%d)",
			   payload_len);
		goto out;
	}

	/* Encode payload */
	payload_b64_len = DID_VP_PAYLOAD_B64_LEN;
	if (b64url_encode((const u8 *) payload, payload_len,
			  payload_b64, &payload_b64_len) != 0) {
		wpa_printf(MSG_ERROR, "EAP-DID: VP payload b64url failed");
		goto out;
	}

	/* Build signing input: header.payload */
	si_len = os_snprintf(signing_input, DID_VP_SIGNING_INPUT_LEN,
			     "%s.%s", header_b64, payload_b64);
	if (si_len >= DID_VP_SIGNING_INPUT_LEN) {
		wpa_printf(MSG_ERROR, "EAP-DID: signing input overflow");
		goto out;
	}

	if (es256k) {
		if (secp256k1_sign(cred->secp256k1_priv, signing_input, si_len,
				   sig_raw) != 0) {
			wpa_printf(MSG_ERROR, "EAP-DID: ES256K sign failed");
			goto out;
		}
	} else if (ed25519_sign(cred->ed25519_priv, signing_input, si_len,
				sig_raw) != 0) {
		wpa_printf(MSG_ERROR, "EAP-DID: EdDSA sign failed");
		goto out;
	}

	/* Encode signature */
	sig_b64_len = sizeof(sig_b64);
	if (b64url_encode(sig_raw, 64, sig_b64, &sig_b64_len) != 0) {
		wpa_printf(MSG_ERROR, "EAP-DID: signature b64url failed");
		goto out;
	}

	/* Assemble final JWT */
	{
		size_t total = header_b64_len + 1 + payload_b64_len + 1 +
			       sig_b64_len + 1;
		if (total > *out_cap) {
			wpa_printf(MSG_ERROR, "EAP-DID: VP output overflow "
				   "(%zu > %zu)", total, *out_cap);
			goto out;
		}
		*out_cap = os_snprintf(out, *out_cap, "%s.%s.%s",
				       header_b64, payload_b64, sig_b64);
	}

	wpa_printf(MSG_DEBUG, "EAP-DID: VP created (%zu bytes, %s, iss=%s)",
		   *out_cap, es256k ? "ES256K" : "EdDSA", iss);
	res = 0;

out:
	bin_clear_free(payload, DID_VP_PAYLOAD_LEN);
	os_free(payload_b64);
	os_free(signing_input);

	return res;
}

/* Credential loading from files / env vars */

static int read_file(const char *path, char *buf, size_t *buf_cap)
{
	FILE *f;
	size_t n;

	f = fopen(path, "r");
	if (!f)
		return -1;
	n = fread(buf, 1, *buf_cap - 1, f);
	fclose(f);
	if (n == 0) {
		return -1;
	}
	/* Strip trailing whitespace/newlines */
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' ||
			 buf[n - 1] == ' ' || buf[n - 1] == '\t'))
		n--;
	buf[n] = '\0';
	*buf_cap = n;
	return 0;
}

/*
 * Decode a base64url string into a fixed-size byte buffer.
 * Returns 0 on success (and sets *out_len), -1 on error.
 */
static int b64url_to_bytes(const char *src, size_t src_len,
			   u8 *out, size_t out_cap, size_t *out_len)
{
	unsigned char *dec;
	size_t dec_len;

	dec = base64_url_decode(src, src_len, &dec_len);
	if (!dec || dec_len > out_cap) {
		free(dec);
		return -1;
	}
	os_memcpy(out, dec, dec_len);
	*out_len = dec_len;
	free(dec);
	return 0;
}

/*
 * Refuse a private key that anyone but its owner can read. An environment
 * variable was the other way of supplying these, and it is readable in
 * /proc/<pid>/environ, inherited by every child and visible in ps e; a file
 * only keeps the key private if its mode says so.
 */
static int private_file_mode_ok(const char *path)
{
	struct stat st;

	if (stat(path, &st) != 0)
		return -1;

	if (st.st_mode & (S_IRWXG | S_IRWXO)) {
		wpa_printf(MSG_ERROR,
			   "EAP-DID: refusing private key %s: mode %04o is readable beyond its owner",
			   path, (unsigned int) (st.st_mode & 07777));
		return -1;
	}

	return 0;
}


/*
 * Load a 32-byte base64url key from the file named by @env_file_name.
 */
static int load_key32(const char *env_file_name, u8 out[32])
{
	const char *path;
	char key_str[128];
	size_t cap = sizeof(key_str);
	size_t dec_len;
	int res = -1;

	path = getenv(env_file_name);
	if (!path || !path[0])
		return -1;

	if (private_file_mode_ok(path) < 0)
		return -1;

	if (read_file(path, key_str, &cap) == 0 &&
	    b64url_to_bytes(key_str, cap, out, 32, &dec_len) == 0 &&
	    dec_len == 32)
		res = 0;

	forced_memzero(key_str, sizeof(key_str));

	return res;
}

/*
 * Read the "sub" of the credential, which names the DID it was issued to.
 * Taking it from the credential rather than from the environment means the
 * presentation cannot end up claiming an identity the credential does not
 * carry, which is exactly what holder binding checks.
 */
static int subject_from_credential(struct did_credential *cred)
{
	const char *first, *second;
	u8 *payload;
	size_t payload_len = 0;
	int res;

	first = os_strchr(cred->vc_jwt, '.');
	if (!first)
		return -1;
	second = os_strchr(first + 1, '.');
	if (!second)
		return -1;

	payload = base64_url_decode(first + 1, second - first - 1,
				    &payload_len);
	if (!payload)
		return -1;

	res = did_json_extract_str((const char *) payload, payload_len, "sub",
				   cred->subject_did,
				   sizeof(cred->subject_did));
	bin_clear_free(payload, payload_len);

	return res;
}


int did_credential_load(struct did_credential *cred)
{
	const char *val;
	int loaded = 0;

	os_memset(cred, 0, sizeof(*cred));

	/* --- VC JWT --- */
	val = getenv("DID_CREDENTIAL_FILE");
	if (val) {
		size_t cap = sizeof(cred->vc_jwt);
		if (read_file(val, cred->vc_jwt, &cap) == 0) {
			cred->vc_jwt_len = cap;
			loaded = 1;
		}
	}
	if (!loaded) {
		val = getenv("DID_CREDENTIAL");
		if (val && val[0]) {
			os_strlcpy(cred->vc_jwt, val, sizeof(cred->vc_jwt));
			cred->vc_jwt_len = os_strlen(cred->vc_jwt);
			loaded = 1;
		}
	}
	if (!loaded) {
		static const char default_vc[] =
			"/etc/wpa_supplicant/credential.jwt";
		size_t cap = sizeof(cred->vc_jwt);
		if (read_file(default_vc, cred->vc_jwt, &cap) == 0) {
			cred->vc_jwt_len = cap;
			loaded = 1;
		}
	}

	if (!loaded) {
		wpa_printf(MSG_INFO, "EAP-DID: no credential configured "
			   "(set DID_CREDENTIAL or DID_CREDENTIAL_FILE)");
		return -1;
	}

	/* --- Holder DID --- */
	val = getenv("DID_HOLDER_DID");
	if (val && val[0]) {
		os_strlcpy(cred->holder_did, val, sizeof(cred->holder_did));
	}

	/* --- Credential subject and its authentication key --- */
	if (subject_from_credential(cred) < 0)
		wpa_printf(MSG_INFO,
			   "EAP-DID: credential carries no subject DID");

	val = getenv("DID_PRISM_KEY_ID");
	os_strlcpy(cred->prism_key_id, val && val[0] ? val : "authKey",
		   sizeof(cred->prism_key_id));

	if (load_key32("DID_SECP256K1_PRIV_FILE",
		       cred->secp256k1_priv) == 0) {
		cred->has_secp256k1 = 1;
		wpa_printf(MSG_DEBUG, "EAP-DID: secp256k1 key loaded");
	} else if (cred->subject_did[0]) {
		wpa_printf(MSG_INFO,
			   "EAP-DID: no secp256k1 key configured; the presentation will be issued by %s instead of the credential subject",
			   cred->holder_did[0] ? cred->holder_did : "nobody");
	}

	/* --- Ed25519 private key (VP signing) --- */
	if (load_key32("DID_ED25519_KEY_FILE", cred->ed25519_priv) == 0) {
		cred->has_ed25519 = 1;
		wpa_printf(MSG_DEBUG, "EAP-DID: Ed25519 key loaded");
	} else {
		wpa_printf(MSG_INFO, "EAP-DID: no Ed25519 key configured "
			   "(set DID_ED25519_KEY_FILE)");
	}

	/* --- X25519 keypair (JWE authcrypt) --- */
	{
		const char *fpath = getenv("DID_X25519_KEY_FILE");
		char json_buf[1024];
		char b64[128];
		size_t json_len = sizeof(json_buf);
		size_t dec_len;

		if (!fpath || !fpath[0])
			fpath = "/etc/wpa_supplicant/holder_keys.json";

		if (private_file_mode_ok(fpath) == 0 &&
		    read_file(fpath, json_buf, &json_len) == 0 &&
		    did_json_extract_str(json_buf, json_len, "x25519_priv",
					 b64, sizeof(b64)) == 0 &&
		    b64url_to_bytes(b64, os_strlen(b64), cred->x25519_priv, 32,
				    &dec_len) == 0 && dec_len == 32 &&
		    did_json_extract_str(json_buf, json_len, "x25519_pub",
					 b64, sizeof(b64)) == 0 &&
		    b64url_to_bytes(b64, os_strlen(b64), cred->x25519_pub, 32,
				    &dec_len) == 0 && dec_len == 32)
			cred->has_x25519 = 1;

		forced_memzero(json_buf, sizeof(json_buf));
		forced_memzero(b64, sizeof(b64));
	}

	if (cred->has_x25519)
		wpa_printf(MSG_DEBUG, "EAP-DID: X25519 keypair loaded");
	else
		wpa_printf(MSG_INFO, "EAP-DID: no X25519 keypair configured "
			   "(set DID_X25519_KEY_FILE)");

	/* --- Trusted Verifier DID --- */
	val = getenv("DID_TRUSTED_VERIFIER_DID");
	if (val && val[0])
		os_strlcpy(cred->trusted_verifier_did, val,
			   sizeof(cred->trusted_verifier_did));

	wpa_printf(MSG_DEBUG, "EAP-DID: credential loaded "
		   "(vc=%zuB, did=%s, ed25519=%d, x25519=%d)",
		   cred->vc_jwt_len,
		   cred->holder_did[0] ? cred->holder_did : "(none)",
		   cred->has_ed25519, cred->has_x25519);

	return 0;
}
