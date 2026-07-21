/*
 * EAP-DID common functions shared between server and peer
 *
 * Key derivation, thid extraction, session ID generation.
 *
 * Issue #16: Transcript hash for key confirmation.
 * Issue #18: AES-GCM VP encryption.
 */

#include "includes.h"
#include "common.h"
#include "eap_common/eap_did_common.h"
#include "wpabuf.h"

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>

/* -----------------------------------------------------------------------
 * Key derivation — HKDF-SHA256 over thid (extract+expand)
 *
 * Extract step uses an empty salt (matching the original implementation).
 * Expand step uses counter-mode HMAC with the given label as info.
 *
 * NOTE: the empty-salt extract should be reviewed in the security
 * audit (issue #13).  It works because thid carries enough entropy
 * for the testbed, but may need strengthening for production.
 * ----------------------------------------------------------------------- */

u8 *eap_did_derive_key(const char *thid, const char *label, size_t out_len)
{
	u8 prk[SHA256_DIGEST_LENGTH];
	u8 *okm;
	unsigned int md_len = SHA256_DIGEST_LENGTH;
	u8 counter = 1;
	size_t done = 0;

	if (!thid || !label || out_len == 0)
		return NULL;

	/* Extract: PRK = HMAC-SHA256(salt="", IKM=thid) */
	HMAC(EVP_sha256(), "", 0,
	     (const unsigned char *)thid, strlen(thid),
	     prk, &md_len);

	okm = os_malloc(out_len);
	if (!okm)
		return NULL;

	/* Expand: RFC 5869 §2.3
	 * T(0) = empty
	 * T(N) = HMAC-SHA256(PRK, T(N-1) | info | N)
	 * OKM = first L octets of T(1) | T(2) | ... | T(N)
	 */
	u8 t_prev[SHA256_DIGEST_LENGTH];
	size_t t_prev_len = 0;

	while (done < out_len) {
		u8 info_buf[256 + SHA256_DIGEST_LENGTH];
		u8 hmac_out[SHA256_DIGEST_LENGTH];
		size_t info_len = 0;
		size_t copy;

		/* Prepend T(N-1) if available (RFC 5869 chaining) */
		if (t_prev_len > 0) {
			os_memcpy(info_buf, t_prev, t_prev_len);
			info_len = t_prev_len;
		}

		/* Append label || counter */
		{
			size_t label_len = strlen(label);
			if (info_len + label_len + 1 > sizeof(info_buf)) {
				os_free(okm);
				return NULL;
			}
			os_memcpy(info_buf + info_len, label, label_len);
			info_len += label_len;
			info_buf[info_len++] = counter;
		}

		HMAC(EVP_sha256(), prk, SHA256_DIGEST_LENGTH,
		     info_buf, info_len, hmac_out, &md_len);

		/* Save T(N) for next iteration */
		os_memcpy(t_prev, hmac_out, SHA256_DIGEST_LENGTH);
		t_prev_len = SHA256_DIGEST_LENGTH;

		copy = (out_len - done < md_len) ? (out_len - done) : md_len;
		os_memcpy(okm + done, hmac_out, copy);
		done += copy;
		counter++;
	}

	return okm;
}


/*
 * CEK-based key derivation (Issue #27)
 *
 * Uses CEK from DIDComm JWE (ECDH-ES output) as IKM and thid as salt.
 * The thid is observable on the EAP channel but the CEK never traverses it.
 *
 * MSK  = HKDF-SHA256(IKM=CEK, salt=thid, info="EAP-DID-MSK",  L=64)
 * EMSK = HKDF-SHA256(IKM=CEK, salt=thid, info="EAP-DID-EMSK", L=64)
 */
u8 *eap_did_derive_key_cek(const u8 *cek, size_t cek_len,
			   const char *thid, const char *label,
			   size_t out_len)
{
	u8 prk[SHA256_DIGEST_LENGTH];
	u8 *okm;
	unsigned int md_len = SHA256_DIGEST_LENGTH;
	u8 counter = 1;
	size_t done = 0;

	if (!cek || cek_len == 0 || !thid || !label || out_len == 0)
		return NULL;

	/* Extract: PRK = HMAC-SHA256(salt=thid, IKM=CEK) */
	HMAC(EVP_sha256(), thid, strlen(thid),
	     cek, cek_len, prk, &md_len);

	okm = os_malloc(out_len);
	if (!okm)
		return NULL;

	/* Expand: T(n) = HMAC-SHA256(PRK, T(n-1) | info | n) */
	while (done < out_len) {
		u8 info_buf[256];
		u8 hmac_out[SHA256_DIGEST_LENGTH];
		size_t info_len;
		size_t copy;

		info_len = strlen(label);
		if (info_len > sizeof(info_buf) - 1) {
			os_free(okm);
			return NULL;
		}
		os_memcpy(info_buf, label, info_len);
		info_buf[info_len++] = counter;

		HMAC(EVP_sha256(), prk, SHA256_DIGEST_LENGTH,
		     info_buf, info_len, hmac_out, &md_len);

		copy = (out_len - done < md_len) ? (out_len - done) : md_len;
		os_memcpy(okm + done, hmac_out, copy);
		done += copy;
		counter++;
	}

	return okm;
}

/* -----------------------------------------------------------------------
 * Session ID derivation — type byte || SHA256(thid)
 * ----------------------------------------------------------------------- */

u8 *eap_did_get_session_id(u8 eap_type, const char *thid, size_t *len)
{
	u8 *sid;

	if (!thid || !len)
		return NULL;

	sid = os_malloc(1 + SHA256_DIGEST_LENGTH);
	if (!sid)
		return NULL;

	sid[0] = eap_type;
	SHA256((const unsigned char *)thid, strlen(thid), sid + 1);
	*len = 1 + SHA256_DIGEST_LENGTH;
	return sid;
}


/* -----------------------------------------------------------------------
 * Issue #18: AES-256-GCM encrypt/decrypt for VP protection
 * ----------------------------------------------------------------------- */

int eap_did_aes_gcm_encrypt(const u8 *key, const u8 *iv,
			    const u8 *plaintext, size_t pt_len,
			    const u8 *aad, size_t aad_len,
			    u8 *ct, u8 *tag)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int ct_len;

	if (!key || !iv || !plaintext || !ct || !tag)
		return -1;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return -1;

	if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
		goto err;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
		goto err;

	if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
		goto err;

	/* Add AAD if provided */
	if (aad && aad_len > 0) {
		if (EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
			goto err;
	}

	if (EVP_EncryptUpdate(ctx, ct, &len, plaintext, (int)pt_len) != 1)
		goto err;
	ct_len = len;

	if (EVP_EncryptFinal_ex(ctx, ct + len, &len) != 1)
		goto err;
	ct_len += len;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
		goto err;

	EVP_CIPHER_CTX_free(ctx);
	(void)ct_len;
	return 0;

err:
	EVP_CIPHER_CTX_free(ctx);
	return -1;
}

int eap_did_aes_gcm_decrypt(const u8 *key, const u8 *iv,
			    const u8 *ct, size_t ct_len,
			    const u8 *aad, size_t aad_len,
			    const u8 *tag, u8 *pt)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	int pt_len;

	if (!key || !iv || !ct || !tag || !pt)
		return -1;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx)
		return -1;

	if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
		goto err;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
		goto err;

	if (EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
		goto err;

	/* Add AAD if provided */
	if (aad && aad_len > 0) {
		if (EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) != 1)
			goto err;
	}

	if (EVP_DecryptUpdate(ctx, pt, &len, ct, (int)ct_len) != 1)
		goto err;
	pt_len = len;

	if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
				(void *)tag) != 1)
		goto err;

	if (EVP_DecryptFinal_ex(ctx, pt + len, &len) != 1)
		goto err;
	pt_len += len;

	EVP_CIPHER_CTX_free(ctx);
	(void)pt_len;
	return 0;

err:
	EVP_CIPHER_CTX_free(ctx);
	return -1;
}

/* -----------------------------------------------------------------------
 * Convenience wrappers for key derivation
 * ----------------------------------------------------------------------- */

u8 *eap_did_get_msk(const char *thid, size_t *len)
{
	if (!thid || !len)
		return NULL;
	*len = 64;
	return eap_did_derive_key(thid, "EAP-DID-MSK", 64);
}

u8 *eap_did_get_emsk(const char *thid, size_t *len)
{
	if (!thid || !len)
		return NULL;
	*len = 64;
	return eap_did_derive_key(thid, "EAP-DID-EMSK", 64);
}
