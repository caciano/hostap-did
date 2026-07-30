/*
 * EAP-DID: Shared routines between server and peer
 * Copyright (c) 2024-2026, Caciano Machado
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "eap_did_common.h"

#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>


/*
 * HKDF-SHA256 (RFC 5869) with the CEK as input keying material, the thid as
 * salt and the label as info:
 *
 *   PRK = HMAC-SHA256(salt = thid, IKM = CEK)                    (extract)
 *   T(0) = empty string
 *   T(n) = HMAC-SHA256(PRK, T(n-1) | label | n)                  (expand)
 *   OKM  = first out_len octets of T(1) | T(2) | ...
 *
 * Feeding T(n-1) back in is what makes the blocks a chain rather than
 * independent PRF outputs, and it is the part section 2.3 of the RFC actually
 * specifies. Leaving it out still yields a pseudorandom string, so nothing
 * observable breaks, but the result is not HKDF and does not match any other
 * implementation.
 */
u8 * eap_did_derive_key_cek(const u8 *cek, size_t cek_len, const char *thid,
			    const char *label, size_t out_len)
{
	u8 prk[SHA256_DIGEST_LENGTH];
	u8 prev[SHA256_DIGEST_LENGTH];
	size_t prev_len = 0;
	u8 *okm;
	unsigned int md_len = SHA256_DIGEST_LENGTH;
	u8 counter = 1;
	size_t done = 0, label_len;

	if (!cek || cek_len == 0 || !thid || !label || out_len == 0)
		return NULL;

	label_len = os_strlen(label);
	if (label_len == 0 || label_len > 254)
		return NULL;

	/* The block counter is a single octet, so at most 255 blocks exist */
	if (out_len > 255 * SHA256_DIGEST_LENGTH)
		return NULL;

	if (!HMAC(EVP_sha256(), thid, os_strlen(thid), cek, cek_len, prk,
		  &md_len))
		return NULL;

	okm = os_malloc(out_len);
	if (!okm) {
		forced_memzero(prk, sizeof(prk));
		return NULL;
	}

	while (done < out_len) {
		u8 input[SHA256_DIGEST_LENGTH + 255];
		u8 t[SHA256_DIGEST_LENGTH];
		size_t input_len = 0;
		size_t copy;

		/* T(n) = HMAC(PRK, T(n-1) | label | n); T(0) is empty */
		os_memcpy(input, prev, prev_len);
		input_len = prev_len;
		os_memcpy(input + input_len, label, label_len);
		input_len += label_len;
		input[input_len++] = counter;

		if (!HMAC(EVP_sha256(), prk, SHA256_DIGEST_LENGTH, input,
			  input_len, t, &md_len)) {
			forced_memzero(input, sizeof(input));
			forced_memzero(prev, sizeof(prev));
			bin_clear_free(okm, out_len);
			forced_memzero(prk, sizeof(prk));
			return NULL;
		}
		forced_memzero(input, sizeof(input));

		copy = out_len - done < md_len ? out_len - done : md_len;
		os_memcpy(okm + done, t, copy);

		/* Carried into the next block, so it outlives t */
		os_memcpy(prev, t, md_len);
		prev_len = md_len;

		forced_memzero(t, sizeof(t));
		done += copy;
		counter++;
	}

	forced_memzero(prev, sizeof(prev));
	forced_memzero(prk, sizeof(prk));

	return okm;
}


u8 * eap_did_session_id(u8 eap_type, const char *thid, size_t *len)
{
	u8 *sid;

	if (!thid || !len)
		return NULL;

	sid = os_malloc(1 + SHA256_DIGEST_LENGTH);
	if (!sid)
		return NULL;

	sid[0] = eap_type;
	SHA256((const u8 *) thid, os_strlen(thid), sid + 1);
	*len = 1 + SHA256_DIGEST_LENGTH;

	return sid;
}


void eap_did_key_id(const char *did, char *buf, size_t buf_len)
{
	const char *pos;
	int n = 0;

	pos = did ? os_strchr(did, '.') : NULL;
	while (pos) {
		const char *next;

		pos++;
		/* Only key segments are numbered; 'S' holds services */
		if (*pos && os_strchr("AEVID", *pos)) {
			n++;
			if (*pos == 'E') {
				os_snprintf(buf, buf_len, "%s#key-%d", did, n);
				return;
			}
		}
		next = os_strchr(pos, '.');
		pos = next;
	}

	wpa_printf(MSG_INFO, "EAP-DID: No key agreement segment in %s",
		   did ? did : "");
	os_snprintf(buf, buf_len, "%s#key-1", did ? did : "");
}


/* Decode base58btc, the multibase encoding used inside did:peer:2 */
static int did_b58_decode(const char *in, size_t in_len, u8 *out,
			      size_t *out_len)
{
	static const char alphabet[] =
		"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
	u8 *buf;
	size_t buf_len, zeros = 0, start, i, j;

	while (zeros < in_len && in[zeros] == '1')
		zeros++;

	/* log(58) / log(256) is about 0.733 */
	buf_len = in_len * 733 / 1000 + 1;
	buf = os_zalloc(buf_len);
	if (!buf)
		return -1;

	for (i = 0; i < in_len; i++) {
		const char *p = os_strchr(alphabet, in[i]);
		int carry;

		if (!p) {
			os_free(buf);
			return -1;
		}
		carry = p - alphabet;

		for (j = buf_len; j > 0; j--) {
			carry += buf[j - 1] * 58;
			buf[j - 1] = carry & 0xff;
			carry >>= 8;
		}

		/*
		 * buf_len is an upper bound on the decoded length, so a carry
		 * left over here means the input was longer than the estimate
		 * and the high octets have been dropped. Silently returning a
		 * truncated key is worse than failing.
		 */
		if (carry) {
			os_free(buf);
			return -1;
		}
	}

	for (start = 0; start < buf_len && buf[start] == 0; start++)
		;

	if (zeros + buf_len - start > *out_len) {
		os_free(buf);
		return -1;
	}

	os_memset(out, 0, zeros);
	os_memcpy(out + zeros, buf + start, buf_len - start);
	*out_len = zeros + buf_len - start;
	os_free(buf);

	return 0;
}


/*
 * Pull the key agreement key out of a did:peer:2. The DID is a sequence of
 * dot separated segments, each introduced by a purpose code: 'A' assertion,
 * 'E' key agreement, 'V' verification, 'I' capability invocation, 'D'
 * capability delegation and 'S' service. The key agreement material sits in
 * the 'E' segment as multibase base58btc over a multicodec prefixed key.
 */
int did_x25519_from_did(const char *did, u8 *pub)
{
	const char *pos;

	pos = did ? os_strchr(did, '.') : NULL;
	if (!pos) {
		wpa_printf(MSG_INFO, "EAP-DID: No segments in DID '%s'",
			   did ? did : "");
		return -1;
	}

	pos++;
	while (*pos) {
		const char *next = os_strchr(pos, '.');
		size_t seg_len = next ? (size_t) (next - pos) : os_strlen(pos);
		u8 key[64];
		size_t key_len = sizeof(key);

		if (seg_len < 2 || pos[0] != 'E' || pos[1] != 'z') {
			if (!next)
				break;
			pos = next + 1;
			continue;
		}

		if (did_b58_decode(pos + 2, seg_len - 2, key,
				       &key_len) < 0 || key_len != 34) {
			wpa_printf(MSG_INFO,
				   "EAP-DID: Could not decode key agreement segment");
			return -1;
		}

		/*
		 * Only X25519. An Ed25519 key here used to be converted
		 * birationally, which took a signing key from an identifier
		 * the peer supplies and made an encryption key out of it.
		 */
		if (key[0] != 0xec || key[1] != 0x01) {
			wpa_printf(MSG_INFO,
				   "EAP-DID: Unsupported key agreement multicodec %02x%02x",
				   key[0], key[1]);
			return -1;
		}

		os_memcpy(pub, key + 2, 32);

		return 0;
	}

	wpa_printf(MSG_INFO, "EAP-DID: No key agreement segment in DID");

	return -1;
}
