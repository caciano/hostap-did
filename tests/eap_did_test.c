/*
 * Unit tests for EAP-DID common functions (did5)
 * Copyright (c) 2025-2026, Caciano Machado
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * Tests key derivation, session ID, gzip, JSON extraction, did:peer:2 key
 * agreement segments, JWE authcrypt/authdecrypt and flags byte encoding.
 *
 * No network, no Identus, no sockets. Pure logic.
 */

#include "includes.h"

#include "common.h"
#include "wpabuf.h"
#include "crypto/crypto.h"

#include "eap_common/eap_did_common.h"
#include "eap_common/eap_did_http.h"
#include "eap_common/eap_did_jwe.h"

#include <openssl/evp.h>
#include <openssl/rand.h>


/* ------------------------------------------------------------------ */
/* Test framework                                                     */
/* ------------------------------------------------------------------ */

static int tests_run = 0;
static int tests_pass = 0;
static int tests_fail = 0;

#define TEST(name) do { \
	printf("  [RUN] %-44s ", name); \
	fflush(stdout); \
	tests_run++; \
} while (0)

#define PASS() do { printf("OK\n"); tests_pass++; } while (0)

#define FAIL(fmt, ...) do { \
	printf("FAIL\n      " fmt "\n", ##__VA_ARGS__); \
	tests_fail++; \
} while (0)


/* ================================================================== */
/* 1. Key derivation from the content encryption key                  */
/* ================================================================== */

static void test_cek_key_derivation_deterministic(void)
{
	TEST("cek_key_derivation_deterministic");

	u8 cek[DID_JWE_CEK_LEN];
	u8 *k1, *k2;

	for (size_t i = 0; i < sizeof(cek); i++)
		cek[i] = i ^ 0x55;

	k1 = eap_did_derive_key_cek(cek, sizeof(cek), "thid-cek",
				    "EAP-DID-MSK", 64);
	k2 = eap_did_derive_key_cek(cek, sizeof(cek), "thid-cek",
				    "EAP-DID-MSK", 64);

	if (!k1 || !k2) { FAIL("NULL"); goto out; }
	if (os_memcmp(k1, k2, 64) != 0) { FAIL("non-deterministic"); goto out; }

	PASS();
out:
	os_free(k1);
	os_free(k2);
}


static void test_cek_key_derivation_labels(void)
{
	TEST("cek_key_derivation_msk_differs_from_emsk");

	u8 cek[DID_JWE_CEK_LEN];
	u8 *msk, *emsk;

	os_memset(cek, 0xAB, sizeof(cek));

	msk = eap_did_derive_key_cek(cek, sizeof(cek), "thid",
				     "EAP-DID-MSK", 64);
	emsk = eap_did_derive_key_cek(cek, sizeof(cek), "thid",
				      "EAP-DID-EMSK", 64);

	if (!msk || !emsk) { FAIL("NULL"); goto out; }
	if (os_memcmp(msk, emsk, 64) == 0) { FAIL("MSK == EMSK"); goto out; }

	PASS();
out:
	os_free(msk);
	os_free(emsk);
}


static void test_cek_key_derivation_different_ceks(void)
{
	TEST("cek_key_derivation_different_ceks");

	u8 cek1[DID_JWE_CEK_LEN], cek2[DID_JWE_CEK_LEN];
	u8 *k1, *k2;

	os_memset(cek1, 0x11, sizeof(cek1));
	os_memset(cek2, 0x22, sizeof(cek2));

	k1 = eap_did_derive_key_cek(cek1, sizeof(cek1), "thid", "label", 32);
	k2 = eap_did_derive_key_cek(cek2, sizeof(cek2), "thid", "label", 32);

	if (!k1 || !k2) { FAIL("NULL"); goto out; }
	if (os_memcmp(k1, k2, 32) == 0) {
		FAIL("same key for different CEKs");
		goto out;
	}

	PASS();
out:
	os_free(k1);
	os_free(k2);
}


static void test_session_id_format(void)
{
	TEST("session_id_format");

	size_t sid_len = 0;
	u8 eap_type_did = 57;
	u8 *sid = eap_did_session_id(eap_type_did, "thid-x", &sid_len);

	if (!sid) { FAIL("NULL"); return; }
	if (sid_len != 33) {
		FAIL("len=%zu expected 33", sid_len);
		goto out;
	}
	if (sid[0] != eap_type_did) {
		FAIL("first octet=%u expected %u", sid[0], eap_type_did);
		goto out;
	}

	PASS();
out:
	os_free(sid);
}


/* ================================================================== */
/* 2. gzip compress / decompress                                      */
/* ================================================================== */

static void test_gzip_roundtrip(void)
{
	TEST("gzip_roundtrip");

	const char *data =
		"Hello EAP-DID World! Test payload for compression. "
		"Repeating data helps compression ratio. "
		"Hello EAP-DID World! Test payload for compression.";
	size_t dlen = os_strlen(data);

	u8 *cout = NULL, *dout = NULL;
	size_t cout_len = 0, dout_len = 0;

	if (did_gzip_compress((const u8 *) data, dlen, &cout, &cout_len) != 0) {
		FAIL("compress failed");
		goto out;
	}

	if (did_gzip_decompress(cout, cout_len, &dout, &dout_len) != 0) {
		FAIL("decompress failed");
		goto out;
	}

	if (dout_len != dlen || os_memcmp(dout, data, dlen) != 0) {
		FAIL("roundtrip mismatch (%zu != %zu)", dout_len, dlen);
		goto out;
	}

	if (cout_len >= dlen) {
		FAIL("no compression %zu >= %zu", cout_len, dlen);
		goto out;
	}

	PASS();
out:
	os_free(cout);
	os_free(dout);
}


static void test_gzip_large(void)
{
	TEST("gzip_large_payload");

	size_t dlen = 10240;
	u8 *data = os_malloc(dlen);
	u8 *cout = NULL, *dout = NULL;
	size_t cout_len = 0, dout_len = 0;

	if (!data) { FAIL("malloc failed"); return; }

	for (size_t i = 0; i < dlen; i++)
		data[i] = (u8)(i * 7 + 13);

	if (did_gzip_compress(data, dlen, &cout, &cout_len) != 0) {
		FAIL("compress failed");
		goto out;
	}

	if (did_gzip_decompress(cout, cout_len, &dout, &dout_len) != 0) {
		FAIL("decompress failed");
		goto out;
	}

	if (dout_len != dlen || os_memcmp(dout, data, dlen) != 0) {
		FAIL("roundtrip mismatch");
		goto out;
	}

	PASS();
out:
	os_free(data);
	os_free(cout);
	os_free(dout);
}


/* ================================================================== */
/* 3. JSON extraction                                                 */
/* ================================================================== */

static void test_json_extract_basic(void)
{
	TEST("json_extract_basic");

	char buf[64];
	const char *json = "{\"thid\":\"abc-123\",\"status\":\"pending\"}";

	if (did_json_extract_str(json, os_strlen(json), "thid",
				 buf, sizeof(buf)) != 0 ||
	    os_strcmp(buf, "abc-123") != 0) {
		FAIL("thid: got '%s'", buf);
		return;
	}

	if (did_json_extract_str(json, os_strlen(json), "status",
				 buf, sizeof(buf)) != 0 ||
	    os_strcmp(buf, "pending") != 0) {
		FAIL("status: got '%s'", buf);
		return;
	}

	PASS();
}


static void test_json_extract_spaces(void)
{
	TEST("json_extract_with_spaces");

	char buf[64];
	const char *json = "{ \"key\" : \"value with spaces\" }";

	if (did_json_extract_str(json, os_strlen(json), "key",
				 buf, sizeof(buf)) != 0 ||
	    os_strcmp(buf, "value with spaces") != 0) {
		FAIL("got '%s'", buf);
		return;
	}

	PASS();
}


static void test_json_extract_missing(void)
{
	TEST("json_extract_missing_key");

	char buf[64];
	const char *json = "{\"foo\":\"bar\"}";

	if (did_json_extract_str(json, os_strlen(json), "baz",
				 buf, sizeof(buf)) == 0) {
		FAIL("should have failed");
		return;
	}

	PASS();
}


static void test_json_extract_nested(void)
{
	TEST("json_extract_nested_member");

	char buf[64];
	const char *json =
		"{\"data\":{\"jwk\":{\"kty\":\"OKP\",\"d\":\"cHJpdmF0ZQ\"}}}";

	if (did_json_extract_str(json, os_strlen(json), "d",
				 buf, sizeof(buf)) != 0 ||
	    os_strcmp(buf, "cHJpdmF0ZQ") != 0) {
		FAIL("got '%s'", buf);
		return;
	}

	PASS();
}


/* D-10: a name appearing inside another member's value is not a member */
static void test_json_extract_name_inside_value(void)
{
	TEST("json_extract_name_inside_value");

	char buf[64];
	const char *json =
		"{\"note\":\"see \\\"skid\\\":\\\"did:example:attacker#key-1\\\"\","
		"\"skid\":\"did:example:honest#key-1\"}";

	if (did_json_extract_str(json, os_strlen(json), "skid",
				 buf, sizeof(buf)) != 0) {
		FAIL("extract failed");
		return;
	}

	if (os_strcmp(buf, "did:example:honest#key-1") != 0) {
		FAIL("took the value out of another member: '%s'", buf);
		return;
	}

	PASS();
}


/* D-10: a value that does not fit is an error, not a truncated success */
static void test_json_extract_truncation_fails(void)
{
	TEST("json_extract_truncation_is_an_error");

	char buf[16];
	const char *json =
		"{\"sub\":\"did:prism:0123456789abcdef0123456789abcdef\"}";

	if (did_json_extract_str(json, os_strlen(json), "sub",
				 buf, sizeof(buf)) == 0) {
		FAIL("truncated to '%s' and reported success", buf);
		return;
	}

	PASS();
}


/* A non-string value is skipped rather than mistaken for the next member */
static void test_json_extract_skips_non_string(void)
{
	TEST("json_extract_skips_non_string_value");

	char buf[64];
	const char *json = "{\"count\":42,\"thid\":\"t-1\"}";

	if (did_json_extract_str(json, os_strlen(json), "count",
				 buf, sizeof(buf)) == 0) {
		FAIL("read a number as a string: '%s'", buf);
		return;
	}

	if (did_json_extract_str(json, os_strlen(json), "thid",
				 buf, sizeof(buf)) != 0 ||
	    os_strcmp(buf, "t-1") != 0) {
		FAIL("thid: got '%s'", buf);
		return;
	}

	PASS();
}


static void test_json_extract_unterminated(void)
{
	TEST("json_extract_unterminated_string");

	char buf[64];
	const char *json = "{\"thid\":\"abc";

	if (did_json_extract_str(json, os_strlen(json), "thid",
				 buf, sizeof(buf)) == 0) {
		FAIL("accepted an unterminated value: '%s'", buf);
		return;
	}

	PASS();
}


/*
 * D-07: the verdict has to come from the record that carries the thread, not
 * from whatever status happens to sit near it in the list.
 */
static void test_json_object_bounds_match_record(void)
{
	TEST("json_object_bounds_match_the_right_record");

	const char *body =
		"{\"contents\":["
		"{\"thid\":\"other-exchange\",\"status\":\"PresentationVerified\"},"
		"{\"thid\":\"ours\",\"status\":\"RequestReceived\"}"
		"]}";
	const char *pos = body, *end = body + os_strlen(body);
	const char *obj, *obj_end;
	char thid[64], status[64];
	int found = 0;

	/* The outer object is bounded first, so start inside the array */
	pos = os_strchr(body, '[');
	if (!pos) { FAIL("no array"); return; }

	while ((obj = did_json_next_object(pos, end, &obj_end)) != NULL) {
		pos = obj_end;

		if (did_json_extract_str(obj, obj_end - obj, "thid",
					 thid, sizeof(thid)) != 0)
			continue;
		if (os_strcmp(thid, "ours") != 0)
			continue;

		found = 1;
		if (did_json_extract_str(obj, obj_end - obj, "status",
					 status, sizeof(status)) != 0) {
			FAIL("no status in our record");
			return;
		}
		if (os_strcmp(status, "RequestReceived") != 0) {
			FAIL("read another record's verdict: '%s'", status);
			return;
		}
	}

	if (!found) {
		FAIL("our record was not reached");
		return;
	}

	PASS();
}


static void test_json_object_bounds_nested(void)
{
	TEST("json_object_bounds_skip_nested_and_strings");

	const char *body =
		"[{\"a\":{\"b\":1},\"note\":\"a } brace in a string\",\"z\":2},"
		"{\"a\":9}]";
	const char *pos = body, *end = body + os_strlen(body);
	const char *obj, *obj_end;
	char buf[64];
	int n = 0;

	while ((obj = did_json_next_object(pos, end, &obj_end)) != NULL) {
		pos = obj_end;
		n++;
		if (n != 1)
			continue;

		/*
		 * The whole first record has to be inside the bounds: a brace
		 * inside a string value must not close it, and the nested
		 * object must not close it either.
		 */
		if (did_json_extract_str(obj, obj_end - obj, "note",
					 buf, sizeof(buf)) != 0 ||
		    os_strcmp(buf, "a } brace in a string") != 0) {
			FAIL("the first record was cut short: '%s'", buf);
			return;
		}
		if (did_json_extract_str(obj, obj_end - obj, "z",
					 buf, sizeof(buf)) == 0) {
			FAIL("z is a number and was read as a string");
			return;
		}
	}

	if (n != 2) {
		FAIL("found %d objects, expected 2", n);
		return;
	}

	PASS();
}


static void test_json_object_bounds_unterminated(void)
{
	TEST("json_object_bounds_reject_unterminated");

	const char *body = "[{\"a\":1},{\"b\":2";
	const char *end = body + os_strlen(body);
	const char *obj, *obj_end;

	obj = did_json_next_object(body, end, &obj_end);
	if (!obj) { FAIL("did not find the first object"); return; }

	if (did_json_next_object(obj_end, end, &obj_end) != NULL) {
		FAIL("returned an object that never closes");
		return;
	}

	PASS();
}


/* ================================================================== */
/* 4. did:peer:2 key agreement segments (D-13, D-14)                  */
/* ================================================================== */

/* multicodec 0xec01 (X25519) over the octets 0x01..0x20, base58btc */
#define DID_SEG_X25519 "z6LSbk7MN8NDFRJBo2wkq5sYG4XonrAvuJVkS4NaaDcbD6Th"
/* the same octets under 0xed01 (Ed25519), which is a signing key */
#define DID_SEG_ED25519 "z6MkeXCES4onVW4up9Qgz1KRnZsKmGufcaZxF6Zpv2w5QwUK"
/* multicodec 0x1200 (P-256), which the method does not implement */
#define DID_SEG_P256 "zQbs4T34iVfXSTV3evo52PaQaNdTNu51gdG9m9MEShpAvt7"

static void test_did_x25519_segment(void)
{
	TEST("did_x25519_from_did_reads_E_segment");

	const char *did = "did:peer:2.V" DID_SEG_ED25519 ".E" DID_SEG_X25519;
	u8 pub[32];
	size_t i;

	if (did_x25519_from_did(did, pub) != 0) {
		FAIL("rejected a well formed key agreement segment");
		return;
	}

	for (i = 0; i < sizeof(pub); i++) {
		if (pub[i] != (u8)(i + 1)) {
			FAIL("octet %zu is %02x, expected %02zx", i, pub[i],
			     i + 1);
			return;
		}
	}

	PASS();
}


/*
 * D-13: an Ed25519 key in the key agreement slot used to be converted
 * birationally, which turned a signing key from a peer supplied identifier
 * into an encryption key.
 */
static void test_did_x25519_rejects_ed25519(void)
{
	TEST("did_x25519_from_did_rejects_ed25519");

	const char *did = "did:peer:2.E" DID_SEG_ED25519;
	u8 pub[32];

	if (did_x25519_from_did(did, pub) == 0) {
		FAIL("converted an Ed25519 key into a key agreement key");
		return;
	}

	PASS();
}


static void test_did_x25519_rejects_unknown_codec(void)
{
	TEST("did_x25519_from_did_rejects_unknown_codec");

	const char *did = "did:peer:2.E" DID_SEG_P256;
	u8 pub[32];

	if (did_x25519_from_did(did, pub) == 0) {
		FAIL("accepted multicodec 0x1200");
		return;
	}

	PASS();
}


/* D-14: a segment that does not decode to a 34 octet multicodec key */
static void test_did_x25519_rejects_short_segment(void)
{
	TEST("did_x25519_from_did_rejects_short_segment");

	const char *did = "did:peer:2.Ez4HhbrPQ7Y1Fx7SfHzNxizPfPvHLV";
	u8 pub[32];

	if (did_x25519_from_did(did, pub) == 0) {
		FAIL("accepted a segment shorter than a key");
		return;
	}

	PASS();
}


static void test_did_x25519_rejects_bad_base58(void)
{
	TEST("did_x25519_from_did_rejects_bad_base58");

	/* '0', 'O', 'I' and 'l' are not in the base58btc alphabet */
	const char *did = "did:peer:2.Ez6LSbk7MN8NDFRJBo2wkq5sYG4X0nrAvuJVkS"
			  "4NaaDcbD6Th";
	u8 pub[32];

	if (did_x25519_from_did(did, pub) == 0) {
		FAIL("accepted a segment with characters outside the alphabet");
		return;
	}

	PASS();
}


/* The V segment carries the signing key and must not be taken for one */
static void test_did_x25519_ignores_v_segment(void)
{
	TEST("did_x25519_from_did_ignores_V_segment");

	const char *did = "did:peer:2.V" DID_SEG_X25519;
	u8 pub[32];

	if (did_x25519_from_did(did, pub) == 0) {
		FAIL("read a key out of the verification segment");
		return;
	}

	PASS();
}


/* ================================================================== */
/* 5. Fragment boundary logic                                         */
/* ================================================================== */

static void test_fragment_boundaries(void)
{
	TEST("fragment_boundaries");

	int frag = EAP_DID_DEFAULT_FRAGMENT_SIZE;
	struct { int msg; int expect; } cases[] = {
		{ 0, 0 },
		{ 1, 1 },
		{ frag - 1, 1 },
		{ frag, 1 },
		{ frag + 1, 2 },
		{ frag * 2, 2 },
		{ frag * 2 + 1, 3 },
		{ frag * 5, 5 },
		{ frag * 5 + 1, 6 },
	};

	for (size_t i = 0; i < ARRAY_SIZE(cases); i++) {
		int msg = cases[i].msg;
		int actual = msg == 0 ? 0 : (msg + frag - 1) / frag;

		if (actual != cases[i].expect) {
			FAIL("msg=%d expected %d got %d",
			     msg, cases[i].expect, actual);
			return;
		}
	}

	PASS();
}


/* ================================================================== */
/* 6. JWE authcrypt and authdecrypt                                   */
/* ================================================================== */

struct did_test_keypair {
	EVP_PKEY *pkey;
	u8 priv[32];
	u8 pub[32];
};

static int did_test_keypair(struct did_test_keypair *kp)
{
	size_t len = 32;

	kp->pkey = EVP_PKEY_Q_keygen(NULL, NULL, "X25519");
	if (!kp->pkey)
		return -1;

	if (EVP_PKEY_get_raw_public_key(kp->pkey, kp->pub, &len) != 1 ||
	    len != 32)
		return -1;
	len = 32;
	if (EVP_PKEY_get_raw_private_key(kp->pkey, kp->priv, &len) != 1 ||
	    len != 32)
		return -1;

	return 0;
}


static void test_jwe_authcrypt_construction(void)
{
	TEST("jwe_authcrypt_construction");

	struct did_test_keypair recv = { 0 }, send = { 0 };
	struct did_jwe_recipient recipients[1];
	const char *plaintext =
		"{\"type\":\"https://didcomm.org/present-proof/3.0/presentation\"}";
	u8 cek[DID_JWE_CEK_LEN];
	char jwe[8192];
	size_t jwe_cap = sizeof(jwe);
	size_t i;
	int cek_nonzero = 0;

	if (did_test_keypair(&recv) || did_test_keypair(&send)) {
		FAIL("X25519 keygen failed");
		goto out;
	}

	recipients[0].x25519_pub = recv.pub;
	recipients[0].kid = "did:example:recipient#key-1";

	if (did_jwe_authcrypt(recipients, 1, send.priv, send.pub,
			      "did:example:sender#key-1",
			      (const u8 *) plaintext, os_strlen(plaintext),
			      cek, jwe, &jwe_cap) != 0) {
		FAIL("authcrypt failed");
		goto out;
	}

	if (!os_strstr(jwe, "ciphertext") || !os_strstr(jwe, "protected") ||
	    !os_strstr(jwe, "recipients")) {
		FAIL("missing a JWE member");
		goto out;
	}

	for (i = 0; i < sizeof(cek); i++) {
		if (cek[i]) {
			cek_nonzero = 1;
			break;
		}
	}
	if (!cek_nonzero) {
		FAIL("CEK is all zeros");
		goto out;
	}

	PASS();
out:
	EVP_PKEY_free(recv.pkey);
	EVP_PKEY_free(send.pkey);
}


static void test_jwe_authdecrypt_roundtrip(void)
{
	TEST("jwe_authdecrypt_roundtrip");

	struct did_test_keypair recv = { 0 }, send = { 0 };
	struct did_jwe_recipient recipients[1];
	const char *plaintext =
		"{\"type\":\"https://didcomm.atalaprism.io/present-proof/3.0/"
		"presentation\",\"thid\":\"abc-123-def\",\"attachments\":[{}]}";
	size_t pt_len = os_strlen(plaintext);
	u8 cek_enc[DID_JWE_CEK_LEN], cek_dec[DID_JWE_CEK_LEN];
	u8 wrong_priv[32];
	u8 pt_dec[1024];
	size_t pt_dec_len = sizeof(pt_dec);
	char jwe[8192];
	size_t jwe_cap = sizeof(jwe);

	if (did_test_keypair(&recv) || did_test_keypair(&send)) {
		FAIL("X25519 keygen failed");
		goto out;
	}

	recipients[0].x25519_pub = recv.pub;
	recipients[0].kid = "did:example:recipient#key-1";

	if (did_jwe_authcrypt(recipients, 1, send.priv, send.pub,
			      "did:example:sender#key-1",
			      (const u8 *) plaintext, pt_len,
			      cek_enc, jwe, &jwe_cap) != 0) {
		FAIL("authcrypt failed");
		goto out;
	}

	/* (a) the recipient recovers the CEK the sender generated */
	if (did_jwe_authdecrypt(recv.priv, send.pub, jwe, jwe_cap, NULL,
				cek_dec, NULL, NULL) != 0) {
		FAIL("authdecrypt (CEK only) failed");
		goto out;
	}
	if (os_memcmp(cek_enc, cek_dec, DID_JWE_CEK_LEN) != 0) {
		FAIL("recovered CEK differs from the generated one");
		goto out;
	}

	/* (b) and the plaintext, with the tag verified */
	if (did_jwe_authdecrypt(recv.priv, send.pub, jwe, jwe_cap, NULL,
				cek_dec, pt_dec, &pt_dec_len) != 0) {
		FAIL("authdecrypt (with plaintext) failed");
		goto out;
	}
	if (pt_dec_len != pt_len || os_memcmp(pt_dec, plaintext, pt_len) != 0) {
		FAIL("plaintext mismatch (len=%zu)", pt_dec_len);
		goto out;
	}

	/* (c) a wrong recipient key does not unwrap */
	os_memset(wrong_priv, 0x01, sizeof(wrong_priv));
	if (did_jwe_authdecrypt(wrong_priv, send.pub, jwe, jwe_cap, NULL,
				cek_dec, NULL, NULL) == 0) {
		FAIL("a wrong recipient key unwrapped the CEK");
		goto out;
	}

	PASS();
out:
	EVP_PKEY_free(recv.pkey);
	EVP_PKEY_free(send.pkey);
}


/*
 * The presentation is addressed to the verifier and to the authenticator, and
 * each has to reach the same CEK from its own entry.
 */
static void test_jwe_two_recipients(void)
{
	TEST("jwe_two_recipients_reach_the_same_cek");

	struct did_test_keypair a = { 0 }, b = { 0 }, send = { 0 };
	struct did_jwe_recipient recipients[2];
	const char *plaintext = "{\"thid\":\"two-recipients\"}";
	u8 cek_enc[DID_JWE_CEK_LEN];
	u8 cek_a[DID_JWE_CEK_LEN], cek_b[DID_JWE_CEK_LEN];
	char jwe[8192];
	size_t jwe_cap = sizeof(jwe);

	if (did_test_keypair(&a) || did_test_keypair(&b) ||
	    did_test_keypair(&send)) {
		FAIL("X25519 keygen failed");
		goto out;
	}

	recipients[0].x25519_pub = a.pub;
	recipients[0].kid = "did:example:verifier#key-1";
	recipients[1].x25519_pub = b.pub;
	recipients[1].kid = "did:example:authenticator#key-1";

	if (did_jwe_authcrypt(recipients, 2, send.priv, send.pub,
			      "did:example:sender#key-1",
			      (const u8 *) plaintext, os_strlen(plaintext),
			      cek_enc, jwe, &jwe_cap) != 0) {
		FAIL("authcrypt failed");
		goto out;
	}

	if (did_jwe_authdecrypt(a.priv, send.pub, jwe, jwe_cap,
				recipients[0].kid, cek_a, NULL, NULL) != 0 ||
	    did_jwe_authdecrypt(b.priv, send.pub, jwe, jwe_cap,
				recipients[1].kid, cek_b, NULL, NULL) != 0) {
		FAIL("a recipient could not open its own entry");
		goto out;
	}

	if (os_memcmp(cek_enc, cek_a, DID_JWE_CEK_LEN) != 0 ||
	    os_memcmp(cek_enc, cek_b, DID_JWE_CEK_LEN) != 0) {
		FAIL("the two entries do not carry the same CEK");
		goto out;
	}

	PASS();
out:
	EVP_PKEY_free(a.pkey);
	EVP_PKEY_free(b.pkey);
	EVP_PKEY_free(send.pkey);
}


/*
 * D-15: a plaintext up to the declared bound encodes, and one past it is
 * refused by name rather than failing somewhere inside the encoder.
 */
static void test_jwe_plaintext_bound(void)
{
	TEST("jwe_plaintext_bound");

	struct did_test_keypair recv = { 0 }, send = { 0 };
	struct did_jwe_recipient recipients[1];
	size_t jwe_size = DID_B64URL_LEN(DID_JWE_MAX_PLAINTEXT + 16) + 8192;
	u8 *pt = os_malloc(DID_JWE_MAX_PLAINTEXT + 1);
	char *jwe = os_malloc(jwe_size);
	/* authdecrypt writes the padded ciphertext before stripping it */
	u8 *pt_dec = os_malloc(DID_JWE_MAX_PLAINTEXT + 16);
	u8 cek[DID_JWE_CEK_LEN];
	size_t jwe_cap, pt_dec_len;

	if (!pt || !jwe || !pt_dec) {
		FAIL("malloc failed");
		goto out;
	}
	for (size_t i = 0; i <= DID_JWE_MAX_PLAINTEXT; i++)
		pt[i] = (u8)(i * 31 + 7);

	if (did_test_keypair(&recv) || did_test_keypair(&send)) {
		FAIL("X25519 keygen failed");
		goto out;
	}

	recipients[0].x25519_pub = recv.pub;
	recipients[0].kid = "did:example:recipient#key-1";

	/* at the bound */
	jwe_cap = jwe_size;
	if (did_jwe_authcrypt(recipients, 1, send.priv, send.pub,
			      "did:example:sender#key-1",
			      pt, DID_JWE_MAX_PLAINTEXT,
			      cek, jwe, &jwe_cap) != 0) {
		FAIL("refused a plaintext of exactly DID_JWE_MAX_PLAINTEXT");
		goto out;
	}

	pt_dec_len = DID_JWE_MAX_PLAINTEXT + 16;
	if (did_jwe_authdecrypt(recv.priv, send.pub, jwe, jwe_cap, NULL,
				cek, pt_dec, &pt_dec_len) != 0 ||
	    pt_dec_len != DID_JWE_MAX_PLAINTEXT ||
	    os_memcmp(pt_dec, pt, DID_JWE_MAX_PLAINTEXT) != 0) {
		FAIL("a message at the bound did not round-trip");
		goto out;
	}

	/* one octet past it */
	jwe_cap = jwe_size;
	if (did_jwe_authcrypt(recipients, 1, send.priv, send.pub,
			      "did:example:sender#key-1",
			      pt, DID_JWE_MAX_PLAINTEXT + 1,
			      cek, jwe, &jwe_cap) == 0) {
		FAIL("encoded a plaintext past the declared bound");
		goto out;
	}

	PASS();
out:
	os_free(pt);
	os_free(jwe);
	os_free(pt_dec);
	EVP_PKEY_free(recv.pkey);
	EVP_PKEY_free(send.pkey);
}


/* ================================================================== */
/* 7. Flags byte encoding                                             */
/* ================================================================== */

static void test_flags_start(void)
{
	TEST("flags_start_bit");

	u8 flags = EAP_DID_FLAGS_START;

	if ((flags & EAP_DID_FLAGS_START) == 0 ||
	    (flags & EAP_DID_FLAGS_MORE_FRAGMENTS) != 0 ||
	    (flags & EAP_DID_FLAGS_LENGTH_INCLUDED) != 0) {
		FAIL("flags %02x", flags);
		return;
	}

	PASS();
}


static void test_flags_version_mask(void)
{
	TEST("flags_version_mask");

	u8 combined = EAP_DID_FLAGS_START | EAP_DID_VERSION;

	if ((EAP_DID_VERSION & ~EAP_DID_VERSION_MASK) != 0) {
		FAIL("the version does not fit its mask");
		return;
	}
	if ((combined & EAP_DID_VERSION_MASK) != EAP_DID_VERSION ||
	    (combined & EAP_DID_FLAGS_START) == 0) {
		FAIL("version and START do not coexist");
		return;
	}

	PASS();
}


/* ================================================================== */
/* Runner                                                             */
/* ================================================================== */

int main(int argc, char *argv[])
{
	(void) argc;
	(void) argv;

	printf("\n");
	printf("============================================\n");
	printf("  EAP-DID Unit Tests (did5)\n");
	printf("============================================\n\n");

	printf("-- Key derivation --\n");
	test_cek_key_derivation_deterministic();
	test_cek_key_derivation_labels();
	test_cek_key_derivation_different_ceks();
	test_session_id_format();

	printf("\n-- gzip --\n");
	test_gzip_roundtrip();
	test_gzip_large();

	printf("\n-- JSON extraction --\n");
	test_json_extract_basic();
	test_json_extract_spaces();
	test_json_extract_missing();
	test_json_extract_nested();
	test_json_extract_name_inside_value();
	test_json_extract_truncation_fails();
	test_json_extract_skips_non_string();
	test_json_extract_unterminated();
	test_json_object_bounds_match_record();
	test_json_object_bounds_nested();
	test_json_object_bounds_unterminated();

	printf("\n-- did:peer:2 key agreement --\n");
	test_did_x25519_segment();
	test_did_x25519_rejects_ed25519();
	test_did_x25519_rejects_unknown_codec();
	test_did_x25519_rejects_short_segment();
	test_did_x25519_rejects_bad_base58();
	test_did_x25519_ignores_v_segment();

	printf("\n-- Fragmentation --\n");
	test_fragment_boundaries();

	printf("\n-- JWE --\n");
	test_jwe_authcrypt_construction();
	test_jwe_authdecrypt_roundtrip();
	test_jwe_two_recipients();
	test_jwe_plaintext_bound();

	printf("\n-- Flags byte --\n");
	test_flags_start();
	test_flags_version_mask();

	printf("\n============================================\n");
	printf("  run %d, passed %d, failed %d\n",
	       tests_run, tests_pass, tests_fail);
	printf("============================================\n\n");

	return tests_fail ? 1 : 0;
}
