/*
 * hostapd / EAP-DID
 * Copyright (c) 2024-2026, Caciano Machado
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * The authenticator asks the Identus verifier for an out-of-band DIDComm
 * invitation, ships it to the supplicant over EAP, and takes back a
 * Verifiable Presentation sealed as a DIDComm v2 JWE. Verifying the
 * presentation is left to the verifier; the authenticator only relays it and
 * acts on the verdict.
 *
 * The MSK is derived from the JWE content encryption key, which the
 * authenticator recovers by unwrapping the verifier recipient entry with the
 * verifier key agreement key. That key is read from the verifier at
 * authentication time, because Identus mints a new peer DID per invitation.
 * Nothing is added to the JWE for the authenticator's benefit, and no key
 * material crosses the EAP channel.
 *
 *   START -> DOWNLINK -> UPLINK -> VERIFYING -> SUCCESS
 *                                          \-> FAILURE
 *
 * The verifier is contacted with blocking HTTP, so that runs on a thread of its
 * own: the poll takes minutes in the worst case, and doing it from the event
 * loop stopped hostapd entirely for that long. The EAP state machine keeps the
 * last response while the worker runs — METHOD_PENDING_WAIT, the same mechanism
 * EAP-SIM uses for its database — and reprocesses it once the answer arrives.
 */

#include "includes.h"

#include "common.h"
#include "utils/base64.h"
#include "utils/eloop.h"
#include "eap_server/eap_i.h"
#include "eap_common/eap_did_common.h"
#include "eap_common/eap_did_http.h"
#include "eap_common/eap_did_jwe.h"
#include "eap_common/eap_did_async.h"

/* Configuration, all taken from the environment */
#define EAP_DID_VERIFIER_URL_ENV "DID_VERIFIER_BASE_URL"
#define EAP_DID_VERIFIER_URL_DEFAULT "http://caddy-verifier:8082"
#define EAP_DID_SCHEMA_ID_ENV "SCHEMA_ID"
#define EAP_DID_ISSUER_DID_ENV "ISSUER_DID"
#define EAP_DID_KEY_URL_ENV "DID_VERIFIER_KEY_URL"
#define EAP_DID_KEY_URL_DEFAULT "http://verifier-keys:8090/peer-did-key"
#define EAP_DID_DOMAIN_ENV "DID_DOMAIN"
#define EAP_DID_DOMAIN_DEFAULT "eduroam"

#define EAP_DID_HTTP_TIMEOUT 30
#define EAP_DID_POLL_TIMEOUT 10
#define EAP_DID_POLL_ROUNDS 60

/* Retransmission timeout advertised to the EAP state machine */
#define EAP_DID_RETRANS_TIMEOUT 5

/*
 * Octets of randomness behind the challenge the supplicant has to sign. It is
 * what makes a presentation good for this authentication and no other, so it
 * is drawn fresh for every invitation.
 */
#define EAP_DID_CHALLENGE_LEN 24

#define EAP_DID_URL_LEN 1024
#define EAP_DID_INVITATION_LEN 8192


struct eap_did_data {
	enum {
		START, DOWNLINK, UPLINK, VERIFYING, SUCCESS, FAILURE
	} state;

	/* Set while an invitation fragment is outstanding */
	bool waiting_ack;

	char verifier_base[256];
	char key_service[256];
	char schema_id[512];
	char issuer_did[256];
	char domain[128];

	/* Drawn fresh for each invitation */
	char challenge[64];

	/* Invitation being fragmented towards the supplicant */
	char thid[128];
	struct wpabuf *out_buf;
	size_t out_used;
	size_t fragment_size;

	/* Presentation being reassembled from the supplicant */
	struct wpabuf *in_buf;

	/* The peer DID the verifier minted for this invitation, and the key
	 * agreement key behind it, which the presentation is wrapped for */
	char verifier_did[EAP_DID_DID_LEN];
	char verifier_kid[EAP_DID_KID_LEN];
	u8 verifier_x25519_priv[32];
	bool has_verifier_key;

	/* Content encryption key recovered from the presentation */
	u8 *cek;
	size_t cek_len;

	/* The verification, running off the event loop */
	struct did_async *verify;
};


static const char * eap_did_state_txt(int state)
{
	switch (state) {
	case START:
		return "START";
	case DOWNLINK:
		return "DOWNLINK";
	case UPLINK:
		return "UPLINK";
	case VERIFYING:
		return "VERIFYING";
	case SUCCESS:
		return "SUCCESS";
	case FAILURE:
		return "FAILURE";
	default:
		return "?";
	}
}


static void eap_did_state(struct eap_did_data *data, int state)
{
	wpa_printf(MSG_DEBUG, "EAP-DID: %s -> %s",
		   eap_did_state_txt(data->state),
		   eap_did_state_txt(state));
	data->state = state;
}


/*
 * Draw the challenge the supplicant has to sign. A presentation is only good
 * for the authentication whose challenge it carries, so a fresh one is what
 * stops a presentation seen once from being offered again, here or anywhere
 * else.
 */
static int eap_did_new_challenge(struct eap_did_data *data)
{
	u8 raw[EAP_DID_CHALLENGE_LEN];
	size_t len = sizeof(data->challenge);

	if (os_get_random(raw, sizeof(raw)) < 0) {
		wpa_printf(MSG_ERROR, "EAP-DID: No randomness for the challenge");
		return -1;
	}

	if (did_b64url_encode(raw, sizeof(raw), data->challenge, &len) < 0) {
		wpa_printf(MSG_ERROR, "EAP-DID: Could not encode the challenge");
		return -1;
	}

	return 0;
}


/* Ask the verifier to mint an out-of-band presentation request */
static int eap_did_fetch_invitation(struct eap_did_data *data)
{
	struct did_http_response resp;
	char url[EAP_DID_URL_LEN];
	char *body, *invitation;
	char inv_url[4096];
	int res;

	if (!data->schema_id[0] || !data->issuer_did[0]) {
		wpa_printf(MSG_ERROR,
			   "EAP-DID: %s and %s must both be configured",
			   EAP_DID_SCHEMA_ID_ENV, EAP_DID_ISSUER_DID_ENV);
		return -1;
	}

	if (eap_did_new_challenge(data) < 0)
		return -1;

	body = os_malloc(2048);
	if (!body)
		return -1;

	res = os_snprintf(body, 2048,
			  "{\"goalCode\":\"verify-eduroam-access\","
			  "\"goal\":\"Usar sua credencial academica para conectar-se a rede Wi-Fi eduroam\","
			  "\"credentialFormat\":\"JWT\","
			  "\"proofs\":[{\"schemaId\":\"%s\",\"trustIssuers\":[\"%s\"]}],"
			  "\"options\":{\"challenge\":\"%s\","
			  "\"domain\":\"%s\"}}",
			  data->schema_id, data->issuer_did, data->challenge,
			  data->domain);
	if (os_snprintf_error(2048, res)) {
		os_free(body);
		return -1;
	}

	os_snprintf(url, sizeof(url),
		    "%s/cloud-agent/present-proof/presentations/invitation",
		    data->verifier_base);

	res = did_http_post(url, "application/json", (const u8 *) body,
			    os_strlen(body), &resp, EAP_DID_HTTP_TIMEOUT);
	os_free(body);

	if (res < 0 || resp.status < 200 || resp.status >= 300) {
		wpa_printf(MSG_INFO,
			   "EAP-DID: Invitation request failed (res=%d status=%d)",
			   res, resp.status);
		did_http_response_free(&resp);
		return -1;
	}

	if (did_json_extract_str(resp.body, resp.body_len, "thid", data->thid,
				 sizeof(data->thid)) < 0) {
		wpa_printf(MSG_INFO,
			   "EAP-DID: No thread id in the invitation response");
		did_http_response_free(&resp);
		return -1;
	}

	/*
	 * The verifier names the peer DID it minted for this invitation. It is
	 * what the supplicant will encrypt to, so it is also what the key
	 * behind the recipient entry has to be looked up by.
	 */
	if (did_json_extract_str(resp.body, resp.body_len, "myDid",
				 data->verifier_did,
				 sizeof(data->verifier_did)) < 0) {
		wpa_printf(MSG_INFO,
			   "EAP-DID: Invitation response names no verifier DID");
		data->verifier_did[0] = '\0';
	}

	/*
	 * Forward just the thread id and the invitation URL when the response
	 * carries one; otherwise pass the whole document through.
	 */
	if (did_json_extract_str(resp.body, resp.body_len, "invitationUrl",
				 inv_url, sizeof(inv_url)) == 0) {
		invitation = os_malloc(EAP_DID_INVITATION_LEN);
		if (!invitation) {
			did_http_response_free(&resp);
			return -1;
		}
		res = os_snprintf(invitation, EAP_DID_INVITATION_LEN,
				  "{\"thid\":\"%s\",\"invitationUrl\":\"%s\"}",
				  data->thid, inv_url);
		if (!os_snprintf_error(EAP_DID_INVITATION_LEN, res))
			data->out_buf = wpabuf_alloc_copy(invitation, res);
		os_free(invitation);
	} else {
		data->out_buf = wpabuf_alloc_copy(resp.body, resp.body_len);
	}

	did_http_response_free(&resp);

	if (!data->out_buf) {
		wpa_printf(MSG_INFO, "EAP-DID: Could not build the invitation");
		return -1;
	}

	data->out_used = 0;
	wpa_printf(MSG_DEBUG,
		   "EAP-DID: Invitation ready (thid=%s, %zu octets)",
		   data->thid, wpabuf_len(data->out_buf));

	return 0;
}


/*
 * Read the key agreement key behind the peer DID the verifier minted for this
 * invitation.
 *
 * Identus keeps that key and offers no way to ask for it, so it is read
 * straight out of the verifier's own store. It has to happen per
 * authentication, because the DID is new every time. This is the seam where
 * the authenticator still leans on the verifier being next to it; it closes
 * once the authenticator verifies presentations itself.
 */
static int eap_did_fetch_verifier_key(struct eap_did_data *data)
{
	struct did_http_response resp;
	char url[EAP_DID_URL_LEN];
	char key_b64[128];
	u8 *raw;
	size_t raw_len = 0;
	int res;

	data->has_verifier_key = false;

	if (!data->verifier_did[0])
		return -1;

	eap_did_key_id(data->verifier_did, data->verifier_kid,
		       sizeof(data->verifier_kid));

	res = os_snprintf(url, sizeof(url), "%s?did=%s", data->key_service,
			  data->verifier_did);
	if (os_snprintf_error(sizeof(url), res)) {
		wpa_printf(MSG_INFO, "EAP-DID: Key service URL too long");
		return -1;
	}

	if (did_http_get(url, &resp, EAP_DID_HTTP_TIMEOUT) < 0 ||
	    resp.status != 200) {
		wpa_printf(MSG_WARNING,
			   "EAP-DID: Key service answered %d; no key material will be available",
			   resp.status);
		did_http_response_free(&resp);
		return -1;
	}

	/* The key pair comes back as a JWK; "d" is the private scalar */
	res = did_json_extract_str(resp.body, resp.body_len, "d", key_b64,
				   sizeof(key_b64));
	did_http_response_free(&resp);
	if (res < 0) {
		wpa_printf(MSG_WARNING,
			   "EAP-DID: Key service returned no private key");
		return -1;
	}

	raw = base64_url_decode(key_b64, os_strlen(key_b64), &raw_len);
	if (!raw || raw_len != 32) {
		wpa_printf(MSG_WARNING,
			   "EAP-DID: Verifier key is %zu octets, expected 32",
			   raw_len);
		bin_clear_free(raw, raw_len);
		return -1;
	}

	os_memcpy(data->verifier_x25519_priv, raw, 32);
	bin_clear_free(raw, raw_len);
	data->has_verifier_key = true;

	wpa_printf(MSG_DEBUG, "EAP-DID: Verifier key agreement key in hand");

	return 0;
}


/*
 * Recover the content encryption key the supplicant generated, which is what
 * both sides derive the MSK from.
 *
 * The presentation is wrapped for the verifier alone, so its entry is the one
 * unwrapped, with the verifier key. The sender static key that ECDH-1PU needs
 * comes from the skid the JWE carries, so nothing about the supplicant has to
 * be configured here either.
 */
static int eap_did_recover_cek(struct eap_did_data *data, const u8 *jwe,
			       size_t jwe_len)
{
	char skid[EAP_DID_KID_LEN];
	char sender_did[EAP_DID_DID_LEN];
	u8 sender_pub[32];
	char *frag;
	u8 *cek;

	if (!data->has_verifier_key) {
		wpa_printf(MSG_WARNING,
			   "EAP-DID: No verifier key; the MSK cannot be derived");
		return -1;
	}

	if (did_jwe_sender_kid((const char *) jwe, jwe_len, skid,
			       sizeof(skid)) < 0) {
		wpa_printf(MSG_WARNING, "EAP-DID: Presentation names no sender key");
		return -1;
	}

	/* The skid is a DID URL; the key lives in the DID it points into */
	os_strlcpy(sender_did, skid, sizeof(sender_did));
	frag = os_strchr(sender_did, '#');
	if (frag)
		*frag = '\0';

	if (did_x25519_from_did(sender_did, sender_pub) < 0) {
		wpa_printf(MSG_WARNING,
			   "EAP-DID: Sender DID carries no key agreement key");
		return -1;
	}

	cek = os_malloc(DID_JWE_CEK_LEN);
	if (!cek)
		return -1;

	if (did_jwe_authdecrypt(data->verifier_x25519_priv, sender_pub,
				(const char *) jwe, jwe_len, data->verifier_kid,
				cek, NULL, NULL) < 0) {
		wpa_printf(MSG_WARNING,
			   "EAP-DID: Could not unpack the presentation JWE");
		bin_clear_free(cek, DID_JWE_CEK_LEN);
		return -1;
	}

	bin_clear_free(data->cek, data->cek_len);
	data->cek = cek;
	data->cek_len = DID_JWE_CEK_LEN;
	wpa_printf(MSG_DEBUG, "EAP-DID: Recovered the content encryption key");

	return 0;
}


/*
 * Look for our thread in the verifier presentation list. Returns 1 once it
 * has been verified, -1 once it has been rejected and 0 while it is still
 * being processed.
 */
static int eap_did_verdict(const char *want_thid, const char *body,
			   size_t body_len)
{
	const char *pos = body, *end = body + body_len;
	const char *obj, *obj_end;

	while ((obj = did_json_next_object(pos, end, &obj_end)) != NULL) {
		char thid[128];
		char status[64];

		pos = obj_end;

		/*
		 * Read both members out of the same record. Taking the status
		 * from wherever it happened to sit behind the thread id made
		 * the verdict of one exchange readable as another's, which is
		 * the normal case for an access point with several stations
		 * authenticating against one Verifier.
		 */
		if (did_json_extract_str(obj, obj_end - obj, "thid", thid,
					 sizeof(thid)) != 0 ||
		    os_strcmp(thid, want_thid) != 0)
			continue;

		if (did_json_extract_str(obj, obj_end - obj, "status", status,
					 sizeof(status)) != 0)
			continue;

		if (os_strcmp(status, "PresentationVerified") == 0 ||
		    os_strcmp(status, "PresentationAccepted") == 0)
			return 1;

		if (os_strcmp(status, "PresentationVerificationFailed") == 0 ||
		    os_strcmp(status, "PresentationRejected") == 0) {
			wpa_printf(MSG_INFO, "EAP-DID: Verifier reported %s",
				   status);
			return -1;
		}

		wpa_printf(MSG_DEBUG, "EAP-DID: Presentation is %s", status);
	}

	return 0;
}


/*
 * Everything the verification needs, copied, so that the worker shares nothing
 * with the session. The session can be torn down while a poll is outstanding.
 */
struct eap_did_verify_job {
	char verifier_base[sizeof(((struct eap_did_data *) 0)->verifier_base)];
	char thid[sizeof(((struct eap_did_data *) 0)->thid)];
	u8 *jwe;
	size_t jwe_len;
};


static void eap_did_verify_job_free(void *ctx)
{
	struct eap_did_verify_job *job = ctx;

	if (!job)
		return;

	os_free(job->jwe);
	os_free(job);
}


/*
 * Hand the presentation to the verifier and wait for its verdict. Runs on a
 * thread of its own: every call below blocks, and the poll runs for minutes in
 * the worst case. Nothing here touches the session.
 */
static int eap_did_verify_worker(void *ctx)
{
	struct eap_did_verify_job *job = ctx;
	struct did_http_response resp;
	char url[EAP_DID_URL_LEN];
	int res, round, verdict = 0;

	os_snprintf(url, sizeof(url), "%s/didcomm", job->verifier_base);
	res = did_http_post(url, "application/didcomm-encrypted+json", job->jwe,
			    job->jwe_len, &resp, EAP_DID_HTTP_TIMEOUT);

	if (res < 0 || (resp.status != 200 && resp.status != 202)) {
		wpa_printf(MSG_INFO,
			   "EAP-DID: Verifier rejected the presentation (status=%d)",
			   resp.status);
		did_http_response_free(&resp);
		return -1;
	}
	did_http_response_free(&resp);

	/*
	 * Ask for this thread rather than for every presentation the verifier
	 * holds. eap_did_presentation_status() matches the record either way;
	 * this keeps the response to one record, which is what makes the match
	 * cheap when an access point has several stations in flight at once.
	 */
	os_snprintf(url, sizeof(url),
		    "%s/cloud-agent/present-proof/presentations?thid=%s",
		    job->verifier_base, job->thid);

	for (round = 0; round < EAP_DID_POLL_ROUNDS && verdict == 0; round++) {
		os_sleep(1, 0);

		if (did_http_get(url, &resp, EAP_DID_POLL_TIMEOUT) < 0 ||
		    resp.status != 200) {
			wpa_printf(MSG_DEBUG,
				   "EAP-DID: Presentation poll %d failed",
				   round);
			did_http_response_free(&resp);
			continue;
		}

		verdict = eap_did_verdict(job->thid, resp.body, resp.body_len);
		did_http_response_free(&resp);
	}

	if (verdict == 0)
		wpa_printf(MSG_INFO,
			   "EAP-DID: Verifier did not answer within %d rounds",
			   EAP_DID_POLL_ROUNDS);

	return verdict == 1 ? 0 : -1;
}


/* The worker has an answer: take it and let the state machine proceed. */
static void eap_did_verify_finished(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct eap_did_data *data = eloop_ctx;
	struct eap_sm *sm = sock_ctx;
	char done;
	int result = -1;

	if (read(sock, &done, 1) < 0) {
		/* Nothing readable is not a reason to hang; fall through to
		 * whatever the job reports. */
	}

	eloop_unregister_read_sock(sock);

	if (did_async_collect(data->verify, &result) < 0) {
		wpa_printf(MSG_INFO,
			   "EAP-DID: Verification signalled without a result");
		result = -1;
	}

	did_async_release(data->verify);
	data->verify = NULL;

	eap_did_state(data, result == 0 ? SUCCESS : FAILURE);

	/*
	 * The EAP server state machine has been sitting in METHOD_RESPONSE
	 * since the last fragment. This is what tells it the wait is over; it
	 * reprocesses the response it kept, and this time isDone() is true.
	 */
	if (sm->cfg->pending_cb)
		sm->cfg->pending_cb(sm->cfg->pending_cb_ctx, sm);
}


/*
 * Recover the key, then start the verification off the event loop. Returns 0
 * once the worker is running, -1 if the exchange has already failed.
 */
static int eap_did_start_verify(struct eap_did_data *data, struct eap_sm *sm)
{
	struct eap_did_verify_job *job;
	u8 *jwe = NULL;
	size_t jwe_len = 0;
	int fd;

	if (!data->in_buf || wpabuf_len(data->in_buf) == 0)
		return -1;

	if (did_gzip_decompress(wpabuf_head_u8(data->in_buf),
				wpabuf_len(data->in_buf), &jwe,
				&jwe_len) < 0) {
		wpa_printf(MSG_INFO,
			   "EAP-DID: Could not decompress the presentation");
		return -1;
	}
	wpa_printf(MSG_DEBUG, "EAP-DID: Presentation JWE is %zu octets",
		   jwe_len);

	/*
	 * Without the content encryption key there is no MSK, and an EAP-Success
	 * would authorise a port whose keys eap_did_getKey() cannot produce: on
	 * 802.11 that is an association failure with no explanation, on wired an
	 * open port with no keys at all. Fail here instead.
	 *
	 * This stays on the event loop: it is one key unwrap, it took under two
	 * milliseconds in every run measured, and it writes into the session.
	 */
	if (eap_did_recover_cek(data, jwe, jwe_len) < 0) {
		os_free(jwe);
		return -1;
	}

	job = os_zalloc(sizeof(*job));
	if (!job) {
		os_free(jwe);
		return -1;
	}

	os_strlcpy(job->verifier_base, data->verifier_base,
		   sizeof(job->verifier_base));
	os_strlcpy(job->thid, data->thid, sizeof(job->thid));
	job->jwe = jwe;
	job->jwe_len = jwe_len;

	data->verify = did_async_start(eap_did_verify_worker, job,
				       eap_did_verify_job_free);
	if (!data->verify)
		return -1;

	fd = did_async_fd(data->verify);
	if (eloop_register_read_sock(fd, eap_did_verify_finished, data,
				     sm) < 0) {
		did_async_release(data->verify);
		data->verify = NULL;
		return -1;
	}

	return 0;
}


static struct wpabuf * eap_did_build_keepalive(u8 id)
{
	struct wpabuf *req;

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_DID, 1,
			    EAP_CODE_REQUEST, id);
	if (!req)
		return NULL;
	wpabuf_put_u8(req, EAP_DID_VERSION);

	return req;
}


static struct wpabuf * eap_did_build_start(struct eap_did_data *data, u8 id)
{
	struct wpabuf *req;

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_DID, 1,
			    EAP_CODE_REQUEST, id);
	if (!req)
		return NULL;
	wpabuf_put_u8(req, EAP_DID_VERSION | EAP_DID_FLAGS_START);

	data->waiting_ack = true;
	wpa_printf(MSG_DEBUG, "EAP-DID: Sending Start (version %d)",
		   EAP_DID_VERSION);

	return req;
}


static struct wpabuf * eap_did_build_fragment(struct eap_did_data *data,
					      u8 id)
{
	struct wpabuf *req;
	size_t remaining, send_len;
	u8 flags = EAP_DID_VERSION;
	int length_included;

	/*
	 * A fragment is only sent once the previous one has been
	 * acknowledged, so that a replayed or reflected response cannot make
	 * the invitation run ahead of the supplicant.
	 */
	if (data->waiting_ack || !data->out_buf)
		return eap_did_build_keepalive(id);

	remaining = wpabuf_len(data->out_buf) - data->out_used;
	send_len = remaining > data->fragment_size ? data->fragment_size :
		remaining;
	if (send_len < remaining)
		flags |= EAP_DID_FLAGS_MORE_FRAGMENTS;

	/* Only the opening fragment of a fragmented message carries the total */
	length_included = data->out_used == 0 &&
		wpabuf_len(data->out_buf) > data->fragment_size;
	if (length_included)
		flags |= EAP_DID_FLAGS_LENGTH_INCLUDED;

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_DID,
			    1 + (length_included ? 4 : 0) + send_len,
			    EAP_CODE_REQUEST, id);
	if (!req)
		return NULL;

	wpabuf_put_u8(req, flags);
	if (length_included)
		wpabuf_put_be32(req, wpabuf_len(data->out_buf));
	wpabuf_put_data(req, wpabuf_head_u8(data->out_buf) + data->out_used,
			send_len);
	data->out_used += send_len;

	wpa_printf(MSG_DEBUG,
		   "EAP-DID: Sending invitation fragment (%zu octets, more=%d)",
		   send_len, send_len < remaining);

	if (send_len < remaining) {
		data->waiting_ack = true;
	} else {
		wpabuf_free(data->out_buf);
		data->out_buf = NULL;
		data->out_used = 0;
		eap_did_state(data, UPLINK);
	}

	return req;
}


static struct wpabuf * eap_did_buildReq(struct eap_sm *sm, void *priv, u8 id)
{
	struct eap_did_data *data = priv;

	switch (data->state) {
	case START:
		return eap_did_build_start(data, id);
	case DOWNLINK:
		return eap_did_build_fragment(data, id);
	case UPLINK:
		return eap_did_build_keepalive(id);
	case VERIFYING:
		/*
		 * Not reached: the state machine holds the response while the
		 * verifier is asked, so it does not come back for a request.
		 */
		return eap_did_build_keepalive(id);
	default:
		return NULL;
	}
}


static void eap_did_process_start_ack(struct eap_did_data *data, u8 flags,
				      size_t len)
{
	u8 version = len >= 1 ? flags & EAP_DID_VERSION_MASK :
		EAP_DID_VERSION;

	if (version != EAP_DID_VERSION) {
		wpa_printf(MSG_INFO,
			   "EAP-DID: Peer offered version %d, expected %d",
			   version, EAP_DID_VERSION);
		eap_did_state(data, FAILURE);
		return;
	}

	wpa_printf(MSG_DEBUG, "EAP-DID: Requesting an invitation");
	if (eap_did_fetch_invitation(data) < 0) {
		wpa_printf(MSG_INFO, "EAP-DID: No invitation available");
		eap_did_state(data, FAILURE);
		return;
	}

	/*
	 * Fetched now rather than when the presentation lands, so that a
	 * verifier that cannot hand over the key is noticed before the
	 * supplicant has done any work.
	 */
	eap_did_fetch_verifier_key(data);

	data->waiting_ack = false;
	eap_did_state(data, DOWNLINK);
}


/*
 * Append one presentation fragment. Returns 1 when more fragments are
 * expected, 0 when the presentation is complete and -1 on a malformed
 * fragment.
 */
static int eap_did_reassemble(struct eap_did_data *data, u8 flags,
			      const u8 *pos, const u8 *end)
{
	u32 message_length = 0;
	size_t len;

	if ((flags & EAP_DID_VERSION_MASK) != EAP_DID_VERSION)
		return -1;

	if (flags & EAP_DID_FLAGS_LENGTH_INCLUDED) {
		if (end - pos < 4)
			return -1;
		message_length = WPA_GET_BE32(pos);
		pos += 4;
	}
	len = end - pos;

	if (!data->in_buf) {
		if (!(flags & EAP_DID_FLAGS_MORE_FRAGMENTS)) {
			if (len == 0)
				return 1;
			data->in_buf = wpabuf_alloc_copy(pos, len);
			return data->in_buf ? 0 : -1;
		}

		if (!message_length || message_length > EAP_DID_MAX_FILE_SIZE)
			return -1;
		data->in_buf = wpabuf_alloc(message_length);
		if (!data->in_buf)
			return -1;
	}

	if (len > wpabuf_tailroom(data->in_buf))
		return -1;

	/* An empty response mid-reassembly answers a keepalive */
	if (len == 0)
		return 1;

	wpabuf_put_data(data->in_buf, pos, len);

	return flags & EAP_DID_FLAGS_MORE_FRAGMENTS ? 1 : 0;
}


static void eap_did_process_uplink(struct eap_sm *sm,
				   struct eap_did_data *data, u8 flags,
				   const u8 *pos, const u8 *end)
{
	int res;

	res = eap_did_reassemble(data, flags, pos, end);
	if (res < 0) {
		wpa_printf(MSG_INFO,
			   "EAP-DID: Malformed presentation fragment");
		eap_did_state(data, FAILURE);
		return;
	}
	if (res > 0)
		return;

	wpa_printf(MSG_DEBUG, "EAP-DID: Presentation complete (%zu octets)",
		   wpabuf_len(data->in_buf));

	if (eap_did_start_verify(data, sm) < 0) {
		eap_did_state(data, FAILURE);
	} else {
		eap_did_state(data, VERIFYING);
		/*
		 * Nothing more is sent until the verifier answers. The state
		 * machine keeps this response and reprocesses it when
		 * eap_did_verify_finished() reports the wait is over.
		 */
		sm->method_pending = METHOD_PENDING_WAIT;
	}

	wpabuf_free(data->in_buf);
	data->in_buf = NULL;
}


static void eap_did_process(struct eap_sm *sm, void *priv,
			    struct wpabuf *respData)
{
	struct eap_did_data *data = priv;
	const u8 *pos, *end;
	size_t len;
	u8 flags = 0;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_DID, respData, &len);
	if (!pos)
		return;
	end = pos + len;
	if (len > 0)
		flags = *pos++;

	if (data->state == START) {
		if (len > 1) {
			wpa_printf(MSG_INFO,
				   "EAP-DID: Expected a Start acknowledgement, got %zu octets",
				   len);
			eap_did_state(data, FAILURE);
			return;
		}
		eap_did_process_start_ack(data, flags, len);
		return;
	}

	if (data->state == DOWNLINK && data->waiting_ack) {
		/*
		 * An acknowledgement carries the flags octet and nothing
		 * else; anything longer is a replay or a reflection and is
		 * dropped rather than mistaken for the next fragment.
		 */
		if (len > 1) {
			wpa_printf(MSG_INFO,
				   "EAP-DID: Ignored %zu octets while waiting for a fragment acknowledgement",
				   len);
			return;
		}
		data->waiting_ack = false;
		return;
	}

	if (data->state == UPLINK) {
		eap_did_process_uplink(sm, data, flags, pos, end);
		return;
	}

	/*
	 * A retransmission of the last fragment while the verifier is being
	 * asked. Keep waiting rather than starting a second verification of
	 * the same presentation.
	 */
	if (data->state == VERIFYING) {
		sm->method_pending = METHOD_PENDING_WAIT;
		return;
	}

	if (len > 1)
		wpa_printf(MSG_DEBUG,
			   "EAP-DID: Ignored %zu octets received in state %s",
			   len, eap_did_state_txt(data->state));
}


static bool eap_did_check(struct eap_sm *sm, void *priv,
			  struct wpabuf *respData)
{
	const u8 *pos;
	size_t len;

	/* Every EAP-DID payload starts with the flags octet */
	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_DID, respData, &len);
	if (!pos || len < 1) {
		wpa_printf(MSG_INFO, "EAP-DID: Invalid frame");
		return true;
	}

	return false;
}


static bool eap_did_isDone(struct eap_sm *sm, void *priv)
{
	struct eap_did_data *data = priv;

	return data->state == SUCCESS || data->state == FAILURE;
}


static bool eap_did_isSuccess(struct eap_sm *sm, void *priv)
{
	struct eap_did_data *data = priv;

	return data->state == SUCCESS;
}


static int eap_did_getTimeout(struct eap_sm *sm, void *priv)
{
	return EAP_DID_RETRANS_TIMEOUT;
}


static u8 * eap_did_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_did_data *data = priv;

	if (data->state != SUCCESS || !data->thid[0] || !data->cek)
		return NULL;

	*len = EAP_DID_KEY_LEN;

	return eap_did_derive_key_cek(data->cek, data->cek_len, data->thid,
				      "EAP-DID-MSK", EAP_DID_KEY_LEN);
}


static u8 * eap_did_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_did_data *data = priv;

	if (data->state != SUCCESS || !data->thid[0] || !data->cek)
		return NULL;

	*len = EAP_DID_KEY_LEN;

	return eap_did_derive_key_cek(data->cek, data->cek_len, data->thid,
				      "EAP-DID-EMSK", EAP_DID_KEY_LEN);
}


static u8 * eap_did_get_session_id(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_did_data *data = priv;

	if (!data->thid[0])
		return NULL;

	return eap_did_session_id(EAP_TYPE_DID, data->thid, len);
}


static void eap_did_load_str(const char *name, char *buf, size_t buf_len,
			     const char *fallback)
{
	const char *val = getenv(name);

	if (!val || !val[0])
		val = fallback;
	if (val)
		os_strlcpy(buf, val, buf_len);
}


static void * eap_did_init(struct eap_sm *sm)
{
	struct eap_did_data *data;

	data = os_zalloc(sizeof(*data));
	if (!data)
		return NULL;

	data->state = START;
	data->fragment_size = sm->cfg && sm->cfg->fragment_size > 0 ?
		(size_t) sm->cfg->fragment_size :
		EAP_DID_DEFAULT_FRAGMENT_SIZE;

	eap_did_load_str(EAP_DID_VERIFIER_URL_ENV, data->verifier_base,
			 sizeof(data->verifier_base),
			 EAP_DID_VERIFIER_URL_DEFAULT);
	eap_did_load_str(EAP_DID_SCHEMA_ID_ENV, data->schema_id,
			 sizeof(data->schema_id), NULL);
	eap_did_load_str(EAP_DID_ISSUER_DID_ENV, data->issuer_did,
			 sizeof(data->issuer_did), NULL);
	eap_did_load_str(EAP_DID_KEY_URL_ENV, data->key_service,
			 sizeof(data->key_service), EAP_DID_KEY_URL_DEFAULT);
	eap_did_load_str(EAP_DID_DOMAIN_ENV, data->domain,
			 sizeof(data->domain), EAP_DID_DOMAIN_DEFAULT);

	wpa_printf(MSG_DEBUG,
		   "EAP-DID: Initialized (verifier=%s, domain=%s)",
		   data->verifier_base, data->domain);

	return data;
}


static void eap_did_reset(struct eap_sm *sm, void *priv)
{
	struct eap_did_data *data = priv;

	if (!data)
		return;

	/*
	 * A verification may still be outstanding: the session can be torn
	 * down while the verifier is being polled, and the poll cannot be
	 * interrupted safely. Stop watching for its answer and let go; the
	 * worker frees the job when it finishes, and it holds nothing of
	 * this session's.
	 */
	if (data->verify) {
		eloop_unregister_read_sock(did_async_fd(data->verify));
		did_async_release(data->verify);
		data->verify = NULL;
	}

	wpabuf_free(data->out_buf);
	wpabuf_free(data->in_buf);
	bin_clear_free(data->cek, data->cek_len);
	bin_clear_free(data, sizeof(*data));
}


int eap_server_did_register(void)
{
	struct eap_method *eap;

	if (did_http_init() < 0)
		return -1;

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_DID, "DID");
	if (!eap)
		return -1;

	eap->init = eap_did_init;
	eap->reset = eap_did_reset;
	eap->buildReq = eap_did_buildReq;
	eap->check = eap_did_check;
	eap->process = eap_did_process;
	eap->isDone = eap_did_isDone;
	eap->isSuccess = eap_did_isSuccess;
	eap->getTimeout = eap_did_getTimeout;
	eap->getKey = eap_did_getKey;
	eap->get_emsk = eap_did_get_emsk;
	eap->getSessionId = eap_did_get_session_id;

	return eap_server_method_register(eap);
}
