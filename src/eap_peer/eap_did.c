/*
 * EAP peer method: EAP-DID
 * Copyright (c) 2024-2026, Caciano Machado
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 *
 * The authenticator sends an out-of-band DIDComm invitation, the supplicant
 * answers with a Verifiable Presentation for the credential it holds, sealed
 * as a DIDComm v2 JWE. Both sides then derive the MSK from the JWE content
 * encryption key, which is never sent over the EAP channel.
 *
 *   START -> DOWNLINK -> UPLINK -> (WAIT_ACK -> UPLINK)* -> DONE
 *                     \-> FAILURE
 */

#include "includes.h"

#include "common.h"
#include "utils/base64.h"
#include "eap_peer/eap_i.h"
#include "eap_common/eap_did_common.h"
#include "eap_common/eap_did_http.h"
#include "eap_common/eap_did_jwe.h"
#include "eap_common/eap_did_vp.h"

/* Overrides the trusted verifier DID carried by the credential */
#define EAP_DID_TRUSTED_DID_ENV "DID_TRUSTED_VERIFIER_DID"

/*
 * Bounds for the intermediate buffers used while building the presentation.
 * The DIDComm message is what gets encrypted, so its bound is the plaintext
 * bound of the JWE layer rather than a number of its own; the encoded output
 * is that much again for the ciphertext, plus the headers and the recipients.
 */
#define EAP_DID_VP_JWT_LEN DID_VP_JWT_LEN
#define EAP_DID_VP_B64_LEN DID_B64URL_LEN(DID_VP_JWT_LEN)
#define EAP_DID_DIDCOMM_LEN DID_JWE_MAX_PLAINTEXT
#define EAP_DID_JWE_LEN (DID_B64URL_LEN(DID_JWE_MAX_PLAINTEXT + 16) + 8192)


struct eap_did_data {
	enum {
		START, DOWNLINK, UPLINK, WAIT_ACK, DONE, FAILURE
	} state;

	size_t fragment_size;

	/* Invitation being reassembled from the authenticator */
	struct wpabuf *in_buf;

	/* Presentation being fragmented towards the authenticator */
	struct wpabuf *out_buf;
	size_t out_used;

	/* Credential and keys loaded at init time */
	struct did_credential cred;

	/* Taken from the invitation */
	char thid[128];
	char verifier_did[EAP_DID_DID_LEN];
	u8 verifier_x25519_pub[32];

	/* Presentation request options, empty when the request omits them */
	char challenge[256];
	char domain[128];

	/* Verifier DID the peer insists on, or an empty string for any */
	char trusted_verifier_did[EAP_DID_DID_LEN];

	/* Content encryption key of the JWE we produced */
	u8 *cek;
	size_t cek_len;
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
	case WAIT_ACK:
		return "WAIT_ACK";
	case DONE:
		return "DONE";
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


/* Wrap the VP JWT in a DIDComm present-proof message */
static char * eap_did_build_didcomm(struct eap_did_data *data,
				    const char *vp_jwt, size_t vp_len,
				    size_t *msg_len)
{
	char *msg, *vp_b64;
	size_t vp_b64_len = EAP_DID_VP_B64_LEN;
	int res;

	vp_b64 = os_malloc(vp_b64_len);
	if (!vp_b64)
		return NULL;

	if (did_b64url_encode((const u8 *) vp_jwt, vp_len, vp_b64,
			      &vp_b64_len) < 0) {
		wpa_printf(MSG_INFO, "EAP-DID: Could not encode VP JWT");
		os_free(vp_b64);
		return NULL;
	}

	msg = os_malloc(EAP_DID_DIDCOMM_LEN);
	if (!msg) {
		os_free(vp_b64);
		return NULL;
	}

	res = os_snprintf(msg, EAP_DID_DIDCOMM_LEN,
			  "{\"type\":\"https://didcomm.atalaprism.io/present-proof/3.0/presentation\","
			  "\"id\":\"%s\",\"thid\":\"%s\",\"from\":\"%s\",\"to\":[\"%s\"],"
			  "\"body\":{\"goal_code\":\"verify-eduroam-access\","
			  "\"comment\":\"EAP-DID presentation\"},"
			  "\"attachments\":[{\"id\":\"att-1\","
			  "\"media_type\":\"application/vc+ld+json\","
			  "\"format\":\"jwt_vc\",\"data\":{\"base64\":\"%s\"}}]}",
			  data->thid, data->thid, data->cred.holder_did,
			  data->verifier_did, vp_b64);
	os_free(vp_b64);

	if (os_snprintf_error(EAP_DID_DIDCOMM_LEN, res)) {
		wpa_printf(MSG_INFO, "EAP-DID: DIDComm message too long");
		os_free(msg);
		return NULL;
	}

	*msg_len = res;
	wpa_printf(MSG_DEBUG, "EAP-DID: DIDComm message built (%d octets)",
		   res);

	return msg;
}


/*
 * Produce the payload the authenticator expects: a DIDComm presentation
 * sealed with authcrypt and deflated. The CEK generated along the way is what
 * the MSK is later derived from.
 */
static int eap_did_build_presentation(struct eap_did_data *data)
{
	char *vp_jwt = NULL, *jwe = NULL, *msg = NULL;
	char sender_kid[EAP_DID_KID_LEN], recipient_kid[EAP_DID_KID_LEN];
	struct did_jwe_recipient recipients[1];
	size_t num_recipients;
	size_t vp_len = EAP_DID_VP_JWT_LEN, jwe_len = EAP_DID_JWE_LEN, msg_len;
	u8 *deflated = NULL;
	size_t deflated_len;
	int res = -1;

	if (!data->cred.has_ed25519 || !data->cred.has_x25519) {
		wpa_printf(MSG_INFO,
			   "EAP-DID: Credential is missing the Ed25519 or X25519 key");
		return -1;
	}

	vp_jwt = os_malloc(vp_len);
	jwe = os_malloc(jwe_len);
	data->cek = os_malloc(DID_JWE_CEK_LEN);
	if (!vp_jwt || !jwe || !data->cek)
		goto done;

	/*
	 * The presentation is addressed to the domain the request names and
	 * signs the challenge it carries; a request without options falls back
	 * to the verifier and the thread, which is all there is to bind to.
	 */
	if (did_vp_create(&data->cred,
			  data->domain[0] ? data->domain : data->verifier_did,
			  data->challenge[0] ? data->challenge : data->thid,
			  vp_jwt, &vp_len) < 0) {
		wpa_printf(MSG_INFO, "EAP-DID: Could not create the VP JWT");
		goto done;
	}
	wpa_printf(MSG_DEBUG, "EAP-DID: VP JWT created (%zu octets)", vp_len);

	msg = eap_did_build_didcomm(data, vp_jwt, vp_len, &msg_len);
	if (!msg)
		goto done;

	eap_did_key_id(data->cred.holder_did, sender_kid, sizeof(sender_kid));
	eap_did_key_id(data->verifier_did, recipient_kid,
		       sizeof(recipient_kid));

	/*
	 * The presentation is encrypted for the verifier alone. The
	 * authenticator recovers the same content encryption key by unwrapping
	 * this entry with the verifier key, which is how the MSK ends up being
	 * shared without the presentation being readable by anyone else.
	 */
	recipients[0].x25519_pub = data->verifier_x25519_pub;
	recipients[0].kid = recipient_kid;
	num_recipients = 1;

	if (did_jwe_authcrypt(recipients, num_recipients,
			      data->cred.x25519_priv, data->cred.x25519_pub,
			      sender_kid, (const u8 *) msg,
			      msg_len, data->cek, jwe, &jwe_len) < 0) {
		wpa_printf(MSG_INFO, "EAP-DID: JWE authcrypt failed");
		goto done;
	}
	data->cek_len = DID_JWE_CEK_LEN;
	wpa_printf(MSG_DEBUG, "EAP-DID: JWE created (%zu octets)", jwe_len);

	if (did_gzip_compress((const u8 *) jwe, jwe_len, &deflated,
			      &deflated_len) < 0) {
		wpa_printf(MSG_INFO, "EAP-DID: Could not compress the JWE");
		goto done;
	}
	wpa_printf(MSG_DEBUG, "EAP-DID: JWE compressed (%zu -> %zu octets)",
		   jwe_len, deflated_len);

	data->out_buf = wpabuf_alloc_copy(deflated, deflated_len);
	if (!data->out_buf)
		goto done;
	data->out_used = 0;
	res = 0;

done:
	if (res < 0) {
		os_free(data->cek);
		data->cek = NULL;
		data->cek_len = 0;
	}
	bin_clear_free(vp_jwt, EAP_DID_VP_JWT_LEN);
	bin_clear_free(jwe, EAP_DID_JWE_LEN);
	bin_clear_free(msg, EAP_DID_DIDCOMM_LEN);
	os_free(deflated);

	return res;
}


/*
 * Acknowledgement carrying nothing but the flags octet. It answers both a
 * Start request and each intermediate invitation fragment, and doubles as the
 * reply to a keepalive.
 */
static struct wpabuf * eap_did_build_ack(u8 id)
{
	struct wpabuf *resp;

	resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_DID, 1,
			     EAP_CODE_RESPONSE, id);
	if (!resp)
		return NULL;
	wpabuf_put_u8(resp, EAP_DID_VERSION);

	return resp;
}


static struct wpabuf * eap_did_build_fragment(struct eap_did_data *data,
					      struct eap_method_ret *ret,
					      u8 id)
{
	struct wpabuf *resp;
	size_t remaining, send_len;
	u8 flags = EAP_DID_VERSION;
	int length_included;

	if (!data->out_buf) {
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}

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

	resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_DID,
			     1 + (length_included ? 4 : 0) + send_len,
			     EAP_CODE_RESPONSE, id);
	if (!resp) {
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}

	wpabuf_put_u8(resp, flags);
	if (length_included)
		wpabuf_put_be32(resp, wpabuf_len(data->out_buf));
	wpabuf_put_data(resp, wpabuf_head_u8(data->out_buf) + data->out_used,
			send_len);
	data->out_used += send_len;

	wpa_printf(MSG_DEBUG,
		   "EAP-DID: Sending presentation fragment (%zu octets, more=%d)",
		   send_len, send_len < remaining);

	if (send_len < remaining) {
		eap_did_state(data, WAIT_ACK);
		ret->methodState = METHOD_MAY_CONT;
	} else {
		wpabuf_free(data->out_buf);
		data->out_buf = NULL;
		data->out_used = 0;
		eap_did_state(data, DONE);
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_COND_SUCC;
	}

	return resp;
}


/*
 * Append one invitation fragment. Returns 1 when more fragments are expected,
 * 0 when the invitation is complete and -1 on a malformed fragment.
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
			/*
			 * A keepalive before the first fragment. Reporting it
			 * complete would send the caller on to read an
			 * invitation that has not been allocated, which is a
			 * null dereference anything on the link can reach.
			 * The authenticator's copy returns 1 here too.
			 */
			if (len == 0)
				return 1;
			data->in_buf = wpabuf_alloc_copy(pos, len);
			return data->in_buf ? 0 : -1;
		}

		if (!message_length ||
		    message_length > EAP_DID_MAX_FILE_SIZE)
			return -1;
		data->in_buf = wpabuf_alloc(message_length);
		if (!data->in_buf)
			return -1;
	}

	if (len > wpabuf_tailroom(data->in_buf))
		return -1;

	/*
	 * The authenticator only clears MORE_FRAGMENTS on a fragment that
	 * still carries payload, so an empty request in the middle of a
	 * reassembly is a keepalive. Taking it for the final fragment would
	 * silently truncate the invitation.
	 */
	if (len == 0)
		return 1;

	wpabuf_put_data(data->in_buf, pos, len);

	return flags & EAP_DID_FLAGS_MORE_FRAGMENTS ? 1 : 0;
}


/* Read the verifier DID out of the base64url encoded _oob query parameter */
static int eap_did_verifier_from_url(const char *url, char *did,
				     size_t did_len,
				     char *challenge, size_t challenge_len,
				     char *domain, size_t domain_len)
{
	char *b64;
	u8 *oob;
	size_t b64_len = 0, oob_len = 0;
	const char *pos;
	int res = -1;

	pos = os_strstr(url, "_oob=");
	if (!pos) {
		wpa_printf(MSG_INFO,
			   "EAP-DID: No _oob parameter in the invitation URL");
		return -1;
	}
	pos += 5;

	b64 = os_malloc(os_strlen(pos) + 1);
	if (!b64)
		return -1;

	while (*pos && *pos != '&') {
		if (*pos == '%') {
			int val;

			if (!pos[1] || !pos[2])
				break;
			val = hex2byte(pos + 1);
			if (val < 0)
				break;
			b64[b64_len++] = val;
			pos += 3;
		} else {
			b64[b64_len++] = *pos++;
		}
	}
	b64[b64_len] = '\0';

	oob = base64_url_decode(b64, b64_len, &oob_len);
	os_free(b64);
	if (!oob || oob_len == 0) {
		wpa_printf(MSG_INFO, "EAP-DID: Could not decode _oob");
		os_free(oob);
		return -1;
	}

	if (did_json_extract_str((const char *) oob, oob_len, "from", did,
				 did_len) == 0)
		res = 0;
	else
		wpa_printf(MSG_INFO, "EAP-DID: No 'from' in the _oob payload");

	/*
	 * The invitation carries the request-presentation, whose attachment
	 * names the challenge to sign and the domain to address the
	 * presentation to. Both are optional.
	 */
	if (res == 0) {
		did_json_extract_str((const char *) oob, oob_len, "challenge",
				     challenge, challenge_len);
		did_json_extract_str((const char *) oob, oob_len, "domain",
				     domain, domain_len);
	}

	bin_clear_free(oob, oob_len);

	return res;
}


static int eap_did_parse_invitation(struct eap_did_data *data)
{
	const char *json;
	size_t json_len;
	char url[4096];

	if (!data->in_buf || wpabuf_len(data->in_buf) == 0)
		return -1;

	json = (const char *) wpabuf_head_u8(data->in_buf);
	json_len = wpabuf_len(data->in_buf);

	/* An out-of-band invitation names the thread in "id", a plain
	 * DIDComm message in "thid" */
	if (did_json_extract_str(json, json_len, "id", data->thid,
				 sizeof(data->thid)) < 0 &&
	    did_json_extract_str(json, json_len, "thid", data->thid,
				 sizeof(data->thid)) < 0) {
		wpa_printf(MSG_INFO, "EAP-DID: No thread id in the invitation");
		return -1;
	}

	if (did_json_extract_str(json, json_len, "from", data->verifier_did,
				 sizeof(data->verifier_did)) < 0) {
		if (did_json_extract_str(json, json_len, "invitationUrl", url,
					 sizeof(url)) < 0) {
			wpa_printf(MSG_INFO,
				   "EAP-DID: Invitation has neither 'from' nor 'invitationUrl'");
			return -1;
		}
		if (eap_did_verifier_from_url(url, data->verifier_did,
					      sizeof(data->verifier_did),
					      data->challenge,
					      sizeof(data->challenge),
					      data->domain,
					      sizeof(data->domain)) < 0)
			return -1;
	} else {
		did_json_extract_str(json, json_len, "challenge",
				     data->challenge, sizeof(data->challenge));
		did_json_extract_str(json, json_len, "domain",
				     data->domain, sizeof(data->domain));
	}

	wpa_printf(MSG_DEBUG,
		   "EAP-DID: Invitation thid=%s from=%s domain=%s",
		   data->thid, data->verifier_did,
		   data->domain[0] ? data->domain : "none");

	if (data->trusted_verifier_did[0] &&
	    os_strcmp(data->verifier_did, data->trusted_verifier_did) != 0) {
		wpa_printf(MSG_INFO,
			   "EAP-DID: Invitation is from an untrusted verifier: %s",
			   data->verifier_did);
		return -1;
	}

	if (did_x25519_from_did(data->verifier_did,
				    data->verifier_x25519_pub) < 0) {
		wpa_printf(MSG_INFO,
			   "EAP-DID: No usable key agreement key for %s",
			   data->verifier_did);
		return -1;
	}

	return 0;
}


static void * eap_did_init(struct eap_sm *sm)
{
	struct eap_did_data *data;
	const char *val;

	data = os_zalloc(sizeof(*data));
	if (!data)
		return NULL;

	data->state = START;
	data->fragment_size = EAP_DID_DEFAULT_FRAGMENT_SIZE;

	if (did_credential_load(&data->cred) < 0) {
		wpa_printf(MSG_WARNING,
			   "EAP-DID: No credential configured; set DID_CREDENTIAL or DID_CREDENTIAL_FILE");
	} else if (data->cred.trusted_verifier_did[0]) {
		os_strlcpy(data->trusted_verifier_did,
			   data->cred.trusted_verifier_did,
			   sizeof(data->trusted_verifier_did));
	}

	val = getenv(EAP_DID_TRUSTED_DID_ENV);
	if (val && val[0])
		os_strlcpy(data->trusted_verifier_did, val,
			   sizeof(data->trusted_verifier_did));

	wpa_printf(MSG_DEBUG, "EAP-DID: Initialized (holder=%s, trusted=%s)",
		   data->cred.holder_did[0] ? data->cred.holder_did : "none",
		   data->trusted_verifier_did[0] ?
		   data->trusted_verifier_did : "any");

	return data;
}


static void eap_did_deinit(struct eap_sm *sm, void *priv)
{
	struct eap_did_data *data = priv;

	if (!data)
		return;

	wpabuf_free(data->in_buf);
	wpabuf_free(data->out_buf);
	bin_clear_free(data->cek, data->cek_len);
	bin_clear_free(data, sizeof(*data));
}


static struct wpabuf * eap_did_failure(struct eap_did_data *data,
				       struct eap_method_ret *ret,
				       const char *msg)
{
	wpa_printf(MSG_INFO, "EAP-DID: %s", msg);
	eap_did_state(data, FAILURE);
	ret->methodState = METHOD_DONE;
	ret->decision = DECISION_FAIL;

	return NULL;
}


static struct wpabuf * eap_did_process_downlink(struct eap_did_data *data,
						struct eap_method_ret *ret,
						u8 flags, const u8 *pos,
						const u8 *end, u8 id)
{
	int res;

	res = eap_did_reassemble(data, flags, pos, end);
	if (res < 0)
		return eap_did_failure(data, ret,
				       "Malformed invitation fragment");

	if (res > 0) {
		if (data->state != DOWNLINK)
			eap_did_state(data, DOWNLINK);
		ret->methodState = METHOD_MAY_CONT;
		return eap_did_build_ack(id);
	}

	wpa_printf(MSG_DEBUG, "EAP-DID: Invitation complete (%zu octets)",
		   wpabuf_len(data->in_buf));

	if (eap_did_parse_invitation(data) < 0)
		return eap_did_failure(data, ret, "Could not parse invitation");

	if (eap_did_build_presentation(data) < 0)
		return eap_did_failure(data, ret,
				       "Could not build the presentation");

	eap_did_state(data, UPLINK);

	return eap_did_build_fragment(data, ret, id);
}


static struct wpabuf * eap_did_process(struct eap_sm *sm, void *priv,
				       struct eap_method_ret *ret,
				       const struct wpabuf *reqData)
{
	struct eap_did_data *data = priv;
	const u8 *pos, *end;
	size_t len;
	u8 flags = 0, id;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_DID, reqData, &len);
	if (!pos) {
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}
	end = pos + len;
	if (len > 0)
		flags = *pos++;
	id = eap_get_id(reqData);

	ret->methodState = METHOD_MAY_CONT;
	ret->decision = DECISION_FAIL;

	if (flags & EAP_DID_FLAGS_START) {
		/*
		 * The Start carries the version the authenticator offers, and
		 * it opens the exchange: accepting one later would let a
		 * fragment sequence be restarted from underneath a reassembly.
		 */
		if ((flags & EAP_DID_VERSION_MASK) != EAP_DID_VERSION)
			return eap_did_failure(data, ret,
					       "Unsupported version in Start");

		if (data->state != START)
			return eap_did_failure(data, ret,
					       "Start received after the exchange began");

		wpa_printf(MSG_DEBUG, "EAP-DID: Start received");
		ret->decision = DECISION_COND_SUCC;
		return eap_did_build_ack(id);
	}

	if (data->state == START || data->state == DOWNLINK)
		return eap_did_process_downlink(data, ret, flags, pos, end,
						id);

	if (data->state == WAIT_ACK) {
		if (len > 1)
			return eap_did_failure(data, ret,
					       "Expected a fragment acknowledgement");
		eap_did_state(data, UPLINK);
		return eap_did_build_fragment(data, ret, id);
	}

	/* Keepalive sent while the authenticator verifies the presentation */
	if (len <= 1) {
		ret->decision = DECISION_COND_SUCC;
		return eap_did_build_ack(id);
	}

	wpa_printf(MSG_DEBUG,
		   "EAP-DID: Ignored %zu octets received in state %s", len,
		   eap_did_state_txt(data->state));

	return NULL;
}


static bool eap_did_isKeyAvailable(struct eap_sm *sm, void *priv)
{
	struct eap_did_data *data = priv;

	return data->thid[0] && data->cek && data->cek_len > 0;
}


static u8 * eap_did_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_did_data *data = priv;

	if (!eap_did_isKeyAvailable(sm, priv))
		return NULL;

	*len = EAP_DID_KEY_LEN;

	return eap_did_derive_key_cek(data->cek, data->cek_len, data->thid,
				      "EAP-DID-MSK", EAP_DID_KEY_LEN);
}


static u8 * eap_did_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_did_data *data = priv;

	if (!eap_did_isKeyAvailable(sm, priv))
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


int eap_peer_did_register(void)
{
	struct eap_method *eap;

	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
				    EAP_VENDOR_IETF, EAP_TYPE_DID, "DID");
	if (!eap)
		return -1;

	eap->init = eap_did_init;
	eap->deinit = eap_did_deinit;
	eap->process = eap_did_process;
	eap->isKeyAvailable = eap_did_isKeyAvailable;
	eap->getKey = eap_did_getKey;
	eap->get_emsk = eap_did_get_emsk;
	eap->getSessionId = eap_did_get_session_id;

	return eap_peer_method_register(eap);
}
