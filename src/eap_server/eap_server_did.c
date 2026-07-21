#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * EAP server method: EAP-DID
 *
 * Talks to the Identus Cloud Agent (verifier) via blocking HTTP (libcurl).
 *
 * State machine:
 *   INIT - (buildReq) -> START_SENT
 *   START_SENT - (process: Start ACK + OOB fetch) -> DOWNLINK_TX
 *   DOWNLINK_TX - (fragments done) -> UPLINK_RX
 *   UPLINK_RX - (VP complete -> verify) -> SUCCESS / FAILURE
 */

#include "includes.h"
#include "common.h"
#include "eap_server/eap_i.h"
#include "eap_common/eap_did_common.h"
#include "eap_common/eap_did_http.h"
#include "wpabuf.h"

#include <stdlib.h>
#include <string.h>
#include <openssl/crypto.h>
#include "utils/base64.h"



/* ----------------------------------------------------------------------- *
 * Configuration (env vars)
 * ----------------------------------------------------------------------- */
#define DID_VERIFIER_BASE_ENV   "DID_VERIFIER_BASE_URL"
#define DID_VERIFIER_DEFAULT    "http://caddy-verifier:8082"
#define DID_SCHEMA_ID_ENV       "SCHEMA_ID"
#define DID_ISSUER_DID_ENV      "ISSUER_DID"
#define DID_OOB_TIMEOUT_S       30
#define DID_VERIFY_TIMEOUT_S   90   /* max seconds for VP verification */
#define DID_PRESENTATION_POLL_S  60   /* max polling iterations */


/* ----------------------------------------------------------------------- *
 * Server states
 * ----------------------------------------------------------------------- */
enum did_srv_state {
	DID_SRV_INIT,
	DID_SRV_START_SENT,
	DID_SRV_DOWNLINK_TX,
	DID_SRV_UPLINK_RX,
	DID_SRV_SUCCESS,
	DID_SRV_FAILURE,
};

enum did_srv_frag {
	DID_SRV_FRAG_MSG,		/* expecting a message (Start ACK or VP) */
	DID_SRV_FRAG_WAIT_ACK,		/* sent a fragment, waiting for ACK */
};


/* ----------------------------------------------------------------------- *
 * Per-session data
 * ----------------------------------------------------------------------- */
struct eap_did_srv_data {
	enum did_srv_state state;
	enum did_srv_frag  frag_state;

	char verifier_base[256];
	char holder_base[256];
	char schema_id[512];
	char issuer_did[256];

	/* OOB downlink */
	char thid[128];
	struct wpabuf *dl_buf;
	size_t dl_used;
	size_t fragment_size;

	/* VP reassembly (uplink) */
	struct wpabuf *ul_buf;

	/* CEK from DIDComm JWE (Issue #27) */
	u8 *cek;
	size_t cek_len;
};


/* ----------------------------------------------------------------------- *
 * Forward declarations
 * ----------------------------------------------------------------------- */
static struct wpabuf *srv_build_start(struct eap_did_srv_data *data, u8 id);
static struct wpabuf *srv_build_oob_fragment(struct eap_did_srv_data *data,
					     u8 id);
static struct wpabuf *srv_build_keepalive(u8 id);
static int  srv_fetch_oob(struct eap_did_srv_data *data);
static void srv_process_start_ack(struct eap_did_srv_data *data,
				  u8 flags, size_t len);
static int  srv_process_uplink(struct eap_did_srv_data *data,
			       u8 flags, const u8 *pos, const u8 *end);
/* Issue #27: CEK fetch from verifier presentation API */
static void srv_fetch_cek(struct eap_did_srv_data *data);


/* ----------------------------------------------------------------------- *
 * Build invitation JSON payload for POST to verifier
 * ----------------------------------------------------------------------- */
static char * build_invitation_json(struct eap_did_srv_data *data)
{
	char *json;

	if (data->schema_id[0] == '\0') {
		wpa_printf(MSG_ERROR, "EAP-DID(srv): SCHEMA_ID not configured");
		return NULL;
	}
	if (data->issuer_did[0] == '\0') {
		wpa_printf(MSG_ERROR, "EAP-DID(srv): ISSUER_DID not configured");
		return NULL;
	}

	json = os_malloc(2048);
	if (!json)
		return NULL;

	snprintf(json, 2048,
		    "{"
		    "\"goalCode\":\"verify-eduroam-access\","
		    "\"goal\":\"Usar sua credencial academica para conectar-se a rede Wi-Fi eduroam\","
		    "\"credentialFormat\":\"JWT\","
		    "\"proofs\":[{"
		    "\"schemaId\":\"%s\","
		    "\"trustIssuers\":[\"%s\"]"
		    "}],"
		    "\"options\":{"
		    "\"challenge\":\"A challenge for the holder to sign\","
		    "\"domain\":\"domain.com\""
		    "}}",
		    data->schema_id,
		    data->issuer_did);

	return json;
}


/* ----------------------------------------------------------------------- *
 * Fetch OOB invitation from Identus verifier (blocking HTTP)
 * ----------------------------------------------------------------------- */
static int srv_fetch_oob(struct eap_did_srv_data *data)
{
	char url[512];
	struct did_http_response resp;
	char *body;
	int rc;

	body = build_invitation_json(data);
	if (!body)
		return -1;

	snprintf(url, sizeof(url), "%s/cloud-agent/present-proof/presentations/invitation",
		    data->verifier_base);

	rc = did_http_post(url, "application/json",
			   (const uint8_t *) body, strlen(body),
			   &resp, DID_OOB_TIMEOUT_S);
	os_free(body);

	if (rc != 0 || resp.status < 200 || resp.status >= 300) {
		wpa_printf(MSG_INFO, "EAP-DID(srv): invitation POST failed: "
			   "rc=%d status=%d", rc, resp.status);
		did_http_response_free(&resp);
		return -1;
	}

	/* Extract thid */
	if (did_json_extract_str(resp.body, resp.body_len,
				 "thid", data->thid,
				 sizeof(data->thid)) != 0) {
		wpa_printf(MSG_INFO, "EAP-DID(srv): no thid in invitation response");
		did_http_response_free(&resp);
		return -1;
	}

	/* Extract invitationUrl (can be ~2 KB due to base64 _oob) */
	{
		char inv_url[4096];

		if (did_json_extract_str(resp.body, resp.body_len,
					 "invitationUrl", inv_url,
					 sizeof(inv_url)) == 0) {
			/* Build OOB payload with thid + invitationUrl */
			char *oob_json = os_malloc(8192);
			if (!oob_json) {
				did_http_response_free(&resp);
				return -1;
			}
			snprintf(oob_json, 8192,
				    "{\"thid\":\"%s\",\"invitationUrl\":\"%s\"}",
				    data->thid, inv_url);

			data->dl_buf = wpabuf_alloc(strlen(oob_json));
			if (data->dl_buf)
				wpabuf_put_data(data->dl_buf, oob_json,
						strlen(oob_json));
			os_free(oob_json);
			did_http_response_free(&resp);
		} else {
			/* Fallback: use entire response as OOB payload */
			data->dl_buf = wpabuf_alloc(resp.body_len);
			if (data->dl_buf)
				wpabuf_put_data(data->dl_buf, resp.body,
						resp.body_len);
			did_http_response_free(&resp);
		}
	}

	if (!data->dl_buf) {
		wpa_printf(MSG_INFO, "EAP-DID(srv): OOB buffer alloc failed");
		return -1;
	}

	data->dl_used = 0;
	wpa_printf(MSG_DEBUG, "EAP-DID(srv): OOB fetched (thid=%s, %zu bytes)",
		   data->thid, wpabuf_len(data->dl_buf));
	return 0;
}


/* ----------------------------------------------------------------------- *
 * Deliver VP: gzip decompress -> POST JWE to /didcomm
 * -> poll presentations for PresentationVerified
 *
 * Returns 0 on ACCEPT, -1 on REJECT/error.
 * ----------------------------------------------------------------------- */
static int srv_start_vp_verify(struct eap_did_srv_data *data)
{
	char url[512];
	struct did_http_response resp;
	uint8_t *gzip_out = NULL;
	size_t   gzip_len = 0;
	int rc = -1;

	if (!data->ul_buf || wpabuf_len(data->ul_buf) == 0)
		return -1;

	/* Issue #47: The uplink payload is gzip(JWE) directly - no AES-GCM envelope.
	 * The peer sends gzip(JWE) without additional encryption.
	 * CEK is fetched AFTER PresentationVerified for MSK derivation only. */
	{
		const uint8_t *raw = wpabuf_head_u8(data->ul_buf);
		size_t raw_len = wpabuf_len(data->ul_buf);

		/* Step 1: gzip decompress -> JWE */
		if (did_gzip_decompress(raw, raw_len,
					&gzip_out, &gzip_len) != 0) {
			wpa_printf(MSG_INFO, "EAP-DID(srv): gzip decompress failed");
			goto out;
		}

		wpa_printf(MSG_DEBUG, "EAP-DID(srv): JWE decompressed (%zu bytes)", gzip_len);

		/* Step 2: POST JWE to verifier /didcomm */
		snprintf(url, sizeof(url), "%s/didcomm", data->verifier_base);

		rc = did_http_post(url, "application/didcomm-encrypted+json",
				   gzip_out, gzip_len, &resp, DID_OOB_TIMEOUT_S);

		if (rc != 0 || (resp.status != 200 && resp.status != 202)) {
			wpa_printf(MSG_INFO, "EAP-DID(srv): /didcomm POST failed: "
				   "status=%d", resp.status);
			did_http_response_free(&resp);
			goto out;
		}
		did_http_response_free(&resp);

		wpa_printf(MSG_DEBUG, "EAP-DID(srv): JWE posted to /didcomm");

		/* Step 3: Poll presentations for result */
		snprintf(url, sizeof(url), "%s/cloud-agent/present-proof/presentations",
			    data->verifier_base);

		{
			int verified = 0;
			int poll_count;

			for (poll_count = 0; poll_count < DID_PRESENTATION_POLL_S;
			     poll_count++) {
				os_sleep(1, 0);

				rc = did_http_get(url, &resp, 10);
				if (rc != 0 || resp.status != 200) {
					wpa_printf(MSG_DEBUG,
						   "EAP-DID(srv): poll error (count=%d)",
						   poll_count);
					did_http_response_free(&resp);
					continue;
				}

				/* Search for our thid and check status */
				{
					const char *p = resp.body;
					const char *end = resp.body + resp.body_len;

					while (p < end) {
						const char *found;

						found = memmem(p, (size_t)(end - p),
							       data->thid,
							       strlen(data->thid));
						if (!found)
							break;

						{
							const char *scan_start = found;
							const char *scan_end = found + 500;
							char local_status[64];

							if (scan_end > end)
								scan_end = end;

							local_status[0] = '\0';
							if (did_json_extract_str(
								    scan_start,
								    (size_t)(scan_end - scan_start),
								    "status",
								    local_status,
								    sizeof(local_status)) == 0) {
								if (strcmp(local_status,
									   "PresentationVerified") == 0 ||
								    strcmp(local_status,
									   "PresentationAccepted") == 0) {
									verified = 1;
									break;
								}
								if (strcmp(local_status,
									   "PresentationVerificationFailed") == 0 ||
								    strcmp(local_status,
									   "PresentationRejected") == 0) {
									wpa_printf(MSG_INFO,
										   "EAP-DID(srv): VP %s",
										   local_status);
									did_http_response_free(&resp);
									goto out;
								}
							}
						}

						p = found + 1;
					}
				}

				did_http_response_free(&resp);

				if (verified)
					break;
			}

			if (verified) {
				wpa_printf(MSG_INFO, "EAP-DID(srv): VP ACCEPT");
				/* Issue #47: Fetch CEK from holder for MSK/EMSK derivation.
				 * Full isolation (#46) requires decrypt-side CEK from Verifier (#45). */
				srv_fetch_cek(data);
				rc = 0;
				goto out;
			}

			wpa_printf(MSG_INFO, "EAP-DID(srv): VP TIMEOUT (no result "
				   "after %d polls)", DID_PRESENTATION_POLL_S);
			rc = -1;
			goto out;
		}
	}

out:
	os_free(gzip_out);
	return rc;
}


/* ----------------------------------------------------------------------- *
 * Build Start packet
 * ----------------------------------------------------------------------- */
static struct wpabuf * srv_build_start(struct eap_did_srv_data *data, u8 id)
{
	struct wpabuf *req;
	u8 *flags;

	data->state = DID_SRV_START_SENT;
	data->frag_state = DID_SRV_FRAG_WAIT_ACK;

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_DID, 1,
			    EAP_CODE_REQUEST, id);
	if (!req)
		return NULL;
	flags = wpabuf_put(req, 1);
	*flags = EAP_DID_VERSION | EAP_DID_FLAGS_START;

	wpa_printf(MSG_DEBUG, "EAP-DID(srv): -> Start (v=%d)", EAP_DID_VERSION);
	return req;
}


/* ----------------------------------------------------------------------- *
 * Build next OOB fragment (or keepalive if dl_buf is exhausted)
 * ----------------------------------------------------------------------- */
static struct wpabuf * srv_build_oob_fragment(struct eap_did_srv_data *data,
					      u8 id)
{
	struct wpabuf *req;
	u8 *flags;
	size_t remaining, send_len;
	int more, length_included;

	if (!data->dl_buf)
		return srv_build_keepalive(id);

	remaining = wpabuf_len(data->dl_buf) - data->dl_used;
	if (remaining > data->fragment_size) {
		more = 1;
		send_len = data->fragment_size;
	} else {
		more = 0;
		send_len = remaining;
	}
	length_included = (data->dl_used == 0 &&
			   wpabuf_len(data->dl_buf) > data->fragment_size);

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_DID,
			    1 + (length_included ? 4 : 0) + send_len,
			    EAP_CODE_REQUEST, id);
	if (!req)
		return NULL;

	flags = wpabuf_put(req, 1);
	*flags = EAP_DID_VERSION;
	if (more)
		*flags |= EAP_DID_FLAGS_MORE_FRAGMENTS;
	if (length_included) {
		*flags |= EAP_DID_FLAGS_LENGTH_INCLUDED;
		wpabuf_put_be32(req, wpabuf_len(data->dl_buf));
	}
	wpabuf_put_data(req,
			wpabuf_head_u8(data->dl_buf) + data->dl_used,
			send_len);
	data->dl_used += send_len;

	if (!more) {
		/* Last OOB fragment delivered - expect VP data from peer */
		wpabuf_free(data->dl_buf);
		data->dl_buf = NULL;
		data->dl_used = 0;
		data->state = DID_SRV_UPLINK_RX;
		data->frag_state = DID_SRV_FRAG_MSG;
	} else {
		data->frag_state = DID_SRV_FRAG_WAIT_ACK;
	}

	wpa_printf(MSG_DEBUG,
		   "EAP-DID(srv): -> OOB frag (%zu bytes, more=%d)",
		   send_len, more);
	return req;
}


/* ----------------------------------------------------------------------- *
 * Build a bare keepalive request (no payload)
 * ----------------------------------------------------------------------- */
static struct wpabuf * srv_build_keepalive(u8 id)
{
	struct wpabuf *req;
	u8 *flags;

	req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_DID, 1,
			    EAP_CODE_REQUEST, id);
	if (!req)
		return NULL;
	flags = wpabuf_put(req, 1);
	*flags = EAP_DID_VERSION;
	return req;
}


/* ----------------------------------------------------------------------- *
 * Main buildReq - state dispatcher
 * ----------------------------------------------------------------------- */
static struct wpabuf * eap_did_srv_buildReq(struct eap_sm *sm, void *priv,
					    u8 id)
{
	struct eap_did_srv_data *data = priv;

	switch (data->state) {
	case DID_SRV_INIT:
		return srv_build_start(data, id);

	case DID_SRV_START_SENT:
		return srv_build_keepalive(id);

	case DID_SRV_DOWNLINK_TX:
		return srv_build_oob_fragment(data, id);

	case DID_SRV_UPLINK_RX:
		return srv_build_keepalive(id);

	default:
		return NULL;
	}
}


/* ----------------------------------------------------------------------- *
 * Process a Start ACK from the peer
 * ----------------------------------------------------------------------- */
static void srv_process_start_ack(struct eap_did_srv_data *data,
				  u8 flags, size_t len)
{
	u8 peer_version;

	peer_version = (len >= 1) ? (flags & EAP_DID_VERSION_MASK)
				  : EAP_DID_VERSION;
	if (peer_version != EAP_DID_VERSION) {
		wpa_printf(MSG_INFO, "EAP-DID(srv): peer v=%d != our v=%d",
			   peer_version, EAP_DID_VERSION);
		data->state = DID_SRV_FAILURE;
		return;
	}

	/* Fetch OOB invitation from Identus verifier (blocking HTTP) */
	wpa_printf(MSG_DEBUG, "EAP-DID(srv): fetching OOB ...");
	if (srv_fetch_oob(data) != 0) {
		wpa_printf(MSG_INFO, "EAP-DID(srv): OOB fetch failed");
		data->state = DID_SRV_FAILURE;
		return;
	}

	data->state = DID_SRV_DOWNLINK_TX;
	data->frag_state = DID_SRV_FRAG_MSG;
	wpa_printf(MSG_DEBUG, "EAP-DID(srv): OOB ready, starting downlink");
}


/* ----------------------------------------------------------------------- *
 * Process uplink VP fragments from the peer
 * ----------------------------------------------------------------------- */
static int srv_process_uplink(struct eap_did_srv_data *data,
			      u8 flags, const u8 *pos, const u8 *end)
{
	u32 message_length = 0;

	if ((flags & EAP_DID_VERSION_MASK) != EAP_DID_VERSION) {
		data->state = DID_SRV_FAILURE;
		return -1;
	}

	if (flags & EAP_DID_FLAGS_LENGTH_INCLUDED) {
		if ((size_t)(end - pos) < 4) {
			data->state = DID_SRV_FAILURE;
			return -1;
		}
		message_length = WPA_GET_BE32(pos);
		pos += 4;
	}

	if (flags & EAP_DID_FLAGS_MORE_FRAGMENTS) {
		/* More fragments to come */
		if (!data->ul_buf) {
			if (!message_length ||
			    message_length > EAP_DID_MAX_FILE_SIZE) {
				data->state = DID_SRV_FAILURE;
				return -1;
			}
			data->ul_buf = wpabuf_alloc(message_length);
			if (!data->ul_buf) {
				data->state = DID_SRV_FAILURE;
				return -1;
			}
		}
		if ((size_t)(end - pos) > wpabuf_tailroom(data->ul_buf)) {
			data->state = DID_SRV_FAILURE;
			return -1;
		}
		wpabuf_put_data(data->ul_buf, pos, (size_t)(end - pos));
		return 0;
	}

	/* Last fragment */
	if (data->ul_buf) {
		size_t remaining = (size_t)(end - pos);
		if (remaining > wpabuf_tailroom(data->ul_buf)) {
			data->state = DID_SRV_FAILURE;
			return -1;
		}
		if (remaining > 0)
			wpabuf_put_data(data->ul_buf, pos, remaining);
	} else {
		size_t remaining = (size_t)(end - pos);
		if (remaining == 0)
			return 0;
		data->ul_buf = wpabuf_alloc(remaining);
		if (!data->ul_buf) {
			data->state = DID_SRV_FAILURE;
			return -1;
		}
		wpabuf_put_data(data->ul_buf, pos, remaining);
	}

	data->frag_state = DID_SRV_FRAG_MSG;

	/* VP complete - start async verification */
	wpa_printf(MSG_DEBUG, "EAP-DID(srv): VP received (%zu bytes), starting verify...",
		   wpabuf_len(data->ul_buf));

	if (srv_start_vp_verify(data) == 0) {
		wpa_printf(MSG_DEBUG, "EAP-DID(srv): VP verified");
		data->state = DID_SRV_SUCCESS;
	} else {
		wpa_printf(MSG_INFO, "EAP-DID(srv): VP verification failed");
		data->state = DID_SRV_FAILURE;
	}

	wpabuf_free(data->ul_buf);
	data->ul_buf = NULL;
	return 0;
}


/* ----------------------------------------------------------------------- *
 * Main process - called for every EAP Response from peer
 * ----------------------------------------------------------------------- */
static void eap_did_srv_process(struct eap_sm *sm, void *priv,
				struct wpabuf *respData)
{
	struct eap_did_srv_data *data = priv;
	const u8 *pos, *end;
	size_t len;
	u8 flags = 0;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_DID, respData, &len);
	if (!pos)
		return;
	end = pos + len;

	if (len > 0)
		flags = *pos++;
	else
		pos = end;

	/* Start ACK - received after we sent Start */
	if (data->state == DID_SRV_START_SENT &&
	    data->frag_state == DID_SRV_FRAG_WAIT_ACK) {
		if (len <= 1) {
			srv_process_start_ack(data, flags, len);
		} else {
			data->state = DID_SRV_FAILURE;
		}
		return;
	}

	/* Fragment ACK during OOB downlink (not during uplink VP phase) */
	if (data->frag_state == DID_SRV_FRAG_WAIT_ACK &&
	    data->state == DID_SRV_DOWNLINK_TX) {
		if (len > 1) {
			data->state = DID_SRV_FAILURE;
			return;
		}
		data->frag_state = DID_SRV_FRAG_MSG;
		return;
	}

	/* Uplink VP fragments from peer */
	if (data->state == DID_SRV_UPLINK_RX) {
		srv_process_uplink(data, flags, pos, end);
		return;
	}

	/* Keepalive / unexpected */
	if (len <= 1)
		return;

	wpa_printf(MSG_DEBUG,
		   "EAP-DID(srv): unexpected data in state=%d", data->state);
}


/* ----------------------------------------------------------------------- *
 * State queries
 * ----------------------------------------------------------------------- */

static bool eap_did_srv_check(struct eap_sm *sm, void *priv,
			      struct wpabuf *respData)
{
	const u8 *pos;
	size_t len;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_DID, respData, &len);
	return pos == NULL;
}

static bool eap_did_srv_isDone(struct eap_sm *sm, void *priv)
{
	struct eap_did_srv_data *data = priv;
	return data->state == DID_SRV_SUCCESS ||
	       data->state == DID_SRV_FAILURE;
}

static bool eap_did_srv_isSuccess(struct eap_sm *sm, void *priv)
{
	struct eap_did_srv_data *data = priv;
	return data->state == DID_SRV_SUCCESS;
}

static int eap_did_srv_getTimeout(struct eap_sm *sm, void *priv)
{
	return 5;
}


/* ----------------------------------------------------------------------- *
 * Key derivation
 * ----------------------------------------------------------------------- */


/* ----------------------------------------------------------------------- *
 * Issue #27: Fetch CEK from Verifier presentation API
 *
 * After PresentationVerified, send GET with X-EAP-KeyMaterial header.
 * If the Cloud Agent supports it, the response includes keyMaterial.cek
 * (hex-encoded).  This is the ECDH-ES output from DIDComm JWE.
 *
 * If the API does not support this header yet (unmodified Identus),
 * the CEK is simply absent and we fall back to thid-based derivation.
 * ----------------------------------------------------------------------- */
static void srv_fetch_cek(struct eap_did_srv_data *data)
{
	char url[512];
	struct did_http_response resp = {0};
	const char *hdrs[] = { "X-EAP-KeyMaterial: 1", NULL };
	char cek_b64[512];

	/* Issue #46: Fetch CEK from Verifier (not Holder) to restore network isolation */
	if (!data->verifier_base[0] || !data->thid[0])
		return;

	snprintf(url, sizeof(url), "%s/cloud-agent/present-proof/presentations?thid=%s",
		 data->verifier_base, data->thid);

	if (did_http_get_hdr(url, hdrs, &resp, 10) != 0 || resp.status != 200) {
		wpa_printf(MSG_DEBUG, "EAP-DID: CEK not available (status=%d)", resp.status);
		did_http_response_free(&resp);
		return;
	}

	if (did_json_extract_str(resp.body, resp.body_len,
				"cek", cek_b64, sizeof(cek_b64)) == 0) {
		/* Issue #50: CEK is Base64URL-encoded, not hex.
		 * base64_url_decode handles padding automatically. */
		size_t b64_len = strlen(cek_b64);
		size_t out_len = 0;
		u8 *bin = base64_url_decode(cek_b64, b64_len, &out_len);

		if (!bin || out_len == 0) {
			wpa_printf(MSG_DEBUG, "EAP-DID: CEK base64url decode failed (len=%zu)", b64_len);
			free(bin);
			did_http_response_free(&resp);
			return;
		}

		data->cek = bin;
		data->cek_len = out_len;
		wpa_printf(MSG_INFO, "EAP-DID: CEK obtained from verifier (%zu bytes)", out_len);
	} else {
		wpa_printf(MSG_WARNING, "EAP-DID(srv): CEK not in verifier response - key derivation will fail (issue #39)");
	}

	did_http_response_free(&resp);
}

static u8 * eap_did_srv_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_did_srv_data *data = priv;
	if (!data->thid[0])
		return NULL;
	/* CEK is mandatory (issue #39) */
	if (!data->cek || data->cek_len == 0)
		return NULL;
	*len = 64;
	wpa_printf(MSG_DEBUG, "EAP-DID: deriving MSK from CEK (%zu bytes)", data->cek_len);
	return eap_did_derive_key_cek(data->cek, data->cek_len,
				      data->thid, "EAP-DID-MSK", 64);
}

static u8 * eap_did_srv_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_did_srv_data *data = priv;
	if (!data->thid[0])
		return NULL;
	/* CEK is mandatory (issue #39) */
	if (!data->cek || data->cek_len == 0)
		return NULL;
	*len = 64;
	return eap_did_derive_key_cek(data->cek, data->cek_len,
				      data->thid, "EAP-DID-EMSK", 64);
}

static u8 * eap_did_srv_get_session_id(struct eap_sm *sm, void *priv,
				       size_t *len)
{
	struct eap_did_srv_data *data = priv;
	if (!data->thid[0])
		return NULL;
	return eap_did_get_session_id(EAP_TYPE_DID, data->thid, len);
}


/* ----------------------------------------------------------------------- *
 * Init / Reset
 * ----------------------------------------------------------------------- */

static void * eap_did_srv_init(struct eap_sm *sm)
{
	struct eap_did_srv_data *data;
	const char *val;

	data = os_zalloc(sizeof(*data));
	if (!data)
		return NULL;

	data->state = DID_SRV_INIT;
	data->frag_state = DID_SRV_FRAG_MSG;
	data->fragment_size = (sm->cfg && sm->cfg->fragment_size > 0) ?
		(size_t) sm->cfg->fragment_size :
		(size_t) EAP_DID_DEFAULT_FRAGMENT_SIZE;

	/* Configuration from env */
	val = getenv(DID_VERIFIER_BASE_ENV);
	if (val)
		os_strlcpy(data->verifier_base, val, sizeof(data->verifier_base));
	else
		os_strlcpy(data->verifier_base, DID_VERIFIER_DEFAULT,
			   sizeof(data->verifier_base));

	val = getenv("DID_HOLDER_BASE_URL");
	if (val)
		os_strlcpy(data->holder_base, val, sizeof(data->holder_base));
	else
		data->holder_base[0] = 0;

	val = getenv(DID_SCHEMA_ID_ENV);
	if (val)
		os_strlcpy(data->schema_id, val, sizeof(data->schema_id));

	val = getenv(DID_ISSUER_DID_ENV);
	if (val)
		os_strlcpy(data->issuer_did, val, sizeof(data->issuer_did));

	wpa_printf(MSG_DEBUG, "EAP-DID(srv): init (verifier=%s)",
		   data->verifier_base);
	return data;
}

static void eap_did_srv_reset(struct eap_sm *sm, void *priv)
{
	struct eap_did_srv_data *data = priv;

	if (!data)
		return;
	wpabuf_free(data->dl_buf);
	wpabuf_free(data->ul_buf);
	os_free(data->cek);
	os_free(data);
}


/* ----------------------------------------------------------------------- *
 * Registration
 * ----------------------------------------------------------------------- */

int eap_server_did_register(void)
{
	struct eap_method *eap;

	wpa_printf(MSG_DEBUG, "EAP-DID(srv): register");
	did_http_init();

	eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
				      EAP_VENDOR_IETF, EAP_TYPE_DID, "DID");
	if (!eap)
		return -1;

	eap->init = eap_did_srv_init;
	eap->reset = eap_did_srv_reset;
	eap->buildReq = eap_did_srv_buildReq;
	eap->check = eap_did_srv_check;
	eap->process = eap_did_srv_process;
	eap->isDone = eap_did_srv_isDone;
	eap->isSuccess = eap_did_srv_isSuccess;
	eap->getTimeout = eap_did_srv_getTimeout;
	eap->getKey = eap_did_srv_getKey;
	eap->get_emsk = eap_did_srv_get_emsk;
	eap->getSessionId = eap_did_srv_get_session_id;

	return eap_server_method_register(eap);
}
