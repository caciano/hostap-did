/*
 * EAP peer method: EAP-DID
 *
 * Talks directly to the Identus Cloud Agent (holder) via blocking HTTP.
 * A libmicrohttpd daemon (epoll mode, registered with eloop) captures
 * the DIDComm JWE envelope pushed by the holder agent on port 9090.
 *
 * No pthread, no pipes, no mutexes — MHD runs inside the existing eloop.
 *
 * State machine:
 *   WAIT_START - (process: Start -> ACK) -> DOWNLINK_RX
 *   DOWNLINK_RX - (OOB complete -> HTTP invitation) -> INVITATION
 *   INVITATION - (JWE captured -> gzip -> AES-GCM encrypt) -> UPLINK_TX
 *   UPLINK_TX - (VP fragments) -> WAIT_FRAG_ACK - (ACK) -> UPLINK_TX
 *   UPLINK_TX - (last fragment) -> DONE
 */

#include "includes.h"
#include "common.h"
#include "eap_peer/eap_i.h"
#include "eap_peer/eap_config.h"
#include "eap_common/eap_did_common.h"
#include "eap_common/eap_did_http.h"
#include "wpabuf.h"
#include "eloop.h"

#include <microhttpd.h>
#include <stdlib.h>
#include <string.h>
#include "utils/base64.h"
#include <openssl/crypto.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
/* ----------------------------------------------------------------------- *
 * Configuration (env vars)
 * ----------------------------------------------------------------------- */
#define DID_HOLDER_BASE_ENV     "DID_HOLDER_BASE_URL"
#define DID_HOLDER_DEFAULT      "http://caddy-holder:8081"
#define DID_CRED_ID_ENV         "DID_CRED_ID"
#define DID_TRUSTED_VERIFIER_DID_ENV  "DID_TRUSTED_VERIFIER_DID"
#define DID_CRED_ID_FILE        "/tmp/holder_cred_id.txt"
#define DIDCOMM_LISTEN_PORT     8082
#define DID_PEER_WAIT_MAX       120   /* max seconds waiting for JWE */
/* ----------------------------------------------------------------------- *
 * Peer states
 * ----------------------------------------------------------------------- */
enum did_peer_state {
	DID_PEER_WAIT_START,
	DID_PEER_DOWNLINK_RX,
	DID_PEER_INVITATION,
	DID_PEER_UPLINK_TX,
	DID_PEER_WAIT_FRAG_ACK,
	DID_PEER_DONE,
	DID_PEER_FAIL,
};
/* ----------------------------------------------------------------------- *
 * Per-session data
 * ----------------------------------------------------------------------- */
struct eap_did_data {
	enum did_peer_state state;

	/* Identus holder base URL */
	char holder_base[256];
	char cred_id[256];

	/* Downlink reassembly (OOB from server) */
	struct wpabuf *dl_in_buf;
	size_t fragment_size;

	/* Uplink fragmentation (VP to server) */
	struct wpabuf *ul_out_buf;
	size_t ul_out_used;

	/* Thread ID extracted from OOB */
	char thid[128];

	/* F-03: Trusted verifier DID for server authentication */
	char trusted_verifier_did[256];

	/* libmicrohttpd DIDComm listener (epoll, no thread) */
	struct MHD_Daemon *mhd_daemon;
	int mhd_epoll_fd;

	/* Captured JWE from holder agent */
	uint8_t *captured_jwe;
	size_t captured_jwe_len;

	/* Tracking MHD request state (per connection) */
	void *conn_state;

	/* Probe / retransmit tracking */
	struct os_reltime invite_start;
	int poll_count;

	/* Async invitation processing */
	int invite_http_done;  /* 0=pending, 1=success, -1=fail */
	int invite_http_started;

	/* CEK from DIDComm JWE (Issue #27) */
	u8 *cek;
	size_t cek_len;
};

/* ----------------------------------------------------------------------- *
 * Forward declarations
 * ----------------------------------------------------------------------- */
static struct wpabuf *peer_build_frag_ack(u8 id);
static struct wpabuf *peer_build_vp_fragment(struct eap_did_data *data,
					     struct eap_method_ret *ret,
					     u8 id);
static int  peer_append_fragment(struct eap_did_data *data, u8 flags,
				 const u8 *pos, const u8 *end);
static int  peer_process_invitation(struct eap_did_data *data);
/* Issue #27: CEK fetch from holder presentation API */
static void peer_fetch_cek(struct eap_did_data *data);

/* ----------------------------------------------------------------------- *
 * MHD accept policy callback — restrict connections to configured IP
 * ----------------------------------------------------------------------- */
static enum MHD_Result mhd_accept_policy_cb(void *cls,
					    const struct sockaddr *addr,
					    socklen_t addrlen)
{
	const char *allowed_ip;
	char client_ip[64] = {0};

	(void) cls;
	(void) addrlen;

	if (addr->sa_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *) addr;
		inet_ntop(AF_INET, &sin->sin_addr, client_ip, sizeof(client_ip));
	} else if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *) addr;
		inet_ntop(AF_INET6, &sin6->sin6_addr, client_ip, sizeof(client_ip));
	}

	allowed_ip = getenv("DID_HOLDER_IP");

	if (allowed_ip && client_ip[0]) {
		if (strcmp(client_ip, allowed_ip) == 0)
			return MHD_YES;
		wpa_printf(MSG_WARNING,
			   "EAP-DID(peer): MHD rejecting connection from %s (expected %s)",
			   client_ip, allowed_ip);
		return MHD_NO;
	}

	/* Issue #49: No DID_HOLDER_IP configured -- restricted RFC1918 mode.
	 * Production deployments MUST set DID_HOLDER_IP for strict enforcement.
	 * The Docker testbed uses multi-network setups where the holder IP cannot
	 * be predicted at init time. Accept RFC1918 but log WARNING for visibility. */
	{
		unsigned int a, b;
		if (sscanf(client_ip, "%u.%u.", &a, &b) == 2 &&
		    ((a == 10) ||
		     (a == 172 && b >= 16 && b <= 31) ||
		     (a == 192 && b == 168) ||
		     (a == 127))) {
			wpa_printf(MSG_WARNING,
				   "EAP-DID(peer): MHD accept from %s (DID_HOLDER_IP not set - set it for production!)",
				   client_ip);
			return MHD_YES;
		}
	}

	wpa_printf(MSG_WARNING,
		   "EAP-DID(peer): MHD rejecting connection from %s (not RFC1918/loopback; set DID_HOLDER_IP)",
		   client_ip);
	return MHD_NO;
}
static enum MHD_Result mhd_jwe_cb(void *cls,
				  struct MHD_Connection *connection,
				  const char *url, const char *method,
				  const char *version,
				  const char *upload_data,
				  size_t *upload_data_size,
				  void **con_cls);
static void mhd_eloop_cb(int sock, void *eloop_ctx, void *sock_ctx);
static void peer_invite_timeout_cb(void *eloop_ctx, void *user_ctx);
/* ----------------------------------------------------------------------- *
 * MHD access handler — captures POST body (JWE) from the holder agent
 * ----------------------------------------------------------------------- */
struct mhd_post_state {
	uint8_t *body;
	size_t body_len;
	size_t body_cap;
};

static void mhd_req_completed_cb(void *cls,
				 struct MHD_Connection *connection,
				 void **con_cls,
				 enum MHD_RequestTerminationCode toe)
{
	struct mhd_post_state *ps = *con_cls;

	(void) cls;
	(void) connection;
	(void) toe;

	if (ps) {
		os_free(ps->body);
		os_free(ps);
		*con_cls = NULL;
	}
}
static enum MHD_Result mhd_jwe_cb(void *cls,
				   struct MHD_Connection *connection,
				   const char *url, const char *method,
				   const char *version,
				   const char *upload_data,
				   size_t *upload_data_size,
				   void **con_cls)
{
	struct eap_did_data *data = cls;

	(void) url;
	(void) version;

	/* Only accept POST */
	if (strcmp(method, "POST") != 0)
		return MHD_NO;

	if (*con_cls == NULL) {
		struct mhd_post_state *ps;

		/* First call for this connection — allocate tracking state */
		ps = os_zalloc(sizeof(*ps));
		if (!ps)
			return MHD_NO;
		*con_cls = ps;
		return MHD_YES;
	}

	if (*upload_data_size > 0) {
		/* Accumulate body chunks */
		struct mhd_post_state *ps = *con_cls;
		size_t needed = ps->body_len + *upload_data_size;

		if (needed > ps->body_cap) {
			uint8_t *nb;

			needed += 1024; /* grow in ~1 KB increments */
			nb = os_realloc(ps->body, needed);
			if (!nb) {
				*upload_data_size = 0;
				return MHD_YES;
			}
			ps->body = nb;
			ps->body_cap = needed;
		}
		os_memcpy(ps->body + ps->body_len, upload_data,
			  *upload_data_size);
		ps->body_len += *upload_data_size;
		*upload_data_size = 0;
		return MHD_YES;
	}

	/* Request fully received — store the JWE in the session */
	{
		struct mhd_post_state *ps = *con_cls;

		os_free(data->captured_jwe);
		if (ps->body && ps->body_len > 0) {
			data->captured_jwe = ps->body;
			data->captured_jwe_len = ps->body_len;
			ps->body = NULL;  /* ownership transferred */
			ps->body_len = 0;
			ps->body_cap = 0;

			wpa_printf(MSG_DEBUG,
				   "EAP-DID(peer): DIDComm JWE captured (%zu bytes)",
				   data->captured_jwe_len);
		} else {
			data->captured_jwe = NULL;
			data->captured_jwe_len = 0;
		}

		/* Send HTTP 200 OK */
		{
			struct MHD_Response *resp;

			resp = MHD_create_response_from_buffer(
				2, (void *) "{}", MHD_RESPMEM_PERSISTENT);
			if (resp) {
				MHD_add_response_header(
					resp, "Content-Type",
					"application/json");
				MHD_queue_response(connection,
						   MHD_HTTP_OK, resp);
				MHD_destroy_response(resp);
			}
		}
	}

	return MHD_YES;
}
/* ----------------------------------------------------------------------- *
 * MHD eloop callback — drives MHD when the epoll fd is readable
 * ----------------------------------------------------------------------- */
static void mhd_eloop_cb(int sock, void *eloop_ctx, void *sock_ctx)
{
	struct eap_did_data *data = eloop_ctx;

	(void) sock;
	(void) sock_ctx;

	if (data->mhd_daemon)
		MHD_run(data->mhd_daemon);
}
/* ----------------------------------------------------------------------- *
 * Eloop timeout callback — runs the blocking HTTP invitation sequence
 * outside of process(), so the eloop stays responsive.
 * ----------------------------------------------------------------------- */
static void peer_invite_timeout_cb(void *eloop_ctx, void *user_ctx)
{
	struct eap_did_data *data = eloop_ctx;
	(void) user_ctx;

	if (!data || data->invite_http_started)
		return;

	data->invite_http_started = 1;
	wpa_printf(MSG_DEBUG, "EAP-DID(peer): invitation HTTP sequence starting...");

	if (peer_process_invitation(data) == 0) {
		data->invite_http_done = 1;
		wpa_printf(MSG_DEBUG, "EAP-DID(peer): invitation HTTP done");
	} else {
		data->invite_http_done = -1;
		wpa_printf(MSG_INFO, "EAP-DID(peer): invitation HTTP failed");
	}
}

/* ----------------------------------------------------------------------- *
 * Process OOB invitation via Identus holder REST API (blocking HTTP)
 * Returns 0 on success, -1 on error.
 * ----------------------------------------------------------------------- */
static int peer_process_invitation(struct eap_did_data *data)
{
	char url[1024];
	struct did_http_response resp;
	char invitation_url[4096];
	char oob_value[4096];
	char presentation_id[256];
	int rc;

	/* Step 1: Parse OOB JSON to get invitationUrl */
	if (!data->dl_in_buf || wpabuf_len(data->dl_in_buf) == 0) {
		wpa_printf(MSG_DEBUG, "EAP-DID(peer): dl_in_buf empty");
		return -1;
	}
	wpa_printf(MSG_DEBUG, "EAP-DID(peer): dl_in_buf has %zu bytes",
		   wpabuf_len(data->dl_in_buf));

	rc = did_json_extract_str(
		(const char *) wpabuf_head_u8(data->dl_in_buf),
		wpabuf_len(data->dl_in_buf),
		"invitationUrl", invitation_url, sizeof(invitation_url));
	if (rc != 0) {
		wpa_printf(MSG_INFO, "EAP-DID(peer): no invitationUrl in OOB");
		return -1;
	}
	wpa_printf(MSG_DEBUG, "EAP-DID(peer): invitationUrl found (%zu chars)",
		   strlen(invitation_url));

	/* Extract thid */
	did_json_extract_str(
		(const char *) wpabuf_head_u8(data->dl_in_buf),
		wpabuf_len(data->dl_in_buf),
		"thid", data->thid, sizeof(data->thid));

	/* F-03: Verify verifier DID if trusted_verifier_did is configured */
	if (data->trusted_verifier_did[0]) {
		char from_did[256];

		if (did_json_extract_str(
			    (const char *) wpabuf_head_u8(data->dl_in_buf),
			    wpabuf_len(data->dl_in_buf),
			    "from", from_did, sizeof(from_did)) == 0) {
			if (os_strcmp(from_did, data->trusted_verifier_did) != 0) {
				wpa_printf(MSG_INFO,
					   "EAP-DID(peer): OOB from DID mismatch: %s != %s",
					   from_did, data->trusted_verifier_did);
				return -1;
			}
			wpa_printf(MSG_DEBUG,
				   "EAP-DID(peer): Verifier DID verified: %s",
				   from_did);
		} else {
			wpa_printf(MSG_INFO,
				   "EAP-DID(peer): No from field in OOB - cannot verify verifier DID");
			return -1;
		}
	} else {
		wpa_printf(MSG_DEBUG,
			   "EAP-DID(peer): DID_TRUSTED_VERIFIER_DID not set - skipping server auth (F-03 open)");
	}

	/* Extract _oob from URL */
	rc = did_extract_oob_from_url(invitation_url, oob_value,
				      sizeof(oob_value));
	if (rc != 0) {
		wpa_printf(MSG_INFO, "EAP-DID(peer): no _oob in invitation URL");
		return -1;
	}
	wpa_printf(MSG_DEBUG, "EAP-DID(peer): _oob extracted (%zu chars), holder=%s",
		   strlen(oob_value), data->holder_base);

	wpa_printf(MSG_DEBUG, "EAP-DID(peer): OOB parsed, accepting invitation ...");

	/* Step 2: POST accept-invitation */
	snprintf(url, sizeof(url),
		    "%s/cloud-agent/present-proof/presentations/accept-invitation",
		    data->holder_base);

	{
		char accept_body[8192];

		snprintf(accept_body, sizeof(accept_body),
			    "{\"invitation\":\"%s\"}", oob_value);

		rc = did_http_post(url, "application/json",
				   (const uint8_t *) accept_body,
				   strlen(accept_body), &resp, 30);
		if (rc != 0 || resp.status < 200 || resp.status >= 300) {
			wpa_printf(MSG_INFO,
				   "EAP-DID(peer): accept-invitation failed: %d",
				   resp.status);
			did_http_response_free(&resp);
			return -1;
		}
	}

	/* Extract presentationId */
	rc = did_json_extract_str(resp.body, resp.body_len,
				  "presentationId", presentation_id,
				  sizeof(presentation_id));
	did_http_response_free(&resp);

	if (rc != 0) {
		wpa_printf(MSG_INFO,
			   "EAP-DID(peer): no presentationId in response");
		return -1;
	}

	wpa_printf(MSG_DEBUG, "EAP-DID(peer): invitation accepted, presId=%s",
		   presentation_id);

	/* Step 3: Read credential ID */
	if (data->cred_id[0] == '\0') {
		const char *env_cred;

		env_cred = getenv(DID_CRED_ID_ENV);
		if (env_cred) {
			os_strlcpy(data->cred_id, env_cred,
				   sizeof(data->cred_id));
		} else {
			/* Try file (set by test script) */
			FILE *f;
			int attempts;

			for (attempts = 0; attempts < 60; attempts++) {
				f = fopen(DID_CRED_ID_FILE, "r");
				if (f)
					break;
				os_sleep(1, 0);
			}
			if (f) {
				char buf[256];

				if (fgets(buf, sizeof(buf), f))
					os_strlcpy(data->cred_id, buf,
						   sizeof(data->cred_id));
				fclose(f);
			}
		}

		/* Strip trailing whitespace */
		{
			size_t cl = strlen(data->cred_id);

			while (cl > 0 &&
			       (data->cred_id[cl - 1] == '\n' ||
				data->cred_id[cl - 1] == '\r' ||
				data->cred_id[cl - 1] == ' ' ||
				data->cred_id[cl - 1] == '\t')) {
				data->cred_id[cl - 1] = '\0';
				cl--;
			}
		}
	}

	if (data->cred_id[0] == '\0') {
		wpa_printf(MSG_INFO, "EAP-DID(peer): no credential ID");
		return -1;
	}

	/* Step 4: PATCH request-accept */
	snprintf(url, sizeof(url),
		    "%s/cloud-agent/present-proof/presentations/%s",
		    data->holder_base, presentation_id);

	{
		char patch_body[512];

		snprintf(patch_body, sizeof(patch_body),
			    "{\"action\":\"request-accept\",\"proofId\":[\"%s\"]}",
			    data->cred_id);

		rc = did_http_patch(url, "application/json",
				    (const uint8_t *) patch_body,
				    strlen(patch_body), &resp, 30);
		if (rc != 0 || resp.status < 200 || resp.status >= 300) {
			wpa_printf(MSG_INFO,
				   "EAP-DID(peer): request-accept failed: %d",
				   resp.status);
			did_http_response_free(&resp);
			return -1;
		}
		did_http_response_free(&resp);
	}

	wpa_printf(MSG_DEBUG, "EAP-DID(peer): request-accept PATCHed");
	/* CEK fetch deferred to peer_check_jwe_captured() — holder hasn't packed VP yet */
	wpa_printf(MSG_DEBUG, "EAP-DID(peer): waiting for DIDComm JWE on port %d ...",
		   DIDCOMM_LISTEN_PORT);
	return 0;
}
/* ----------------------------------------------------------------------- *
 * Check whether the JWE has been captured and, if so, compress and encrypt
 * it for uplink transport.
 *
 * Called from process() while in INVITATION state.
 *
 * Returns  0 when JWE has been processed (ul_out_buf is ready).
 * Returns  1 when still waiting for JWE.
 * Returns -1 on error.
 * ----------------------------------------------------------------------- */
static int peer_check_jwe_captured(struct eap_did_data *data)
{
	uint8_t *compressed = NULL;
	size_t compressed_len = 0;
	int rc = -1;

	if (!data->captured_jwe || data->captured_jwe_len == 0)
		return 1;  /* still waiting */

	wpa_printf(MSG_DEBUG, "EAP-DID(peer): JWE captured (%zu bytes), processing ...",
		   data->captured_jwe_len);

	/* Issue #46: Fetch CEK for MSK derivation (not for VP encryption).
	 * The JWE is already authcrypt (ECDH-1PU + AES-256-GCM by DIDComm).
	 * We send gzip(JWE) directly over EAP - no additional AES-GCM envelope. */
	if (!data->cek || data->cek_len == 0)
		peer_fetch_cek(data);

	/* gzip compress the JWE for transport efficiency */
	if (did_gzip_compress(data->captured_jwe, data->captured_jwe_len,
			      &compressed, &compressed_len) != 0) {
		wpa_printf(MSG_INFO, "EAP-DID(peer): gzip compress failed");
		goto out;
	}

	wpa_printf(MSG_DEBUG, "EAP-DID(peer): JWE gzip %zu -> %zu bytes",
		   data->captured_jwe_len, compressed_len);

	/* Set up uplink buffer with gzip(JWE) directly - no AES-GCM envelope.
	 * #46: The JWE is already encrypted by DIDComm. The AES-GCM layer was
	 * redundant and created a circular CEK dependency between Holder and Verifier. */
	data->ul_out_buf = wpabuf_alloc(compressed_len);
	if (data->ul_out_buf)
		wpabuf_put_data(data->ul_out_buf, compressed, compressed_len);
	data->ul_out_used = 0;

	wpa_printf(MSG_DEBUG,
		   "EAP-DID(peer): VP payload ready (%zu bytes, gzip/JWE)",
		   compressed_len);

	os_free(data->captured_jwe);
	data->captured_jwe = NULL;
	data->captured_jwe_len = 0;

	rc = 0;

out:
	os_free(compressed);
	return rc;
}
/* ----------------------------------------------------------------------- *
 * Fragment helpers
 * ----------------------------------------------------------------------- */

static struct wpabuf * peer_build_frag_ack(u8 id)
{
	struct wpabuf *resp;
	u8 *flags;

	resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_DID, 1,
			     EAP_CODE_RESPONSE, id);
	if (!resp)
		return NULL;
	flags = wpabuf_put(resp, 1);
	*flags = EAP_DID_VERSION;
	return resp;
}
static struct wpabuf * peer_build_vp_fragment(struct eap_did_data *data,
					      struct eap_method_ret *ret,
					      u8 id)
{
	struct wpabuf *resp;
	u8 *flags;
	size_t remaining, send_len;
	int more, length_included;

	if (!data->ul_out_buf) {
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}

	remaining = wpabuf_len(data->ul_out_buf) - data->ul_out_used;
	if (remaining > data->fragment_size) {
		more = 1;
		send_len = data->fragment_size;
	} else {
		more = 0;
		send_len = remaining;
	}
	length_included = (data->ul_out_used == 0 &&
			   wpabuf_len(data->ul_out_buf) > data->fragment_size);

	resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_DID,
			     1 + (length_included ? 4 : 0) + send_len,
			     EAP_CODE_RESPONSE, id);
	if (!resp) {
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}

	flags = wpabuf_put(resp, 1);
	*flags = EAP_DID_VERSION;
	if (more)
		*flags |= EAP_DID_FLAGS_MORE_FRAGMENTS;
	if (length_included) {
		*flags |= EAP_DID_FLAGS_LENGTH_INCLUDED;
		wpabuf_put_be32(resp, wpabuf_len(data->ul_out_buf));
	}
	wpabuf_put_data(resp,
			wpabuf_head_u8(data->ul_out_buf) + data->ul_out_used,
			send_len);
	data->ul_out_used += send_len;

	if (more) {
		data->state = DID_PEER_WAIT_FRAG_ACK;
		ret->methodState = METHOD_MAY_CONT;
	} else {
		wpabuf_free(data->ul_out_buf);
		data->ul_out_buf = NULL;
		data->ul_out_used = 0;
		data->state = DID_PEER_DONE;
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_COND_SUCC;
	}

	wpa_printf(MSG_DEBUG,
		   "EAP-DID(peer): -> VP frag (%zu bytes, more=%d)",
		   send_len, more);
	return resp;
}
static int peer_append_fragment(struct eap_did_data *data, u8 flags,
				const u8 *pos, const u8 *end)
{
	u32 message_length = 0;

	if ((flags & EAP_DID_VERSION_MASK) != EAP_DID_VERSION)
		return -1;

	if (flags & EAP_DID_FLAGS_LENGTH_INCLUDED) {
		if ((size_t)(end - pos) < 4)
			return -1;
		message_length = WPA_GET_BE32(pos);
		pos += 4;
	}

	if (flags & EAP_DID_FLAGS_MORE_FRAGMENTS) {
		if (!data->dl_in_buf) {
			if (!message_length ||
			    message_length > EAP_DID_MAX_FILE_SIZE)
				return -1;
			data->dl_in_buf = wpabuf_alloc(message_length);
			if (!data->dl_in_buf)
				return -1;
		}
		if ((size_t)(end - pos) > wpabuf_tailroom(data->dl_in_buf))
			return -1;
		wpabuf_put_data(data->dl_in_buf, pos, (size_t)(end - pos));
		return 1;  /* more to come */
	}

	/* Last fragment */
	if (data->dl_in_buf) {
		size_t remaining = (size_t)(end - pos);

		if (remaining > wpabuf_tailroom(data->dl_in_buf))
			return -1;
		if (remaining > 0)
			wpabuf_put_data(data->dl_in_buf, pos, remaining);
	} else {
		size_t remaining = (size_t)(end - pos);

		if (remaining == 0)
			return 0;
		data->dl_in_buf = wpabuf_alloc(remaining);
		if (!data->dl_in_buf)
			return -1;
		wpabuf_put_data(data->dl_in_buf, pos, remaining);
	}

	return 0;  /* complete */
}
/* ----------------------------------------------------------------------- *
 * Init / Deinit
 * ----------------------------------------------------------------------- */

static void * eap_did_peer_init(struct eap_sm *sm)
{
	struct eap_did_data *data;

	(void) sm;

	data = os_zalloc(sizeof(*data));
	if (!data)
		return NULL;

	data->state = DID_PEER_WAIT_START;
	data->fragment_size = EAP_DID_DEFAULT_FRAGMENT_SIZE;

	/* Configuration from env */
	{
		const char *val;

		val = getenv(DID_HOLDER_BASE_ENV);
		if (val)
			os_strlcpy(data->holder_base, val,
				   sizeof(data->holder_base));
		else
			os_strlcpy(data->holder_base, DID_HOLDER_DEFAULT,
				   sizeof(data->holder_base));

		val = getenv(DID_TRUSTED_VERIFIER_DID_ENV);
	if (val && val[0])
		os_strlcpy(data->trusted_verifier_did, val,
			   sizeof(data->trusted_verifier_did));

	val = getenv(DID_CRED_ID_ENV);
		if (val)
			os_strlcpy(data->cred_id, val,
				   sizeof(data->cred_id));
	}

	/* Start libmicrohttpd in epoll mode (no internal thread) */
	data->mhd_epoll_fd = -1;
	{
		unsigned int mhd_flags = MHD_USE_EPOLL | MHD_USE_ITC;

		data->mhd_daemon = MHD_start_daemon(
			mhd_flags, DIDCOMM_LISTEN_PORT,
			&mhd_accept_policy_cb, data,
			&mhd_jwe_cb, data,
			MHD_OPTION_NOTIFY_COMPLETED, &mhd_req_completed_cb, data,
			MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 2,
			MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) (128 * 1024),
			MHD_OPTION_END);
		if (data->mhd_daemon) {
			const union MHD_DaemonInfo *di;

			di = MHD_get_daemon_info(data->mhd_daemon,
						 MHD_DAEMON_INFO_EPOLL_FD,
						 NULL);
			if (di) {
				data->mhd_epoll_fd = di->epoll_fd;
				if (data->mhd_epoll_fd >= 0) {
					eloop_register_read_sock(
						data->mhd_epoll_fd,
						mhd_eloop_cb, data, NULL);
					wpa_printf(MSG_DEBUG,
						   "EAP-DID(peer): MHD epoll "
						   "listener on :%d",
						   DIDCOMM_LISTEN_PORT);
				}
			} else {
				wpa_printf(MSG_INFO,
					   "EAP-DID(peer): MHD started but "
					   "no epoll fd available");
			}
		} else {
			wpa_printf(MSG_WARNING,
				   "EAP-DID(peer): MHD start failed on port %d",
				   DIDCOMM_LISTEN_PORT);
		}
	}

	wpa_printf(MSG_DEBUG, "EAP-DID(peer): init (holder=%s)",
		   data->holder_base);
	return data;
}
static void eap_did_peer_deinit(struct eap_sm *sm, void *priv)
{
	struct eap_did_data *data = priv;

	(void) sm;

	if (!data)
		return;

	/* Cancel pending invitation timeout */
	eloop_cancel_timeout(peer_invite_timeout_cb, data, NULL);

	/* Clean up MHD */
	if (data->mhd_epoll_fd >= 0)
		eloop_unregister_read_sock(data->mhd_epoll_fd);
	if (data->mhd_daemon) {
		MHD_stop_daemon(data->mhd_daemon);
		data->mhd_daemon = NULL;
	}

	os_free(data->captured_jwe);
	data->captured_jwe = NULL;
	data->captured_jwe_len = 0;

	wpabuf_free(data->dl_in_buf);
	wpabuf_free(data->ul_out_buf);
	os_free(data->cek);
	os_free(data);
}
/* ----------------------------------------------------------------------- *
 * Main process — called for every EAP Request from server
 * ----------------------------------------------------------------------- */

static struct wpabuf * eap_did_peer_process(struct eap_sm *sm, void *priv,
					    struct eap_method_ret *ret,
					    const struct wpabuf *reqData)
{
	struct eap_did_data *data = priv;
	const u8 *pos, *end;
	size_t len;
	u8 flags = 0;

	(void) sm;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_DID, reqData, &len);
	if (!pos) {
		ret->methodState = METHOD_DONE;
		ret->decision = DECISION_FAIL;
		return NULL;
	}
	end = pos + len;
	if (len > 0)
		flags = *pos++;
	else
		pos = end;

	ret->methodState = METHOD_MAY_CONT;
	ret->decision = DECISION_FAIL;

	/* Handle Start packet from server */
	if (flags & EAP_DID_FLAGS_START) {
		/* Reply with version ACK */
		struct wpabuf *resp;

		resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_DID, 1,
				     EAP_CODE_RESPONSE,
				     eap_get_id(reqData));
		if (resp) {
			u8 *f = wpabuf_put(resp, 1);

			*f = EAP_DID_VERSION;
			ret->methodState = METHOD_MAY_CONT;
			ret->decision = DECISION_COND_SUCC;
			wpa_printf(MSG_DEBUG, "EAP-DID(peer): -> Start ACK");
			return resp;
		}
		return NULL;
	}

	/* Downlink (OOB from server) */
	if (data->state == DID_PEER_WAIT_START ||
	    data->state == DID_PEER_DOWNLINK_RX) {
		int rc;

		rc = peer_append_fragment(data, flags, pos, end);
		if (rc < 0) {
			wpa_printf(MSG_INFO,
				   "EAP-DID(peer): fragment append failed");
			data->state = DID_PEER_FAIL;
			ret->methodState = METHOD_DONE;
			ret->decision = DECISION_FAIL;
			return NULL;
		}

		if (rc > 0) {
			/* More fragments coming */
			data->state = DID_PEER_DOWNLINK_RX;
			ret->methodState = METHOD_MAY_CONT;
			return peer_build_frag_ack(eap_get_id(reqData));
		}

		/* OOB complete â schedule invitation HTTP via eloop timeout */
		wpa_printf(MSG_DEBUG,
			   "EAP-DID(peer): OOB complete (%zu bytes), "
			   "scheduling invitation ...",
			   wpabuf_len(data->dl_in_buf));

		data->state = DID_PEER_INVITATION;
		os_get_reltime(&data->invite_start);
		data->poll_count = 0;
		data->invite_http_done = 0;
		data->invite_http_started = 0;

		/* Schedule invitation HTTP for next eloop tick (non-blocking) */
		eloop_register_timeout(0, 0, peer_invite_timeout_cb, data, NULL);

		ret->methodState = METHOD_MAY_CONT;
		return peer_build_frag_ack(eap_get_id(reqData));
	}

	/* INVITATION state — check if JWE has been captured */
	if (data->state == DID_PEER_INVITATION) {
		int captured;

		/* Check for JWE capture */
		/* Check if invitation HTTP failed */
		if (data->invite_http_done < 0) {
			wpa_printf(MSG_INFO, "EAP-DID(peer): invitation HTTP failed");
			data->state = DID_PEER_FAIL;
			ret->methodState = METHOD_DONE;
			ret->decision = DECISION_FAIL;
			return NULL;
		}

		/* If invitation HTTP not done yet, keep waiting */
		if (data->invite_http_done == 0) {
			struct os_reltime now;
			os_get_reltime(&now);
			if (os_reltime_expired(&now, &data->invite_start,
						       DID_PEER_WAIT_MAX)) {
				wpa_printf(MSG_INFO, "EAP-DID(peer): invitation timeout");
				data->state = DID_PEER_FAIL;
				ret->methodState = METHOD_DONE;
				ret->decision = DECISION_FAIL;
				return NULL;
			}
			ret->methodState = METHOD_MAY_CONT;
			return peer_build_frag_ack(eap_get_id(reqData));
		}

		captured = peer_check_jwe_captured(data);
		if (captured == 0) {
			/* JWE ready — start uplink */
			wpa_printf(MSG_DEBUG,
				   "EAP-DID(peer): VP ready, starting uplink");
			data->state = DID_PEER_UPLINK_TX;
			return peer_build_vp_fragment(data, ret,
						      eap_get_id(reqData));
		}

		if (captured < 0) {
			wpa_printf(MSG_INFO,
				   "EAP-DID(peer): JWE processing error");
			data->state = DID_PEER_FAIL;
			ret->methodState = METHOD_DONE;
			ret->decision = DECISION_FAIL;
			return NULL;
		}

		/* Still waiting for JWE — check timeout */
		data->poll_count++;
		{
			struct os_reltime now;

			os_get_reltime(&now);
			if (os_reltime_expired(&now, &data->invite_start,
					       DID_PEER_WAIT_MAX)) {
				wpa_printf(MSG_INFO,
					   "EAP-DID(peer): JWE capture timed out");
				data->state = DID_PEER_FAIL;
				ret->methodState = METHOD_DONE;
				ret->decision = DECISION_FAIL;
				return NULL;
			}
		}

		/* Back-off: only actively drive MHD every few calls to
		 * avoid busy-looping when the server retransmits quickly. */
		if (data->poll_count % 3 == 0 && data->mhd_daemon)
			MHD_run(data->mhd_daemon);

		ret->methodState = METHOD_MAY_CONT;
		return peer_build_frag_ack(eap_get_id(reqData));
	}

	/* Fragment ACK from server during uplink */
	if (data->state == DID_PEER_WAIT_FRAG_ACK) {
		if (len > 1) {
			wpa_printf(MSG_INFO,
				   "EAP-DID(peer): expected ACK, got data");
			data->state = DID_PEER_FAIL;
			ret->methodState = METHOD_DONE;
			ret->decision = DECISION_FAIL;
			return NULL;
		}
		data->state = DID_PEER_UPLINK_TX;
		return peer_build_vp_fragment(data, ret,
					      eap_get_id(reqData));
	}

	/* Keepalive — return minimal ACK */
	if (len <= 1) {
		struct wpabuf *resp;

		resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_DID, 1,
				     EAP_CODE_RESPONSE,
				     eap_get_id(reqData));
		if (resp) {
			u8 *f = wpabuf_put(resp, 1);

			*f = EAP_DID_VERSION;
			return resp;
		}
		return NULL;
	}

	/* Unexpected */
	wpa_printf(MSG_DEBUG, "EAP-DID(peer): unexpected state=%d len=%zu",
		   data->state, len);
	return NULL;
}
/* ----------------------------------------------------------------------- *
 * Key derivation
 * ----------------------------------------------------------------------- */

static bool eap_did_peer_isKeyAvailable(struct eap_sm *sm, void *priv)
{
	struct eap_did_data *data = priv;

	(void) sm;

	return data->thid[0] != '\0';
}

/* ----------------------------------------------------------------------- *
 * Issue #27: Fetch CEK from Holder presentation API
 *
 * After PresentationSent, GET with X-EAP-KeyMaterial header.
 * If the Cloud Agent supports it, the response includes keyMaterial.cek.
 * Falls back gracefully if not available.
 * ----------------------------------------------------------------------- */
static void peer_fetch_cek(struct eap_did_data *data)
{
	char url[1024];
	struct did_http_response resp = {0};
	const char *hdrs[] = { "X-EAP-KeyMaterial: 1", NULL };
	char cek_b64[512];

	if (!data->holder_base[0] || !data->thid[0])
		return;

	/* Use thid query parameter instead of record UUID — more reliable */
	snprintf(url, sizeof(url), "%s/cloud-agent/present-proof/presentations?thid=%s",
		 data->holder_base, data->thid);

	if (did_http_get_hdr(url, hdrs, &resp, 10) != 0 || resp.status != 200) {
		wpa_printf(MSG_DEBUG, "EAP-DID: peer CEK not available (status=%d)", resp.status);
		did_http_response_free(&resp);
		return;
	}

	if (did_json_extract_str(resp.body, resp.body_len,
				"cek", cek_b64, sizeof(cek_b64)) == 0) {
		/* Issue #50: CEK is Base64URL-encoded, not hex. */
		size_t b64_len = strlen(cek_b64);
		size_t out_len = 0;
		u8 *bin = base64_url_decode(cek_b64, b64_len, &out_len);

		if (!bin || out_len == 0) {
			wpa_printf(MSG_DEBUG, "EAP-DID: peer CEK base64url decode failed (len=%zu)", b64_len);
			free(bin);
			did_http_response_free(&resp);
			return;
		}

		data->cek = bin;
		data->cek_len = out_len;
		wpa_printf(MSG_INFO, "EAP-DID: peer CEK obtained from holder (%zu bytes)", out_len);
	} else {
		wpa_printf(MSG_WARNING, "EAP-DID(peer): CEK not in response — key derivation will fail (issue #39)");
	}

	did_http_response_free(&resp);
}

static u8 * eap_did_peer_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_did_data *data = priv;

	(void) sm;

	if (!data->thid[0])
		return NULL;
	/* CEK is mandatory (issue #39) */
	if (!data->cek || data->cek_len == 0)
		return NULL;
	*len = 64;
	return eap_did_derive_key_cek(data->cek, data->cek_len,
				      data->thid, "EAP-DID-MSK", 64);
}
static u8 * eap_did_peer_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
	struct eap_did_data *data = priv;

	(void) sm;

	if (!data->thid[0])
		return NULL;
	/* CEK is mandatory (issue #39) */
	if (!data->cek || data->cek_len == 0)
		return NULL;
	*len = 64;
	return eap_did_derive_key_cek(data->cek, data->cek_len,
				      data->thid, "EAP-DID-EMSK", 64);
}
static u8 * eap_did_peer_get_session_id(struct eap_sm *sm, void *priv,
					size_t *len)
{
	struct eap_did_data *data = priv;

	(void) sm;

	if (!data->thid[0])
		return NULL;
	return eap_did_get_session_id(EAP_TYPE_DID, data->thid, len);
}
/* ----------------------------------------------------------------------- *
 * Registration
 * ----------------------------------------------------------------------- */

int eap_peer_did_register(void)
{
	struct eap_method *eap;

	wpa_printf(MSG_DEBUG, "EAP-DID(peer): register");
	did_http_init();

	eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
				    EAP_VENDOR_IETF, EAP_TYPE_DID, "DID");
	if (!eap)
		return -1;

	eap->init = eap_did_peer_init;
	eap->deinit = eap_did_peer_deinit;
	eap->process = eap_did_peer_process;
	eap->isKeyAvailable = eap_did_peer_isKeyAvailable;
	eap->getKey = eap_did_peer_getKey;
	eap->get_emsk = eap_did_peer_get_emsk;
	eap->getSessionId = eap_did_peer_get_session_id;

	return eap_peer_method_register(eap);
}
