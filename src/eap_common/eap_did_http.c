/*
 * EAP-DID: Blocking HTTP client and payload helpers
 * Copyright (c) 2024-2026, Caciano Machado
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include <curl/curl.h>
#include <zlib.h>

#include "common.h"
#include "eap_did_http.h"

/* Upper bound on inflated output, to bound the cost of a hostile payload */
#define DID_GZIP_MAX_OUTPUT (10 * 1024 * 1024)

#define DID_HTTP_CONNECT_TIMEOUT 10L


static size_t did_http_write_cb(char *ptr, size_t size, size_t nmemb,
				void *ctx)
{
	struct did_http_response *resp = ctx;
	size_t len = size * nmemb;
	char *body;

	body = os_realloc(resp->body, resp->body_len + len + 1);
	if (!body)
		return 0; /* tells curl to abort the transfer */

	resp->body = body;
	os_memcpy(resp->body + resp->body_len, ptr, len);
	resp->body_len += len;
	resp->body[resp->body_len] = '\0';

	return len;
}


/*
 * Peer certificate validation is off by default because the testbed fronts
 * the Cloud Agents with self-signed certificates. Set DID_TLS_VERIFY=1 (and
 * optionally DID_CA_BUNDLE) to enable it.
 */
static void did_http_set_tls_opts(CURL *curl, const char *url)
{
	const char *ca_bundle, *tls_verify;

	if (os_strncmp(url, "https://", 8) != 0)
		return;

	ca_bundle = getenv("DID_CA_BUNDLE");
	tls_verify = getenv("DID_TLS_VERIFY");

	if (tls_verify && atoi(tls_verify) != 0) {
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
		curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
		if (ca_bundle)
			curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);
		return;
	}

	wpa_printf(MSG_WARNING,
		   "EAP-DID: TLS verification disabled for %s", url);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
}


static int did_http_request(const char *url, int post,
			    const char *content_type, const u8 *body,
			    size_t body_len, struct did_http_response *resp,
			    int timeout_s)
{
	CURL *curl;
	struct curl_slist *hdrs = NULL;
	CURLcode res;

	os_memset(resp, 0, sizeof(*resp));

	curl = curl_easy_init();
	if (!curl)
		return -1;

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long) timeout_s);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT,
			 DID_HTTP_CONNECT_TIMEOUT);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, did_http_write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	did_http_set_tls_opts(curl, url);

	if (post) {
		curl_easy_setopt(curl, CURLOPT_POST, 1L);
		if (body && body_len > 0) {
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE,
					 (long) body_len);
		}
	}

	if (content_type) {
		char hdr[256];

		os_snprintf(hdr, sizeof(hdr), "Content-Type: %s",
			    content_type);
		hdrs = curl_slist_append(hdrs, hdr);
		if (hdrs)
			curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);
	}

	res = curl_easy_perform(curl);
	if (res == CURLE_OK) {
		long code = 0;

		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
		resp->status = (int) code;
	}

	if (hdrs)
		curl_slist_free_all(hdrs);
	curl_easy_cleanup(curl);

	return res == CURLE_OK ? 0 : -1;
}


int did_http_init(void)
{
	if (curl_global_init(CURL_GLOBAL_DEFAULT) != CURLE_OK) {
		wpa_printf(MSG_ERROR, "EAP-DID: curl_global_init failed");
		return -1;
	}

	return 0;
}


void did_http_cleanup(void)
{
	curl_global_cleanup();
}


int did_http_get(const char *url, struct did_http_response *resp,
		 int timeout_s)
{
	return did_http_request(url, 0, NULL, NULL, 0, resp, timeout_s);
}


int did_http_post(const char *url, const char *content_type, const u8 *body,
		  size_t body_len, struct did_http_response *resp,
		  int timeout_s)
{
	return did_http_request(url, 1, content_type, body, body_len, resp,
				timeout_s);
}


void did_http_response_free(struct did_http_response *resp)
{
	if (!resp)
		return;

	os_free(resp->body);
	resp->body = NULL;
	resp->body_len = 0;
	resp->status = 0;
}


/*
 * Consume the string token at @pos, which must be its opening quote, and
 * report the octets between the quotes. Returns the position just past the
 * closing quote, or NULL if the string does not terminate before @end.
 * Escapes are not interpreted: the callers read base64url and identifiers,
 * where an escape is a malformed value rather than a value to be decoded.
 */
static const char * did_json_string(const char *pos, const char *end,
				    const char **val, size_t *val_len)
{
	const char *start = ++pos;

	while (pos < end && *pos != '"') {
		if (*pos == '\\' && pos + 1 < end)
			pos++;
		pos++;
	}

	if (pos >= end)
		return NULL;

	*val = start;
	*val_len = pos - start;

	return pos + 1;
}


static bool did_json_ws(char c)
{
	return c == ' ' || c == '\t' || c == '\r' || c == '\n';
}


const char * did_json_next_object(const char *pos, const char *end,
				  const char **obj_end)
{
	const char *start = NULL;
	int depth = 0;

	if (!pos || !end || !obj_end)
		return NULL;

	while (pos < end) {
		if (*pos == '"') {
			const char *val;
			size_t val_len;

			pos = did_json_string(pos, end, &val, &val_len);
			if (!pos)
				return NULL;
			continue;
		}

		if (*pos == '{') {
			if (!depth)
				start = pos;
			depth++;
		} else if (*pos == '}') {
			depth--;
			if (depth < 0)
				return NULL;
			if (!depth) {
				*obj_end = pos + 1;
				return start;
			}
		}

		pos++;
	}

	return NULL;
}


/*
 * Read the value of member @key. The buffer is walked as a token stream and
 * @key is matched only where a string stands in member name position, so an
 * occurrence of the name inside some other member's value is not a match. The
 * match is not confined to one nesting level: several callers read a member of
 * an object nested in what they pass. Truncation is an error, not a warning —
 * a prefix of a DID is a different DID.
 */
int did_json_extract_str(const char *json, size_t json_len, const char *key,
			 char *buf, size_t buf_size)
{
	const char *end, *pos;
	size_t key_len;

	if (!json || !key || !buf || buf_size == 0)
		return -1;

	end = json + json_len;
	pos = json;
	key_len = os_strlen(key);

	while (pos < end) {
		const char *name, *val;
		size_t name_len, val_len;

		if (*pos != '"') {
			pos++;
			continue;
		}

		pos = did_json_string(pos, end, &name, &name_len);
		if (!pos)
			return -1;

		while (pos < end && did_json_ws(*pos))
			pos++;

		/* A string not followed by a colon is a value, not a name */
		if (pos >= end || *pos != ':')
			continue;

		pos++;
		while (pos < end && did_json_ws(*pos))
			pos++;

		if (pos >= end)
			return -1;

		if (*pos != '"') {
			/* Not a string value; keep looking */
			continue;
		}

		if (name_len != key_len ||
		    os_memcmp(name, key, key_len) != 0) {
			pos = did_json_string(pos, end, &val, &val_len);
			if (!pos)
				return -1;
			continue;
		}

		if (!did_json_string(pos, end, &val, &val_len))
			return -1;

		if (val_len >= buf_size) {
			wpa_printf(MSG_INFO,
				   "EAP-DID: JSON value for '%s' does not fit (%zu octets, buffer %zu)",
				   key, val_len, buf_size);
			return -1;
		}

		os_memcpy(buf, val, val_len);
		buf[val_len] = '\0';

		return 0;
	}

	return -1;
}


int did_gzip_compress(const u8 *in, size_t in_len, u8 **out, size_t *out_len)
{
	uLongf bound = compressBound(in_len);
	u8 *buf;

	buf = os_malloc(bound);
	if (!buf)
		return -1;

	if (compress2(buf, &bound, in, in_len, Z_BEST_COMPRESSION) != Z_OK) {
		os_free(buf);
		return -1;
	}

	*out = buf;
	*out_len = bound;

	return 0;
}


int did_gzip_decompress(const u8 *in, size_t in_len, u8 **out,
			size_t *out_len)
{
	uLongf size = in_len * 8;
	u8 *buf;
	int res;

	if (size < 4096)
		size = 4096;

	buf = os_malloc(size);
	if (!buf)
		return -1;

	while ((res = uncompress(buf, &size, in, in_len)) == Z_BUF_ERROR) {
		uLongf grown = size * 2;
		u8 *tmp;

		if (grown > DID_GZIP_MAX_OUTPUT) {
			wpa_printf(MSG_INFO,
				   "EAP-DID: inflated payload exceeds %d octets",
				   DID_GZIP_MAX_OUTPUT);
			os_free(buf);
			return -1;
		}

		tmp = os_realloc(buf, grown);
		if (!tmp) {
			os_free(buf);
			return -1;
		}
		buf = tmp;
		size = grown;
	}

	if (res != Z_OK) {
		os_free(buf);
		return -1;
	}

	*out = buf;
	*out_len = size;

	return 0;
}
