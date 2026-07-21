#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
/*
 * EAP-DID HTTP Client Wrapper — implementation (libcurl + zlib)
 *
 * Branch did2: eliminates Python proxies by making HTTP calls
 * directly from the hostapd/wpa_supplicant C code.
 */

#include "includes.h"
#include "common.h"
#include "eap_did_http.h"

#include <curl/curl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#define DID_GZIP_MAX_OUTPUT  (10 * 1024 * 1024)  /* F-27: 10 MB cap */

/* ------------------------------------------------------------------- *
 * curl write callback — append to our growing buffer
 * ------------------------------------------------------------------- */
static size_t write_cb(char *ptr, size_t size, size_t nmemb, void *ud)
{
	struct did_http_response *resp = ud;
	size_t total = size * nmemb;
	char *newbody = realloc(resp->body, resp->body_len + total + 1);
	if (!newbody)
		return 0; /* signal error to curl */
	resp->body = newbody;
	memcpy(resp->body + resp->body_len, ptr, total);
	resp->body_len += total;
	resp->body[resp->body_len] = '\0';
	return total;
}

/* ------------------------------------------------------------------- *
 * Generic request helper
 * ------------------------------------------------------------------- */
static int do_request_hdr(const char *url, const char *method,
			const char *content_type,
			const uint8_t *body, size_t body_len,
			const char **extra_headers,
			struct did_http_response *resp,
			int timeout_s)
{
	CURL *curl;
	struct curl_slist *hdrs = NULL;
	CURLcode rc;

	memset(resp, 0, sizeof(*resp));

	curl = curl_easy_init();
	if (!curl)
		return -1;

	curl_easy_setopt(curl, CURLOPT_URL, url);
	curl_easy_setopt(curl, CURLOPT_TIMEOUT, (long)timeout_s);
	curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	/* TLS verification configurable via env vars.
	 * DID_TLS_VERIFY=1 enables; DID_CA_BUNDLE sets CA path.
	 * Default: disabled for testbed (self-signed Caddy). */
	{
		const char *ca_bundle = getenv("DID_CA_BUNDLE");
		const char *tls_verify = getenv("DID_TLS_VERIFY");
		int is_https = (strncmp(url, "https://", 8) == 0);

		if (is_https && tls_verify && atoi(tls_verify) != 0) {
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
			if (ca_bundle)
				curl_easy_setopt(curl, CURLOPT_CAINFO, ca_bundle);
		} else {
			if (is_https)
				wpa_printf(MSG_WARNING, "EAP-DID: TLS verification disabled for %s", url);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
			curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		}
	}

	if (strcmp(method, "POST") == 0) {
		curl_easy_setopt(curl, CURLOPT_POST, 1L);
		if (body && body_len > 0) {
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body_len);
		}
	} else if (strcmp(method, "PATCH") == 0) {
		curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PATCH");
		if (body && body_len > 0) {
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, body);
			curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)body_len);
		}
	}

	if (content_type) {
		char ct_header[256];
		snprintf(ct_header, sizeof(ct_header), "Content-Type: %s", content_type);
		hdrs = curl_slist_append(hdrs, ct_header);
	}

	/* Extra custom headers (Issue #27: X-EAP-KeyMaterial) */
	if (extra_headers) {
		int i;
		for (i = 0; extra_headers[i]; i++)
			hdrs = curl_slist_append(hdrs, extra_headers[i]);
	}
	if (hdrs)
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, hdrs);

	rc = curl_easy_perform(curl);

	if (rc == CURLE_OK) {
		long code = 0;
		curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
		resp->status = (int)code;
	} else {
		/* transport error */
		resp->status = 0;
	}

	if (hdrs)
		curl_slist_free_all(hdrs);
	curl_easy_cleanup(curl);

	return (rc == CURLE_OK) ? 0 : -1;
}

/* ------------------------------------------------------------------- *
 * Public API
 * ------------------------------------------------------------------- */

int did_http_init(void)
{
	curl_global_init(CURL_GLOBAL_DEFAULT);
	return 0;
}

void did_http_cleanup(void)
{
	curl_global_cleanup();
}

int did_http_get(const char *url, struct did_http_response *resp, int timeout_s)
{
	return do_request_hdr(url, "GET", NULL, NULL, 0, NULL, resp, timeout_s);
}

int did_http_get_hdr(const char *url,
		     const char **headers,
		     struct did_http_response *resp,
		     int timeout_s)
{
	return do_request_hdr(url, "GET", NULL, NULL, 0, headers, resp, timeout_s);
}

int did_http_post(const char *url,
		  const char *content_type,
		  const uint8_t *body, size_t body_len,
		  struct did_http_response *resp, int timeout_s)
{
	return do_request_hdr(url, "POST", content_type, body, body_len, NULL,
			  resp, timeout_s);
}

int did_http_patch(const char *url,
		   const char *content_type,
		   const uint8_t *body, size_t body_len,
		   struct did_http_response *resp, int timeout_s)
{
	return do_request_hdr(url, "PATCH", content_type, body, body_len, NULL,
			  resp, timeout_s);
}


/* F-28: Simple URL-encode for query parameter values */
int did_url_encode(const char *in, char *buf, size_t buf_size)
{
	size_t pos = 0;

	if (!in || !buf || buf_size == 0)
		return -1;

	while (*in && pos < buf_size - 4) {
		char c = *in;
		if ((c >= 'A' && c <= 'Z') ||
		    (c >= 'a' && c <= 'z') ||
		    (c >= '0' && c <= '9') ||
		    c == '-' || c == '_' || c == '.' || c == '~') {
			buf[pos++] = c;
		} else {
			pos += (size_t)snprintf(buf + pos, buf_size - pos,
						"%%%02X", (unsigned char)c);
		}
		in++;
	}
	if (*in) /* input too long */
		return -1;
	buf[pos] = '\0';
	return 0;
}

void did_http_response_free(struct did_http_response *resp)
{
	if (!resp)
		return;
	free(resp->body);
	resp->body = NULL;
	resp->body_len = 0;
	resp->status = 0;
}

/* ------------------------------------------------------------------- *
 * Minimal JSON helpers — good enough for known Identus responses
 * ------------------------------------------------------------------- */

int did_json_extract_str(const char *json, size_t json_len,
			 const char *key,
			 char *buf, size_t buf_size)
{
	/* Search for "key" : "value" */
	char pattern[256];
	snprintf(pattern, sizeof(pattern), "\"%s\"", key);

	const char *search_end = json + json_len;
	const char *p = json;

	while (p < search_end) {
		const char *found = memmem(p, search_end - p,
					   pattern, strlen(pattern));
		if (!found)
			return -1;

		/* Move past the key */
		const char *cursor = found + strlen(pattern);

		/* Skip whitespace and colon */
		while (cursor < search_end && (*cursor == ' ' || *cursor == '\t' ||
					       *cursor == ':' || *cursor == '\n' ||
					       *cursor == '\r'))
			cursor++;

		if (cursor >= search_end)
			return -1;

		if (*cursor == '"') {
			/* String value */
			cursor++; /* skip opening quote */
			const char *start = cursor;
			while (cursor < search_end && *cursor != '"') {
				if (*cursor == '\\' && cursor + 1 < search_end)
					cursor++; /* skip escaped char */
				cursor++;
			}
			size_t val_len = cursor - start;
			if (val_len >= buf_size) {
				wpa_printf(MSG_WARNING,
					   "EAP-DID: JSON key '%s' value truncated (%zu -> %zu bytes)",
					   key, val_len, buf_size - 1);
				val_len = buf_size - 1;
			}
			memcpy(buf, start, val_len);
			buf[val_len] = '\0';
			return 0;
		}

		/* Not a string value after this key — try next occurrence */
		p = found + 1;
	}

	return -1;
}

int did_extract_oob_from_url(const char *url,
			     char *buf, size_t buf_size)
{
	const char *p = strstr(url, "_oob=");
	if (!p)
		return -1;
	p += 5; /* skip "_oob=" */

	/* Value runs until & or end of string */
	const char *end = strchr(p, '&');
	if (!end)
		end = p + strlen(p);

	size_t val_len = end - p;
	if (val_len >= buf_size)
		val_len = buf_size - 1;
	memcpy(buf, p, val_len);
	buf[val_len] = '\0';
	return 0;
}

/* ------------------------------------------------------------------- *
 * gzip helpers
 * ------------------------------------------------------------------- */

int did_gzip_compress(const uint8_t *in, size_t in_len,
		      uint8_t **out, size_t *out_len)
{
	uLongf bound = compressBound(in_len);
	uint8_t *buf = malloc(bound);
	if (!buf)
		return -1;

	if (compress2(buf, &bound, in, in_len, Z_BEST_COMPRESSION) != Z_OK) {
		free(buf);
		return -1;
	}
	*out = buf;
	*out_len = (size_t)bound;
	return 0;
}

int did_gzip_decompress(const uint8_t *in, size_t in_len,
			uint8_t **out, size_t *out_len)
{
	/* Start with 4x the compressed size, grow if needed */
	uLongf out_size = in_len * 8;
	if (out_size < 4096)
		out_size = 4096;

	uint8_t *buf = malloc(out_size);
	if (!buf)
		return -1;

	int rc;
	while ((rc = uncompress(buf, &out_size, in, in_len)) == Z_BUF_ERROR) {
		uLongf new_size = out_size * 2;
		if (new_size > DID_GZIP_MAX_OUTPUT) {  /* F-27: zip bomb protection */
			free(buf);
			return -1;
		}
		uint8_t *new_buf = realloc(buf, new_size);
		if (!new_buf) {
			free(buf);
			return -1;
		}
		buf = new_buf;
		out_size = new_size;
	}

	if (rc != Z_OK) {
		free(buf);
		return -1;
	}

	*out = buf;
	*out_len = (size_t)out_size;
	return 0;
}
