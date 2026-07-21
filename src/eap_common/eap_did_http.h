/*
 * EAP-DID HTTP Client Wrapper (libcurl)
 *
 * Provides simple blocking HTTP GET/POST/PATCH for talking directly
 * to Identus Cloud Agent REST APIs from C code.
 *
 * Used in branch did2 to replace the Python proxy layer.
 */

#ifndef EAP_DID_HTTP_H
#define EAP_DID_HTTP_H

#include <stddef.h>
#include <stdint.h>

/*
 * HTTP response container.  Caller owns body and must free with
 * did_http_response_free().
 */
struct did_http_response {
	int status;		/* HTTP status code (0 on transport error) */
	char *body;		/* allocated response body (null-terminated) */
	size_t body_len;	/* body length excluding null terminator */
};

/*
 * Global init/cleanup for libcurl.  Call did_http_init() once at
 * startup (e.g. from eap_server_did_register or peer init).
 */
int did_http_init(void);
void did_http_cleanup(void);

/*
 * Blocking HTTP GET.
 *   url       : full URL (e.g. "http://caddy-verifier:8082/cloud-agent/...")
 *   resp      : response struct (caller frees with did_http_response_free)
 *   timeout_s : timeout in seconds
 * Returns 0 on success (HTTP transport ok, resp.status populated),
 *        -1 on transport error (resp.status == 0).
 */
int did_http_get(const char *url,
		 struct did_http_response *resp,
		 int timeout_s);

/*
 * Blocking HTTP GET with extra headers.
 *   headers: NULL-terminated array of "Key: Value" strings, or NULL.
 */
int did_http_get_hdr(const char *url,
		     const char **headers,
		     struct did_http_response *resp,
		     int timeout_s);

/*
 * Blocking HTTP POST with optional body.
 *   url         : full URL
 *   content_type: Content-Type header (e.g. "application/json")
 *   body        : request body (may be NULL for empty body)
 *   body_len    : body length
 *   resp        : response struct
 *   timeout_s   : timeout in seconds
 */
int did_http_post(const char *url,
		  const char *content_type,
		  const uint8_t *body, size_t body_len,
		  struct did_http_response *resp,
		  int timeout_s);

/*
 * Blocking HTTP PATCH with optional body.  Same semantics as POST.
 */
int did_http_patch(const char *url,
		   const char *content_type,
		   const uint8_t *body, size_t body_len,
		   struct did_http_response *resp,
		   int timeout_s);

/*
 * Free memory allocated in a did_http_response.
 * Safe to call on a zeroed struct.
 */
void did_http_response_free(struct did_http_response *resp);

/*
 * Extract a string field from a JSON blob using simple key matching.
 * Returns 0 on success (buf populated, null-terminated), -1 if not found.
 * Caller provides buffer; buf_size includes space for null terminator.
 * Only handles flat string values: "key":"value" or "key": "value".
 */
int did_json_extract_str(const char *json, size_t json_len,
			 const char *key,
			 char *buf, size_t buf_size);

/*
 * Extract the _oob query parameter value from a URL string.
 * Returns 0 on success, -1 if not found.
 */
int did_extract_oob_from_url(const char *url,
			     char *buf, size_t buf_size);

/*
 * gzip-compress a buffer using zlib.
 * Returns 0 on success.  Caller must free *out.
 */
int did_gzip_compress(const uint8_t *in, size_t in_len,
		      uint8_t **out, size_t *out_len);

/*
 * gzip-decompress a buffer using zlib.
 * Returns 0 on success.  Caller must free *out.
 */
int did_gzip_decompress(const uint8_t *in, size_t in_len,
			uint8_t **out, size_t *out_len);

/*
 * URL-encode a string for use in query parameters (F-28).
 * Returns 0 on success, -1 if buf too small.
 */
int did_url_encode(const char *in, char *buf, size_t buf_size);

#endif /* EAP_DID_HTTP_H */
