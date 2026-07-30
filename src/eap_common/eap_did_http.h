/*
 * EAP-DID: Blocking HTTP client and payload helpers
 * Copyright (c) 2024-2026, Caciano Machado
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef EAP_DID_HTTP_H
#define EAP_DID_HTTP_H

/**
 * struct did_http_response - Result of an HTTP request
 * @status: HTTP status code, or 0 on a transport error
 * @body: Response body, NUL terminated; freed with did_http_response_free()
 * @body_len: Length of @body excluding the terminator
 */
struct did_http_response {
	int status;
	char *body;
	size_t body_len;
};

/**
 * did_http_init - Initialize the HTTP backend
 * Returns: 0 on success, -1 on failure
 *
 * Must be called once before any request, e.g. from method registration.
 */
int did_http_init(void);

/**
 * did_http_cleanup - Release resources allocated by did_http_init()
 */
void did_http_cleanup(void);

/**
 * did_http_get - Perform a blocking HTTP GET
 * @url: Request URL
 * @resp: Buffer for the response; released with did_http_response_free()
 * @timeout_s: Request timeout in seconds
 * Returns: 0 when the exchange completed and @resp->status is valid, -1 on a
 * transport error
 */
int did_http_get(const char *url, struct did_http_response *resp,
		 int timeout_s);

/**
 * did_http_post - Perform a blocking HTTP POST
 * @url: Request URL
 * @content_type: Value for the Content-Type header, or %NULL
 * @body: Request body, or %NULL for an empty body
 * @body_len: Length of @body
 * @resp: Buffer for the response; released with did_http_response_free()
 * @timeout_s: Request timeout in seconds
 * Returns: 0 when the exchange completed and @resp->status is valid, -1 on a
 * transport error
 */
int did_http_post(const char *url, const char *content_type, const u8 *body,
		  size_t body_len, struct did_http_response *resp,
		  int timeout_s);

/**
 * did_http_response_free - Release a response body
 * @resp: Response to clear; may already be zeroed
 */
void did_http_response_free(struct did_http_response *resp);

/**
 * did_json_extract_str - Read a string member out of a JSON document
 * @json: JSON text, not necessarily NUL terminated
 * @json_len: Length of @json
 * @key: Member name to look for
 * @buf: Buffer for the NUL terminated value
 * @buf_size: Size of @buf including the terminator
 * Returns: 0 when the member was found and @buf was filled in, -1 otherwise
 *
 * This only understands "key":"value" pairs, which is all the Identus Cloud
 * Agent responses consumed here require. The name is matched only where a
 * string stands in member name position, so an occurrence inside another
 * member's value is not a match, but the match is not confined to one nesting
 * level. A value that does not fit @buf is an error, not a truncation.
 *
 * Where a document holds several records that carry the same member names, use
 * did_json_next_object() to bound the record first.
 */
int did_json_extract_str(const char *json, size_t json_len, const char *key,
			 char *buf, size_t buf_size);

/**
 * did_json_next_object - Bound the next JSON object in a buffer
 * @pos: Where to start looking
 * @end: End of the buffer
 * @obj_end: Set to just past the closing brace
 * Returns: The opening brace of the object, or %NULL when there is no complete
 * object left
 *
 * Braces inside string values are not counted. Starting again from @obj_end
 * walks the elements of an array of objects in order, which is what reading one
 * record out of a list of them requires.
 */
const char * did_json_next_object(const char *pos, const char *end,
				  const char **obj_end);

/**
 * did_gzip_compress - Deflate a buffer
 * @in: Input data
 * @in_len: Length of @in
 * @out: Buffer for the allocated result; caller frees with os_free()
 * @out_len: Buffer for the length of the result
 * Returns: 0 on success, -1 on failure
 */
int did_gzip_compress(const u8 *in, size_t in_len, u8 **out, size_t *out_len);

/**
 * did_gzip_decompress - Inflate a buffer produced by did_gzip_compress()
 * @in: Compressed data
 * @in_len: Length of @in
 * @out: Buffer for the allocated result; caller frees with os_free()
 * @out_len: Buffer for the length of the result
 * Returns: 0 on success, -1 on failure
 *
 * The output is capped at %DID_GZIP_MAX_OUTPUT so that a hostile peer cannot
 * force unbounded allocation.
 */
int did_gzip_decompress(const u8 *in, size_t in_len, u8 **out,
			size_t *out_len);

#endif /* EAP_DID_HTTP_H */
