/*
 * EAP DID common definitions
 * Copyright (c) 2025, Caciano Machado
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef EAP_DID_COMMON_H
#define EAP_DID_COMMON_H

#include "wpabuf.h"

/* EAP-DID flags byte (inside EAP payload) */
#define EAP_DID_FLAGS_LENGTH_INCLUDED 0x80
#define EAP_DID_FLAGS_MORE_FRAGMENTS  0x40
#define EAP_DID_FLAGS_START           0x20
#define EAP_DID_FLAGS_KEY_CONFIRM     0x10
#define EAP_DID_VERSION_MASK          0x07

#define EAP_DID_VERSION     1
#define EAP_DID_MAX_VERSION 1

/* Maximum payload size (1 MB) */
#define EAP_DID_MAX_FILE_SIZE 1000000

/* Default fragment size when none configured */
#define EAP_DID_DEFAULT_FRAGMENT_SIZE 1300

/* VP encryption constants (shared between server and peer) */
#define DID_VP_KEY_LEN          32   /* AES-256-GCM key size */
#define DID_AES_IV_LEN          12
#define DID_AES_TAG_LEN         16


/* -----------------------------------------------------------------------
 * Shared functions (implemented in eap_did_common.c)
 * ----------------------------------------------------------------------- */

/*
 * Derive keying material via HKDF-SHA256 over thid.
 * Returns allocated buffer (caller must os_free) or NULL on error.
 */
u8 *eap_did_derive_key(const char *thid, const char *label, size_t out_len);

/*
 * CEK-based key derivation (Issue #27).
 * Uses CEK from DIDComm JWE (ECDH-ES) as IKM and thid as salt.
 * Returns allocated buffer (caller must os_free) or NULL on error.
 */
u8 *eap_did_derive_key_cek(const u8 *cek, size_t cek_len,
			   const char *thid, const char *label,
			   size_t out_len);

/*
 * Build EAP session ID: type_byte || SHA256(thid).
 * Returns allocated buffer (caller must os_free) or NULL on error.
 * Sets *len to the output length.
 */
/*
 * Convenience wrappers for key derivation (MSK, EMSK).
 * Returns allocated buffer (caller must os_free) or NULL on error.
 * Sets *len to the output length.
 */
u8 *eap_did_get_msk(const char *thid, size_t *len);
u8 *eap_did_get_emsk(const char *thid, size_t *len);

u8 *eap_did_get_session_id(u8 eap_type, const char *thid, size_t *len);
/* -----------------------------------------------------------------------
 * Issue #18: AES-GCM VP encryption
 * ----------------------------------------------------------------------- */

/*
 * AES-256-GCM encrypt.
 *   key      : 32-byte key
 *   iv       : 12-byte nonce
 *   plaintext: data to encrypt
 *   pt_len   : plaintext length
 *   aad      : additional authenticated data (may be NULL)
 *   aad_len  : AAD length
 *   ct       : output ciphertext (caller-allocated, pt_len bytes)
 *   tag      : output tag (caller-allocated, 16 bytes)
 * Returns 0 on success, -1 on error.
 */
int eap_did_aes_gcm_encrypt(const u8 *key, const u8 *iv,
			    const u8 *plaintext, size_t pt_len,
			    const u8 *aad, size_t aad_len,
			    u8 *ct, u8 *tag);

/*
 * AES-256-GCM decrypt.
 *   key      : 32-byte key
 *   iv       : 12-byte nonce
 *   ct       : ciphertext to decrypt
 *   ct_len   : ciphertext length
 *   aad      : additional authenticated data (may be NULL)
 *   aad_len  : AAD length
 *   tag      : authentication tag (16 bytes)
 *   pt       : output plaintext (caller-allocated, ct_len bytes)
 * Returns 0 on success, -1 on error (auth failure or other).
 */
int eap_did_aes_gcm_decrypt(const u8 *key, const u8 *iv,
			    const u8 *ct, size_t ct_len,
			    const u8 *aad, size_t aad_len,
			    const u8 *tag, u8 *pt);

/* VP encryption constants (shared by server and peer) */
#define DID_VP_KEY_LABEL        "EAP-DID-VP-KEY"
#define DID_VP_KEY_LEN          32   /* AES-256-GCM key size */
#define DID_AES_IV_LEN          12
#define DID_AES_TAG_LEN         16

#endif /* EAP_DID_COMMON_H */
