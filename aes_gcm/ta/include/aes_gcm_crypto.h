#ifndef _AES_GCM_CRYPTO_H
#define _AES_GCM_CRYPTO_H

TEE_Result aes_gcm_encrypt(const uint8_t *key, const uint8_t key_len,
			   const uint8_t *in, const uint32_t in_len,
			   uint8_t *out, uint32_t *out_len,
			   const uint8_t *aad, const uint32_t aad_len,
			   const uint8_t *nonce, const uint32_t nonce_len,
			   uint8_t *tag, uint32_t *tag_len);

TEE_Result aes_gcm_decrypt(const uint8_t *key, const uint8_t key_len,
			   const uint8_t *in, const uint32_t in_len,
			   uint8_t *out, uint32_t *out_len,
			   const uint8_t *aad, const uint32_t aad_len,
			   const uint8_t *nonce, const uint32_t nonce_len,
			   const uint8_t *tag, const uint32_t tag_len);
#endif
