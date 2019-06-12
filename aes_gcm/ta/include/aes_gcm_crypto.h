#ifndef _AES_GCM_CRYPTO_H
#define _AES_GCM_CRYPTO_H

/*
 * Function that does AES-GCM encrypt.
 *
 * This also wraps all the necessary GP code, so this should serve as a good
 * example of what needs to be done when doing AES-GCM from a Trusted
 * Application.
 *
 * @param key		Key that is used to encrypt and integrity protect.
 * @param key_len	Size of the key (in bytes). 128, 196 and 256 are
 * 			allowed values.
 * @param in		Data to be encrypted (plaintext)
 * @param in_len	Size of data to be encrypted.
 * @param out		Buffer to store the encrypted data (ciphertext)
 * @param out_len	Size of the buffer for encrypted data.
 * @param aad		Additional Authenticated Data.
 * @param aad_len	Size of the AAD.
 * @param nonce		Nonce (IV) for the AES-GCM operation.
 * @param nonce_len	Size of the nonce.
 * @param tag		Buffer for the produced tag.
 * @param tag_len	Size of the buffer for the produced tag.
 */
TEE_Result aes_gcm_encrypt(const uint8_t *key, const uint8_t key_len,
			   const uint8_t *in, const uint32_t in_len,
			   uint8_t *out, uint32_t *out_len,
			   const uint8_t *aad, const uint32_t aad_len,
			   const uint8_t *nonce, const uint32_t nonce_len,
			   uint8_t *tag, uint32_t *tag_len);

/*
 * Function that does AES-GCM decrypt.
 *
 * This also wraps all the necessary GP code, so this should serve as a good
 * example of what needs to be done when doing AES-GCM from a Trusted
 * Application.
 *
 * @param key		Key that is used to decrypt and check the integrity.
 * @param key_len	Size of the key (in bytes). 128, 196 and 256 are
 * 			allowed values.
 * @param in		Data to be decrypted (ciphertext)
 * @param in_len	Size of data to be decrypted.
 * @param out		Buffer to store the decrypted data (plaintext)
 * @param out_len	Size of the buffer for decrypted data.
 * @param aad		Additional Authenticated Data.
 * @param aad_len	Size of the AAD.
 * @param nonce		Nonce (IV) for the AES-GCM operation.
 * @param nonce_len	Size of the nonce.
 * @param tag		Tag that data should be validated against.
 * @param tag_len	Size of validation tag.
 */
TEE_Result aes_gcm_decrypt(const uint8_t *key, const uint8_t key_len,
			   const uint8_t *in, const uint32_t in_len,
			   uint8_t *out, uint32_t *out_len,
			   const uint8_t *aad, const uint32_t aad_len,
			   const uint8_t *nonce, const uint32_t nonce_len,
			   const uint8_t *tag, const uint32_t tag_len);
#endif
