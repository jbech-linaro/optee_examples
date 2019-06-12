/*
 * Copyright (c) 2019, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <tee_internal_api.h>

#include <aes_gcm_crypto.h>

TEE_Result aes_gcm_encrypt(const uint8_t *key, const uint8_t key_len,
			   const uint8_t *in, const uint32_t in_len,
			   uint8_t *out, uint32_t *out_len,
			   const uint8_t *aad, const uint32_t aad_len,
			   const uint8_t *nonce, const uint32_t nonce_len,
			   uint8_t *tag, uint32_t *tag_len)
{
	TEE_Attribute attrs = { };
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	TEE_OperationHandle operation = { 0 };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t algorithm = TEE_ALG_AES_GCM;
	uint32_t mode = TEE_MODE_ENCRYPT;
	uint32_t obj_keysize = key_len * 8;
	uint32_t op_keysize = obj_keysize;

	/* Allocate a handle for the crypto operation. */
	res = TEE_AllocateOperation(&operation, algorithm, mode, op_keysize);
	if (res != TEE_SUCCESS) {
		EMSG("Failed calling TEE_AllocateOperation");
		return res;
	}

	/* Allocate the container for attributes. */
	res = TEE_AllocateTransientObject(TEE_TYPE_AES, obj_keysize, &object);
	if (res != TEE_SUCCESS) {
		EMSG("Failed calling TEE_AllocateTransientObject");
		goto err;
	}

	/* Set the attributes, here we set the key. */
	attrs.attributeID = TEE_ATTR_SECRET_VALUE;
	attrs.content.ref.buffer = (void *)key;
	attrs.content.ref.length = key_len;

	/* Populate the transient object with the attributes. */
	res = TEE_PopulateTransientObject(object, &attrs, 1);
	if (res != TEE_SUCCESS) {
		EMSG("Failed calling TEE_PopulateTransientObject");
		goto err;
	}

	/* Associate an operation with the key. */
	res = TEE_SetOperationKey(operation, object);
	if (res != TEE_SUCCESS) {
		EMSG("Failed calling TEE_SetOperationKey");
		goto err;
	}

	/*
	 * Start the actual AES GCM encryption, note that we multiply tag_len
	 * with 8 to get it in bits which is what TEE_AEInit expects.
	 */
	res = TEE_AEInit(operation, nonce, nonce_len, *tag_len * 8, 0, 0);
	if (res != TEE_SUCCESS) {
		EMSG("Failed calling TEE_AEInit");
		goto err;
	}

	/* If we have AAD, then use that also. */
	if (aad && aad_len > 0)
		TEE_AEUpdateAAD(operation, aad, aad_len);

	/*
	 * Finalize the AES-GCM operation, note that we're directly using the
	 * "final" function. One could also split up the call by doing multiple
	 * TEE_AEUpdate calls and the do a last final TEE_AEEncryptFinal call.
	 */
	res = TEE_AEEncryptFinal(operation,
				 in, in_len,
				 out, out_len,
				 tag, tag_len);
	if (res != TEE_SUCCESS)
		EMSG("Failed calling TEE_AEEncryptFinal");

err:
	if (object)
		TEE_FreeTransientObject(object);

	return res;
}

TEE_Result aes_gcm_decrypt(const uint8_t *key, const uint8_t key_len,
			   const uint8_t *in, const uint32_t in_len,
			   uint8_t *out, uint32_t *out_len,
			   const uint8_t *aad, const uint32_t aad_len,
			   const uint8_t *nonce, const uint32_t nonce_len,
			   const uint8_t *tag, const uint32_t tag_len)
{
	TEE_Attribute attrs = { };
	TEE_ObjectHandle object = TEE_HANDLE_NULL;
	TEE_OperationHandle operation = { 0 };
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t algorithm = TEE_ALG_AES_GCM;
	uint32_t mode = TEE_MODE_DECRYPT;
	uint32_t obj_keysize = key_len * 8;
	uint32_t op_keysize = obj_keysize;

	/* Allocate a handle for the crypto operation. */
	res = TEE_AllocateOperation(&operation, algorithm, mode, op_keysize);
	if (res != TEE_SUCCESS) {
		EMSG("Failed calling TEE_AllocateOperation");
		return res;
	}

	/* Allocate the container for attributes. */
	res = TEE_AllocateTransientObject(TEE_TYPE_AES, obj_keysize, &object);
	if (res != TEE_SUCCESS) {
		EMSG("Failed calling TEE_AllocateTransientObject");
		goto err;
	}

	/* Set the attributes, here we set the key. */
	attrs.attributeID = TEE_ATTR_SECRET_VALUE;
	attrs.content.ref.buffer = (void *)key;
	attrs.content.ref.length = key_len;

	/* Populate the transient object with the attributes. */
	res = TEE_PopulateTransientObject(object, &attrs, 1);
	if (res != TEE_SUCCESS) {
		EMSG("Failed calling TEE_PopulateTransientObject");
		goto err;
	}

	/* Associate an operation with the key. */
	res = TEE_SetOperationKey(operation, object);
	if (res != TEE_SUCCESS) {
		EMSG("Failed calling TEE_SetOperationKey");
		goto err;
	}

	/*
	 * Start the actual AES GCM decryption, note that we multiply tag_len
	 * with 8 to get it in bits which is what TEE_AEInit expects.
	 */
	res = TEE_AEInit(operation, nonce, nonce_len, tag_len * 8, 0, 0);
	if (res != TEE_SUCCESS) {
		EMSG("Failed calling TEE_AEInit");
		goto err;
	}

	/* If we have AAD, then use that also. */
	if (aad && aad_len > 0)
		TEE_AEUpdateAAD(operation, aad, aad_len);

	/*
	 * Finalize the AES-GCM operation, note that we're directly using the
	 * "final" function. One could also split up the call by doing multiple
	 * TEE_AEUpdate calls and the do a last final TEE_AEDecryptFinal call.
	 */
	res = TEE_AEDecryptFinal(operation,
				 in, in_len,
				 out, out_len,
				 (void *)tag, tag_len);
	if (res != TEE_SUCCESS)
		EMSG("Failed calling TEE_AEDecryptFinal");

err:
	if (object)
		TEE_FreeTransientObject(object);

	return res;
}
