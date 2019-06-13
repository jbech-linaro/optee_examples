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
#include <tee_internal_api_extensions.h>

#include <aes-gcm_ta.h>

/*
 * Called when the instance of the TA is created. This is the first call in the
 * TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("AES-GCM TA instance created");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not crashed or
 * panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("AES-GCM TA instance destroyed");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated with
 * a value to be able to identify this session in subsequent calls to the TA.
 * In this function you will normally do the global initialization for the TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __maybe_unused params[4],
				    void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("AES-GCM TA has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("AES-GCM TA session successfully opened\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was assigned
 * by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	DMSG("AES-GCM TA session closed\n");
}

/*
 * Same test vector as used in xtest, originally it comes from:
 *   http://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
 *
 * Test case 2
 *              K 00000000000000000000000000000000
 *              P 00000000000000000000000000000000
 *             IV 000000000000000000000000
 *              H 66e94bd4ef8a2c3b884cfa59ca342b2e
 *             Y0 00000000000000000000000000000001
 *       E(K, Y0) 58e2fccefa7e3061367f1d57a4e7455a
 *             Y1 00000000000000000000000000000002
 *       E(K, Y1) 0388dace60b6a392f328c2b971b2fe78
 *             X1 5e2ec746917062882c85b0685353deb7
 * len(A)||len(C) 00000000000000000000000000000080
 *  GHASH(H, A, C) f38cbb1ad69223dcc3457ae5b6b0f885
 *              C 0388dace60b6a392f328c2b971b2fe78
 *              T ab6e47d42cec13bdf53a67b21257bddf
 */

static const uint8_t aes_gcm_key[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t aes_gcm_nonce[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
};
#define ae_data_aes_gcm_vect2_aad NULL
static const uint8_t aes_gcm_plaintext[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};
static const uint8_t aes_gcm_ciphertext[] = {
        0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
        0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78
};
static const uint8_t aes_gcm_tag[] = {
        0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
        0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf
};

static TEE_Result aes256gcm_encrypt(const uint8_t *key, const uint8_t key_len,
				    const uint8_t *in, const uint32_t in_len,
				    uint8_t *out, uint32_t *out_len,
				    uint8_t *aad __unused, uint32_t *aad_len __unused,
				    const uint8_t *nonce, const uint32_t nonce_len,
				    uint8_t *tag, uint32_t *tag_len)
{
	TEE_Attribute attrs = {};
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

	/* Set the attributes, here we set the encryption key. */
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
	 * Start the actual AES GCM encryption, not that we multiply tag_len
	 * with 8 to get it in bits which is what TEE_AEInit expects.
	 */
	res = TEE_AEInit(operation, nonce, nonce_len, *tag_len * 8, 0, 0);
	if (res != TEE_SUCCESS) {
		EMSG("Failed calling TEE_AEInit");
		goto err;
	}

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

static TEE_Result ta_aes_gcm_encrypt(uint32_t param_types,
				     TEE_Param params[4] __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t tag[sizeof(aes_gcm_tag)] = {};
	uint32_t tag_len = sizeof(aes_gcm_tag);
	uint8_t ciphertext[sizeof(aes_gcm_ciphertext)] = {};
	uint32_t ciphertext_len = sizeof(ciphertext);

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = aes256gcm_encrypt(aes_gcm_key, sizeof(aes_gcm_key),
				aes_gcm_plaintext, sizeof(aes_gcm_plaintext),
				ciphertext, &ciphertext_len,
				NULL, NULL,
				aes_gcm_nonce, sizeof(aes_gcm_nonce),
				tag, &tag_len);

	if (TEE_MemCompare(ciphertext, aes_gcm_ciphertext, ciphertext_len) != 0) {
		EMSG("Generated ciphertext not as expected");
		res = TEE_ERROR_GENERIC;
	}

	if (TEE_MemCompare(tag, aes_gcm_tag, tag_len) != 0) {
		EMSG("Generated tag not as expected");
		res = TEE_ERROR_GENERIC;
	} else
		DMSG("Successfully AES-GCM encrypted buffer");

	return res;
}

static TEE_Result ta_aes_gcm_decrypt(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("AES-GCM TA has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("Got value: %u from Normal World", params[0].value.a);

	params[0].value.a--;
	IMSG("Decreased value to: %u", params[0].value.a);

	return TEE_SUCCESS;
}

/*
 * Called when a TA is invoked. sess_ctx hold that value that was assigned by
 * TA_OpenSessionEntryPoint(). The rest of the paramters comes from normal
 * world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
				      uint32_t cmd_id, uint32_t param_types,
				      TEE_Param params[4])
{
	switch (cmd_id) {
	case TA_AES_GCM_CMD_ENCRYPT:
		return ta_aes_gcm_encrypt(param_types, params);

	case TA_AES_GCM_CMD_DECRYPT:
		return ta_aes_gcm_decrypt(param_types, params);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
