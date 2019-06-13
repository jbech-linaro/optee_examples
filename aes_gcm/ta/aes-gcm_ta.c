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

/*******************************************************************************
 * Test data
 *
 * It's the same test vector as used in xtest, originally it comes from:
 *   http://luca-giuzzi.unibs.it/corsi/Support/papers-cryptography/gcm-spec.pdf
 ******************************************************************************/

/*
 * Test case 2 - No AAD
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


/*
 * Test case 5 - AAD
 *                 K feffe9928665731c6d6a8f9467308308
 *                 P d9313225f88406e5a55909c5aff5269a
 *                   86a7a9531534f7da2e4c303d8a318a72
 *                   1c3c0c95956809532fcf0e2449a6b525
 *                   b16aedf5aa0de657ba637b39
 *                 A feedfacedeadbeeffeedfacedeadbeef
 *                   abaddad2
 *                IV cafebabefacedbad
 *                 H b83b533708bf535d0aa6e52980d53b78
 *                N1 6f288b846e5fed9a18376829c86a6a16
 * len({})||len(IV ) 00000000000000000000000000000040
 *                Y0 c43a83c4c4badec4354ca984db252f7d
 *          E(K, Y0) e94ab9535c72bea9e089c93d48e62fb0
 *                X1 ed56aaf8a72d67049fdb9228edba1322
 *                X2 cd47221ccef0554ee4bb044c88150352
 *                Y1 c43a83c4c4badec4354ca984db252f7e
 *          E(K, Y1) b8040969d08295afd226fcda0ddf61cf
 *                Y2 c43a83c4c4badec4354ca984db252f7f
 *          E(K, Y2) ef3c83225af93122192ad5c4f15dfe51
 *                Y3 c43a83c4c4badec4354ca984db252f80
 *          E(K, Y3) 6fbc659571f72de104c67b609d2fde67
 *                Y4 c43a83c4c4badec4354ca984db252f81
 *          E(K, Y4) f8e3581441a1e950785c3ea1430c6fa6
 *                X3 9379e2feae14649c86cf2250e3a81916
 *                X4 65dde904c92a6b3db877c4817b50a5f4
 *                X5 48c53cf863b49a1b0bbfc48c3baaa89d
 *                X6 08c873f1c8cec3effc209a07468caab1
 *    len(A)||len(C) 00000000000000a000000000000001e0
 *     GHASH(H, A, C) df586bb4c249b92cb6922877e444d37b
 *                 C 61353b4c2806934a777ff51fa22a4755
 *                   699b2a714fcdc6f83766e5f97b6c7423
 *                   73806900e49f24b22b097544d4896b42
 *                   4989b5e1ebac0f07c23f4598
 *    T              3612d2e79e3b0785561be14aaca2fccb
 */

static const uint8_t aes_gcm_key_aad[] = {
	0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
	0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08
};

static const uint8_t aes_gcm_nonce_aad[] = {
	0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad
};

static const uint8_t aes_gcm_aad_aad[] = {
	0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
	0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
	0xab, 0xad, 0xda, 0xd2
};

static const uint8_t aes_gcm_plaintext_aad[] = {
	0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
	0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
	0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
	0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
	0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
	0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
	0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
	0xba, 0x63, 0x7b, 0x39
};

static const uint8_t aes_gcm_ciphertext_aad[] = {
	0x61, 0x35, 0x3b, 0x4c, 0x28, 0x06, 0x93, 0x4a,
	0x77, 0x7f, 0xf5, 0x1f, 0xa2, 0x2a, 0x47, 0x55,
	0x69, 0x9b, 0x2a, 0x71, 0x4f, 0xcd, 0xc6, 0xf8,
	0x37, 0x66, 0xe5, 0xf9, 0x7b, 0x6c, 0x74, 0x23,
	0x73, 0x80, 0x69, 0x00, 0xe4, 0x9f, 0x24, 0xb2,
	0x2b, 0x09, 0x75, 0x44, 0xd4, 0x89, 0x6b, 0x42,
	0x49, 0x89, 0xb5, 0xe1, 0xeb, 0xac, 0x0f, 0x07,
	0xc2, 0x3f, 0x45, 0x98
};

static const uint8_t aes_gcm_tag_aad[] = {
	0x36, 0x12, 0xd2, 0xe7, 0x9e, 0x3b, 0x07, 0x85,
	0x56, 0x1b, 0xe1, 0x4a, 0xac, 0xa2, 0xfc, 0xcb
};


/*******************************************************************************
 * Helper functions for doing en-/decryption
 ******************************************************************************/
static TEE_Result aes_gcm_encrypt(const uint8_t *key, const uint8_t key_len,
				  const uint8_t *in, const uint32_t in_len,
				  uint8_t *out, uint32_t *out_len,
				  const uint8_t *aad, const uint32_t aad_len,
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

static TEE_Result aes_gcm_decrypt(const uint8_t *key, const uint8_t key_len,
				  const uint8_t *in, const uint32_t in_len,
				  uint8_t *out, uint32_t *out_len,
				  const uint8_t *aad, const uint32_t aad_len,
				  const uint8_t *nonce, const uint32_t nonce_len,
				  const uint8_t *tag, const uint32_t tag_len)
{
	TEE_Attribute attrs = {};
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

/*******************************************************************************
 * Main TA functions
 ******************************************************************************/
/*
 * Called when the instance of the TA is created. This is the first call in the
 * TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("instance created");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not crashed or
 * panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("instance destroyed");
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

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("session successfully opened\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was assigned
 * by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	DMSG("session closed\n");
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

	res = aes_gcm_encrypt(aes_gcm_key, sizeof(aes_gcm_key),
			      aes_gcm_plaintext, sizeof(aes_gcm_plaintext),
			      ciphertext, &ciphertext_len,
			      NULL, 0,
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
		DMSG("Successfully AES-GCM encrypted the buffer");

	return res;
}

static TEE_Result ta_aes_gcm_encrypt_aad(uint32_t param_types,
					 TEE_Param params[4] __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t tag[sizeof(aes_gcm_tag_aad)] = {};
	uint32_t tag_len = sizeof(aes_gcm_tag_aad);
	uint8_t ciphertext[sizeof(aes_gcm_ciphertext_aad)] = {};
	uint32_t ciphertext_len = sizeof(ciphertext);

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = aes_gcm_encrypt(aes_gcm_key_aad, sizeof(aes_gcm_key_aad),
			      aes_gcm_plaintext_aad, sizeof(aes_gcm_plaintext_aad),
			      ciphertext, &ciphertext_len,
			      aes_gcm_aad_aad, sizeof(aes_gcm_aad_aad),
			      aes_gcm_nonce_aad, sizeof(aes_gcm_nonce_aad),
			      tag, &tag_len);

	if (TEE_MemCompare(ciphertext, aes_gcm_ciphertext_aad, ciphertext_len) != 0) {
		EMSG("Generated ciphertext not as expected");
		res = TEE_ERROR_GENERIC;
	}

	if (TEE_MemCompare(tag, aes_gcm_tag_aad, tag_len) != 0) {
		EMSG("Generated tag not as expected");
		res = TEE_ERROR_GENERIC;
	} else
		DMSG("Successfully AES-GCM (AAD) encrypted the buffer");

	return res;
}

static TEE_Result ta_aes_gcm_decrypt(uint32_t param_types, TEE_Param params[4] __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t plaintext[sizeof(aes_gcm_plaintext)] = {};
	uint32_t plaintext_len = sizeof(plaintext);

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = aes_gcm_decrypt(aes_gcm_key, sizeof(aes_gcm_key),
			      aes_gcm_ciphertext, sizeof(aes_gcm_ciphertext),
			      plaintext, &plaintext_len,
			      NULL, 0,
			      aes_gcm_nonce, sizeof(aes_gcm_nonce),
			      aes_gcm_tag, sizeof(aes_gcm_tag));

	if (TEE_MemCompare(plaintext, aes_gcm_plaintext, plaintext_len) != 0) {
		EMSG("Plaintext is not as expected");
		res = TEE_ERROR_GENERIC;
	} else
		DMSG("Successfully decrypted the AES-GCM buffer");

	return res;
}

static TEE_Result ta_aes_gcm_decrypt_aad(uint32_t param_types, TEE_Param
					 params[4] __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	uint8_t plaintext[sizeof(aes_gcm_plaintext_aad)] = {};
	uint32_t plaintext_len = sizeof(plaintext);

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	res = aes_gcm_decrypt(aes_gcm_key_aad, sizeof(aes_gcm_key_aad),
			      aes_gcm_ciphertext_aad, sizeof(aes_gcm_ciphertext_aad),
			      plaintext, &plaintext_len,
			      aes_gcm_aad_aad, sizeof(aes_gcm_aad_aad),
			      aes_gcm_nonce_aad, sizeof(aes_gcm_nonce_aad),
			      aes_gcm_tag_aad, sizeof(aes_gcm_tag_aad));

	if (TEE_MemCompare(plaintext, aes_gcm_plaintext_aad, plaintext_len) != 0) {
		EMSG("Generated plaintext not as expected");
		res = TEE_ERROR_GENERIC;
	} else
		DMSG("Successfully decrypted the AES-GCM (AAD) buffer");

	return res;
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

	case TA_AES_GCM_CMD_ENCRYPT_AAD:
		return ta_aes_gcm_encrypt_aad(param_types, params);

	case TA_AES_GCM_CMD_DECRYPT_AAD:
		return ta_aes_gcm_decrypt_aad(param_types, params);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
