/*
 * Copyright (c) 2017, Linaro Limited
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
#include <hotp_ta.h>
#include <string.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>

/*
 * This macro checks whether the return value is not equal to TEE_SUCCESS, if it
 * is not equal, then it will set the return value to 'res' and then goto
 * 'label'.
 */
#define CHECK_EXIT(label, res, ret_val) \
	if (ret_val != TEE_SUCCESS) { \
		EMSG("0x%08x", ret_val); \
		res = ret_val; \
		goto label; }

/* 
 * This macro checks the expected parameters, if they are not the same, then it
 * will set 'res' to TEE_ERROR_BAD_PARAMETERS and will goto label 'label'.
 */
#define CHECK_EXP_PARAM_EXIT(label, res, pt, ept) \
	if (pt != ept) { \
		EMSG("Expected: 0x%x, got: 0x%x", ept, pt); \
		res = TEE_ERROR_BAD_PARAMETERS; \
		goto label; }

#define SWAP64(v) \
	(((uint64_t)(v) << 56) | \
	 (((uint64_t)(v) & 0x000000000000FF00) << 40) | \
	 (((uint64_t)(v) & 0x0000000000FF0000) << 24) | \
	 (((uint64_t)(v) & 0x00000000FF000000) << 8) | \
	 (((uint64_t)(v) & 0x000000FF00000000) >> 8) | \
	 (((uint64_t)(v) & 0x0000FF0000000000) >> 24) | \
	 (((uint64_t)(v) & 0x00FF000000000000) >> 40) | \
	 ((uint64_t)(v) >> 56))

/* The size of a SHA1 hash in bytes. */
#define SHA1_HASH_SIZE 20

/* GP says that for HMAC SHA-1, max is 512 bits and min 80 bits. */
#define MAX_KEY_SIZE 64 /* In bytes */
#define MIN_KEY_SIZE 10 /* In bytes */

/* Dynamic Binary Code 2 Modulu, which is 10^6 according to the spec. */
#define DBC2_MODULU 1000000

/* 
 * Currently this only supports a single key, in the future this could be update
 * to support multiple uses, all with different unique keys (stored using secure
 * storage).
 */
static uint8_t K[MAX_KEY_SIZE];
static uint32_t K_len;

/*
 * The HOTP counter should be a 8 byte array with where byte 0 is the MSB and
 * byte 7 is the LSB. To make it easier to update the variable, just simply use
 * a uint64_t instead. Since this will be in big endian, we need to swap it when
 * incrementing.
 */
static uint64_t counter_be = 0;

static void inc_counter(uint64_t *c_be)
{
	uint64_t c_le = SWAP64(*c_be);
	c_le++;
	*c_be = SWAP64(c_le);
}

static void hexdump(const void *buf, size_t len)
{
#if defined(DEBUG)
	uint8_t i = 0;
	uint8_t *b = (uint8_t *)buf;
	for (i = 0; i < len; i++) {
		printf("%02x ", b[i]);
	}
	printf("\n");
#else
	(void)buf;
	(void)len;
#endif
}

/*
 *  HMAC a block of memory to produce the authentication tag
 *  @param key       The secret key
 *  @param keylen    The length of the secret key (bytes)
 *  @param in        The data to HMAC
 *  @param inlen     The length of the data to HMAC (bytes)
 *  @param out       [out] Destination of the authentication tag
 *  @param outlen    [in/out] Max size and resulting size of authentication tag
 */
static TEE_Result hmac_sha1(const uint8_t *key, const size_t keylen,
			    const uint8_t *in, const size_t inlen,
			    uint8_t *out, size_t *outlen)
{
	TEE_Attribute attr = { 0 };
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;

	if (keylen < MIN_KEY_SIZE || keylen > MAX_KEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	if (!in || !out || !outlen)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * 1. Allocate cryptographic (operation) handle for the HMAC operation.
	 *    Note that size here is in bits (and therefore times 8)!
	 */
	CHECK_EXIT(exit, res,
		   TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA1,
					 TEE_MODE_MAC, keylen * 8));

	/*
	 * 2. Allocate a container (key handle) for the HMAC attributes. Note
	 *    that size here is in bits (and therefore times 8)!
	 */
	CHECK_EXIT(exit, res,
		   TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA1, keylen * 8,
					       &key_handle));

	/*
	 * 3. Initialize the attributes, i.e., point to the actual HMAC key.
	 *    Here, size is in bytes and not bits as above!
	 */
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keylen);

	/* 4. Populate/assign the attributes with the key object */
	CHECK_EXIT(exit, res,
		   TEE_PopulateTransientObject(key_handle, &attr, 1));

	/* 5. Associate the key (object) with the operation */
	CHECK_EXIT(exit, res, TEE_SetOperationKey(op_handle, key_handle));

	/* 6. Initialize the HMAC operation */
	TEE_MACInit(op_handle, NULL, 0);

	/* 7. Update the HMAC operation */
	TEE_MACUpdate(op_handle, in, inlen);

	/* 8. Finalize the HMAC operation */
	CHECK_EXIT(exit, res,
		   TEE_MACComputeFinal(op_handle, NULL, 0, out, outlen));
exit:
	if (op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(op_handle);

	/* It is OK to call this when key_handle is TEE_HANDLE_NULL */
	TEE_FreeTransientObject(key_handle);

	return res;
}

/*
 * Truncate function working as described in RFC4226.
 */
static void truncate(uint8_t *hmac_result, uint32_t *bin_code)
{
	int offset = hmac_result[19] & 0xf;

	*bin_code = (hmac_result[offset] & 0x7f) << 24 |
		(hmac_result[offset+1] & 0xff) << 16 |
		(hmac_result[offset+2] & 0xff) <<  8 |
		(hmac_result[offset+3] & 0xff);

	*bin_code %= DBC2_MODULU;
}

static TEE_Result register_shared_key(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	CHECK_EXP_PARAM_EXIT(exit, res, param_types, exp_param_types);

	memset(K, 0, sizeof(K));
	memcpy(K, params[0].memref.buffer, params[0].memref.size);

	K_len = params[0].memref.size;
	DMSG("Got shared key %s (%u bytes).", K, params[0].memref.size);

	hexdump(K, sizeof(K));
exit:
	return res;
}

static TEE_Result get_hotp(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t hotp_val = 0;
	uint8_t mac[SHA1_HASH_SIZE];
	size_t mac_len = sizeof(mac);

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	CHECK_EXP_PARAM_EXIT(exit, res, param_types, exp_param_types);

	CHECK_EXIT(exit, res,
		   hmac_sha1(K, K_len, (uint8_t *)&counter_be,
			     sizeof(counter_be), mac, &mac_len));

	inc_counter(&counter_be);
	hexdump((uint8_t *)&counter_be, 8);

	truncate(mac, &hotp_val);
	DMSG("HOTP is: %d", hotp_val);
	params[0].value.a = hotp_val;
exit:
	return res;
}

/*******************************************************************************
 * Mandatory TA functions.
 ******************************************************************************/
TEE_Result TA_CreateEntryPoint(void)
{
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
		TEE_Param __maybe_unused params[4],
		void __maybe_unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	(void)params;
	(void)sess_ctx;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)sess_ctx;
}

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
				      uint32_t cmd_id,
				      uint32_t param_types, TEE_Param params[4])
{
	(void)sess_ctx;

	switch (cmd_id) {
	case TA_HOTP_CMD_STORE_SHARED_KEY:
		return register_shared_key(param_types, params);

	case TA_HOTP_CMD_GET_HOTP:
		return get_hotp(param_types, params);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
