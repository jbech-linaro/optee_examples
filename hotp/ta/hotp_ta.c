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

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <string.h>

#include <hotp_ta.h>


/* This define uses the exit label and goes to that */
#define CHECK_EXIT(ret_val) \
	if (ret_val != TEE_SUCCESS) { \
		EMSG("0x%08x", ret_val); \
		res = ret_val; \
		goto exit; }

/* This define uses the exit label and goes to that */
#define CHECK_EXP_PARAM_EXIT(result_var, pt, ept) \
	if (pt != ept) { \
		DMSG("Expected: 0x%x, got: 0x%x (line: %03d)", ept, pt, __LINE__); \
		result_var = TEE_ERROR_BAD_PARAMETERS; \
		goto exit; }

#define SHA1_SIZE 20

/* GP says that for HMAC SHA-1, max is 512 bits and min 80 bits */
#define MAX_KEY_SIZE 64 /* In bytes */
#define MIN_KEY_SIZE 10 /* In bytes */

/* Dynamic Binary Code 2 Modulu, which is 10^6 according to the spec */
#define DBC2_MODULU 1000000

static uint8_t K_saved[MAX_KEY_SIZE];
static uint32_t K_len_saved;


/*
 * The HOTP counter should be a 8 byte array with where byte 0 is the MSB and
 * byte 7 is the LSB. To make it easier to update the variable, just simply use
 * a uint64_t instead. Since this will be in big endian, we need to swap it when
 * incrementing.
 */
static uint64_t counter_be = 0;

#define SWAP64(v) \
	(((uint64_t)(v) << 56) | \
	 (((uint64_t)(v) & 0x000000000000FF00) << 40) | \
	 (((uint64_t)(v) & 0x0000000000FF0000) << 24) | \
	 (((uint64_t)(v) & 0x00000000FF000000) << 8) | \
	 (((uint64_t)(v) & 0x000000FF00000000) >> 8) | \
	 (((uint64_t)(v) & 0x0000FF0000000000) >> 24)| \
	 (((uint64_t)(v) & 0x00FF000000000000) >> 40)| \
	 ((uint64_t)(v) >> 56))

static void inc_counter(uint64_t *c_be)
{
	uint64_t c_le = SWAP64(*c_be);
	c_le++;
	*c_be = SWAP64(c_le);
}

static void hexdump(uint8_t *buf, size_t len)
{
	uint8_t i = 0;
	(void)buf;
	for (i = 0; i < len; i++) {
		printf("%02x ", buf[i]);
	}
	printf("\n");
}

static TEE_Result hmac_sha1(uint8_t *K, const size_t K_len, uint8_t *C, uint8_t *mac)
{
	TEE_ObjectHandle key_handle = TEE_HANDLE_NULL;
	TEE_OperationHandle op_handle = TEE_HANDLE_NULL;
	TEE_Result res = TEE_SUCCESS;
	TEE_Attribute attr;

	uint32_t mac_len = SHA1_SIZE;

	if (K_len < MIN_KEY_SIZE || K_len > MAX_KEY_SIZE)
		return TEE_ERROR_BAD_PARAMETERS;

	DMSG("K_len: %d", K_len);

	/*
	 * 1. Allocate cryptographic (operation) handle for the HMAC operation.
	 *    Note that size here is in bits!
	 */
	CHECK_EXIT(TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA1, TEE_MODE_MAC, K_len * 8));

	/*
	 * 2. Allocate a container (key handle) for the HMAC attributes. Note
	 *    that size here is in bits!
	 */
	CHECK_EXIT(TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA1, K_len * 8, &key_handle));

	/*
	 * 3. Initialize the attributes, i.e., point to the actual HMAC key.
	 *    Here, size is in bytes and not bits as above!
	 */
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, K, K_len);

	/* 4. Populate/assign the attributes with the key object */
	CHECK_EXIT(TEE_PopulateTransientObject(key_handle, &attr, 1));

	/* 5. Associate the key (object) with the operation */
	CHECK_EXIT(TEE_SetOperationKey(op_handle, key_handle));

	/* 6. Initialize the HMAC operation */
	TEE_MACInit(op_handle, NULL, 0);

	/* 7. Update the HMAC operation */
	TEE_MACUpdate(op_handle, C, 8);

	/* Finalize the HMAC operation */
	CHECK_EXIT(TEE_MACComputeFinal(op_handle, NULL, 0, mac, &mac_len));
	DMSG("hmac len: %d", mac_len);
	hexdump(mac, mac_len);
exit:
	if (op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(op_handle);

	if (key_handle != TEE_HANDLE_NULL)
		TEE_FreeTransientObject(key_handle);

	return res;
}

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

	(void)&params;
	(void)&sess_ctx;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __maybe_unused *sess_ctx)
{
	(void)&sess_ctx;
}

static TEE_Result truncate(uint8_t *hmac_result, uint32_t *bin_code)
{
	int offset   =  hmac_result[19] & 0xf;

	*bin_code = (hmac_result[offset] & 0x7f) << 24 |
		(hmac_result[offset+1] & 0xff) << 16 |
		(hmac_result[offset+2] & 0xff) <<  8 |
		(hmac_result[offset+3] & 0xff);

	*bin_code %= DBC2_MODULU;

	return TEE_SUCCESS;
}

static TEE_Result store_shared_key(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	DMSG("has been called");
	CHECK_EXP_PARAM_EXIT(res, param_types, exp_param_types);

	memset(K_saved, 0, sizeof(K_saved));
	memcpy(K_saved, params[0].memref.buffer, params[0].memref.size);
	K_len_saved = params[0].memref.size;
	IMSG("Got shared key %s (%u bytes).", K_saved, params[0].memref.size);
	hexdump(K_saved, sizeof(K_saved));
exit:
	return res;
}

static TEE_Result get_hotp(uint32_t param_types, TEE_Param params[4])
{
	TEE_Result res = TEE_SUCCESS;

	uint8_t *mac = NULL;
	uint32_t hotp_val = 0;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");
	CHECK_EXP_PARAM_EXIT(res, param_types, exp_param_types);

	mac = TEE_Malloc(SHA1_SIZE, 0);
	if (!mac)
		goto exit;

	CHECK_EXIT(hmac_sha1(K_saved, K_len_saved, (uint8_t *)&counter_be, mac));
	/* FIXME: Handle more than 255 values */
	inc_counter(&counter_be);
	hexdump((uint8_t *)&counter_be, 8);

	truncate(mac, &hotp_val);
	IMSG("HOTP is: %d", hotp_val);
	params[0].value.a = hotp_val;
exit:
	if (mac)
		TEE_Free(mac);

	DMSG("Done");
	return res;
}

TEE_Result TA_InvokeCommandEntryPoint(void __maybe_unused *sess_ctx,
			uint32_t cmd_id,
			uint32_t param_types, TEE_Param params[4])
{
	(void)&sess_ctx;

	switch (cmd_id) {
	case TA_HOTP_CMD_STORE_SHARED_KEY:
		return store_shared_key(param_types, params);
	case TA_HOTP_CMD_GET_HOTP:
		return get_hotp(param_types, params);
	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
