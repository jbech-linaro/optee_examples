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

#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the UUID (found in the TA's h-file(s)) */
#include <aes_gcm_ta.h>

/* Abbreviation for OP-TEE AES-GCM. */
#define PREFIX "OTE-AG: "

#define EMSG(fmt, ... ) \
		      do { fprintf(stderr, PREFIX "%s@%d: " fmt, __func__, \
			      __LINE__, ##__VA_ARGS__); } while(0)

#define MSG(fmt, ... ) \
		      do { fprintf(stdout, PREFIX "%s@%d: " fmt, __func__, \
			      __LINE__, ##__VA_ARGS__); } while(0)

/*
 * This functions just starts the encryption/decryption in the TA itself, i.e.,
 * there are no data sent back and forth between secure- and normal world.
 */
TEEC_Result ta_only_encryption(void)
{
	TEEC_Context ctx = { 0 };
	TEEC_Operation op = { 0 };
	TEEC_Result res = TEEC_ERROR_BAD_PARAMETERS;
	TEEC_Session sess = { 0 };
	TEEC_UUID uuid = AES_GCM_TA_UUID;
	uint32_t err_origin = 0;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS) {
		EMSG("TEEC_InitializeContext failed with code 0x%x\n", res);
		return res;
	}

	/* Open a session to the AES-GCM TA. */
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	if (res != TEEC_SUCCESS) {
		EMSG("TEEC_Opensession failed with code 0x%x origin 0x%x\n",
		     res, err_origin);
		goto err;
	}

	MSG("Initiate local only TA AES-GCM encryption/decryption\n");
	res = TEEC_InvokeCommand(&sess, TA_AES_GCM_CMD_LOCAL_ONLY, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		EMSG("TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n",
		     res, err_origin);

	TEEC_CloseSession(&sess);
err:
	TEEC_FinalizeContext(&ctx);

	return res;
}

TEEC_Result aes_gcm_enc(void)
{
	TEEC_Result res = TEEC_ERROR_GENERIC;
	TEEC_Context ctx = { 0 };
	TEEC_Operation op = { 0 };
	TEEC_Session sess = { 0 };
	TEEC_UUID uuid = AES_GCM_TA_UUID;
	uint32_t err_origin = 0;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		EMSG("TEEC_InitializeContext failed with code 0x%x\n", res);

	/* Open a session to the aes-gcm TA. */
	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC, NULL,
			       NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		EMSG("TEEC_Opensession failed with code 0x%x origin 0x%x\n",
		     res, err_origin);

	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT,
					 TEEC_MEMREF_TEMP_INPUT);

	op.params[0].tmpref.buffer = malloc(10);
	op.params[0].tmpref.size = 10;

	MSG("Doing AES-GCM encrypt (no AAD)\n");
	res = TEEC_InvokeCommand(&sess, TA_AES_GCM_CMD_ENCRYPT, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		EMSG("TEEC_InvokeCommand failed with code 0x%x origin 0x%x\n",
		     res, err_origin);

#if 0
	MSG("Doing AES-GCM decrypt (no AAD)\n");
	res = TEEC_InvokeCommand(&sess, TA_AES_GCM_CMD_DECRYPT, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin "
		     "0x%x", res, err_origin);

	MSG("Doing AES-GCM encrypt with AAD\n");
	res = TEEC_InvokeCommand(&sess, TA_AES_GCM_CMD_ENCRYPT_AAD, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin "
		     "0x%x", res, err_origin);

	MSG("Doing AES-GCM decrypt with AAD\n");
	res = TEEC_InvokeCommand(&sess, TA_AES_GCM_CMD_DECRYPT_AAD, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin "
		     "0x%x", res, err_origin);
#endif

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return res;
}

int main(void)
{
	int res = 0;
	if (ta_only_encryption() != TEEC_SUCCESS) {
		EMSG("Local TA encryption failed\n");
		res = 1;
	}
	else
		MSG("Local TA encryption succeeded\n");

	if (aes_gcm_enc() != TEEC_SUCCESS) {
		EMSG("AES-GCM encryption failed\n");
		res = 1;
	}
	else
		EMSG("AES-GCM encryption succeeded\n");

	return res;
}
