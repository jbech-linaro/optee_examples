/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>
#include <aes-cbc-mac_ta.h>

int main(int argc, char *argv[])
{
	TEEC_Context ctx;
	TEEC_Operation op = { 0 };
	TEEC_Result res;
	TEEC_Session sess;
	TEEC_UUID uuid = TA_AES_CBC_MAC_UUID;

	uint32_t err_origin;

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
		     res, err_origin);

	/* 1. Register the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE, TEEC_NONE,
					 TEEC_NONE);

	res = TEEC_InvokeCommand(&sess, TA_AES_CBC_MAC_CMD_RUN,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS)
		fprintf(stderr, "TEEC_InvokeCommand failed with code 0x%x "
			"origin 0x%x\n", res, err_origin);

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);

	return 0;
}
