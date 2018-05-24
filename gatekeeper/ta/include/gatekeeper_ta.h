/*
 * Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef __GATEKEEPER_TA_H__
#define __GATEKEEPER_TA_H__

#include <stdint.h>

#define TA_GATEKEEPER_UUID \
	{ 0x47617465, 0x4b65, 0x6570, \
		{ 0x65, 0x72, 0x20, 0x4a, 0x42, 0x65, 0x63, 0x68 } }

#define TA_GATEKEEPER_ENROLL 0
#define TA_GATEKEEPER_VERIFY 1

/* Types etc coming from the AOSP and Trusty side */
#define STORAGE_ID_LENGTH_MAX 64
#define GATEKEEPER_PREFIX "gatekeeper."

struct __attribute__((packed)) failure_record_t {
	uint64_t secure_user_id;
	uint64_t last_checked_timestamp;
	uint32_t failure_counter;
};

typedef uint64_t secure_id_t;

#endif
