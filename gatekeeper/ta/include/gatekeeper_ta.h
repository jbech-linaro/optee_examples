/*
 * Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#ifndef __GATEKEEPER_TA_H__
#define __GATEKEEPER_TA_H__

#include <stdint.h>
#include <stdbool.h>
/*******************************************************************************
 * TA specifics
 ******************************************************************************/

#define TA_GATEKEEPER_UUID \
	{ 0x47617465, 0x4b65, 0x6570, \
		{ 0x65, 0x72, 0x20, 0x4a, 0x42, 0x65, 0x63, 0x68 } }

#define TA_GATEKEEPER_ENROLL 0
#define TA_GATEKEEPER_VERIFY 1

/*******************************************************************************
 * Misc
 ******************************************************************************/
/* The size of a SHA256 hash in bytes. */
#define SHA256_HASH_SIZE 32

/* GP says that for HMAC SHA256, max is 1024 bits and min 192 bits. */
#define MAX_KEY_SIZE 128 /* In bytes */
#define MIN_KEY_SIZE 24 /* In bytes */


/*******************************************************************************
 * Types etc coming from the AOSP and Trusty side.
 ******************************************************************************/
#define STORAGE_ID_LENGTH_MAX 64
#define GATEKEEPER_PREFIX "gatekeeper."

struct __attribute__((packed)) failure_record_t {
	uint64_t secure_user_id;
	uint64_t last_checked_timestamp;
	uint32_t failure_counter;
};

/*
 * Defines, typedefs, structs coming from:
 * system/gatekeeper/include/gatekeeper/password_handle.h
 *
 * TODO: License! This file is Apache 2.0, need to check this before going
 * public.
 */
#define HANDLE_FLAG_THROTTLE_SECURE 1
#define HANDLE_VERSION_THROTTLE 2

typedef uint64_t secure_id_t;
typedef uint64_t salt_t;

/**
 * structure for easy serialization
 * and deserialization of password handles.
 */

static const uint8_t HANDLE_VERSION = 2;
struct __attribute__ ((__packed__)) password_handle_t {
	// fields included in signature
	uint8_t version;
	secure_id_t user_id;
	uint64_t flags;

	// fields not included in signature
	salt_t salt;
	uint8_t signature[32];

	bool hardware_backed;
};

/*
 * Defines, typedefs, structs coming from:
 * system/gatekeeper/include/gatekeeper/gatekeeper_messages.h
 *
 * TODO: License! This file is Apache 2.0, need to check this before going
 * public.
 */
typedef enum {
	ERROR_NONE = 0,
	ERROR_INVALID = 1,
	ERROR_RETRY = 2,
	ERROR_UNKNOWN = 3,
} gatekeeper_error_t;

/*******************************************************************************
 * OP-TEE equivalent of AOSP classes etc
 ******************************************************************************/
struct gatekeeper_message {
	gatekeeper_error_t error;
	uint32_t user_id;
	uint32_t retry_timeout;
};

/*
 * OP-TEE variant of EnrollRequest.
 */
struct enroll_request {
	struct gatekeeper_message msg;
	uint8_t *password_handle;
	uint8_t *enrolled_password;
	uint8_t *provided_password;
};

/*
 * OP-TEE variant of EnrollResponse.
 */
struct enroll_response {
	struct gatekeeper_message msg;
	uint8_t *enrolled_password_handle;
};

#endif
