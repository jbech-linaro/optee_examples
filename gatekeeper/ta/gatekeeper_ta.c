/*
 * Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <gatekeeper_ta.h>
#include <string.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>

#define DAY_IN_MS (1000 * 60 * 60 * 24)
#define MS_PER_S 1000

/*******************************************************************************
 * Functions defined in:
 * system/gatekeeper/include/gatekeeper/gatekeeper_messages.h
 * system/gatekeeper/gatekeeper_messages.cpp
 ******************************************************************************/
static void SetRetryTimeout(struct gatekeeper_response *response, uint32_t retry_timeout) {
	response->retry_timeout = retry_timeout;
	response->error = ERROR_RETRY;
}

/*******************************************************************************
 * Protected functions in the gatekeeper.h in AOSP
 ******************************************************************************/
static bool GetAuthTokenKey(const uint8_t **auth_token_key, uint32_t *length)
{
	// FIXME: Implementation
	(void)auth_token_key;
	(void)length;
	return false;
}

static void GetPasswordKey(const uint8_t **password_key, uint32_t *length)
{
	// FIXME: Implementation
	(void)password_key;
	(void)length;
}

static void ComputePasswordSignature(
	uint8_t *signature, uint32_t signature_length,
	const uint8_t *key, uint32_t key_length,
	const uint8_t *password, uint32_t password_length,
	salt_t salt)
{
	// FIXME: Implementation
	(void)signature;
(void)signature_length;
	(void)key;
	(void)key_length;
	(void)password;
	(void)password_length;
	(void)salt;
}

/**
 * Retrieves a unique, cryptographically randomly generated buffer for use in
 * password hashing, etc.
 */
static void GetRandom(void *random, uint32_t requested_size)
{
	TEE_GenerateRandom(random, requested_size);
}

static void ComputeSignature(uint8_t *signature, uint32_t signature_length,
			     const uint8_t *key, uint32_t key_length,
			     const uint8_t *message, const uint32_t length)
{
	// FIXME: Implementation
	(void)signature;
	(void)signature_length;
	(void)key;
	(void)key_length;
	(void)message;
	(void)length;
}

/**
 * Get the time since boot in milliseconds.
 *
 * Should return 0 on error.
 */
static uint64_t GetMillisecondsSinceBoot(void)
{
	TEE_Time time;
	TEE_GetSystemTime(&time);

	return (time.seconds * MS_PER_S) + time.millis;
}

static bool GetFailureRecord(uint32_t uid, secure_id_t user_id,
			     struct failure_record_t *record, bool secure)
{
	char object_id[STORAGE_ID_LENGTH_MAX] = { 0 };
	struct failure_record_t owner_record;
	TEE_ObjectHandle obj_handle = TEE_HANDLE_NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t count;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ;

	/* TODO: what about bool secure, we are always secure? */
	(void)secure;

	snprintf(object_id, STORAGE_ID_LENGTH_MAX, GATEKEEPER_PREFIX "%u",
		 uid);

	/* TODO: Consider use TEE_STORAGE_PRIVATE_RPMB instead */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       &object_id, sizeof(object_id),
				       flags, &obj_handle);
	if (res != TEE_SUCCESS)
		return false;

	res = TEE_ReadObjectData(obj_handle, &owner_record,
				 sizeof(struct failure_record_t),
				 &count);

	if (res != TEE_SUCCESS || count != sizeof(struct failure_record_t))
		return false;

	if (owner_record.secure_user_id != user_id)
		return false;

	*record = owner_record;
	return true;
}

static bool WriteFailureRecord(uint32_t uid, struct failure_record_t *record, bool secure)
{
	char object_id[STORAGE_ID_LENGTH_MAX] = { 0 };
	TEE_ObjectHandle obj_handle = TEE_HANDLE_NULL;
	TEE_Result res = TEE_ERROR_GENERIC;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_WRITE;

	/* TODO: what about bool secure, we are always secure? */
	(void)secure;

	snprintf(object_id, STORAGE_ID_LENGTH_MAX, GATEKEEPER_PREFIX "%u",
		 uid);

	/* TODO: Consider use TEE_STORAGE_PRIVATE_RPMB instead */
	res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
				       &object_id, sizeof(object_id),
				       flags, &obj_handle);
	if (res != TEE_SUCCESS)
		return false;

	res = TEE_WriteObjectData(obj_handle, record, sizeof(*record));
	if (res != TEE_SUCCESS)
		return false;

	return true;
}

static bool ClearFailureRecord(uint32_t uid, secure_id_t user_id, bool secure)
{
	// FIXME: Implementation
	(void)uid;
	(void)user_id;
	(void)secure;
	return false;
}

static uint32_t ComputeRetryTimeout(const struct failure_record_t *record)
{
	// FIXME: Implementation
	(void)record;
	return 0;
}

static bool IsHardwareBacked(void)
{
	return true;
}

// FIXME: Implement SizedBuffer
typedef uint8_t SizedBuffer;

static bool DoVerify(const struct password_handle_t *expected_handle,
		     const SizedBuffer *password)
{
	// FIXME: Implementation
	(void)expected_handle;
	(void)password;
	return false;
}

/*******************************************************************************
 * Private functions in the gatekeeper.h in AOSP
 ******************************************************************************/
static void MintAuthToken(uint8_t *auth_token, uint32_t *length,
			  uint64_t timestamp, secure_id_t user_id,
			  secure_id_t authenticator_id, uint64_t challenge)
{
	// FIXME: Implementation
	(void)auth_token;
	(void)length;
	(void)timestamp;
	(void)user_id;
	(void)authenticator_id;
	(void)challenge;
}

static bool CreatePasswordHandle(
	SizedBuffer *password_handle, salt_t salt, secure_id_t secure_id,
	secure_id_t authenticator_id, uint8_t handle_version,
	const uint8_t *password, uint32_t password_length)
{
	// FIXME: Implementation
	(void)password_handle;
	(void)salt;
	(void)secure_id;
	(void)authenticator_id;
	(void)handle_version;
	(void)password;
	(void)password_length;
	return false;
}

static bool IncrementFailureRecord(uint32_t uid, secure_id_t user_id, uint64_t timestamp,
				   struct failure_record_t *record, bool secure)
{
	record->secure_user_id = user_id;
	record->failure_counter++;
	record->last_checked_timestamp = timestamp;

	return WriteFailureRecord(uid, record, secure);
}

// FIXME: Implement GateKeeperMessage
typedef uint8_t GateKeeperMessage;

/* TODO: Function copy/pasted with minor tweaks from AOSP, i.e., licence! */
static bool ThrottleRequest(uint32_t uid, uint64_t timestamp,
			    struct failure_record_t *record,
			    bool secure, struct gatekeeper_response *response)
{
	uint64_t last_checked = record->last_checked_timestamp;
	uint32_t timeout = ComputeRetryTimeout(record);

	if (timeout > 0) {
		/* We have a pending timeout. */
		if (timestamp < last_checked + timeout && timestamp > last_checked) {
			// attempt before timeout expired, return remaining time
			SetRetryTimeout(response, timeout - (timestamp - last_checked));
			return true;
		} else if (timestamp <= last_checked) {
			/*
			 * Device was rebooted or timer reset, don't count as
			 * new failure but reset timeout.
			 */
			record->last_checked_timestamp = timestamp;
			if (!WriteFailureRecord(uid, record, secure)) {
				response->error = ERROR_UNKNOWN;
				return true;
			}
			SetRetryTimeout(response, timeout);
			return true;
		}
	}

	return false;
}

/*******************************************************************************
 * Public functions in the gatekeeper.h in AOSP
 ******************************************************************************/
static TEE_Result enroll(uint32_t __unused param_types, TEE_Param __unused params[4])
{
	TEE_Result res = TEE_SUCCESS;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

	return res;
}

#if 0 // From gatekeeper.cpp in AOSP
void GateKeeper::Enroll(const EnrollRequest &request, EnrollResponse *response) {
    if (response == NULL) return;

    if (!request.provided_password.buffer.get()) {
        response->error = ERROR_INVALID;
        return;
    }

    secure_id_t user_id = 0;// todo: rename to policy
    uint32_t uid = request.user_id;

    if (request.password_handle.buffer.get() == NULL) {
        // Password handle does not match what is stored, generate new SecureID
        GetRandom(&user_id, sizeof(secure_id_t));
    } else {
        password_handle_t *pw_handle =
            reinterpret_cast<password_handle_t *>(request.password_handle.buffer.get());

        if (pw_handle->version > HANDLE_VERSION) {
            response->error = ERROR_INVALID;
            return;
        }

        user_id = pw_handle->user_id;

        uint64_t timestamp = GetMillisecondsSinceBoot();

        uint32_t timeout = 0;
        bool throttle = (pw_handle->version >= HANDLE_VERSION_THROTTLE);
        if (throttle) {
            bool throttle_secure = pw_handle->flags & HANDLE_FLAG_THROTTLE_SECURE;
            failure_record_t record;
            if (!GetFailureRecord(uid, user_id, &record, throttle_secure)) {
                response->error = ERROR_UNKNOWN;
                return;
            }

            if (ThrottleRequest(uid, timestamp, &record, throttle_secure, response)) return;

            if (!IncrementFailureRecord(uid, user_id, timestamp, &record, throttle_secure)) {
                response->error = ERROR_UNKNOWN;
                return;
            }

            timeout = ComputeRetryTimeout(&record);
        }

        if (!DoVerify(pw_handle, request.enrolled_password)) {
            // incorrect old password
            if (throttle && timeout > 0) {
                response->SetRetryTimeout(timeout);
            } else {
                response->error = ERROR_INVALID;
            }
            return;
        }
    }

    uint64_t flags = 0;
    if (ClearFailureRecord(uid, user_id, true)) {
        flags |= HANDLE_FLAG_THROTTLE_SECURE;
    } else {
        ClearFailureRecord(uid, user_id, false);
    }

    salt_t salt;
    GetRandom(&salt, sizeof(salt));

    SizedBuffer password_handle;
    if (!CreatePasswordHandle(&password_handle,
            salt, user_id, flags, HANDLE_VERSION, request.provided_password.buffer.get(),
            request.provided_password.length)) {
        response->error = ERROR_INVALID;
        return;
    }

    response->SetEnrolledPasswordHandle(&password_handle);
}
#endif

static TEE_Result verify(uint32_t __unused param_types, TEE_Param __unused params[4])
{
	TEE_Result res = TEE_SUCCESS;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (param_types != exp_param_types) {
		EMSG("Expected: 0x%x, got: 0x%x", exp_param_types, param_types);
		return TEE_ERROR_BAD_PARAMETERS;
	}

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
				    TEE_Param __unused params[4],
				    void __unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
}

TEE_Result TA_InvokeCommandEntryPoint(void __unused *sess_ctx,
				      uint32_t cmd_id,
				      uint32_t param_types, TEE_Param params[4])
{
	switch (cmd_id) {
	case TA_GATEKEEPER_ENROLL:
		return enroll(param_types, params);

	case TA_GATEKEEPER_VERIFY:
		return verify(param_types, params);

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
