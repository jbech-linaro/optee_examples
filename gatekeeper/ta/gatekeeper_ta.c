/*
 * Copyright (c) 2018, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */
#include <gatekeeper_ta.h>
#include <string.h>
#include <string_ext.h>
#include <tee_internal_api_extensions.h>
#include <tee_internal_api.h>

#define DAY_IN_MS (1000 * 60 * 60 * 24)
#define MS_PER_S 1000


/*
 *  HMAC a block of memory to produce the authentication tag
 *  @param key       The secret key
 *  @param keylen    The length of the secret key (bytes)
 *  @param in        The data to HMAC
 *  @param inlen     The length of the data to HMAC (bytes)
 *  @param out       [out] Destination of the authentication tag
 *  @param outlen    [in/out] Max size and resulting size of authentication tag
 */
static TEE_Result hmac_sha256(const uint8_t *key, const size_t keylen,
			      const uint8_t *in, const size_t inlen,
			      uint8_t *out, uint32_t *outlen)
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
	 *    Note that the expected size here is in bits (and therefore times
	 *    8)!
	 */
	res = TEE_AllocateOperation(&op_handle, TEE_ALG_HMAC_SHA256,
				    TEE_MODE_MAC, keylen * 8);
	if (res != TEE_SUCCESS) {
		EMSG("0x%08x", res);
		goto exit;
	}

	/*
	 * 2. Allocate a container (key handle) for the HMAC attributes. Note
	 *    that the expected size here is in bits (and therefore times 8)!
	 */
	res = TEE_AllocateTransientObject(TEE_TYPE_HMAC_SHA1, keylen * 8,
					  &key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("0x%08x", res);
		goto exit;
	}

	/*
	 * 3. Initialize the attributes, i.e., point to the actual HMAC key.
	 *    Here, the expected size is in bytes and not bits as above!
	 */
	TEE_InitRefAttribute(&attr, TEE_ATTR_SECRET_VALUE, key, keylen);

	/* 4. Populate/assign the attributes with the key object */
	res = TEE_PopulateTransientObject(key_handle, &attr, 1);
	if (res != TEE_SUCCESS) {
		EMSG("0x%08x", res);
		goto exit;
	}

	/* 5. Associate the key (object) with the operation */
	res = TEE_SetOperationKey(op_handle, key_handle);
	if (res != TEE_SUCCESS) {
		EMSG("0x%08x", res);
		goto exit;
	}

	/* 6. Do the HMAC operations */
	TEE_MACInit(op_handle, NULL, 0);
	TEE_MACUpdate(op_handle, in, inlen);
	res = TEE_MACComputeFinal(op_handle, NULL, 0, out, outlen);
exit:
	if (op_handle != TEE_HANDLE_NULL)
		TEE_FreeOperation(op_handle);

	/* It is OK to call this when key_handle is TEE_HANDLE_NULL */
	TEE_FreeTransientObject(key_handle);

	return res;
}

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
	uint8_t buf[SHA256_HASH_SIZE];
	size_t buf_len;
	size_t to_write;
	TEE_Result res = TEE_ERROR_GENERIC;

	res = hmac_sha256(key, key_length, message, length, buf, &buf_len);
	if (res != TEE_SUCCESS) {
		memset(signature, 0, signature_length);
		signature_length = 0;
		return;
	}

	to_write = buf_len;

	if (buf_len > signature_length)
		to_write = signature_length;

	memset(signature, 0, signature_length);
	memcpy(signature, buf, to_write);
}

static void ComputePasswordSignature(
	uint8_t *signature, uint32_t signature_length,
	const uint8_t *key, uint32_t key_length,
	const uint8_t *password, uint32_t password_length,
	salt_t salt)
{
	uint8_t salted_password[password_length + sizeof(salt)];
	memcpy(salted_password, &salt, sizeof(salt));
	memcpy(salted_password + sizeof(salt), password, password_length);
	ComputeSignature(signature, signature_length, key, key_length,
			 salted_password, password_length + sizeof(salt));
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
	struct failure_record_t record;
	record.secure_user_id = user_id;
	record.last_checked_timestamp = 0;
	record.failure_counter = 0;
	return WriteFailureRecord(uid, &record, secure);
}

/*
 * Calculates the timeout in milliseconds as a function of the failure
 * counter 'x' as follows:
 *
 * [0. 5) -> 0
 * 5 -> 30
 * [6, 10) -> 0
 * [11, 30) -> 30
 * [30, 140) -> 30 * (2^((x - 30)/10))
 * [140, inf) -> 1 day
 *
 * TODO: Function more or less a copy/paste from AOSP, license!
 */
static uint32_t ComputeRetryTimeout(const struct failure_record_t *record)
{
	static const int failure_timeout_ms = 30000;
	if (record->failure_counter == 0)
		return 0;

	if (record->failure_counter > 0 && record->failure_counter <= 10) {
		if (record->failure_counter % 5 == 0) {
			return failure_timeout_ms;
		}  else {
			return 0;
		}
	} else if (record->failure_counter < 30) {
		return failure_timeout_ms;
	} else if (record->failure_counter < 140) {
		return failure_timeout_ms << ((record->failure_counter - 30) / 10);
	}

	return DAY_IN_MS;
}

static bool IsHardwareBacked(void)
{
	return true;
}

/* TODO: This is in the "private" area below */
static bool CreatePasswordHandle(struct password_handle_t *password_handle,
				 salt_t salt, secure_id_t user_id,
				 uint64_t flags, uint8_t handle_version,
				 const uint8_t *password, uint32_t password_length);

static bool DoVerify(const struct password_handle_t *expected_handle,
		     const uint8_t *password, size_t password_length)
{
	struct password_handle_t provided_handle;

	if (!password)
		return false;

	if (!CreatePasswordHandle(&provided_handle,
				  expected_handle->salt, expected_handle->user_id,
				  expected_handle->flags, expected_handle->version,
				  password, password_length)) {
		return false;
	}

	return buf_compare_ct(provided_handle.signature, expected_handle->signature,
			sizeof(expected_handle->signature)) == 0;
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

static bool CreatePasswordHandle(struct password_handle_t *password_handle,
				 salt_t salt, secure_id_t user_id,
				 uint64_t flags, uint8_t handle_version,
				 const uint8_t *password, uint32_t password_length)
{
	uint32_t metadata_length = sizeof(user_id) + sizeof(flags) +
		sizeof(HANDLE_VERSION);

	const size_t to_sign_size = password_length + metadata_length;
	const uint8_t *password_key = NULL;
	uint32_t password_key_length = 0;
	uint8_t *to_sign;

	password_handle->version = handle_version;
	password_handle->salt = salt;
	password_handle->user_id = user_id;
	password_handle->flags = flags;
	password_handle->hardware_backed = IsHardwareBacked();

	to_sign = TEE_Malloc(to_sign_size, TEE_MALLOC_FILL_ZERO);
	if (!to_sign)
		return false;

	memcpy(to_sign, password_handle, metadata_length);
	memcpy(to_sign + metadata_length, password, password_length); 

	GetPasswordKey(&password_key, &password_key_length);
	if (!password_key || password_key_length == 0) {
		TEE_Free(to_sign);
		return false;
	}

	ComputePasswordSignature(password_handle->signature,
				 sizeof(password_handle->signature),
				 password_key, password_key_length,
				 to_sign, to_sign_size, salt);
	TEE_Free(to_sign);

	return true;
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
