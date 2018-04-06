/*
 * Copyright (c) 2017, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

/* The name of this file must not be modified */
#ifndef USER_TA_HEADER_DEFINES_H
#define USER_TA_HEADER_DEFINES_H

#include <aes-cbc-mac_ta.h>

#define TA_UUID		TA_AES_CBC_MAC_UUID
#define TA_FLAGS	TA_FLAG_EXEC_DDR
#define TA_STACK_SIZE	(2 * 1024)
#define TA_DATA_SIZE	(32 * 1024)

#define TA_CURRENT_TA_EXT_PROPERTIES \
	{ "gp.ta.description", USER_TA_PROP_TYPE_STRING, \
	  "AES-CBC-MAC" }, \
	{ "gp.ta.version", USER_TA_PROP_TYPE_U32, &(const uint32_t){ 0x0010 } }

#endif
