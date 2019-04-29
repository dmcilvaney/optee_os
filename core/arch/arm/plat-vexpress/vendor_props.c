// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited.
 */
#include <tee/tee_svc.h>
#include <user_ta_header.h>
#include <util.h>
#include <kernel/tee_ta_manager.h>
#include <kernel/tee_common_otp.h>
#include <tee/tee_cryp_utl.h>

/*
 * This property generates a seed value
 * for each TA (as identified by its UUID)
 * which is tied to the hardware.
 * 
 * Note: Use tee_otp_get_hw_unique_key() instead
 * of tee_otp_get_die_id() to generate a seed
 * which is uinique for individual devices rather
 * than the more generic device type as might be
 * provided by the die ID.
 * 
 * The data to hash is 48 bytes made up of:
 * - 16 bytes: the UUID of the calling TA.
 * - 32 bytes: the hardware die ID
 * 
 * The resulting endorsement seed is the 
 * SHA256 hash of the above data.
 *
 */
static TEE_Result get_prop_endorsement(struct tee_ta_session *sess,
				       void *buf, size_t *blen)
{
	TEE_Result res;
	uint8_t ta_endorsement_seed[TEE_SHA256_HASH_SIZE];
	uint32_t ta_endorsement_seed_size = sizeof(ta_endorsement_seed);
	uint8_t input_data[sizeof(TEE_UUID) + TEE_SHA256_HASH_SIZE];

	if (*blen < ta_endorsement_seed_size) {
		*blen =ta_endorsement_seed_size;
		return TEE_ERROR_SHORT_BUFFER;
	}
	*blen = ta_endorsement_seed_size;

	// Copy UUID into the data to be hashed
	memcpy(input_data, &sess->ctx->uuid, sizeof(TEE_UUID));

	// Add the die ID after the UUID
	if (tee_otp_get_die_id(&input_data[sizeof(TEE_UUID)],
			       TEE_SHA256_HASH_SIZE))
		return TEE_ERROR_BAD_STATE;

	res = tee_hash_createdigest(TEE_ALG_SHA256, input_data, sizeof(input_data),
				    ta_endorsement_seed, ta_endorsement_seed_size);
	if (res != TEE_SUCCESS)
		return TEE_ERROR_BAD_STATE;

	return tee_svc_copy_to_user((void *)buf, ta_endorsement_seed, ta_endorsement_seed_size);
}

static const struct tee_props vendor_propset_array_tee[] = {
	{
		.name = "com.microsoft.ta.endorsementSeed",
		.prop_type = USER_TA_PROP_TYPE_BINARY_BLOCK,
		.get_prop_func = get_prop_endorsement
	},
};

const struct tee_vendor_props vendor_props_tee = {
	.props = vendor_propset_array_tee,
	.len = ARRAY_SIZE(vendor_propset_array_tee),
};
