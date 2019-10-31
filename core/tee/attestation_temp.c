// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Microsoft Corporation
 */

#include <compiler.h>
#include <initcall.h>
#include <kernel/huk_subkey.h>
#include <kernel/linker.h>
#include <kernel/mutex.h>
#include <kernel/user_ta.h>
#include <libfdt.h>
#include <printk.h>
#include <stdio.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <tee/attestation.h>
#include <tee/attestation_db.h>
#include <trace.h>
#include <util.h>


static struct attest_db *cert_blob;
static struct attestation_alias_data optee_data;

#ifdef CFG_ATTESTATION_PREBAKED
extern const uint8_t attestation_prebaked_fdt[];
#endif

struct attestation_state {
	uint8_t fwid[ATTESTATION_MEASUREMENT_SIZE];
};

__weak TEE_Result attestation_get_ta_certs(struct attestation_alias_data *ctx,
					   char *buf, size_t *buf_len)
{
	uint8_t *fwid = NULL;

	if (!buf_len || !ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	fwid = ((struct attestation_state *)ctx->plat_data)->fwid;
	return attest_db_get_chain(&cert_blob, fwid,
				   ATTESTATION_MEASUREMENT_SIZE, buf, buf_len);
}

__weak TEE_Result attestation_get_all_certs(struct attestation_alias_data *ctx,
					    char *buf, size_t *buf_len)
{
	if (!buf_len || !ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	return attest_db_get_tree(&cert_blob, buf, buf_len);
}


__weak TEE_Result attestation_create_alias(struct attestation_alias_data *ctx)
{
	TEE_Result res;
	struct user_ta_ctx *utc;
	struct tee_ta_session *ta_session = NULL;
	struct attestation_cert_data *cert = NULL;
	struct attestation_state *optee_state = NULL;
	struct attestation_state *subject_state = NULL;
	struct tee_attestation_data *ta_measurements = NULL;
	char ta_uuid_name[64];

	char test_data[] = "-----BEGIN CERTIFICATE-----\n"
			   "YOUR PEM HERE\n"
			   "-----END CERTIFICATE-----";

	if(ctx->has_alias)
		return TEE_SUCCESS;

	if(!ctx->plat_data) {
		/*
		 * Default implementation just tracks the fwid, this
		 * could be something like TPM objects, or other platform
		 * specific data. This should be cleaned up in
		 * attestation_cleanup() which will be called automatically.
		 */
		ctx->plat_data = calloc(1, sizeof(struct attestation_state));
		if (!ctx->plat_data)
			return TEE_ERROR_OUT_OF_MEMORY;
	}

	ta_session = tee_ta_get_calling_session();
	if (!ta_session)
		return TEE_ERROR_BAD_STATE;

	snprintk(ta_uuid_name, sizeof(ta_uuid_name), "%pUl",
		 (void *)&ta_session->ctx->uuid);
	utc = to_user_ta_ctx(ta_session->ctx);
	DMSG("Attesting to ta %s", ta_uuid_name);

	/*
	 * Derive a fwid for this TA based on OP-TEE's alias and the
	 * measurement of the TA.
	 */
	subject_state = (struct attestation_state *)ctx->plat_data;
	optee_state = (struct attestation_state *)optee_data.plat_data;
	ta_measurements = &utc->attestation_data;

	//TODO: Calculate actual fwid, alias
	DMSG("Measurement which would be used:");
	DHEXDUMP(ta_measurements->static_measurement,
		 sizeof(ta_measurements->static_measurement));
	memcpy(ctx->alias_identity, utc->attestation_data.static_measurement,
	       sizeof(subject_state->fwid));
	memcpy(subject_state->fwid, ctx->alias_identity,
	       sizeof(subject_state->fwid));

	cert = calloc(1, sizeof(*cert));
	strlcpy(cert->issuer, "optee", sizeof(cert->issuer));
	strlcpy(cert->subject, ta_uuid_name, sizeof(cert->subject));
	memcpy(cert->pem, test_data, sizeof(test_data));
	memcpy(cert->subject_fwid, subject_state->fwid,
	       sizeof(cert->subject_fwid));
	memcpy(cert->issuer_fwid, optee_state->fwid,
	       sizeof(cert->issuer_fwid));

	res = attest_db_add_cert(&cert_blob, cert);
	if(!res)
		ctx->has_alias = true;

	free(cert);

	attest_db_dump(&cert_blob);

	return res;
}

__weak void attestation_cleanup(struct attestation_alias_data *ctx)
{
	struct tee_ta_session *ta_session = NULL;
	struct user_ta_ctx *utc;

	ta_session = tee_ta_get_calling_session();
	if(ta_session) {
		utc = to_user_ta_ctx(ta_session->ctx);
		DMSG("Stopping attestation for TA %pUl",
		     (void *)&utc->ctx.uuid);
	}

	if (ctx->plat_data)
		free(ctx->plat_data);
}

__weak TEE_Result attestation_start(struct attestation_alias_data *ctx)
{
	struct tee_ta_session *ta_session = NULL;
	struct user_ta_ctx *utc;

	(void)ctx;

	ta_session = tee_ta_get_calling_session();
	if (!ta_session)
		return TEE_ERROR_BAD_STATE;

	utc = to_user_ta_ctx(ta_session->ctx);
	DMSG("Attestation starting for TA %pUl with measurement:",
	     (void *)&utc->ctx.uuid);
	DHEXDUMP(utc->attestation_data.static_measurement,
		 sizeof(utc-> attestation_data.static_measurement));

	return TEE_SUCCESS;
}

#ifdef CFG_ATTESTATION_PREBAKED
/*
 * See attestation_db.h for details.
 *
 * Initialize the attestation database with a premade database image which is
 * compiled into OP-TEE. This premade image should contain at least a node
 * for OP-TEE, along with OP-TEE's private data.
 */
static TEE_Result initialize_prebaked_chain(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct attestation_state *optee_state = NULL;
	void *prebaked_fdt = NULL;
	const uint8_t *property;
	int fdt_res = 0;

	prebaked_fdt = (void *)attestation_prebaked_fdt;

	if (!optee_data.plat_data) {
		optee_data.plat_data = calloc(1,
					      sizeof(struct attestation_state));
		if (!optee_data.plat_data)
			return TEE_ERROR_OUT_OF_MEMORY;
	}
	optee_state = (struct attestation_state *)optee_data.plat_data;

	property = fdt_getprop(prebaked_fdt, 0, "optee_prebaked_alias",
			       &fdt_res);
	if (!property)
		return TEE_ERROR_ITEM_NOT_FOUND;
	if (fdt_res != sizeof(optee_data.alias_identity))
		return TEE_ERROR_BAD_FORMAT;
	memcpy(optee_data.alias_identity, property,
	       sizeof(optee_data.alias_identity));
	optee_data.has_alias = true;

	property = fdt_getprop(prebaked_fdt, 0, "optee_prebaked_fwid",
			       &fdt_res);
	if (!property)
		return TEE_ERROR_ITEM_NOT_FOUND;
	if (fdt_res != sizeof(optee_state->fwid))
		return TEE_ERROR_BAD_FORMAT;
	memcpy(optee_state->fwid, property, sizeof(optee_state->fwid));

	//TODO: Consume the pre-baked PEM encoded key for OP-TEE here!
	property = fdt_getprop(prebaked_fdt, 0, "optee_prebaked_key_pem",
			       &fdt_res);
	if (!property)
		return TEE_ERROR_ITEM_NOT_FOUND;
	//if (fdt_res != sizeof(OPTEE PEM)
	//	return TEE_ERROR_BAD_FORMAT;
	//TODO: Extract key into optee_data.alias_key

	res = attest_db_inject_fdt(&cert_blob, prebaked_fdt);
	attest_db_dump(&cert_blob);

	return res;
}
#else
static TEE_Result add_optee_root(void)
{
	TEE_Result res;

	struct attestation_cert_data *root_cert = NULL;
	char name[] = "optee";
	struct attestation_state *optee_state = NULL;
	char temp_pem[] = "-----BEGIN CERTIFICATE-----\n"
			  "OPTEE PEM\n"
			  "-----END CERTIFICATE-----"; //TODO
	if (!optee_data.plat_data) {
		optee_data.plat_data = calloc(1,
					      sizeof(struct attestation_state));
		if (!optee_data.plat_data)
			return TEE_ERROR_OUT_OF_MEMORY;
	}

	/*
	 * Derive a root of trust for this device from the HUK. Ideally
	 * this would be calculated by a trusted external source such as
	 * an earlier firmware stage, and would include an independent
	 * measurement of OP-TEE's code.
	 */
	res = huk_subkey_derive(HUK_ATTESTATION_ROOT,
				core_v_str, strlen(core_v_str),
				optee_data.alias_identity,
				sizeof(optee_data.alias_identity));
	if (res)
		return res;
	
	root_cert = calloc(1, sizeof(*root_cert));
	if (!root_cert)
		return TEE_ERROR_OUT_OF_MEMORY;
	optee_state = (struct attestation_state *)optee_data.plat_data;
	//TODO: Compute actual useful fwid.
	memcpy(optee_state->fwid, optee_data.alias_identity,
	       sizeof(optee_state->fwid));
	memcpy(root_cert->subject_fwid, optee_data.alias_identity,
	       sizeof(root_cert->subject_fwid));
	optee_data.has_alias = true;

	/* Self signed, so the fwids are the same. */
	memcpy(root_cert->issuer_fwid, root_cert->subject_fwid,
	       sizeof(root_cert->subject_fwid));

	//TODO: Generate our signing keys here?

	//TODO: Create the x509 cert here?

	strlcpy(root_cert->subject, name, sizeof(root_cert->subject));
	strlcpy(root_cert->issuer, name, sizeof(root_cert->issuer));
	strlcpy(root_cert->pem, temp_pem, sizeof(temp_pem));

	/*
	 * Add the self-signed root of trust to the certificate store. This
	 * certificate should be unique to the device it was created on
	 */
	res =  attest_db_add_cert(&cert_blob, root_cert);

	free(root_cert);
	return res;
}
#endif /* CFG_ATTESTATION_PREBAKED */

__weak TEE_Result initialize_cert_chain(void)
{
	TEE_Result res;

	/*
	 * Create an empty set of certificates. Ideally an earlier firmware
	 * stage would have created and signed a certificate for OP-TEE which
	 * we could store here instead.
	 */
	cert_blob = NULL;
	res = attest_db_initialize(&cert_blob);
	if (res)
		return res;

#ifdef CFG_ATTESTATION_PREBAKED
	/* Load a pre-build fdt from the OP-TEE binary. For testing purposes. */
	res = initialize_prebaked_chain();
#else

	/* Add a self-signed certificate for OP-TEE */
	res = add_optee_root();
#endif
	if (res)
		goto error;

	return TEE_SUCCESS;
error:
	free(cert_blob);
	cert_blob = NULL;
	return res;
}

static void test_cert_chain(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	struct attestation_cert_data *cert = NULL;
	uint8_t *optee_fwid = NULL;
	size_t optee_fwid_size = 0;
	char test_data[] = "-----BEGIN CERTIFICATE-----\n"
			   "TEST PEM\n"
			   "-----END CERTIFICATE-----";
	uint8_t baz_fwid[] = "BAZ FWID";
	uint8_t bang_fwid[] = "BANG FWID";
	uint8_t wizz_fwid[] = "WIZZ FWID";
	uint8_t misc_data[] = "MISC DATA FOR BAZ";
	uint8_t *data_back = NULL;
	size_t data_back_len = 0;

	cert = calloc(1, sizeof(*cert));
	optee_fwid = ((struct attestation_state *)optee_data.plat_data)->fwid;
	optee_fwid_size = ATTESTATION_MEASUREMENT_SIZE;

	strlcpy(cert->issuer, "optee", sizeof(cert->issuer));
	strlcpy(cert->subject, "Baz", sizeof(cert->subject));
	strlcpy(cert->pem, test_data, sizeof(test_data));
	memcpy(cert->subject_fwid, baz_fwid, sizeof(baz_fwid));
	memcpy(cert->issuer_fwid, optee_fwid, optee_fwid_size);
	res = attest_db_add_cert(&cert_blob, cert);
	if (res != TEE_SUCCESS)
		panic("cert test fail");

	res = attest_db_set_misc_data(&cert_blob, cert->subject_fwid,
				      sizeof(cert->subject_fwid), misc_data,
				      sizeof(misc_data));
	if (res != TEE_SUCCESS)
		panic("cert test fail");
	res = attest_db_get_misc_data(&cert_blob, cert->subject_fwid,
				      sizeof(cert->subject_fwid), NULL,
				      &data_back_len);
	if (res != TEE_ERROR_SHORT_BUFFER)
		panic("cert test fail");
	data_back = malloc(data_back_len);
	res = attest_db_get_misc_data(&cert_blob, cert->subject_fwid,
				      sizeof(cert->subject_fwid), data_back,
				      &data_back_len);
	if (res != TEE_SUCCESS)
		panic("cert test fail");
	if (memcmp(data_back, misc_data, data_back_len) ||
	    data_back_len != sizeof(misc_data))
		panic("cert test fail");
	free(data_back);

	memset(cert, 0, sizeof(*cert));
	strlcpy(cert->issuer, "optee", sizeof(cert->issuer));
	strlcpy(cert->subject, "Bang", sizeof(cert->subject));
	strlcpy(cert->pem, test_data, sizeof(test_data));
	memcpy(cert->subject_fwid, bang_fwid, sizeof(bang_fwid));
	memcpy(cert->issuer_fwid, optee_fwid, optee_fwid_size);
	res = attest_db_add_cert(&cert_blob, cert);
	if (res != TEE_SUCCESS)
		panic("cert test fail");

	memset(cert, 0, sizeof(*cert));
	strlcpy(cert->issuer, "Baz", sizeof(cert->issuer));
	strlcpy(cert->subject, "Wizz", sizeof(cert->subject));
	strlcpy(cert->pem, test_data, sizeof(test_data));
	memcpy(cert->subject_fwid, wizz_fwid, sizeof(wizz_fwid));
	memcpy(cert->issuer_fwid, baz_fwid, sizeof(baz_fwid));
	res = attest_db_add_cert(&cert_blob, cert);
	if (res != TEE_SUCCESS)
		panic("cert test fail");

	/* Try to re-add, make sure we only get one */
	res = attest_db_add_cert(&cert_blob, cert);
	if (res != TEE_SUCCESS)
		panic("cert test fail");

	/* Create a non-unique cert for an existing fwid */
	cert->pem[0] += 1;
	res = attest_db_add_cert(&cert_blob, cert);
	if (res != TEE_ERROR_SECURITY)
		panic("cert test fail");

	free(cert);
}

static TEE_Result attestation_initialization(void)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	/*
	 * Platform specific method to pick up private certificate data.
	 * Default implementation will initialize a new certificate chain.
	 */
	res = initialize_cert_chain();
	if (res)
		return res;

	test_cert_chain();

	res = attest_db_dump(&cert_blob);

	return res;
}

service_init_late(attestation_initialization);