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
#include <stdio.h>
#include <string.h>
#include "string_ext.h"
#include <tee_api_types.h>
#include <tee/attestation.h>
#include <tee/attestation_db.h>
#include <trace.h>
#include <util.h>


static struct attestation_cert_blob *cert_blob;
static struct attestation_alias_data optee_data;

struct attestation_state {
	uint8_t fwid[ATTESTATION_MEASUREMENT_SIZE];
};

__weak TEE_Result attestation_get_certs(struct attestation_alias_data *ctx,
					char *buf, size_t *buf_len)
{
	uint8_t *fwid = NULL;

	if (!buf_len || !ctx)
		return TEE_ERROR_BAD_PARAMETERS;

	fwid = ((struct attestation_state *)ctx->plat_data)->fwid;
	return get_certs_fdt(&cert_blob, fwid, ATTESTATION_MEASUREMENT_SIZE,
			     buf, buf_len);
}



__weak TEE_Result attestation_create_alias(struct attestation_alias_data *ctx)
{
	struct attestation_cert_data *cert = NULL;
	uint8_t *optee_fwid = NULL;
	uint8_t *subject_fwid = NULL;
	TEE_Result res;
	char ta_uuid_name[64];
	struct tee_ta_session *ta_session = NULL;
	struct user_ta_ctx *utc;

	char test_data[] = "YOUR PEM HERE";

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

	snprintf(ta_uuid_name, sizeof(ta_uuid_name), "%pUl",
		 (void *)&ta_session->ctx->uuid);
	utc = to_user_ta_ctx(ta_session->ctx);

	subject_fwid = ((struct attestation_state *)ctx->plat_data)->fwid;
	memcpy(subject_fwid, utc->attestation_data.static_measurement,
	       sizeof(utc->attestation_data.static_measurement));

	DMSG("Attesting to ta %s (%pUl)", ta_uuid_name, (void *)&ta_session->ctx->uuid);

	cert = calloc(1, sizeof(*cert));
	strlcpy(cert->issuer, "optee", sizeof(cert->issuer));
	optee_fwid = ((struct attestation_state *)optee_data.plat_data)->fwid;

	strlcpy(cert->subject, ta_uuid_name, sizeof(cert->subject));
	memcpy(cert->pem, test_data, sizeof(test_data));
	memcpy(cert->subject_fwid, subject_fwid, sizeof(cert->subject_fwid));
	memcpy(cert->issuer_fwid, optee_fwid, ATTESTATION_MEASUREMENT_SIZE);

	res = add_cert_fdt(&cert_blob, cert);
	if(!res)
		ctx->has_alias = true;

	free(cert);
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

static TEE_Result add_optee_root(void)
{
	struct attestation_cert_data *root_cert = NULL;
	char name[] = "optee";
	struct attestation_state *optee_state = NULL;
	char temp_pem[] = "OPTEE PEM HERE!"; //TODO
	TEE_Result res;

	optee_data.plat_data = calloc(1, sizeof(struct attestation_state));
	if (!optee_data.plat_data)
		return TEE_ERROR_OUT_OF_MEMORY;

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
	
	//TODO: Don't use the alias directly as the fwid!
	root_cert = calloc(1, sizeof(*root_cert));
	if (!root_cert)
		return TEE_ERROR_OUT_OF_MEMORY;
	optee_state = (struct attestation_state *)optee_data.plat_data;
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
	res =  add_cert_fdt(&cert_blob, root_cert);

	free(root_cert);
	return res;
}

__weak TEE_Result initialize_cert_chain(void)
{
	TEE_Result res;

	/*
	 * Create an empty set of certificates. Ideally an earlier firmware
	 * stage would have created and signed a certificate for OP-TEE which
	 * we could store here instead.
	 */
	cert_blob = NULL;
	res = initialize_empty_fdt(&cert_blob);
	if (res)
		return res;

	/* Add a self-signed certificate for OP-TEE */
	res = add_optee_root();
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
	struct attestation_cert_data *cert = NULL;
	uint8_t *optee_fwid = NULL;
	size_t optee_fwid_size = 0;
	char test_data[] = "PEM HERE";
	char baz_fwid[] = "BAZ FWID";
	char bang_fwid[] = "BANG FWID";
	char wizz_fwid[] = "WIZZ FWID";

	cert = calloc(1, sizeof(*cert));
	optee_fwid = ((struct attestation_state *)optee_data.plat_data)->fwid;
	optee_fwid_size = ATTESTATION_MEASUREMENT_SIZE;

	strlcpy(cert->issuer, "optee", sizeof(cert->issuer));
	strlcpy(cert->subject, "Baz", sizeof(cert->subject));
	strlcpy(cert->pem, test_data, sizeof(test_data));
	memcpy(cert->subject_fwid, baz_fwid, sizeof(baz_fwid));
	memcpy(cert->issuer_fwid, optee_fwid, optee_fwid_size);
	add_cert_fdt(&cert_blob, cert);

	memset(cert, 0, sizeof(*cert));
	strlcpy(cert->issuer, "optee", sizeof(cert->issuer));
	strlcpy(cert->subject, "Bang", sizeof(cert->subject));
	strlcpy(cert->pem, test_data, sizeof(test_data));
	memcpy(cert->subject_fwid, bang_fwid, sizeof(bang_fwid));
	memcpy(cert->issuer_fwid, optee_fwid, optee_fwid_size);
	add_cert_fdt(&cert_blob, cert);

	memset(cert, 0, sizeof(*cert));
	strlcpy(cert->issuer, "Baz", sizeof(cert->issuer));
	strlcpy(cert->subject, "Wizz", sizeof(cert->subject));
	strlcpy(cert->pem, test_data, sizeof(test_data));
	memcpy(cert->subject_fwid, wizz_fwid, sizeof(wizz_fwid));
	memcpy(cert->issuer_fwid, baz_fwid, sizeof(baz_fwid));
	add_cert_fdt(&cert_blob, cert);

	/* Try to re-add, make sure we only get one */
	add_cert_fdt(&cert_blob, cert);

	cert->pem[0] += 1;
	add_cert_fdt(&cert_blob, cert);

	free(cert);
}

static TEE_Result attestation_initialization(void)
{
	/*
	 * Platform specific method to pick up private certificate data.
	 * Default implementation will initialize a new certificate chain.
	 */
	initialize_cert_chain();

	test_cert_chain();

	dump_fdt(&cert_blob);

	return TEE_SUCCESS;
}

service_init_late(attestation_initialization);