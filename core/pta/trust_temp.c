#include <tee/attestation.h>
#include <kernel/pseudo_ta.h>
#include <pta_trust_temp.h>
#include <kernel/user_ta.h>

/*
 * Just initialize the certificate in the store.
 */
static TEE_Result trust_add_ta_cert(
	struct attestation_alias_data *ctx,
	uint32_t param_types __unused,
	TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	return attestation_create_alias(ctx);
}

static TEE_Result trust_get_certs(
	struct attestation_alias_data *ctx,
	uint32_t param_types __unused,
	TEE_Param params[TEE_NUM_PARAMS] __unused)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	size_t buf_len = 0;
	char *buf = NULL;

	res = attestation_get_ta_certs(ctx, NULL, &buf_len);
	if (res)
		return res;

	DMSG("Making buffer of length %d", buf_len);
	buf = malloc(buf_len);
	if(!buf)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = attestation_get_ta_certs(ctx, buf, &buf_len);
	if (!res) {
		DMSG("Got the string back:");
		trace_ext_puts(buf);
		trace_ext_puts("\n");
	}
	free(buf);

	res = attestation_get_all_certs(ctx, NULL, &buf_len);
	if (res)
		return res;

	DMSG("Making buffer of length %d", buf_len);
	buf = malloc(buf_len);
	if (!buf)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = attestation_get_all_certs(ctx, buf, &buf_len);
	if (!res) {
		DMSG("Got the string back:");
		trace_ext_puts(buf);
		trace_ext_puts("\n");
	}
	free(buf);

	return res;
}

static TEE_Result trust_invoke_command(void *sess_ctx, uint32_t cmd_id, 
				       uint32_t param_types,
				       TEE_Param params[TEE_NUM_PARAMS])
{
	struct attestation_alias_data *ctx = NULL;

	ctx = (struct attestation_alias_data *)sess_ctx;

	switch (cmd_id) {
	case CMD_TRUST_TEST:
		return trust_add_ta_cert(ctx, param_types, params);
	case CMD_GET_CERTS:
		return trust_get_certs(ctx, param_types, params);
	default:
		return TEE_ERROR_NOT_IMPLEMENTED;
	}
}

static TEE_Result trust_open_session(
	uint32_t param_types __unused,
	TEE_Param params[TEE_NUM_PARAMS] __unused,
	void **sess_ctx)
{
	struct attestation_alias_data *ctx;
	struct tee_ta_session *ta_session = NULL;

	ta_session = tee_ta_get_calling_session();
	if (!ta_session)
		return TEE_ERROR_BAD_STATE;

	if (!is_user_ta_ctx(ta_session->ctx))
		return TEE_ERROR_NOT_SUPPORTED;

	/* trust_close_session() handles cleanup even after errors */
	ctx = calloc(1, sizeof(struct attestation_alias_data));
	if (!ctx)
		return TEE_ERROR_OUT_OF_MEMORY;

	*sess_ctx = ctx;

	return attestation_start(ctx);
}

static void trust_close_session(void *sess_ctx)
{
	struct attestation_alias_data *ctx = sess_ctx;

	attestation_cleanup(ctx);

	if (ctx)
		free(ctx);
}

pseudo_ta_register(.uuid = PTA_TRUST_UUID, .name = "pta_trust",
		   .flags = PTA_DEFAULT_FLAGS,
		   .open_session_entry_point = trust_open_session,
		   .close_session_entry_point = trust_close_session,
		   .invoke_command_entry_point = trust_invoke_command);
