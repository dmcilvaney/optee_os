#ifndef __TEE_ATTESTATION_DB_H
#define __TEE_ATTESTATION_DB_H

#include <utee_defines.h>

struct attest_db {
	size_t alloc_size;
	size_t fdt_size;
	struct fdt_header fdt;
	char _body[1];
};

TEE_Result attest_db_initialize(struct attest_db **attest_blob);

/*
 * Ensure a certificate is pressent in the cert group, if there is not
 * already an identical certificate (matching measurement, etc) add it.
 */
TEE_Result attest_db_add_cert(struct attest_db **attest_blob,
			      struct attestation_cert_data *cert);

/*
 * Populate the data for a given fwid value.
 */
TEE_Result attest_db_get_cert(struct attest_db **attest_blob,
			      uint8_t *fwid, size_t fwid_len,
			      struct attestation_cert_data *cert);

/*
 * Return a buffer of all certificate PEMs in a chain
 */
TEE_Result attest_db_get_chain(struct attest_db **attest_blob,
			       uint8_t *fwid, size_t fwid_len, char *buf,
			       size_t *buf_size);

void attest_db_dump(struct attest_db **attest_blob);

#endif /* __TEE_ATTESTATION_DB_H */