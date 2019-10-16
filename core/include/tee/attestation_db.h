#ifndef __TEE_ATTESTATION_DB_H
#define __TEE_ATTESTATION_DB_H

#include <utee_defines.h>

struct attestation_cert_blob {
	size_t alloc_size;
	size_t fdt_size;
	struct fdt_header fdt;
	char _body[1];
};

TEE_Result initialize_empty_fdt(struct attestation_cert_blob **cert_blob);

/*
 * Ensure a certificate is pressent in the cert group, if there is not
 * already an identical certificate (matching measurement, etc) add it.
 */
TEE_Result add_cert_fdt(struct attestation_cert_blob **cert_blob,
			struct attestation_cert_data *cert);

/*
 * Return a buffer of all certificate PEMs
 */
TEE_Result get_certs_fdt(struct attestation_cert_blob **cert_blob,
			 uint8_t *fwid, size_t fwid_len, char *buf,
			 size_t *buf_size);

void dump_fdt(struct attestation_cert_blob **cert_blob);

#endif /* __TEE_ATTESTATION_DB_H */