/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Microsoft Corporation.
 */

#ifndef __TEE_ATTESTATION_H
#define __TEE_ATTESTATION_H

#include <crypto/crypto.h>
#include <utee_defines.h>

/* 
 * Attestation:
 * Attestation of user TAs in OP-TEE is done via code measurement at load
 * time. If CFG_ATTESTATION_MEASURE is enabled the System PTA will request
 * a hash from the user TA store. Each time a new binary is loaded (ie 
 * shared libraries) for a given TA context the existing measurement is 
 * combined with the incoming measurement to form a new hash. The
 * measurement is dependent on the order in which binaries are loaded. A 
 * copy of the running measurement is frozen before the first session to
 * the TA is opened.
 * 
 * This static measurement is included in a x509 certificate signed by
 * OP-TEE, along with other information. The measurement can also be used
 * to create binary locked encrypted objects and derive additional keys.
 *
 * Run Time Binary Loading:
 * The system PTA offers the option to load binaries after a TA has started
 * running (dlopen etc). This poses an interesting challenge for attestation
 * since the original measurement will no longer be valid. While the frozen
 * measurement is always available, a dynamic measurement is also maintained
 * which includes all dynamically loaded components.
 * 
 * TODO: Flesh out this description
 * 
 * Issues:
 * 
 * - Inconsistent Measurements
 * Secstor and Ree FS TAs are not measured the same as Early TAs. Early TAs do
 * not include any headers when they are encoded into the OP-TEE binary and
 * are a simple hash over the (default compressed) .elf being loaded. The
 * other user TA measurements are based on the existing verification flow and
 * include parts of the TA headers.
 *
 * - Measurements too early
 * Ideally measurements should be taked during mapping of the TAs rather than
 * during initial binary loading. The much simpler measurement is being used
 * for version 1.
 * 
 */
#ifdef CFG_ATTESTATION_MEASURE

#define ATTESTATION_MEASUREMENT_SIZE	TEE_SHA256_HASH_SIZE
#define ATTESTATION_MEASUREMENT_ALGO	TEE_ALG_SHA256
#define ATTESTATION_VERSION		1
#define DER_MAX_PEM			0x500
#define ATTESTATION_NAME_MAX		0x50

/*
 * Certificates are stored in an FDT with the following layout:
 * fdt:
 *	version: 1234
 *	certs:
 *		cert-1:	<node>
 *			cert-1: <node>
 *			cert-2: <node>
 *			...
 *		cert-2:	<node>
 *		...
 *
 * Node layout:
 * cert:
 *	subject:	"<UUID>/optee"
 *	issuer:		<&issuer>
 *	fwid:		"<derived SHA256>"
 *	pem:		"<certificate in PEM format>"
 *	phandle:	<node #>
 *	certs:		{cert-1, cert-2,...}
 *
 * The subject is a friendly name for the node, such as "optee", or a TA's
 * UUID. Each object which is attested to has a unique fwid which is used
 * to identify it.
 * Each node is given a phandle which may be referenced by the issuer
 * property in another node.
 */

/*
 * struct attestation_cert_data - Data about a new certificate to store in the
 *				  certificate database.
 * @subject		Name of the entinty this certificate represents
 * @subject_fwid	The unique fingerprint of the subject
 * @issuer		Name of the signer of the certificate
 * @issuer_fwid		The unique fingerprint of the issuer
 * @pem			Base 64 encoded certificate string
 */
struct attestation_cert_data {
	char subject[ATTESTATION_NAME_MAX];
	uint8_t subject_fwid[ATTESTATION_MEASUREMENT_SIZE];
	char issuer[ATTESTATION_NAME_MAX];
	uint8_t issuer_fwid[ATTESTATION_MEASUREMENT_SIZE];
	char pem[DER_MAX_PEM];
};

/*
 * struct attestation_alias_data - The private identity of a component for
 *				   attestation purposes.
 * @alias_identity	Derived identity, used to derive alias identities
 *			for further components, and the attestation key
 *			***Must be kept secret***
 * @alias_key		Derived key used to sign attestation certificates,
 *			***Private component must be kept secret***
 * @has_alias		Tracks lazy initialization of the context, true once
 *			attestation_create_alias() runs.
 * @plat_data		Platform unique state, must be managed by the platform
 *			specific implementations if used.
 */
struct attestation_alias_data {
	uint8_t alias_identity[ATTESTATION_MEASUREMENT_SIZE];
	struct ecc_keypair alias_key;
	bool has_alias;
	void *plat_data;
};

/*
 * struct tee_attestation_data - user TA attestation measurements
 * @dynamic_measurement	A running hash of all binary components loaded,
 *			including runtime dynamic libraries
 * @static_measurement	A measurement of the TA as it existed when execution
 *			started (first session start)
 * @is_measured		True if the static measurement has been set
 * @ta_version		The TA version as defined in the shdr_bootstrap_ta
 *			bootstrap header
 * @signer_measurement	Hash of the signing key used to verify the TA
 */
struct tee_attestation_data {
	bool is_measured;
	uint8_t dynamic_measurement[ATTESTATION_MEASUREMENT_SIZE];
	uint8_t static_measurement[ATTESTATION_MEASUREMENT_SIZE];
	uint32_t ta_version;
	uint8_t signer_measurement[ATTESTATION_MEASUREMENT_SIZE];
};

/*
 * Initialization of the attestation certificates, __weak, overridable. Leaves
 * a valid certificate chain in memory, used for attestation. Default
 * implementation creates a self-signed certificate based on OP-TEEs
 * tee_otp_get_hw_unique_key() function. Ideally a platform should either
 * generate this in co-operation with earlier firmware stages, or an external
 * device such as a TPM.
 */
TEE_Result initialize_cert_chain(void);

/*
 * Triggered when a user TA opens a session to the trust PTA, __weak,
 * overridable. In the default implementation this does nothing. A
 * platform specific implmementation could use this oportunity to initialize
 * the alias state data if needed.
 */
TEE_Result attestation_start(struct attestation_alias_data *ctx);

/*
 * Creates an alias identity in preperation for signing a certificate, __weak,
 * overridable. Called before generating certificates, keys, etc.
 */
TEE_Result attestation_create_alias(struct attestation_alias_data *ctx);

/*
 * Get a string containing the attestation certificates for the current TA.
 */
TEE_Result attestation_get_ta_certs(struct attestation_alias_data *ctx,
				    char *buf, size_t *buf_len);
/*
 * Get a string containing all stored attestation certificates.
 */
TEE_Result attestation_get_all_certs(struct attestation_alias_data *ctx,
				     char *buf, size_t *buf_len);

void attestation_cleanup(struct attestation_alias_data *ctx);

#endif /* CFG_ATTESTATION_MEASURE */

#endif /* __TEE_ATTESTATION_H */