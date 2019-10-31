/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) Microsoft Corporation.
 */
#ifndef __TEE_ATTESTATION_DB_H
#define __TEE_ATTESTATION_DB_H

#include <utee_defines.h>
#include <libfdt.h>

/*
 * Attestation Database:
 *
 * A fdt based store for attestation data. Each node in the fdt represents an
 * attestation claim for an entity (uniquely identified by a 'fwid').
 *
 * Each node has a link (via fdt phandle) to an issuer node which issued the
 * certificate for the current node. This forms a chain of trust down to a root
 * node. A 'root' node is special in that it is its own issuer. In the default,
 * platform agnostic implementation OP-TEE will generate its own root node
 * derived from its hardware unique key (HUK) via a call to huk_subkey_derive().
 *
 * A platform may use attest_db_inject_fdt() to insert a pre-baked chain into
 * the database.
 *
 * A TA may request its certificate chain, or the full certificate tree, encoded
 * as a concatenated list of PEM encoded certs.
 *
 * Pre-Baked Database:
 *
 * A dtb may be included with the OP-TEE binary for either testing or use in
 * secure environments (the dtb will contain private information which should
 * not be made available outside the trusted execution environment, such as
 * OP-TEE's private attestation key).
 *
 * This feature may be enabled by setting:
 *	CFG_ATTESTATION_PREBAKED=y
 *	CFG_ATTESTATION_PREBAKED_FILE=/path/to/certs.dts
 *
 * The certs.dts file will be compiled into a .dtb, then converted to a byte
 * array in the OP-TEE binary.
 *
 * When OP-TEE initializes the attestation system it will use the certificates
 * encoded in the dtb instead of generating a new OP-TEE root based on the HUK.
 * The dtb must contain at least the cert with the subject "optee", but may also
 * contain additional certificates. Each node must either be a root node
 * (issuer == subject), or link to an existing node. Note that this does not
 * require the actual PEM encoded certificate to be a root, only the fdt node.
 * A prebaked node may contain multiple certificates encoded as a single PEM if
 * desired.
 *
 * NOTE: Nodes must be entered in topological order (root nodes first, then leaf
 * nodes).
 *
 * Example Database:
 *
 * The "optee_prebaked_*" buffers are required. They may either point to an
 * external bin, or be written directly in the dts file. The alias is the secret
 * identity of OP-TEE, while the fwid is the unique public identifier for the
 * binary. The key is what OP-TEE will use to sign additional attestation
 * certificates for TAs.
 *
 * An additional "root" certificate is used here. Note the issuer field
 * references itself. The node names (ie "root_node: prebaked-cert-1") are
 * arbitrary and may be picked as desired.
 *
 * The "optee" node must be present, and must have the same fwid as above. The
 * subject name must be "optee".
 *
 * /dts-v1/;
 * / {
 *         version = <0x1>;
 *         optee_prebaked_alias = /incbin/("/path/to/optee_alias.bin");
 *         optee_prebaked_fwid = /incbin/("/path/to/optee_fwid.bin");
 *         optee_prebaked_key_pem = /incbin/("/path/to/optee_key_pem.bin");
 *         certs {
 *                 root_node: prebaked-cert-1 {
 *                         pem = /incbin/("/path/to/root_pem.bin");
 *                         fwid = /incbin/("/path/to/root_fwid.bin");
 *                         subject = "root";
 *                         issuer = < &root_node >;
 *                 };
 *                 optee_node: prebaked-cert-2 {
 *                         pem = /incbin/("/path/to/optee_pem.bin");
 *                         fwid = /incbin/("/path/to/optee_fwid.bin");
 *                         subject = "optee";
 *                         issuer = < &root_node >;
 *                 };
 *         };
 * };
 */

/*
 * struct attest_db - Certificate database which holds all attestation certs
 * @alloc_size	Total allocated size of the db structure
 * @fdt_size	Size remaining for the fdt_header + fdt data
 * @fdt		Fdt meta data
 * @_body	Variable size fdt data. Size is tracked with alloc_size and
 *		fdt_size
 */
struct attest_db {
	size_t alloc_size;
	size_t fdt_size;
	struct fdt_header fdt;
	char _body[1];
};

/*
 * Allocate and initialize a new, empty certificate database strucutre. Caller
 * is responsible for freeing the allocated structure.
 */
TEE_Result attest_db_initialize(struct attest_db **attest_blob);

/*

/*
 * Add a certificate to the database if it is not present. Ensure that if a
 * certificate exists with a matching fwid it is identical (matching
 * measurement, issuer, etc). This function will fail if there is a fwid
 * collision that is not identical, or if the issuer certificate is missing. A
 * certificate may be rooted back to itself if there is no issuer available by
 * making the issuer equal the subject.
 */
TEE_Result attest_db_add_cert(struct attest_db **attest_blob,
			      struct attestation_cert_data *cert);

/*
/*
 * Populate the certificate for a given fwid value.
 */
TEE_Result attest_db_get_cert(struct attest_db **attest_blob,
			      uint8_t *fwid, size_t fwid_len,
			      struct attestation_cert_data *cert);

/*
 * Return a buffer containing a concatenated list of PEM encoded certificates
 * leading to fwid's certificate to a root certificate (subject == issuer).
 * If buf is NULL buf_size will contain the required length of the buffer.
 */
TEE_Result attest_db_get_chain(struct attest_db **attest_blob, uint8_t *fwid,
			       size_t fwid_len, char *buf, size_t *buf_size);

/*
 * Return a buffer containing a concatenated list of PEM encoded certificates
 * for the entire tree. If buf is NULL buf_size will contain the required length
 * of the buffer.
 */
TEE_Result attest_db_get_tree(struct attest_db **attest_blob, char *buf,
			      size_t *buf_size);

/*
 * Dump the contents of a certificate database over serial (TRACE_LEVEL >=
 * TRACE_DEBUG) as a formated string which can be used to invoke device tree
 * compiler on a linux machine.
 * Will be of the form:
 *	printf "%b" '\x00x\x01x\x02x...' | dtc -I dtb -O dts
 */
TEE_Result attest_db_dump(struct attest_db **attest_blob);

#endif /* __TEE_ATTESTATION_DB_H */