// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Microsoft Corporation
 */

#include <compiler.h>
#include <initcall.h>
#include <kernel/mutex.h>
#include <stdio.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <tee/attestation.h>
#include <tee/attestation_db.h>
#include <trace.h>
#include <util.h>

/*
 * This should cover the worst case when adding a new cert. The fdt will be
 * expanded by this ammount when there is no longer enough space for a new
 * certificate to be added. The database will not be allowed to grow past
 * CERT_DB_MAX_ALLOC_SIZE bytes.
 */
#define CERT_DB_ALLOC_SIZE (DER_MAX_PEM + 0x100 - 0x100)
#define CERT_DB_MAX_ALLOC_SIZE (0x4000)

/*
 * Adding and removing nodes may affect the FDT, this mutex protects the
 * fdt blob and must be held whenever accessing the attest blob structure.
 */
static struct mutex cert_db_mutex = MUTEX_INITIALIZER;

#if (TRACE_LEVEL < TRACE_DEBUG)
static void dump_fdt_internal(void *fdt __unused)
#else
static void dump_fdt_internal(void *fdt)
{
	size_t i = 0;
	size_t len = 0;
	char *dumpstr = NULL;
	char str_byte[5]; /* "\x00\0" */

	/* 4 chars per byte ("\x00"), + null terminator. */
	len = fdt_totalsize(fdt) * 4 + 1;
	dumpstr = calloc(1, len);

	for (i = 0; i < fdt_totalsize(fdt); i++) {
		snprintf(str_byte, sizeof(str_byte),
			 "\\x%02x", ((uint8_t *)fdt)[i]);
		strlcat(dumpstr, str_byte, len);
	}

	DMSG("DUMP FDT (0x%x bytes):", fdt_totalsize(fdt));
	trace_ext_puts("printf \"%b\" \'");
	trace_ext_puts(dumpstr);
	trace_ext_puts("\' | dtc -I dtb -O dts");
	trace_ext_puts("\n");

	free(dumpstr);
}
#endif /* (TRACE_LEVEL < TRACE_DEBUG) */

static TEE_Result fdt_error(int fdt_error)
{
	if (fdt_error) {
		FMSG("FDT Error: %s", fdt_strerror(fdt_error));
		switch (fdt_error) {
		case -FDT_ERR_NOTFOUND:
			return TEE_ERROR_ITEM_NOT_FOUND;
		case -FDT_ERR_NOSPACE:
			return TEE_ERROR_SHORT_BUFFER;
		default:
			return TEE_ERROR_GENERIC;
		}
	} else {
		return TEE_SUCCESS;
	}
}

/*
 * Sets issuer_offset to the offset of the issuer node for the cert at.
 * cert_node. If the cert is self-signed the offset returned will be the same
 * as cert_node.
 */
static TEE_Result get_issuer_offs(void *fdt, int cert_node, int *issuer_offset)
{
	int fdt_res = 0;
	const void *data = 0;
	int issuer_phandle = 0;

	if (!fdt || !issuer_offset)
		return TEE_ERROR_BAD_PARAMETERS;
	*issuer_offset = 0;

	data = fdt_getprop(fdt, cert_node, "issuer", &fdt_res);
	if (!data)
		return fdt_error(fdt_res);
	if (fdt_res != sizeof(uint32_t))
		return TEE_ERROR_BAD_FORMAT;

	issuer_phandle = fdt32_to_cpu(*(const uint32_t *)data);

	/* This may refer back to itself if self signed */
	fdt_res = fdt_node_offset_by_phandle(fdt, issuer_phandle);
	if (fdt_res < 0)
		return fdt_error(fdt_res);
	*issuer_offset = fdt_res;

	return TEE_SUCCESS;
}

/*
 * Retrieve the certificate data for the cert stored at offset cert_node and
 * stores it in an attestation_cert_data structure.
 */
static TEE_Result get_cert_data(void *fdt,
				int cert_node,
				struct attestation_cert_data *cert)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	int fdt_res = 0;
	const char *fdt_property = NULL;
	int issuer_offset = 0;

	if (!fdt || !cert)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Get the issuer
	 */
	res = get_issuer_offs(fdt, cert_node, &issuer_offset);
	if (res)
		return res;

	/* issuer subject */
	fdt_property = fdt_getprop(fdt, issuer_offset, "subject", &fdt_res);
	if (fdt_property  == NULL)
		return fdt_error(fdt_res);
	if ((size_t)fdt_res > sizeof(cert->issuer))
		return TEE_ERROR_BAD_FORMAT;
	strlcpy(cert->issuer, fdt_property, sizeof(cert->issuer));

	/* issuer fwid */
	fdt_property = fdt_getprop(fdt, issuer_offset, "fwid", &fdt_res);
	if (fdt_property  == NULL)
		return fdt_error(fdt_res);
	if ((size_t)fdt_res != sizeof(cert->issuer_fwid))
		return TEE_ERROR_BAD_FORMAT;
	memcpy(cert->issuer_fwid, fdt_property,
	       MIN((size_t)fdt_res, sizeof(cert->issuer_fwid)));

	/* Now get the actual certificate, starting with subject */
	fdt_property = fdt_getprop(fdt, cert_node, "subject", &fdt_res);
	if (fdt_property == NULL)
		return fdt_error(fdt_res);
	if ((size_t)fdt_res > sizeof(cert->subject))
		return TEE_ERROR_BAD_FORMAT;
	strlcpy(cert->subject, fdt_property, sizeof(cert->subject));

	/* fwid */
	fdt_property = fdt_getprop(fdt, cert_node, "fwid", &fdt_res);
	if (fdt_property  == NULL)
		return fdt_error(fdt_res);
	if ((size_t)fdt_res != sizeof(cert->subject_fwid))
		return TEE_ERROR_BAD_FORMAT;
	memcpy(cert->subject_fwid, fdt_property,
	       MIN((size_t)fdt_res, sizeof(cert->subject_fwid)));

	/* Cert PEM */
	fdt_property = fdt_getprop(fdt, cert_node, "pem", &fdt_res);
	if (fdt_property  == NULL)
		return fdt_error(fdt_res);
	if ((size_t)fdt_res > sizeof(cert->pem))
		return TEE_ERROR_BAD_FORMAT;
	strlcpy(cert->pem, fdt_property, sizeof(cert->pem));

	return TEE_SUCCESS;
}

/*
 * Look for a certificate which matches the attestation data. Sets
 * matching_offset to the offset of the existing node if found.
 * Returns an error if a certificate with the same fwid is found that
 * does not match perfectly.
 */
static TEE_Result check_uniquness(void *fdt,
				  int root_offset,
				  struct attestation_cert_data *cert,
				  int *matching_offset)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct attestation_cert_data *matching_data = NULL;
	int cert_offs = 0;

	if (!fdt || !cert || !matching_offset)
		return TEE_ERROR_BAD_PARAMETERS;
	*matching_offset = -FDT_ERR_NOTFOUND;

	/* Check if any certificate exists with a matching fwid */
	cert_offs = fdt_node_offset_by_prop_value(fdt, root_offset, "fwid",
						  cert->subject_fwid,
						  sizeof(cert->subject_fwid));
	if (cert_offs == -FDT_ERR_NOTFOUND)
		return TEE_SUCCESS;
	if (cert_offs < 0)
		return fdt_error(cert_offs);

	/* Possible match, check that each field is identical */
	matching_data = calloc(1, sizeof(*matching_data));
	if (!matching_data)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = get_cert_data(fdt, cert_offs, matching_data);
	if (res)
		goto cleanup;

	res = TEE_ERROR_SECURITY;
	/* Issuer */
	if (strcmp(matching_data->issuer, cert->issuer))
		goto cleanup;
	if (memcmp(matching_data->issuer_fwid, cert->issuer_fwid,
		   sizeof(matching_data->issuer_fwid)))
		goto cleanup;
	/* Subject */
	if (strcmp(matching_data->subject, cert->subject))
		goto cleanup;
	if (memcmp(matching_data->subject_fwid, cert->subject_fwid,
		   sizeof(matching_data->subject_fwid)))
		goto cleanup;
	/* Pem */
	if (strcmp(matching_data->pem, cert->pem))
		goto cleanup;

	/* Passed all the checks */
	*matching_offset = cert_offs;
	res = TEE_SUCCESS;

cleanup:
	free(matching_data);
	return res;
}

/*
 * Return a string containing the concatenated pem encoded certificates for the
 * entire tree. If buf is NULL the required buf_size will be returned.
 */
static TEE_Result get_tree_pems(void *fdt, int root_offs, char *buf,
				size_t *buf_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct attestation_cert_data *cert = NULL;
	size_t actual_len = 0;
	size_t node_len = 0;
	int cert_offs = -1;

	if (!fdt || !buf_size)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Start with an empty string */
	actual_len = 1;
	if (buf && *buf_size > 0)
		buf[0] = '\0';

	cert = calloc(1, sizeof(*cert));
	if (!cert)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Get the pem for every node in the tree */
	fdt_for_each_subnode(cert_offs, fdt, root_offs) {
		res = get_cert_data(fdt, cert_offs, cert);
		if (res)
			goto err;

		node_len = strlen(cert->pem);
		actual_len += node_len;

		if (buf) {
			if (strlcat(buf, cert->pem, *buf_size) >= *buf_size) {
				*buf_size = actual_len;
				res = TEE_ERROR_SHORT_BUFFER;
				goto err;
			}
		}
	}

	if (cert_offs < 0 && (cert_offs != -FDT_ERR_NOTFOUND)) {
		res = TEE_ERROR_BAD_STATE;
		goto err;
	}

	*buf_size = actual_len;
	res = TEE_SUCCESS;
err:
	if (cert)
		free(cert);
	return res;
}

/*
 * Return a string containing the concatenated pem encoded certificates for the
 * node at cert_offs which make up the chain leading from the root the node at
 * cert_offs. If buf is NULL the required buf_size will be returned.
 */
static TEE_Result get_chain_pems(void *fdt, int cert_offs, char *buf,
				 size_t *buf_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct attestation_cert_data *cert = NULL;
	size_t actual_len = 0;
	size_t node_len = 0;
	int prev_offs = -1;


	if (!fdt || !buf_size)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Start with an empty string */
	actual_len = 1;
	if (buf && *buf_size > 0)
		buf[0] = '\0';

	cert = calloc(1, sizeof(*cert));
	if (!cert)
		return TEE_ERROR_OUT_OF_MEMORY;

	/* Walk the phandle links until a root cert (self signed) is found */
	do {
		res = get_cert_data(fdt, cert_offs, cert);
		if (res)
			goto err;

		node_len = strlen(cert->pem);
		actual_len += node_len;

		if (buf) {
			if (strlcat(buf, cert->pem, *buf_size) >= *buf_size) {
				*buf_size = actual_len;
				res = TEE_ERROR_SHORT_BUFFER;
				goto err;
			}
		}

		prev_offs = cert_offs;
		res = get_issuer_offs(fdt, cert_offs, &cert_offs);
	} while (cert_offs != prev_offs);

	*buf_size = actual_len;
	res = TEE_SUCCESS;
err:
	if (cert)
		free(cert);
	return res;
}

/*
 * Allocate a new buffer to hold a larger fdt. Increase CERT_DB_ALLOC_SIZE
 * bytes at a time. This will move the location of attest_blob, and may
 * break any existing offsets inside the fdt.
 */
static TEE_Result expand_blob(struct attest_db **attest_blob)
{
	int fdt_res = 0;
	size_t new_alloc_size = (*attest_blob)->alloc_size + CERT_DB_ALLOC_SIZE;
	size_t new_fdt_size = new_alloc_size -
			      sizeof(struct attest_db) +
			      sizeof(struct fdt_header);
	struct attest_db *new_blob = NULL;

	if (!attest_blob || !(*attest_blob))
		return TEE_ERROR_BAD_PARAMETERS;
	
	if (new_alloc_size > CERT_DB_MAX_ALLOC_SIZE)
		return TEE_ERROR_EXCESS_DATA;

	new_blob = realloc(*attest_blob, new_alloc_size);
	if (!new_blob)
		return TEE_ERROR_OUT_OF_MEMORY;
	new_blob->alloc_size = new_alloc_size;

	/* Switch to the new buffer */
	*attest_blob = new_blob;

	/* Optimize the fdt */
	fdt_res = fdt_pack(&(*attest_blob)->fdt);
	if (fdt_res < 0)
		return fdt_error(fdt_res);

	/* Expand the fdt to fill the larger buffer */
	new_blob->fdt_size = new_fdt_size;
	fdt_res = fdt_open_into(&(*attest_blob)->fdt,
				&(*attest_blob)->fdt,
				(*attest_blob)->fdt_size);
	if (fdt_res < 0) {
		/* Existing fdt and header should still be valid... */
		return fdt_error(fdt_res);
	}

	return TEE_SUCCESS;
}

/*
 * Insert a new certificate into a group. If the fdt is too small it will
 * clean up after itself and retrun TEE_ERROR_OUT_OF_MEMORY. The new node
 * will link back to the issuing node if issuer_node_offset is valid,
 * otherwise it will link to itself. This may invalidate any existing
 * offsets inside the fdt.
 */
static TEE_Result add_cert_to_fdt(void *fdt,
				  int root_node_offset,
				  int issuer_node_offset,
				  struct attestation_cert_data *cert)
{
	int fdt_res = 0;
	int cert_id = 0;
	int issuer_phandle = -1;
	int new_node = 0;
	int current_phandle = -1;
	char node_name[20] = {0};

	if (!fdt || !cert)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Grab the issuer phandle before we move or add anything to the fdt */
	if (issuer_node_offset > 0) {
		issuer_phandle = fdt_get_phandle(fdt, issuer_node_offset);
	}

	/* Find an empty slot for the new cert */
	do {
		cert_id++;
		snprintf(node_name, sizeof(node_name), "cert-%d", cert_id);
		fdt_res = fdt_add_subnode(fdt, root_node_offset, node_name);
	} while (fdt_res == -FDT_ERR_EXISTS);
	if (fdt_res < 0)
		return fdt_error(fdt_res);
	
	new_node = fdt_res;
	
	/*
	 * Get a phandle so we can reference the node later. OP-TEE does not
	 * have a function to set phandles, do it manually
	 */
	current_phandle = fdt_get_max_phandle(fdt);
	if (current_phandle < 0) {
		fdt_res = current_phandle;
		goto cleanup;
	}
	fdt_res = fdt_setprop_u32(fdt, new_node, "phandle",
				  current_phandle + 1);
	if (fdt_res < 0)
		goto cleanup;

	/* Link the node to its parent via phandle */
	if (issuer_phandle < 0) {
		/* No issuer from before, this node will link to itself */
		issuer_phandle = fdt_get_phandle(fdt, new_node);
	}
	fdt_res = fdt_setprop_u32(fdt, new_node, "issuer", issuer_phandle);
	if (fdt_res < 0)
		goto cleanup;

	/* Populate the certificate information */
	fdt_res = fdt_setprop_string(fdt, new_node, "subject",
				     cert->subject);
	if (fdt_res < 0)
		goto cleanup;

	fdt_res = fdt_setprop(fdt, new_node, "fwid", cert->subject_fwid,
			      sizeof(cert->subject_fwid));
	if (fdt_res < 0)
		goto cleanup;
	fdt_res = fdt_setprop_string(fdt, new_node, "pem", cert->pem);
	if (fdt_res < 0)
		goto cleanup;

	return TEE_SUCCESS;
	
cleanup:
	/* Delete partial nodes, if we ran out of memory try again later */
	fdt_del_node(fdt, new_node);
	return fdt_error(fdt_res);
}

TEE_Result attest_db_dump(struct attest_db **attest_blob)
{
	struct fdt_header *fdt = NULL;

	if (!attest_blob || !(*attest_blob))
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_read_lock(&cert_db_mutex);
	fdt = &(*attest_blob)->fdt;
	dump_fdt_internal(fdt);
	mutex_read_unlock(&cert_db_mutex);

	return TEE_SUCCESS;
}

static TEE_Result insert_certificate(struct attest_db **attest_blob,
				     struct attestation_cert_data *cert)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct fdt_header *fdt = NULL;
	int root_offs = 0;
	int cert_node = 0;
	int issuer = 0;
	bool retry = false;

	if (!attest_blob || !(*attest_blob) || !cert)
		return TEE_ERROR_BAD_PARAMETERS;

	do {
		/*
		 * Find the certificate group and fdt. The fdt may have moved
		 * after a resize.
		 */
		fdt = &(*attest_blob)->fdt;
		root_offs = fdt_subnode_offset(fdt, /* root */ 0,
					       "certs");
		if (root_offs < 0)
			return fdt_error(root_offs);

		/*
		 * Don't bother adding a duplicate certificate, but verify it
		 * is identical.
		 */
		res = check_uniquness(fdt, root_offs, cert,
				      &cert_node);
		if (res)
			return res;
		if (cert_node > 0) {
			DMSG("Re-using identical certificate");
			return TEE_SUCCESS;
		}

		/*
		 * Try and find the issuer, if one exists (otherwise it might
		 * be a new root). Two certificates may not have the same fwid.
		 */
		issuer = fdt_node_offset_by_prop_value(fdt, root_offs, "fwid",
						       cert->issuer_fwid,
						       sizeof(cert->issuer_fwid));
		if (issuer < 0 && issuer != -FDT_ERR_NOTFOUND)
			return fdt_error(issuer);
		if (issuer < 0) {
			/* Self signed certs are ok */
			if (memcmp(cert->subject_fwid, cert->issuer_fwid,
				   sizeof(cert->subject_fwid))) {
				EMSG("Unknown issuer");
				return TEE_ERROR_BAD_PARAMETERS;
			}
		}

		res = add_cert_to_fdt(fdt, root_offs, issuer, cert);
		/* May need to expand the fdt and try again */
		if (res == TEE_ERROR_SHORT_BUFFER) {
			res = expand_blob(attest_blob);
			if (res)
				return res;
			retry = true;
		} else {
			retry = false;
		}
	} while (retry);

	return res;
}

TEE_Result attest_db_get_cert(struct attest_db **attest_blob,
			      uint8_t *fwid, size_t fwid_len,
			      struct attestation_cert_data *cert)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct fdt_header *fdt = NULL;
	int cert_node = 0;

	if (!attest_blob || !(*attest_blob) || !fwid || !cert)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_read_lock(&cert_db_mutex);
	fdt = &(*attest_blob)->fdt;

	/* Check if any certificate exists with a matching fwid */
	cert_node = fdt_node_offset_by_prop_value(fdt, 0, "fwid",
						  fwid, fwid_len);
	if (cert_node == -FDT_ERR_NOTFOUND) {
		res = TEE_ERROR_ITEM_NOT_FOUND;
		goto err;
	}
	if (cert_node < 0) {
		res = fdt_error(cert_node);
		goto err;
	}

	/*
	 * We have a match, get the data.
	 */
	res = get_cert_data(fdt, cert_node, cert);
err:
	mutex_read_unlock(&cert_db_mutex);

	return res;
}

TEE_Result attest_db_get_tree(struct attest_db **attest_blob, char *buf,
			      size_t *buf_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct fdt_header *fdt = NULL;
	int leaf_offset = -1;
	int root_offs;

	if (!attest_blob || !(*attest_blob) || !buf_size)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_read_lock(&cert_db_mutex);
	fdt = &(*attest_blob)->fdt;

	root_offs = fdt_subnode_offset(fdt, /* root */ 0, "certs");
	if (root_offs < 0) {
		res = fdt_error(leaf_offset);
		goto err;
	}

	res = get_tree_pems(fdt, root_offs, buf, buf_size);
err:
	mutex_read_unlock(&cert_db_mutex);
	return res;
}

TEE_Result attest_db_get_chain(struct attest_db **attest_blob,
			       uint8_t *fwid, size_t fwid_len, char *buf,
			       size_t *buf_size)
{
	TEE_Result res = TEE_ERROR_GENERIC;
	struct fdt_header *fdt = NULL;
	int leaf_offset = -1;
	int root_offs;

	if (!attest_blob || !(*attest_blob) || !fwid || !buf_size)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_read_lock(&cert_db_mutex);
	fdt = &(*attest_blob)->fdt;

	root_offs = fdt_subnode_offset(fdt, /* root */ 0, "certs");
	if (root_offs < 0) {
		res = fdt_error(leaf_offset);
		goto err;
	}

	leaf_offset = fdt_node_offset_by_prop_value(fdt, root_offs, "fwid",
						    fwid, fwid_len);
	if (leaf_offset < 0) {
		res = fdt_error(leaf_offset);
		goto err;
	}

	res = get_chain_pems(fdt, leaf_offset, buf, buf_size);
err:
	mutex_read_unlock(&cert_db_mutex);
	return res;
}

TEE_Result attest_db_add_cert(struct attest_db **attest_blob,
			      struct attestation_cert_data *cert)
{
	TEE_Result res = TEE_ERROR_GENERIC;

	mutex_lock(&cert_db_mutex);
	res = insert_certificate(attest_blob, cert);
	mutex_unlock(&cert_db_mutex);

	return res;
}
	struct fdt_header *fdt = NULL;
	int root_offs = 0;
	int cert_node = 0;
	int issuer = 0;

	mutex_lock(&cert_db_mutex);

	do {
		/*
		 * Find the certificate group and fdt. The fdt may have moved
		 * after a resize.
		 */
		fdt = &(*attest_blob)->fdt;
		root_offs = fdt_subnode_offset(fdt, /* root */ 0,
					       "certs");
		if (root_offs < 0) {
			res = fdt_error(root_offs);
			goto cleanup;
		}

		/*
		 * Don't bother adding a duplicate certificate, but verify it
		 * is identical.
		 */
		res = check_uniquness(attest_blob, root_offs, cert,
				      &cert_node);
		if (res)
			goto cleanup;
		if (cert_node > 0) {
			DMSG("Re-using identical certificate");
			res = TEE_SUCCESS;
			goto cleanup;
		}

		/*
		 * Try and find the issuer, if one exists (otherwise it might 
		 * be a new root). Two certificates may not have the same fwid.
		 */
		issuer = fdt_node_offset_by_prop_value(fdt, root_offs, "fwid",
						       cert->issuer_fwid,
						       sizeof(cert->issuer_fwid));
		if (issuer < 0 && issuer != -FDT_ERR_NOTFOUND) {
			res = fdt_error(issuer);
			goto cleanup;
		}
		if (issuer < 0) {
			/* Self signed certs are ok */
			if (memcmp(cert->subject_fwid, cert->issuer_fwid,
				   sizeof(cert->subject_fwid))) {
				EMSG("Unknown issuer");
				res = TEE_ERROR_BAD_PARAMETERS;
				goto cleanup;
			}
		}

		res = insert_certificate(attest_blob, root_offs, issuer, cert);
		/* May need to expand the fdt and try again */
		if (res == TEE_ERROR_OUT_OF_MEMORY) {
			res = expand_blob(attest_blob);
			if (res)
				goto cleanup;
			res = TEE_ERROR_OUT_OF_MEMORY;
		}
	} while (res == TEE_ERROR_OUT_OF_MEMORY);

cleanup:
	mutex_unlock(&cert_db_mutex);

	return res;
}

TEE_Result attest_db_initialize(struct attest_db **attest_blob)
{
	TEE_Result res = TEE_SUCCESS;
	int alloc_size = 0;
	int fdt_res = 0;
	int fdt_size = 0;
	struct fdt_header *fdt = NULL;
	struct attest_db *new_blob = NULL;

	if (!attest_blob)
		return TEE_ERROR_BAD_PARAMETERS;

	mutex_lock(&cert_db_mutex);

	alloc_size = sizeof(struct attest_db) +
		     CERT_DB_ALLOC_SIZE;
	/* The fdt can use all of the _body[] and the fdt structure */
	fdt_size = alloc_size - sizeof(struct attest_db) +
		   sizeof(struct fdt_header);

	new_blob = calloc(1, alloc_size);
	if (!new_blob) {
		res = TEE_ERROR_OUT_OF_MEMORY;
		goto err;
	}
	
	new_blob->alloc_size = alloc_size;
	new_blob->fdt_size = fdt_size;

	fdt = &new_blob->fdt; 
	fdt_res = fdt_create_empty_tree(fdt, fdt_size);
	if (fdt_res < 0) {
		EMSG("FDT Error: %s", fdt_strerror(fdt_res));
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	fdt_res = fdt_setprop_u32(fdt, /*root*/ 0, "version",
				  ATTESTATION_VERSION);
	if (fdt_res < 0) {
		EMSG("FDT Error: %s", fdt_strerror(fdt_res));
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	fdt_res = fdt_add_subnode(fdt, /*root*/ 0, "certs");
	if (fdt_res < 0) {
		EMSG("FDT Error: %s", fdt_strerror(fdt_res));
		res = TEE_ERROR_GENERIC;
		goto err;
	}

	*attest_blob = new_blob;
	res = TEE_SUCCESS;
	goto cleanup;
err:
	free(new_blob);
cleanup:
	mutex_unlock(&cert_db_mutex);
	return res;
}