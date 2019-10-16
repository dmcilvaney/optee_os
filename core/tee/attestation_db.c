// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) Microsoft Corporation
 */

#include <compiler.h>
#include <initcall.h>
#include <kernel/mutex.h>
#include <libfdt.h>
#include <stdio.h>
#include <string.h>
#include <string_ext.h>
#include <tee_api_types.h>
#include <tee/attestation.h>
#include <tee/attestation_db.h>
#include <trace.h>
#include <util.h>

/* This should cover the worst case when adding a new cert */
#define CERT_DB_ALLOC_SIZE (DER_MAX_PEM + 0x100)

/*
 * Adding and removing nodes may affect the FDT, all accesses should be in
 * a critical section.
 */
static struct mutex cert_db_mutex = MUTEX_INITIALIZER;

static void dump_fdt_internal(struct attestation_cert_blob **cert_blob)
{
	size_t i = 0;
	int len = 0;
	char *dumpstr = NULL;
	char *strptr = NULL;

	//4 chars per byte ("\x00"), + null term.
	len = (*cert_blob)->fdt_size * 4 + 1;
	dumpstr = calloc(1, len);
	strptr = dumpstr;

	for(i = 0; i < (*cert_blob)->fdt_size; i++) {
		snprintf(strptr,5,"\\x%02x", ((uint8_t *)&(*cert_blob)->fdt)[i]);
		strptr += 4;
	}

	// DHEXDUMP(dumpstr, len);
	// DHEXDUMP((uint8_t *)&cert_blob->fdt, cert_blob->fdt_size);
	EMSG("DUMP FDT:");
	trace_ext_puts("printf \"%b\" \'");
	trace_ext_puts(dumpstr);
	trace_ext_puts("\' > attestation.fdt");
	trace_ext_puts("\n");
	free(dumpstr);
}

void dump_fdt(struct attestation_cert_blob **cert_blob)
{
	mutex_lock(&cert_db_mutex);
	dump_fdt_internal(cert_blob);
	mutex_unlock(&cert_db_mutex);
}

static TEE_Result fdt_error(int fdt_error)
{
	EMSG("FDT Error: %s", fdt_strerror(fdt_error));
	switch (fdt_error) {
		case -FDT_ERR_NOTFOUND:
			return TEE_ERROR_ITEM_NOT_FOUND;
		case -FDT_ERR_NOSPACE:
			return TEE_ERROR_OUT_OF_MEMORY;
		default:
			return TEE_ERROR_GENERIC;
	}
}

/*
 * Sets issuer_node to the offset of the issuing node.
 */
static TEE_Result get_issuer_fdt(struct attestation_cert_blob **cert_blob,
				 int cert_node,
				 int *issuer_offset)
{
	const void *data = 0;
	struct fdt_header *fdt = &(*cert_blob)->fdt;
	int fdt_res = 0;
	int issuer_phandle = 0;

	*issuer_offset = 0;

	data = fdt_getprop(fdt, cert_node, "issuer", &fdt_res);
	if (!data)
		return fdt_error(fdt_res);
	if (fdt_res != sizeof(uint32_t))
		return TEE_ERROR_BAD_FORMAT;

	issuer_phandle = fdt32_to_cpu(*(const uint32_t *)data);

	/* This may refer back to itself if self signed */
	*issuer_offset = fdt_node_offset_by_phandle(fdt, issuer_phandle);

	return TEE_SUCCESS;
}

/*
 * Retrieve the certificate data for the cert stored at offset cert_node.
 */
static TEE_Result get_cert_data_fdt(struct attestation_cert_blob **cert_blob,
				    int cert_node,
				    struct attestation_cert_data *cert)
{
	struct fdt_header *fdt = &(*cert_blob)->fdt;
	int fdt_res = 0;
	const char *fdt_property = NULL;
	int issuer_offset = 0;
	TEE_Result res = TEE_SUCCESS;

	if (!cert)	
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * Get the issuer
	 */
	res = get_issuer_fdt(cert_blob, cert_node, &issuer_offset);
	if (res)
		return res;

	/* issuer subject */
	fdt_property = fdt_getprop(fdt, issuer_offset, "subject", &fdt_res);
	if (fdt_property  == NULL)
		return fdt_error(fdt_res);
	strlcpy(cert->issuer, fdt_property, sizeof(cert->issuer));

	/* issuer fwid */
	fdt_property = fdt_getprop(fdt, issuer_offset, "fwid", &fdt_res);
	if (fdt_property  == NULL)
		return fdt_error(fdt_res);
	memcpy(cert->issuer_fwid, fdt_property,
	       MIN((size_t)fdt_res, sizeof(cert->issuer_fwid)));

	/* Now check the actual certificate, starting with subject */
	fdt_property = fdt_getprop(fdt, cert_node, "subject", &fdt_res);
	if (fdt_property == NULL)
		return fdt_error(fdt_res);
	strlcpy(cert->subject, fdt_property, sizeof(cert->subject));

	/* fwid */
	fdt_property = fdt_getprop(fdt, cert_node, "fwid", &fdt_res);
	if (fdt_property  == NULL)
		return fdt_error(fdt_res);
	memcpy(cert->subject_fwid, fdt_property,
	       MIN((size_t)fdt_res, sizeof(cert->subject_fwid)));

	/* Cert PEM */
	fdt_property = fdt_getprop(fdt, cert_node, "pem", &fdt_res);
	if (fdt_property  == NULL)
		return fdt_error(fdt_res);
	strlcpy(cert->pem, fdt_property, sizeof(cert->pem));

	return TEE_SUCCESS;
}

/*
 * Return a buffer containing all pem encoded certificates as a null
 * terminated string.
 */
static TEE_Result get_chain_pems_fdt(struct attestation_cert_blob **cert_blob,
				     int cert_node, char *buf,
				     size_t *buf_size)
{
	size_t actual_len = 0;
	struct attestation_cert_data *cert = NULL;
	size_t node_len = 0;
	int prev_node = -1;
	TEE_Result res = TEE_SUCCESS;


	if (!buf_size)
		return TEE_ERROR_BAD_PARAMETERS;

	/* Start with an empty string */
	actual_len = 1;
	if (buf && *buf_size > 0) {
		buf[0] = '\0';
	}

	cert = calloc(1, sizeof(*cert));
	if (!cert)
		return TEE_ERROR_OUT_OF_MEMORY;

	do {
		res = get_cert_data_fdt(cert_blob, cert_node, cert);
		if(res)
			goto err;

		/* string length without NULL */
		node_len = strlen(cert->pem);
		/* Initialization of acutal_len already tracks the final NULL */
		actual_len += node_len;
		if (buf)
			if (strlcat(buf, cert->pem, *buf_size) >= *buf_size) {
				*buf_size = actual_len;
				res = TEE_ERROR_SHORT_BUFFER;
				goto err;
			}
		prev_node = cert_node;
		res = get_issuer_fdt(cert_blob, cert_node, &cert_node);
	} while (cert_node != prev_node);

	*buf_size = actual_len;
	res = TEE_SUCCESS;
err:
	if (cert)
		free(cert);
	return res;
}

/*
 * Look for a certificate which matches the attestation data. Sets
 * matching_offset to the offset of the existing node if found.
 * Returns an error if a certificate with the same fwid is found that
 * does not match perfectly.
 */
static TEE_Result check_uniquness_fdt(struct attestation_cert_blob **cert_blob,
				      int root_offset,
				      struct attestation_cert_data *cert,
				      int *matching_offset)
{
	int cert_node = 0;
	struct fdt_header *fdt = &(*cert_blob)->fdt;
	struct attestation_cert_data *matching_data = NULL;
	TEE_Result res = TEE_SUCCESS;
	
	*matching_offset = 0;

	/* Check if any certificate exists with a matching fwid */
	cert_node = fdt_node_offset_by_prop_value(fdt, root_offset, "fwid",
						  cert->subject_fwid,
						  sizeof(cert->subject_fwid));
	if (cert_node == -FDT_ERR_NOTFOUND)
		return TEE_SUCCESS;
	if (cert_node < 0)
		return fdt_error(cert_node);

	/*
	 * We have a possible match, check that each field matches.
	 */
	matching_data = calloc(1, sizeof(*matching_data));
	if (!matching_data)
		return TEE_ERROR_OUT_OF_MEMORY;
	res = get_cert_data_fdt(cert_blob, cert_node, matching_data);
	if (res)
		return res;

	res = TEE_ERROR_BAD_STATE;
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
	if (strcmp(matching_data->pem, cert->pem))
		goto cleanup;

	/* Passed all the checks */
	*matching_offset = cert_node;
	res = TEE_SUCCESS;

cleanup:
	free(matching_data);
	return res;
}

TEE_Result get_certs_fdt(struct attestation_cert_blob **cert_blob,
			 uint8_t *fwid, size_t fwid_len, char *buf,
			 size_t *buf_size)
{
	struct fdt_header *fdt = NULL;
	int leaf_offset = -1;
	int root;

	fdt = &(*cert_blob)->fdt;
	root = fdt_subnode_offset(fdt, /* root */ 0, "certs");
	if (root < 0)
		return fdt_error(root);

	leaf_offset = fdt_node_offset_by_prop_value(fdt, root, "fwid",
						    fwid, fwid_len);
	if (leaf_offset < 0)
		return fdt_error(leaf_offset);

	return get_chain_pems_fdt(cert_blob, leaf_offset, buf, buf_size);
}

/*
 * Allocate a new buffer to hold a larger fdt. Increase CERT_DB_ALLOC_SIZE
 * bytes at a time.
 */
static TEE_Result expand_cert_fdt(struct attestation_cert_blob **cert_blob)
{
	int fdt_res = 0;
	size_t new_alloc_size = (*cert_blob)->alloc_size + CERT_DB_ALLOC_SIZE;
	size_t new_fdt_size = new_alloc_size -
			      sizeof(struct attestation_cert_blob) +
			      sizeof(struct fdt_header);
	struct attestation_cert_blob *new_blob = NULL;
	
	new_blob = calloc(1, new_alloc_size);	
	if (!new_blob)
		return TEE_ERROR_OUT_OF_MEMORY;
	new_blob->alloc_size = new_alloc_size;
	new_blob->fdt_size = new_fdt_size;

	/* Load the fdt into the larger buffer */
	fdt_res = fdt_open_into(&(*cert_blob)->fdt, &new_blob->fdt,
				new_fdt_size);
	if (fdt_res < 0) {
		free(new_blob);
		return fdt_error(fdt_res);
	}

	/* Switch to the new buffer */
	free(*cert_blob);
	*cert_blob = new_blob;

	return TEE_SUCCESS;
}

/*
 * Insert a new certificate into a group. If the fdt is too small it will
 * clean up after itself and retrun TEE_ERROR_OUT_OF_MEMORY;
 */
static TEE_Result create_certificate_fdt(struct attestation_cert_blob **cert_blob,
					 int root_node_offset,
					 int issuer_node_offset,
					 struct attestation_cert_data *cert)
{
	int cert_id = 0;
	int issuer_phandle = 0;
	struct fdt_header *fdt = &(*cert_blob)->fdt;
	int fdt_res = 0;
	int new_node = 0;
	int current_phandle = -1;
	char node_name[20];

	/* Find an empty slot for the new cert */
	do {
		cert_id++;
		snprintf(node_name, sizeof(node_name), "cert-%d", cert_id);
		fdt_res = fdt_add_subnode(fdt, root_node_offset, node_name);
	} while (fdt_res == -FDT_ERR_EXISTS);

	if (fdt_res < 0)
		return fdt_error(fdt_res);
	
	new_node = fdt_res;
	
	/* Get a phandle so we can reference these nodes later */
	current_phandle = fdt_get_max_phandle(fdt);
	if (current_phandle < 0) {
		fdt_res = current_phandle;
		goto cleanup;
	}
	fdt_res = fdt_setprop_u32(fdt, new_node, "phandle",
				  current_phandle + 1);
	if (fdt_res < 0)
		goto cleanup;
//TODO: Handle Errors better here!
	/* Populate the certificate information */
	fdt_res = fdt_setprop_string(fdt, new_node, "subject",
				     cert->subject);
	if (fdt_res < 0)
		goto cleanup;

	if (issuer_node_offset > 0) {
		/* Find the issuer and link using phandles */
		issuer_phandle = fdt_get_phandle(fdt, issuer_node_offset);
	} else {
		/* Self signed, link back to itself */
		issuer_phandle = fdt_get_phandle(fdt, new_node);
	}
	fdt_res = fdt_setprop_u32(fdt, new_node, "issuer", issuer_phandle);
	if (fdt_res < 0)
		goto cleanup;

	int temp_off = fdt_node_offset_by_phandle(fdt, current_phandle + 1);
	fdt_res = fdt_setprop(fdt, new_node, "fwid", cert->subject_fwid,
			      sizeof(cert->subject_fwid));
	temp_off = fdt_node_offset_by_phandle(fdt, current_phandle + 1);

	const uint8_t *f = fdt_getprop(fdt, new_node, "fwid", NULL);

	EMSG("%x", (uint32_t)f);
	EMSG("%d", temp_off);

	if (fdt_res < 0)
		goto cleanup;
	
	fdt_res = fdt_setprop_string(fdt, new_node, "pem", cert->pem);
	if (fdt_res < 0)
		goto cleanup;

	return TEE_SUCCESS;
	
cleanup:
	/* Delete the node, if we ran out of memory we will try again */
	fdt_del_node(fdt, new_node);
	return fdt_error(fdt_res);
}


TEE_Result add_cert_fdt(struct attestation_cert_blob **cert_blob,
			       struct attestation_cert_data *cert)
{
	
	int root = 0;
	int cert_node = 0;
	struct fdt_header *fdt = NULL;
	int issuer = 0;
	TEE_Result res = TEE_SUCCESS;

	mutex_lock(&cert_db_mutex);

	while (true) {
		/*
		 * Find the certificate group and fdt. The fdt may have moved
		 * after a resize.
		 */
		fdt = &(*cert_blob)->fdt;
		root = fdt_subnode_offset(fdt, /* root */ 0,
						"certs");
		if (root < 0) {
			res = fdt_error(root);
			goto cleanup;
		}

		/*
		 * Don't bother adding a duplicate certificate
		 */
		res = check_uniquness_fdt(cert_blob, root, cert,
					  &cert_node);
		if (res)
			goto cleanup;
		if (cert_node) {
			DMSG("Don't add duplicate cert");
			res = TEE_SUCCESS;
			goto cleanup;
		}

		/*
		 * Try and find the issuer, if one exists (otherwise it might 
		 * be a new root). Two certificates may not have the same fwid.
		 */
		issuer = fdt_node_offset_by_prop_value(fdt, root,
						       "fwid",
						       cert->issuer_fwid,
						       sizeof(cert->issuer_fwid));
		if (issuer < 0 && issuer != -FDT_ERR_NOTFOUND) {
			res = fdt_error(issuer);
			goto cleanup;
		}
		if (issuer < 0) {
			/* Self signed certs are ok, leave them in the root */
			if (memcmp(cert->subject_fwid, cert->issuer_fwid,
				   sizeof(cert->subject_fwid))) {
				EMSG("Unknown issuer");
				res = TEE_ERROR_BAD_PARAMETERS;
				goto cleanup;
			}
		} else {
			/* Verify the issuer name is correct */
			/* Place the new node under its parrent */
			root = issuer;
		}		

		res = create_certificate_fdt(cert_blob, root, issuer, cert);
		/* May need to expand the fdt and try again */
		if (res == TEE_ERROR_OUT_OF_MEMORY) {
			res = expand_cert_fdt(cert_blob);
			if (res)
				goto cleanup;
			continue;
		} else
			goto cleanup;
	} while (true);

cleanup:
	mutex_unlock(&cert_db_mutex);

	return res;
}

TEE_Result initialize_empty_fdt(struct attestation_cert_blob **cert_blob)
{
	int alloc_size = 0;
	int fdt_res = 0;
	int fdt_size = 0;
	struct fdt_header *fdt = NULL;
	struct attestation_cert_blob *new_blob = NULL;
	TEE_Result tee_res = TEE_SUCCESS;

	mutex_lock(&cert_db_mutex);

	alloc_size = sizeof(struct attestation_cert_blob) +
		     CERT_DB_ALLOC_SIZE;
	/* The fdt can use all of the _body[] and the fdt structure */
	fdt_size = alloc_size - sizeof(struct attestation_cert_blob) +
		   sizeof(struct fdt_header);

	new_blob = calloc(1, alloc_size);
	if(!new_blob)
		return TEE_ERROR_OUT_OF_MEMORY;
	
	new_blob->alloc_size = alloc_size;
	new_blob->fdt_size = fdt_size;

	fdt = &new_blob->fdt; 
	fdt_res = fdt_create_empty_tree(fdt, fdt_size);
	if (fdt_res < 0) {
		EMSG("FDT Error: %s", fdt_strerror(fdt_res));
		tee_res = TEE_ERROR_GENERIC;
		goto error;
	}

	fdt_res = fdt_setprop_u32(fdt, /*root*/ 0, "version",
				  ATTESTATION_VERSION);
	if (fdt_res < 0) {
		EMSG("FDT Error: %s", fdt_strerror(fdt_res));
		tee_res = TEE_ERROR_GENERIC;
		goto error;
	}

	fdt_res = fdt_add_subnode(fdt, /*root*/ 0, "certs");
	if (fdt_res < 0) {
		EMSG("FDT Error: %s", fdt_strerror(fdt_res));
		tee_res = TEE_ERROR_GENERIC;
		goto error;
	}

	*cert_blob = new_blob;
	mutex_unlock(&cert_db_mutex);
	return TEE_SUCCESS;
error:
	free(new_blob);
	return tee_res;
}