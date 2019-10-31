CFG_CRYPTO ?= y

ifeq (y,$(CFG_CRYPTO))

# HMAC-based Extract-and-Expand Key Derivation Function
# http://tools.ietf.org/html/rfc5869
# This is an OP-TEE extension, not part of the GlobalPlatform Internal API v1.0
CFG_CRYPTO_HKDF ?= y

# NIST SP800-56A Concatenation Key Derivation Function
# This is an OP-TEE extension
CFG_CRYPTO_CONCAT_KDF ?= y

# PKCS #5 v2.0 / RFC 2898 key derivation function 2
# This is an OP-TEE extension
CFG_CRYPTO_PBKDF2 ?= y

endif

srcs-y += tee_cryp_utl.c
srcs-$(CFG_CRYPTO_HKDF) += tee_cryp_hkdf.c
srcs-$(CFG_CRYPTO_CONCAT_KDF) += tee_cryp_concat_kdf.c
srcs-$(CFG_CRYPTO_PBKDF2) += tee_cryp_pbkdf2.c

ifeq ($(CFG_WITH_USER_TA),y)

srcs-y += tee_svc.c
cppflags-tee_svc.c-y += -DTEE_IMPL_VERSION=$(TEE_IMPL_VERSION)
srcs-y += tee_svc_cryp.c
srcs-y += tee_svc_storage.c
srcs-$(CFG_RPMB_FS) += tee_rpmb_fs.c
srcs-$(CFG_REE_FS) += tee_ree_fs.c
srcs-$(call cfg-one-enabled,CFG_REE_FS CFG_TEE_CORE_EMBED_INTERNAL_TESTS) += \
	fs_htree.c
srcs-$(CFG_REE_FS) += fs_dirfile.c
srcs-$(CFG_REE_FS) += tee_fs_rpc.c
srcs-$(call cfg-one-enabled,CFG_REE_FS CFG_RPMB_FS) += tee_fs_rpc_cache.c
srcs-y += tee_fs_key_manager.c
srcs-y += tee_obj.c
srcs-y += tee_pobj.c
srcs-y += tee_time_generic.c
srcs-$(CFG_SECSTOR_TA) += tadb.c
srcs-$(CFG_GP_SOCKETS) += socket.c
srcs-$(CFG_ATTESTATION_MEASURE) += attestation_temp.c
srcs-$(CFG_ATTESTATION_MEASURE) += attestation_db.c

ifeq ($(CFG_ATTESTATION_PREBAKED),y)
# Allow a pre-generated attestation root of trust to be baked into the OP-TEE
# image at compile time. If this is used for a secure device it is critical to
# protect the comiled binaries which include the root of trust.
attestation-test-fdt-dts = $(CFG_ATTESTATION_PREBAKED_FILE)
attestation-test-fdt-dtb = $(sub-dir-out)/attestation_test_dtb.dtb
attestation-test-fdt-c = $(sub-dir-out)/attestation_test_dtb.c

gensrcs-y += attestation_test_dtb
cleanfiles += $(attestation-test-fdt-c) $(attestation-test-fdt-dtb)
produce-attestation_test_dtb = attestation_test_dtb.c
depends-attestation_test_dtb = $(attestation-test-fdt-dtb) \
				scripts/bin_to_c.py
recipe-attestation_test_dtb = scripts/bin_to_c.py \
				--bin $(attestation-test-fdt-dtb) \
				--vname attestation_prebaked_fdt \
				--out $(attestation-test-fdt-c)
$(eval $(call gen-dtb-file,$(attestation-test-fdt-dts),$(attestation-test-fdt-dtb)))
endif

endif #CFG_WITH_USER_TA,y

srcs-y += uuid.c
