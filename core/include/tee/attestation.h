/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2017, Linaro Limited
 */

#ifndef __TEE_ATTESTATION_H
#define __TEE_ATTESTATION_H

/* 
 * Attestation of user TAs in OP-TEE is done via code measurement at load
 * time. If CFG_ATTESTATION_MEASURE is enabled the System PTA will request
 * a hash from the user TA store. Each time a new binary is loaded (ie 
 * shared libraries) for a given TA context the existing measurement is 
 * combined with the incoming measurement to form a new hash. The
 * measurement is dependent on the order in which binaries are loaded. A 
 * copy of the running measurement is frozen before the first session to
 * the TA is opened.
 * 
 * Run Time Binary Loading:
 * The system PTA offers the option to load binaries after a TA has started
 * running (dlopen etc). This poses an interesting challenge for attestation
 * since the original measurement will no longer be valid.
 * 
 * TODO: Flesh out this description
 * 
 * Issues:
 * 
 * - Inconsistent Measurements
 * Secstor and Ree FS TAs are not measured the same as Early TAs. Early TAs do
 * not include any headers when they are encoded into the OP-TEE binary and
 * are a simple hash over the .elf being loaded. The other user TA measurements
 * are based on the existing verification flow and include parts of the TA
 * headers.
 * 
 */

#define ATTESTATION_MEASUREMENT_SIZE TEE_SHA256_HASH_SIZE
#define ATTESTATION_MEASUREMENT_ALGO TEE_ALG_SHA256

#endif /* __TEE_ATTESTATION_H */