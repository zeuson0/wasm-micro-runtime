/*
 * Copyright (c) 2022 Intel Corporation
 * Copyright (c) 2020-2021 Alibaba Cloud
 *
 * SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
 */

#ifndef _RATS_WAMR_API_H
#define _RATS_WAMR_API_H

#include <stdint.h>
#include <string.h>
#include "lib_rats_common.h"

#ifdef __cplusplus
extern "C" {
#endif

int
librats_collect(rats_sgx_evidence_t *evidence, uint32_t evidence_size,
                const char *buffer, uint32_t buffer_size);

int
librats_verify(rats_sgx_evidence_t *evidence, uint32_t evidence_size,
               const char *wasm_hash, uint32_t hash_size, const char *buffer,
               uint32_t buffer_size);

int
librats_parse_evidence(const char *evidence_json,uint32_t json_size, rats_sgx_evidence_t *evidence, uint32_t evidence_size);

#define librats_collect(evidence, buffer)                          \
    librats_collect(evidence, sizeof(rats_sgx_evidence_t), buffer, \
                    buffer ? strlen(buffer) + 1 : 0)

#define librats_verify(evidence, wasm_hash, buffer)                  \
    librats_verify(evidence, sizeof(rats_sgx_evidence_t), wasm_hash, \
                    wasm_hash ? strlen(wasm_hash) + 1 : 0, buffer,    \
                    buffer ? strlen(buffer) + 1 : 0)

#define librats_parse_evidence(evidence_json,evidence) \
    librats_parse_evidence(evidence_json, evidence_json ? strlen(evidence_json) + 1 : 0, evidence,sizeof(rats_sgx_evidence_t));

#ifdef __cplusplus
}
#endif

#endif