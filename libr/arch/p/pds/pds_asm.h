/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2026 Josep Torra */
/* pds_asm.h — encode one PDS instruction (see pds_forms.c). */
#ifndef PDS_ASM_H
#define PDS_ASM_H
#include <stdint.h>

/* Encode text, written as pds-dis prints it, into *w. Return 1 on success.
 * Numeric operands may name labels through usse_form_set_resolver(). */
int pds_encode(const char *text, uint32_t *w);

#endif /* PDS_ASM_H */
