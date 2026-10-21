/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2026 Josep Torra */
/* usse.h — SGX Series-5 USSE instruction decoder: the whole SGX545 instruction
 * set, with the SGX540 readings where they differ (usse_set_core()).
 *
 * The USSE instruction word is 64-bit little-endian. The top 5 bits (enc[63:59])
 * select the major opcode class; class 0x1F (0xF8..0xFF) is the control/special
 * group with further sub-opcode bits. The field layouts (the form tables in
 * usse.c and forms/) were derived by bit-correlation against the SGX540
 * ground-truth disassembly (solve.py) and by black-box probing of the SGX545
 * reference disassembler (see tools/usse-dis/README.md), not guessed.
 *
 * This core is standalone (no radare2 dependency) so it can be regression-tested
 * against the oracle via the usse-dis CLI; r2/ wraps it as an r2 RArch plugin. */
#ifndef USSE_H
#define USSE_H
#include <stdint.h>
#include <stddef.h>

/* The longest instruction text (efo and smlsi with immediates reach past 191). */
#define USSE_TEXT_MAX 256

typedef struct {
    int      valid;          /* 1 if fully decoded, 0 if opcode unknown */
    uint64_t enc;            /* the raw 64-bit instruction word */
    char     text[USSE_TEXT_MAX]; /* decoded mnemonic + operands (oracle-compatible) */
} usse_insn;

/* Decode one 64-bit USSE word. `pc` is the instruction index (for future
 * branch-target resolution). Always fills out->text (".long 0x…" if unknown). */
void usse_decode(uint64_t enc, uint32_t pc, usse_insn *out);

/* Select the core whose reading the decoder (and assembler) follows: 545
 * (the default) or 540. They differ in the load/store cache bits. */
void usse_set_core(int core);

/* Base mnemonic for a top-5-bit opcode class, or NULL if unmapped. */
const char *usse_class_name(unsigned top5);

/* Coarse instruction category, for an analysis frontend (e.g. the r2 plugin).
 * r2-independent so the core stays free of radare2 headers. */
typedef enum {
    USSE_T_UNK = 0, USSE_T_MOV, USSE_T_ALU, USSE_T_MUL,
    USSE_T_LOAD, USSE_T_STORE, USSE_T_JMP, USSE_T_CJMP,
    USSE_T_CALL, USSE_T_NOP, USSE_T_SYNC, USSE_T_RET, USSE_T_CRET
} usse_op_type;

usse_op_type usse_classify(uint64_t enc);

/* If enc is a ba/br branch, return 1 and fill the out params:
 *   is_call   — ba.savelink (branch + link)
 *   is_cond   — predicated (conditional)
 *   is_rel    — br (pc-relative); else ba (absolute, from image base 0)
 *   off_words — target offset in 8-byte instruction units (signed for br). */
int usse_branch(uint64_t enc, int *is_call, int *is_cond, int *is_rel, int32_t *off_words);

#endif /* USSE_H */
