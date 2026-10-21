// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: 2026 Josep Torra
/* pds_forms.c — the PDS instruction forms the assembler matches text against.
 *
 * The PDS decoder (tools/usse-dis/pds.c) is a compact field decoder rather
 * than a table, so the assembler describes the same layouts here, in the form
 * table format of usse_form.h, and checks every word it builds against
 * pds_decode(): an encoding is accepted only if the decoder prints it with the
 * form's text. A layout here that disagreed with pds.c could only make an
 * instruction fail to assemble, never assemble wrong (the round-trip tests
 * would show it). Names come from pds.c (pds_pred_name() and friends). */
#include "pds_asm.h"
#include "pds.h"
#include "usse_form.h"
#include <ctype.h>
#include <stdio.h>
#include <string.h>

/* ---- kinds ---------------------------------------------------------------- */

/* Predicate w[26:24] as a "(p0) " prefix; 7 (always) prints nothing. */
static int k_pred_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    const char *p = pds_pred_name(v);
    (void)k;
    if (p) snprintf(out, n, "(%s) ", p);
    else   out[0] = '\0';
    return 1;
}

static int k_port_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    const char *p = pds_movs_dst_name(v);
    (void)k;
    if (!p) return 0;
    snprintf(out, n, "%s", p);
    return 1;
}

/* movs/movsa sources, v = w[23:5]: four 2-bit selectors [7:0] (slot s at
 * 2s: bit 0 the high half, bit 1 ds1), the ds1 pair [12:8], the ds0 pair or
 * input register [17:13], and [18] which of the two that field names. Slots
 * print from 3 down to 0. */
static int k_movs_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    unsigned b1 = (v >> 8 & 31) * 2, b0 = v >> 13 & 31, ir = v >> 18 & 1;
    int uses_base = 0;
    size_t at = 0;
    (void)k;
    for (int s = 0; s < 4; s++) uses_base |= !(v >> (2 * s + 1) & 1);
    if (ir && uses_base && !pds_special_name(b0, 0)) return 0;
    out[0] = '\0';
    for (int s = 3; s >= 0; s--) {
        unsigned sel = v >> (2 * s) & 3, hi = sel & 1;
        const char *sep = s == 3 ? "" : ", ";
        if (sel & 2)  at += (size_t)snprintf(out + at, n - at, "%sds1[%u]", sep, b1 + hi);
        else if (ir)  at += (size_t)snprintf(out + at, n - at, "%s%s.%c", sep,
                                             pds_special_name(b0, 0), hi ? 'h' : 'l');
        else          at += (size_t)snprintf(out + at, n - at, "%sds0[%u]", sep, b0 * 2 + hi);
        if (at >= n) return 0;
    }
    return 1;
}

static const char *skip_ws(const char *s) {
    while (isspace((unsigned char)*s)) s++;
    return s;
}

/* "ds<bank>[<n>]": 1 and the bank and index, else 0. */
static int parse_ds(const char *s, const char **end, unsigned *bank, unsigned *idx) {
    uint64_t x;
    if (strncmp(s, "ds", 2) || (s[2] != '0' && s[2] != '1') || s[3] != '[') return 0;
    if (!usse_parse_uint(s + 4, end, &x) || **end != ']' || x > 127) return 0;
    *bank = (unsigned)(s[2] - '0');
    *idx = (unsigned)x;
    (*end)++;
    return 1;
}

/* The inverse of k_movs_print. Fields no operand uses stay 0. */
static int k_movs_parse(const usse_kind *k, const char *s, const char **end, uint32_t *v) {
    int b0 = -1, b1 = -1, ir = -1;
    uint32_t sel = 0;
    (void)k;
    for (int i = 0; i < 4; i++) {
        unsigned bank, idx, slot = 3 - (unsigned)i, hi;
        const char *e;
        s = skip_ws(s);
        if (i) {
            if (*s != ',') return 0;
            s = skip_ws(s + 1);
        }
        if (parse_ds(s, &e, &bank, &idx)) {
            hi = idx & 1;
            idx >>= 1;
            if (idx > 31) return 0;
            if (bank) {
                if (b1 >= 0 && b1 != (int)idx) return 0;
                b1 = (int)idx;
                sel |= (2 | hi) << (2 * slot);
            } else {
                if (ir == 1 || (b0 >= 0 && b0 != (int)idx)) return 0;
                ir = 0;
                b0 = (int)idx;
                sel |= hi << (2 * slot);
            }
        } else {
            unsigned r;
            for (r = 0; r < 4; r++) {
                const char *name = pds_special_name(r, 0);
                size_t l = strlen(name);
                if (!strncmp(s, name, l) && s[l] == '.' && (s[l + 1] == 'l' || s[l + 1] == 'h')) {
                    hi = s[l + 1] == 'h';
                    e = s + l + 2;
                    break;
                }
            }
            if (r == 4 || ir == 0 || (b0 >= 0 && b0 != (int)r)) return 0;
            ir = 1;
            b0 = (int)r;
            sel |= hi << (2 * slot);
        }
        s = e;
    }
    *v = sel | (uint32_t)(b1 < 0 ? 0 : b1) << 8 | (uint32_t)(b0 < 0 ? 0 : b0) << 13 |
         (uint32_t)(ir == 1) << 18;
    *end = s;
    return 1;
}

/* 7-bit destination ds0[0-63], ds1[0-63]. */
static int k_dst7_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    snprintf(out, n, "ds%u[%u]", v >> 6, v & 63);
    return 1;
}

/* 7-bit first source: ds0[0-63] and the first arg input registers. */
static int k_src7_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    unsigned nspecial = (unsigned)(uintptr_t)k->arg;
    if (v < 64) { snprintf(out, n, "ds0[%u]", v); return 1; }
    if (v - 64 < nspecial) { snprintf(out, n, "%s", pds_special_name(v - 64, 0)); return 1; }
    return 0;
}

/* mov16 source, 9 bits in 16-bit halves: ds0, ds1, then specials with pc. */
static int k_src9h_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    char hl = (v & 1) ? 'h' : 'l';
    unsigned r = v >> 1;
    (void)k;
    if (r < 128) snprintf(out, n, "ds%u[%u].%c", r >> 6, r & 63, hl);
    else if (pds_special_name(r - 128, 1))
        snprintf(out, n, "%s.%c", pds_special_name(r - 128, 1), hl);
    else return 0;
    return 1;
}

/* mov32 source, 8 bits: ds0, ds1, then specials with pc. */
static int k_src8_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    if (v < 128) snprintf(out, n, "ds%u[%u]", v >> 6, v & 63);
    else if (pds_special_name(v - 128, 1)) snprintf(out, n, "%s", pds_special_name(v - 128, 1));
    else return 0;
    return 1;
}

/* mov64 source, 7 bits: even pairs of ds0/ds1, then mr01, mr23. */
static int k_src64_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    if (v < 64) snprintf(out, n, "ds%u[%u]", v >> 5, (v & 31) * 2);
    else if (v < 66) snprintf(out, n, "mr%s", v == 64 ? "01" : "23");
    else return 0;
    return 1;
}

/* mov128 source pair, 5 bits, below 16. */
static int k_src128_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    if (v >= 16) return 0;
    snprintf(out, n, "%u", v * 2);
    return 1;
}

/* load/store registers: v = first[3:0] (from ds48) | count[6:4] (1-8, 0 is 8). */
static int k_ldrange_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    unsigned r = 48 + (v & 15), cnt = ((v >> 4) - 1) & 7;
    (void)k;
    if (cnt) snprintf(out, n, "%u-%u]", r, r + cnt);
    else     snprintf(out, n, "%u]", r);
    return 1;
}

/* mul first source, 8 bits in halves: ds0, then ir0/ir1/tim. */
static int k_mula_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    char hl = (v & 1) ? 'h' : 'l';
    (void)k;
    if (v < 128) snprintf(out, n, "ds0[%u].%c", v >> 1, hl);
    else if ((v - 128) >> 1 < 3) snprintf(out, n, "%s.%c", pds_special_name((v - 128) >> 1, 0), hl);
    else return 0;
    return 1;
}

static int k_half_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    snprintf(out, n, "ds1[%u].%c", v >> 1, (v & 1) ? 'h' : 'l');
    return 1;
}

/* shl/shr source, 8 bits: ds0/ds1, then ir0, ir1. */
static int k_shsrc_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    if (v < 128) snprintf(out, n, "ds%u[%u]", v >> 6, v & 63);
    else if (v - 128 < 2) snprintf(out, n, "%s", pds_special_name(v - 128, 0));
    else return 0;
    return 1;
}

/* Signed 7-bit shift amount, printed as an unsigned 32-bit number. */
static int k_shamt_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    snprintf(out, n, "%u", (uint32_t)((int32_t)(v << 25) >> 25));
    return 1;
}

static int k_shamt_parse(const usse_kind *k, const char *s, const char **end, uint32_t *v) {
    uint64_t x;
    (void)k;
    if (!usse_parse_uint(s, end, &x)) return 0;
    if (x < 64) *v = (uint32_t)x;
    else if (x >= 0xffffffc0ull) *v = (uint32_t)x & 0x7f;
    else return 0;
    return 1;
}

#define KIND(name, print, parse, arg) static const usse_kind name = { print, parse, arg }
KIND(K_PRED, k_pred_print, NULL, NULL);
KIND(K_PORT, k_port_print, NULL, NULL);
KIND(K_MOVS, k_movs_print, k_movs_parse, NULL);
KIND(K_DST7, k_dst7_print, NULL, NULL);
KIND(K_SRC7_2, k_src7_print, NULL, (void *)(uintptr_t)2);
KIND(K_SRC7_3, k_src7_print, NULL, (void *)(uintptr_t)3);
KIND(K_SRC9H, k_src9h_print, NULL, NULL);
KIND(K_SRC8, k_src8_print, NULL, NULL);
KIND(K_SRC64, k_src64_print, NULL, NULL);
KIND(K_SRC128, k_src128_print, NULL, NULL);
KIND(K_LDRANGE, k_ldrange_print, NULL, NULL);
KIND(K_MULA, k_mula_print, NULL, NULL);
KIND(K_HALF, k_half_print, NULL, NULL);
KIND(K_SHSRC, k_shsrc_print, NULL, NULL);
KIND(K_SHAMT, k_shamt_print, k_shamt_parse, NULL);

static const usse_num N_DEC = { "%u", 1, 0 }, N_X2 = { "%u", 2, 0 };
static const usse_num N_HEX = { "0x%08X", 1, 0 }, N_ADDR = { "0x%08X", 4, 0 };
KIND(K_DEC, usse_k_num_print, usse_k_num_parse, &N_DEC);
KIND(K_X2, usse_k_num_print, usse_k_num_parse, &N_X2);
KIND(K_HEX, usse_k_num_print, usse_k_num_parse, &N_HEX);
KIND(K_ADDR, usse_k_num_print, usse_k_num_parse, &N_ADDR);

#define ENUM(name, n, ...) \
    static const char *const name##_T[n] = { __VA_ARGS__ }; \
    KIND(name, usse_k_enum_print, NULL, name##_T)
ENUM(ALU, 32, [0x08] = "add", [0x09] = "sub", [0x0a] = "adc", [0x0b] = "sbc",
     [0x18] = "or", [0x19] = "and", [0x1a] = "xor", [0x1c] = "nor", [0x1d] = "nand");
ENUM(FENCE, 2, "rfence", "rwfence");
ENUM(TSTP, 8, "p0", "p1", "p2", "", "", "", "", "");
ENUM(SWAP, 2, "", ", swap");
ENUM(ALUM, 2, "unsigned", "signed");

/* ---- the table -------------------------------------------------------------- */

#define OPM          (0x1fu << 27)
#define OP(o)        ((uint64_t)(o) << 27)
#define C(lo, w)     { lo, w }
#define FLD(k, ...)  { &k, { __VA_ARGS__ } }
#define PRED         FLD(K_PRED, C(24, 3))
#define DST7         FLD(K_DST7, C(0, 7))

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
static const usse_form pds_forms[] = {
    { "{0}movs {1}, {2}", OPM, OP(0x00), { PRED, FLD(K_PORT, C(0, 4)), FLD(K_MOVS, C(5, 19)) } },
    { "{0}movsa {1}, {2}", OPM, OP(0x05), { PRED, FLD(K_PORT, C(0, 4)), FLD(K_MOVS, C(5, 19)) } },
    { "{0}mov16 ds{1}[{2}], {3}", OPM, OP(0x01),
      { PRED, FLD(K_DEC, C(7, 1)), FLD(K_DEC, C(0, 7)), FLD(K_SRC9H, C(8, 9)) } },
    { "{0}mov32 ds{1}[{2}], {3}", OPM, OP(0x02),
      { PRED, FLD(K_DEC, C(7, 1)), FLD(K_DEC, C(1, 6)), FLD(K_SRC8, C(9, 8)) } },
    { "{0}mov64 ds{1}[{2}], {3}", OPM, OP(0x03),
      { PRED, FLD(K_DEC, C(7, 1)), FLD(K_X2, C(2, 5)), FLD(K_SRC64, C(10, 7)) } },
    { "{0}mov128 ds[{1}], ds[{2}]{3}", OPM, OP(0x04),
      { PRED, FLD(K_X2, C(2, 5)), FLD(K_SRC128, C(10, 5)), FLD(SWAP, C(8, 1)) } },
    { "load {0}, ds{1}[{2}", OPM, OP(0x06),
      { FLD(K_ADDR, C(0, 18)), FLD(K_DEC, C(22, 1)), FLD(K_LDRANGE, C(18, 4), C(24, 3)) } },
    { "store {0}, ds{1}[{2}", OPM, OP(0x07),
      { FLD(K_ADDR, C(0, 18)), FLD(K_DEC, C(22, 1)), FLD(K_LDRANGE, C(18, 4), C(24, 3)) } },
    { "{0}{1} {2}, {3}, ds1[{4}]", 0, 0,
      { PRED, FLD(ALU, C(27, 5)), DST7, FLD(K_SRC7_3, C(17, 7)), FLD(K_DEC, C(10, 6)) } },
    { "{0}mul {1}, {2}, {3}", OPM, OP(0x0c),
      { PRED, DST7, FLD(K_MULA, C(16, 8)), FLD(K_HALF, C(9, 7)) } },
    { "{0}abs {1}, ds1[{2}]", OPM | 1u << 8, OP(0x0d) | 1u << 8,
      { PRED, DST7, FLD(K_DEC, C(10, 5)) } },
    { "{0}abs {1}, {2}", OPM | 1u << 8, OP(0x0d), { PRED, DST7, FLD(K_SRC7_2, C(17, 7)) } },
    { "{0}not {1}, ds1[{2}]", OPM | 1u << 8, OP(0x1b) | 1u << 8,
      { PRED, DST7, FLD(K_DEC, C(10, 6)) } },
    { "{0}not {1}, {2}", OPM | 1u << 8, OP(0x1b), { PRED, DST7, FLD(K_SRC7_3, C(17, 7)) } },
    { "{0}", OPM, OP(0x0f), { FLD(FENCE, C(0, 1)) } },
    { "{0}tstz {1}, ds1[{2}]", OPM | 1u << 8, OP(0x10) | 1u << 8,
      { PRED, FLD(TSTP, C(0, 3)), FLD(K_DEC, C(10, 6)) } },
    { "{0}tstz {1}, {2}", OPM | 1u << 8, OP(0x10),
      { PRED, FLD(TSTP, C(0, 3)), FLD(K_SRC7_2, C(17, 7)) } },
    { "{0}tstn {1}, ds1[{2}]", OPM | 1u << 8, OP(0x11) | 1u << 8,
      { PRED, FLD(TSTP, C(0, 3)), FLD(K_DEC, C(10, 6)) } },
    { "{0}tstn {1}, {2}", OPM | 1u << 8, OP(0x11),
      { PRED, FLD(TSTP, C(0, 3)), FLD(K_SRC7_2, C(17, 7)) } },
    { "{0}bra {1}", OPM, OP(0x12), { PRED, FLD(K_HEX, C(0, 19)) } },
    { "{0}call {1}", OPM, OP(0x13), { PRED, FLD(K_HEX, C(0, 19)) } },
    { "{0}rtn", OPM, OP(0x14), { PRED } },
    { "{0}halt", OPM, OP(0x15), { PRED } },
    { "nop", OPM, OP(0x16), { { 0 } } },
    { "{0}alum {1}", OPM, OP(0x17), { PRED, FLD(ALUM, C(0, 1)) } },
    { "{0}shl {1}, {2}, {3}", OPM, OP(0x1e),
      { PRED, DST7, FLD(K_SHSRC, C(16, 8)), FLD(K_SHAMT, C(8, 7)) } },
    { "{0}shr {1}, {2}, {3}", OPM, OP(0x1f),
      { PRED, DST7, FLD(K_SHSRC, C(16, 8)), FLD(K_SHAMT, C(8, 7)) } },
};

#pragma GCC diagnostic pop

static int decode(uint64_t w, char *out, size_t n) {
    return pds_decode((uint32_t)w, out, (unsigned)n);
}

static const usse_table pds_table = { pds_forms, sizeof pds_forms / sizeof pds_forms[0], decode };

int pds_encode(const char *text, uint32_t *w) {
    uint64_t e;
    if (!usse_form_encode_in(&pds_table, text, &e)) return 0;
    *w = (uint32_t)e;
    return 1;
}
