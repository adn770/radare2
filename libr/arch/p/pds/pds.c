/* pds.c — SGX Series-5 PDS instruction decoder (see pds.h).
 *
 * Word layout: opcode = w[31:27], predicate = w[26:24] (7 = always), and a 24-bit
 * operand body whose shape depends on the opcode group. Registers are the two
 * data-segment banks ds0/ds1 plus a few specials (ir0/ir1/ir2 input registers,
 * tim, pc, mr01/mr23). Any encoding that selects a reserved register or opcode
 * is reported as undecoded rather than guessed. */
#include "pds.h"
#include <stdarg.h>
#include <stdio.h>

#define BITS(w, hi, lo) (((w) >> (lo)) & ((1u << ((hi) - (lo) + 1)) - 1))

static const char *const PRED[8] = { "p0", "p1", "p2", "if0", "if1", "aluz", "alun", NULL };

/* movs/movsa destinations; 10-14 are reserved. */
static const char *const MOVS_DST[16] = {
    "mr", "slc", "douti", "doutd", "doutt", "doutu", "douta", "tim",
    "doutc", "douts", NULL, NULL, NULL, NULL, NULL, "ir0",
};

typedef struct { char *p; unsigned left; int ok; } out_t;

static void put(out_t *o, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(o->p, o->left, fmt, ap);
    va_end(ap);
    if (n < 0 || (unsigned)n >= o->left) { o->ok = 0; return; }
    o->p += n;
    o->left -= n;
}

/* Input/special register by index. The mov16/mov32 source fields also have pc,
 * which shifts the numbering; other groups expose only a prefix of the list. */
static const char *special(unsigned i, int with_pc) {
    static const char *const PLAIN[] = { "ir0", "ir1", "tim", "ir2" };
    static const char *const WITHPC[] = { "ir0", "ir1", "pc", "tim", "ir2" };
    if (with_pc) return i < 5 ? WITHPC[i] : NULL;
    return i < 4 ? PLAIN[i] : NULL;
}

const char *pds_pred_name(unsigned p) { return p < 8 ? PRED[p] : NULL; }
const char *pds_movs_dst_name(unsigned d) { return d < 16 ? MOVS_DST[d] : NULL; }
const char *pds_special_name(unsigned i, int with_pc) { return special(i, with_pc); }

/* 7-bit destination: ds0[0-63], ds1[0-63]. */
static void dst7(out_t *o, unsigned v) {
    put(o, "ds%u[%u]", v >> 6, v & 0x3f);
}

/* 7-bit first source: ds0[0-63], then the first `nspecial` of ir0, ir1, tim. */
static void src7(out_t *o, unsigned v, unsigned nspecial) {
    if (v < 0x40) { put(o, "ds0[%u]", v); return; }
    if (v - 0x40 < nspecial) { put(o, "%s", special(v - 0x40, 0)); return; }
    o->ok = 0;
}

/* Predicate prefix, if the group shows one. */
static void pred(out_t *o, uint32_t w) {
    const char *p = PRED[BITS(w, 26, 24)];
    if (p) put(o, "(%s) ", p);
}

static void movs(out_t *o, uint32_t w, const char *mn) {
    const char *dst = MOVS_DST[BITS(w, 3, 0)];
    unsigned ir = BITS(w, 23, 23), b0 = BITS(w, 22, 18), b1 = BITS(w, 17, 13) * 2;
    int uses_base = 0;
    for (int s = 0; s < 4; s++) uses_base |= !(BITS(w, 6 + 2 * s, 6 + 2 * s));
    if (!dst || (ir && uses_base && !special(b0, 0))) { o->ok = 0; return; }
    pred(o, w);
    put(o, "%s %s", mn, dst);
    for (int s = 3; s >= 0; s--) {
        unsigned sel = BITS(w, 6 + 2 * s, 5 + 2 * s), hi = sel & 1;
        if (sel & 2)  put(o, ", ds1[%u]", b1 + hi);
        else if (ir)  put(o, ", %s.%c", special(b0, 0), hi ? 'h' : 'l');
        else          put(o, ", ds0[%u]", b0 * 2 + hi);
    }
}

/* 9-bit source in 16-bit halves (mov16): ds0, ds1, then specials incl. pc. */
static void src9h(out_t *o, unsigned v) {
    char hl = (v & 1) ? 'h' : 'l';
    unsigned r = v >> 1;
    if (r < 0x40)      put(o, "ds0[%u].%c", r, hl);
    else if (r < 0x80) put(o, "ds1[%u].%c", r - 0x40, hl);
    else if (special(r - 0x80, 1)) put(o, "%s.%c", special(r - 0x80, 1), hl);
    else o->ok = 0;
}

static void decode_body(out_t *o, uint32_t w) {
    static const char *const ARITH[] = { "add", "sub", "adc", "sbc" };
    static const char *const LOGIC[] = { "or", "and", "xor", NULL, "nor", "nand" };
    unsigned op = BITS(w, 31, 27);

    switch (op) {
    case 0x00: movs(o, w, "movs");  return;
    case 0x05: movs(o, w, "movsa"); return;
    case 0x01: {                                /* mov16 */
        pred(o, w);
        put(o, "mov16 ds%u[%u], ", BITS(w, 7, 7), BITS(w, 6, 0));
        src9h(o, BITS(w, 16, 8));
        return;
    }
    case 0x02: {                                /* mov32 */
        unsigned s = BITS(w, 16, 9);
        pred(o, w);
        put(o, "mov32 ds%u[%u], ", BITS(w, 7, 7), BITS(w, 6, 1));
        if (s < 0x80) put(o, "ds%u[%u]", s >> 6, s & 0x3f);
        else if (special(s - 0x80, 1)) put(o, "%s", special(s - 0x80, 1));
        else o->ok = 0;
        return;
    }
    case 0x03: {                                /* mov64 */
        unsigned s = BITS(w, 16, 10);
        pred(o, w);
        put(o, "mov64 ds%u[%u], ", BITS(w, 7, 7), BITS(w, 6, 2) * 2);
        if (s < 0x40) put(o, "ds%u[%u]", s >> 5, (s & 0x1f) * 2);
        else if (s < 0x42) put(o, "mr%s", s == 0x40 ? "01" : "23");
        else o->ok = 0;
        return;
    }
    case 0x04: {                                /* mov128 */
        unsigned s = BITS(w, 14, 10);
        if (s >= 16) { o->ok = 0; return; }
        pred(o, w);
        put(o, "mov128 ds[%u], ds[%u]%s", BITS(w, 6, 2) * 2, s * 2,
            BITS(w, 8, 8) ? ", swap" : "");
        return;
    }
    case 0x06: case 0x07: {                     /* load/store: 1-8 dwords from ds48+ */
        unsigned r = 48 + BITS(w, 21, 18), n = (BITS(w, 26, 24) - 1) & 7;
        put(o, "%s 0x%08X, ds%u[%u", op == 6 ? "load" : "store", BITS(w, 17, 0) << 2,
            BITS(w, 22, 22), r);
        put(o, n ? "-%u]" : "]", r + n);
        return;
    }
    case 0x08: case 0x09: case 0x0a: case 0x0b:
    case 0x18: case 0x19: case 0x1a: case 0x1c: case 0x1d: {
        const char *mn = op < 0x18 ? ARITH[op - 8] : LOGIC[op - 0x18];
        pred(o, w);
        put(o, "%s ", mn);
        dst7(o, BITS(w, 6, 0));
        put(o, ", ");
        src7(o, BITS(w, 23, 17), 3);
        put(o, ", ds1[%u]", BITS(w, 15, 10));
        return;
    }
    case 0x0c: {                                /* mul: 16x16 */
        unsigned a = BITS(w, 23, 16), b = BITS(w, 15, 9);
        pred(o, w);
        put(o, "mul ");
        dst7(o, BITS(w, 6, 0));
        if (a < 0x80) put(o, ", ds0[%u].%c", a >> 1, (a & 1) ? 'h' : 'l');
        else if (special((a - 0x80) >> 1, 0) && (a - 0x80) >> 1 < 3)
            put(o, ", %s.%c", special((a - 0x80) >> 1, 0), (a & 1) ? 'h' : 'l');
        else o->ok = 0;
        put(o, ", ds1[%u].%c", b >> 1, (b & 1) ? 'h' : 'l');
        return;
    }
    case 0x0d: case 0x1b: {                     /* abs/not: one source */
        pred(o, w);
        put(o, "%s ", op == 0x0d ? "abs" : "not");
        dst7(o, BITS(w, 6, 0));
        put(o, ", ");
        if (BITS(w, 8, 8)) put(o, "ds1[%u]", op == 0x0d ? BITS(w, 14, 10) : BITS(w, 15, 10));
        else src7(o, BITS(w, 23, 17), op == 0x0d ? 2 : 3);
        return;
    }
    case 0x0f:
        put(o, "%s", BITS(w, 0, 0) ? "rwfence" : "rfence");
        return;
    case 0x10: case 0x11: {                     /* tstz/tstn */
        unsigned p = BITS(w, 2, 0);
        pred(o, w);
        put(o, "%s %s, ", op == 0x10 ? "tstz" : "tstn", p < 3 ? PRED[p] : "");
        if (BITS(w, 8, 8)) put(o, "ds1[%u]", BITS(w, 15, 10));
        else src7(o, BITS(w, 23, 17), 2);
        return;
    }
    case 0x12: case 0x13:
        pred(o, w);
        put(o, "%s 0x%08X", op == 0x12 ? "bra" : "call", BITS(w, 18, 0));
        return;
    case 0x14: pred(o, w); put(o, "rtn");  return;
    case 0x15: pred(o, w); put(o, "halt"); return;
    case 0x16: put(o, "nop"); return;
    case 0x17:
        pred(o, w);
        put(o, "alum %s", BITS(w, 0, 0) ? "signed" : "unsigned");
        return;
    case 0x1e: case 0x1f: {                     /* shl/shr by a signed 7-bit amount */
        unsigned s = BITS(w, 23, 16);
        int32_t n = (int32_t)(BITS(w, 14, 8) << 25) >> 25;
        pred(o, w);
        put(o, "%s ", op == 0x1e ? "shl" : "shr");
        dst7(o, BITS(w, 6, 0));
        if (s < 0x80) put(o, ", ds%u[%u]", s >> 6, s & 0x3f);
        else if (s - 0x80 < 2) put(o, ", %s", special(s - 0x80, 0));
        else o->ok = 0;
        put(o, ", %u", (uint32_t)n);
        return;
    }
    default:                                    /* 0x0e: reserved arithmetic type */
        o->ok = 0;
        return;
    }
}

int pds_decode(uint32_t w, char *text, unsigned len) {
    out_t o = { text, len, 1 };
    if (len) text[0] = '\0';
    decode_body(&o, w);
    if (!o.ok) snprintf(text, len, ".word 0x%08X", w);
    return o.ok;
}

pds_op_type pds_classify(uint32_t w) {
    static const pds_op_type T[32] = {
        PDS_T_MOV,  PDS_T_MOV,  PDS_T_MOV,  PDS_T_MOV,  PDS_T_MOV,  PDS_T_MOV,  PDS_T_LOAD, PDS_T_STORE,
        PDS_T_ADD,  PDS_T_SUB,  PDS_T_ADD,  PDS_T_SUB,  PDS_T_MUL,  PDS_T_ABS,  PDS_T_UNK,  PDS_T_SYNC,
        PDS_T_CMP,  PDS_T_CMP,  PDS_T_JMP,  PDS_T_CALL, PDS_T_RET,  PDS_T_HALT, PDS_T_NOP,  PDS_T_UNK,
        PDS_T_OR,   PDS_T_AND,  PDS_T_XOR,  PDS_T_NOT,  PDS_T_NOR,  PDS_T_NAND, PDS_T_SHL,  PDS_T_SHR,
    };
    unsigned op = BITS(w, 31, 27), dst = BITS(w, 3, 0);
    if (op == 0x00 || op == 0x05)               /* movs/movsa: dout* ports are I/O */
        return (dst >= 2 && dst <= 6) || dst == 8 || dst == 9 ? PDS_T_IO : PDS_T_MOV;
    return T[op];
}

int pds_predicated(uint32_t w) {
    unsigned op = BITS(w, 31, 27);
    if (op == 0x06 || op == 0x07 || op == 0x0f || op == 0x16)
        return 0;
    return BITS(w, 26, 24) != 7;
}

int pds_branch(uint32_t w, int *is_call, int *is_cond, uint32_t *target) {
    unsigned op = BITS(w, 31, 27);
    if (op != 0x12 && op != 0x13)
        return 0;
    *is_call = op == 0x13;
    *is_cond = pds_predicated(w);
    *target = BITS(w, 18, 0);
    return 1;
}
