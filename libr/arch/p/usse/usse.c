/* usse.c — SGX Series-5 USSE decoder core: the instruction-form table that
 * usse_decode() walks and the assembler (tools/usse-asm) inverts (see
 * usse_form.h). Field layouts were derived from the SGX540 oracle disassembly
 * by bit-correlation (solve.py) and by black-box probing of refdisasm545.
 * Invariant: a form that decodes a word must print exactly what the oracle
 * prints, never a guess (oracle_check.py, random_oracle_check.py). */
#include "usse.h"
#include "usse_form.h"
#include <ctype.h>
#include <stdio.h>

/* Major opcode class = enc[63:59]. Base mnemonic per class (NULL = unmapped),
 * enumerated from the 540 oracle histogram; used only as a readable hint for
 * not-yet-decoded instructions. */
static const char *CLASS[32] = {
    [0]  = "fmad",   [5]  = "mov",    [7]  = "efo",
    [9]  = "and",    [10] = "and",    [11] = "xor",
    [12] = "shl",    [13] = "shr",    [20] = "ima16",
    [21] = "imae",   [29] = "ldad",   [30] = "stad",
    [31] = "special",
};
const char *usse_class_name(unsigned top5) { return (top5 < 32) ? CLASS[top5] : 0; }

static inline uint32_t cbit(uint64_t e, unsigned n) { return (uint32_t)((e >> n) & 1u); }
static inline uint32_t cbits(uint64_t e, unsigned hi, unsigned lo) {
    return (uint32_t)((e >> lo) & ((1ull << (hi - lo + 1)) - 1));
}

/* True iff enc is a class-31 FLOWCTRL ba/br (shared by classify + branch). */
static int is_flowctrl(uint64_t e, unsigned *op2) {
    if (cbits(e, 63, 59) != 0x1fu) return 0;   /* SPECIAL class   */
    if (cbits(e, 53, 52) != 0u)    return 0;   /* op_category==FLOWCTRL */
    if (cbit(e, 54))               return 0;   /* not OTHER2      */
    unsigned o = cbits(e, 40, 38);
    if (o != 0u && o != 1u) return 0;          /* 0=ba 1=br       */
    if (op2) *op2 = o;
    return 1;
}

usse_op_type usse_classify(uint64_t e) {
    unsigned op2;
    if (is_flowctrl(e, &op2)) {
        if (cbit(e, 41)) return USSE_T_CALL;             /* .savelink */
        return cbits(e, 58, 56) ? USSE_T_CJMP : USSE_T_JMP;  /* predicated? */
    }
    unsigned cls = cbits(e, 63, 59);
    if (cls == 31) {
        if (cbits(e, 63, 54) == 0x3F0u && cbit(e, 53)) return USSE_T_MOV; /* limm */
        if (e == 0xF800014000000000ull) return USSE_T_NOP;               /* nop  */
        return USSE_T_SYNC;   /* idf/wdf/lock/ci/cfi/str/ldr/smlsi/... */
    }
    switch (cls) {
    case 0:  return USSE_T_MUL;    /* fmad */
    case 5:  return USSE_T_MOV;
    case 9: case 10: case 11: case 12: case 13: return USSE_T_ALU;
    case 20: case 21: return USSE_T_MUL;
    case 29: return USSE_T_LOAD;
    case 30: return USSE_T_STORE;
    default: return USSE_T_UNK;
    }
}

int usse_branch(uint64_t e, int *is_call, int *is_cond, int *is_rel, int32_t *off_words) {
    unsigned op2;
    if (!is_flowctrl(e, &op2)) return 0;
    uint32_t raw = cbits(e, 17, 0);            /* 18-bit PC field (SGX545) */
    *is_call = cbit(e, 41) ? 1 : 0;
    *is_cond = cbits(e, 58, 56) ? 1 : 0;
    *is_rel  = (op2 == 1u) ? 1 : 0;            /* br is pc-relative */
    *off_words = (op2 == 1u && (raw & 0x20000u)) ? (int32_t)raw - (1 << 18) : (int32_t)raw;
    return 1;
}


/* ==== operand kinds ========================================================
 * The USSE names a register by a 7-bit number plus bank bits, and the banks
 * read differently for destinations and sources. These printers were derived
 * by sweeping every number and bank value through refdisasm545 (limm and mov
 * destinations, mov/emitpix/phas sources): the same rules hold everywhere they
 * have been checked, and random_oracle_check.py keeps them honest per form. */

/* Bank 0: temporaries r0-r123, then the internal registers i0-i3. */
static int print_temp(char *out, size_t n, unsigned r) {
    if (r < 124) snprintf(out, n, "r%u", r);
    else         snprintf(out, n, "i%u", r - 124);
    return 1;
}

/* Indexed: [6:5] the bank (r, o, pa, sa), [4] il/ih, [3:0] the offset. */
static int print_indexed(char *out, size_t n, unsigned r) {
    static const char *const B[4] = { "r", "o", "pa", "sa" };
    snprintf(out, n, "%s[%s + #%u]", B[r >> 5], (r & 16) ? "ih" : "il", r & 15);
    return 1;
}

/* c0-c63 constants, then g0-g63 globals. */
static int print_const(char *out, size_t n, unsigned r) {
    if (r < 64) snprintf(out, n, "c%u", r);
    else        snprintf(out, n, "g%u", r - 64);
    return 1;
}

/* Destination: v = number[6:0] | bank[8:7] | ext[9]. */
static int k_dst_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    unsigned r = v & 0x7f;
    (void)k;
    switch (v >> 7) {
    case 0: return print_temp(out, n, r);
    case 1: snprintf(out, n, "o%u", r); return 1;
    case 2: snprintf(out, n, "pa%u", r); return 1;
    case 3: return print_indexed(out, n, r);
    case 4: snprintf(out, n, "sa%u", r); return 1;
    case 5: return print_const(out, n, r);
    case 6: snprintf(out, n, "i.%s%s", (r & 1) ? "l" : "", (r & 2) ? "h" : ""); return 1;
    default: snprintf(out, n, "i%u", r); return 1;
    }
}

/* Source 1 or 2: v = number[6:0] | bank[8:7] | ext[9]; arg is the format of
 * the 7-bit immediate (bank 2 with ext), which differs per instruction. */
static int k_src_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    unsigned r = v & 0x7f;
    switch (v >> 7) {
    case 0: return print_temp(out, n, r);
    case 1: snprintf(out, n, "o%u", r); return 1;
    case 2: snprintf(out, n, "pa%u", r); return 1;
    case 3: snprintf(out, n, "sa%u", r); return 1;
    case 4: return print_indexed(out, n, r);
    case 5: return print_const(out, n, r);
    case 6: snprintf(out, n, (const char *)k->arg, r); return 1;
    default: snprintf(out, n, "i%u", r); return 1;
    }
}

/* Source 0: v = number[6:0] | bank[7] | ext[8]. */
static int k_src0_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    static const char *const B[4] = { NULL, "pa", "o", "sa" };
    unsigned r = v & 0x7f;
    (void)k;
    if (!(v >> 7)) return print_temp(out, n, r);
    snprintf(out, n, "%s%u", B[v >> 7], r);
    return 1;
}

/* Rotated immediate of and/or/xor: v = mantissa[15:0] | rotate[20:16]. */
static uint32_t rol32(uint32_t x, unsigned r) {
    r &= 31u;
    return r ? (x << r) | (x >> (32u - r)) : x;
}

static int k_rotimm_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    snprintf(out, n, "0x%08X", rol32(v & 0xffff, v >> 16));
    return 1;
}

static int k_rotimm_parse(const usse_kind *k, const char *s, const char **end, uint32_t *v) {
    uint64_t x;
    (void)k;
    if (!usse_parse_uint(s, end, &x)) return 0;
    for (unsigned r = 0; r < 32; r++) {
        uint32_t m = rol32((uint32_t)x, (32u - r) & 31u);   /* ror by r */
        if (m <= 0xffff) { *v = m | r << 16; return 1; }
    }
    return 0;
}

/* br target: a signed 18-bit instruction offset (the SGX545 PC width),
 * printed by magnitude. */
static int k_br_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    if (v & 0x20000u) snprintf(out, n, "-#0x%08X", (1u << 18) - v);
    else              snprintf(out, n, "#0x%08X", v);
    return 1;
}

static int k_br_parse(const usse_kind *k, const char *s, const char **end, uint32_t *v) {
    int neg = *s == '-';
    uint64_t x;
    (void)k;
    s += neg;
    /* a number only: a label's index is not an offset from this instruction */
    if (*s++ != '#' || !isdigit((unsigned char)*s) || !usse_parse_uint(s, end, &x)) return 0;
    if (neg) {
        if (x < 1 || x > 0x20000) return 0;
        *v = (uint32_t)((1u << 18) - x);
    } else {
        if (x >= 0x20000) return 0;
        *v = (uint32_t)x;
    }
    return 1;
}

/* Load/store flags. Common part: skipinv, syncs, the 2-bit cache mode, and
 * enc[53] with the 4-bit count enc[47:44]: clear, a fetch of count+1
 * registers; set, a repeat count (count+1, nothing for 0). */
static const char *const LS_CACHE_T[4] = { "", ".bpcache", ".fcfill", ".bypassl1" };
static int core = 545;

void usse_set_core(int c) { core = c; }

/* v = enc[33] | enc[51] << 1 */
static const char *ls_cache(uint32_t v) {
    if (core == 540) v = (v & 1) << 1 | v >> 1;
    return LS_CACHE_T[v];
}

static size_t ls_count(char *out, size_t n, unsigned moe, unsigned cnt) {
    if (!moe) return (size_t)snprintf(out, n, ".fetch%u", cnt + 1);
    if (cnt)  return (size_t)snprintf(out, n, ".repeat%u", cnt + 1);
    out[0] = '\0';
    return 0;
}

/* v = skipinv | syncs << 1 | cache << 2 | moe << 4 | count << 5 */
static int k_ldflags_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    size_t at = (size_t)snprintf(out, n, "%s%s%s", (v & 1) ? ".skipinv" : "",
                                 (v >> 1 & 1) ? ".syncs" : "", ls_cache(v >> 2 & 3));
    ls_count(out + at, n - at, v >> 4 & 1, v >> 5 & 15);
    return 1;
}

/* v = skipinv | syncs << 1 | nosched << 2 | cache << 3 | noread << 5 |
 *     rangeenable << 6 | moe << 7 | count << 8 */
static int k_stflags_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    size_t at = (size_t)snprintf(out, n, "%s%s%s%s%s%s", (v & 1) ? ".skipinv" : "",
                                 (v >> 1 & 1) ? ".syncs" : "", (v >> 2 & 1) ? ".nosched" : "",
                                 ls_cache(v >> 3 & 3), (v >> 5 & 1) ? ".noread" : "",
                                 (v >> 6 & 1) ? ".rangeenable" : "");
    ls_count(out + at, n - at, v >> 7 & 1, v >> 8 & 15);
    return 1;
}

/* Load destination: v = number[6:0] | pa[7]; r124-r127 keep their names. */
static int k_lsdst_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    snprintf(out, n, "%s%u", (v >> 7) ? "pa" : "r", v & 0x7f);
    return 1;
}

static int k_src_print(const usse_kind *k, uint32_t v, char *out, size_t n);
static const usse_kind K_SRCD;

/* Load range: v = source-2 operand[9:0] | present[10]. */
static int k_range_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    if (!(v >> 10)) { out[0] = '\0'; return 1; }
    out[0] = ',';
    out[1] = ' ';
    return k_src_print(&K_SRCD, v & 0x3ff, out + 2, n - 2);
}

static const usse_kind K_LDFLAGS = { k_ldflags_print, NULL, NULL };
static const usse_kind K_STFLAGS = { k_stflags_print, NULL, NULL };
static const usse_kind K_LSDST   = { k_lsdst_print, NULL, NULL };
static const usse_kind K_RANGE   = { k_range_print, NULL, NULL };

/* Several one-bit flags, printed in field order: arg names each bit. */
static int k_flags_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    const char *const *name = k->arg;
    size_t at = 0;
    out[0] = '\0';
    for (unsigned i = 0; v >> i; i++)
        if (v >> i & 1) at += (size_t)snprintf(out + at, at < n ? n - at : 0, "%s", name[i]);
    return at < n;
}

static int k_temp_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    return print_temp(out, n, v);
}

static const char *const ALUFLAGS_T[] = { ".skipinv", ".syncs", ".nosched", ".end", ".partial" };
/* Branch flags: v = nosched | sync << 1 | nt << 2 | savelink << 3 | mon << 4.
 * With sync set, enc[44] picks .syncent, which prints after the others. */
static int k_brflags_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    int sync = v >> 1 & 1, nt = v >> 2 & 1;
    (void)k;
    snprintf(out, n, "%s%s%s%s%s", (v & 1) ? ".nosched" : "", sync && !nt ? ".synce" : "",
             (v >> 3 & 1) ? ".savelink" : "", (v >> 4 & 1) ? ".mon" : "",
             sync && nt ? ".syncent" : "");
    return 1;
}
static const usse_kind K_ALUFLAGS = { k_flags_print, NULL, ALUFLAGS_T };
static const usse_kind K_BRFLAGS = { k_brflags_print, NULL, NULL };
static const usse_kind K_TEMP = { k_temp_print, NULL, NULL };

/* Multiply flags: v = skipinv | nosched << 1 | end << 2 | repeat-1 << 3. */
static int k_mulflags_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    size_t at = (size_t)snprintf(out, n, "%s%s%s", (v & 1) ? ".skipinv" : "",
                                 (v & 2) ? ".nosched" : "", (v & 4) ? ".end" : "");
    if (v >> 3) snprintf(out + at, n - at, ".repeat%u", (v >> 3) + 1);
    return 1;
}
static const usse_kind K_MULFLAGS = { k_mulflags_print, NULL, NULL };
static const char *const LDRFLAGS_T[] = { ".skipinv", ".nosched" };
static const usse_kind K_LDRFLAGS = { k_flags_print, NULL, LDRFLAGS_T };
static const char *const TESTFLAGS_T[] = { ".skipinv", ".syncs", ".nosched", ".partial", ".onceonly" };
static const char *const TESTFLAGS4_T[] = { ".skipinv", ".syncs", ".nosched", ".onceonly" };
static const usse_kind K_TESTFLAGS = { k_flags_print, NULL, TESTFLAGS_T };
static const usse_kind K_TESTFLAGS4 = { k_flags_print, NULL, TESTFLAGS4_T };

/* Test type enc[43:36]: sign test [7:6] (t/n/p), all-or-any [3], zero test
 * [5:4] (t/z/nz) and the channel selection [2:0]. */
static int k_test_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    static const char *const SIGN[4] = { "t", "n", "p", NULL };
    static const char *const ZERO[4] = { "t", "z", "nz", NULL };
    static const char *const CHAN[8] = { "chan0", "chan1", "chan2", "chan3",
                                         "andall", "orall", "and02", "or02" };
    (void)k;
    if (!SIGN[v >> 6] || !ZERO[v >> 4 & 3]) return 0;
    snprintf(out, n, "test%s%s%s.%s", SIGN[v >> 6], (v & 8) ? "a" : "o", ZERO[v >> 4 & 3],
             CHAN[v & 7]);
    return 1;
}
static const usse_kind K_TEST = { k_test_print, NULL, NULL };
static const usse_kind K_DST  = { k_dst_print, NULL, NULL };
static const usse_kind K_SRCH = { k_src_print, NULL, "#0x%08X" };
static const usse_kind K_SRCD = { k_src_print, NULL, "#%u" };
static const usse_kind K_SRC0 = { k_src0_print, NULL, NULL };
static const usse_kind K_ROT  = { k_rotimm_print, k_rotimm_parse, NULL };
static const usse_kind K_BR   = { k_br_print, k_br_parse, NULL };

static const usse_num N_DEC = { "%u", 1, 0 }, N_HEX = { "0x%08X", 1, 0 };
static const usse_num N_X4 = { "%u", 4, 0 };
static const usse_kind K_DEC = { usse_k_num_print, usse_k_num_parse, &N_DEC };
static const usse_kind K_HEX = { usse_k_num_print, usse_k_num_parse, &N_HEX };
static const usse_kind K_X4  = { usse_k_num_print, usse_k_num_parse, &N_X4 };

#define ENUM(name, n, ...) \
    static const char *const name##_T[n] = { __VA_ARGS__ }; \
    static const usse_kind name = { usse_k_enum_print, NULL, name##_T }

/* Predicates. The full set is what refdisasm545 prints for the 3-bit field of
 * limm and mov; the narrower sets are the values the older, corpus-derived
 * forms have been checked with (an unchecked value is left undecoded). */
ENUM(PRED_ALL, 8, "", "p0 ", "p1 ", "p2 ", "p3 ", "!p0 ", "!p1 ", "Pn ");
ENUM(PRED_MUL, 4, "", "p0 ", "p1 ", "!p0 ");

ENUM(F_SKIPINV, 2, "", ".skipinv");
ENUM(F_NOSCHED, 2, "", ".nosched");
ENUM(F_SYNCS, 2, "", ".syncs");
ENUM(F_END, 2, "", ".end");
ENUM(F_FREEP, 2, "", ".freep");
ENUM(F_TOG, 2, "", ".tog");
ENUM(F_TRIGGER, 2, "", ".trigger");
ENUM(F_INV, 2, "", "~");
ENUM(F_SIGN, 2, "+", "-");
ENUM(SU, 2, "u", "s");
ENUM(SIGNSAT, 4, "u", "usat", "s", "ssat");                 /* enc[42] sat, enc[43] s */
ENUM(RS, 8, "", ".rs1", ".rs2", ".rs3", ".rs4", ".rs5", ".rs6", ".rs7");
ENUM(F_ABS, 2, "", ".abs");
ENUM(F_NEG, 2, "", ".neg");
ENUM(LOWHIGH, 2, "low", "high");
ENUM(OP_BW_ANDXOR, 4, "and", "or", "xor", NULL);   /* enc[35], enc[59] */
ENUM(OP_BW_SHIFT, 4, "shl", "rol", "shr", "asr");
/* load/store: v = data type[1:0] | address mode[3:2] */
ENUM(AMDT, 16, "ad", "aw", "ab", NULL, "ld", "lw", "lb", NULL, "td", "tw", "tb", NULL,
     NULL, NULL, NULL, NULL);
ENUM(IMODE_PLAIN, 4, "", NULL, NULL, "");                /* enc[41:40]: 0 and 3 */
ENUM(F_SIGN2, 2, "++", "--");

/* Test-group operations enc[19:14], by operand count and immediate style. */
ENUM(TESTOP_2, 64, "fadd", NULL, NULL, "fsubflr", NULL, NULL, NULL, NULL,
     "fdp", "fmin", "fmax", "fdsx", "fdsy", "fmul", "fsub", NULL,
     NULL, NULL, NULL, NULL, NULL, NULL, "iadd16", "isub16",
     "imul16", "iaddu16", "isubu16", "imulu16", "iadd32", "iaddu32", NULL, NULL,
     "iadd8", "isub8", "iaddu8", "isubu8", "imul8", "fpmul8", "imulu8", "fpadd8",
     "fpsub8");
ENUM(TESTOP_1, 64, [4] = "frcp", [5] = "frsq", [6] = "flog", [7] = "fexp");
ENUM(TESTOP_BW, 64, [48] = "and", [49] = "or", [50] = "xor", [51] = "shl", [52] = "shr",
     [53] = "rol", [55] = "asr");
ENUM(F_WRITE, 2, "!", "");

/* mov destination write mask (enc[47:44], wzyx): x alone prints nothing. */
ENUM(WMASK, 16, ".", "", ".y", ".xy", ".z", ".xz", ".yz", ".xyz",
     ".w", ".xw", ".yw", ".xyw", ".zw", ".xzw", ".yzw", ".xyzw");
/* ... or, with enc[53] set, the repeat count minus one. */
ENUM(REPEAT, 16, "", ".repeat2", ".repeat3", ".repeat4", ".repeat5", ".repeat6",
     ".repeat7", ".repeat8", ".repeat9", ".repeat10", ".repeat11", ".repeat12",
     ".repeat13", ".repeat14", ".repeat15", ".repeat16");

/* phas */
ENUM(PHAS_RATE, 4, "pixel", "selective", "sample", NULL);
ENUM(PHAS_WAIT, 8, "none", "pt", "vcull", NULL, NULL, NULL, NULL, "end");
ENUM(PHAS_MODE, 2, "parallel", "perinstance");

/* ==== the form table ===================================================== */

#define B(n)      (1ull << (n))
#define M(hi, lo) ((~0ull >> (63 - (hi))) & (~0ull << (lo)))
#define CLS(c)    ((uint64_t)(c) << 59)
#define CLSM      M(63, 59)
#define C(lo, w)  { lo, w }
#define FLD(k, ...) { &k, { __VA_ARGS__ } }
#define EXACT(w, text) { text, ~0ull, w, { { 0 } } }
#define REJECT(w)      { NULL, ~0ull, w, { { 0 } } }

/* The closed toolchain writes an unused source 2 as immediate 0 (bank 2 with
 * the extension bit): every class-5 mov and every load without a range
 * operand of the ukernels and the transfer programs does. */
#define UNUSED_SRC2 (B(48) | B(29))

/* Shared operand fields. */
#define F_DST   FLD(K_DST, C(21, 7), C(32, 2), C(51, 1))
#define F_SRC1H FLD(K_SRCH, C(7, 7), C(30, 2), C(49, 1))
#define F_SRC1D FLD(K_SRCD, C(7, 7), C(30, 2), C(49, 1))
#define F_SRC2D FLD(K_SRCD, C(0, 7), C(28, 2), C(48, 1))
#define F_SRC0  FLD(K_SRC0, C(14, 7), C(34, 1), C(51, 1))
#define F_LIMM  FLD(K_HEX, C(0, 21), C(36, 5), C(44, 6))
#define F_ALUFLAGS FLD(K_ALUFLAGS, C(55, 1), C(52, 1), C(54, 1), C(50, 1), C(34, 1))
#define F_BRFLAGS  FLD(K_BRFLAGS, C(43, 1), C(55, 1), C(44, 1), C(41, 1), C(42, 1))
#define F_LSDST   FLD(K_LSDST, C(21, 7), C(39, 1))
#define F_TESTFLAGS FLD(K_TESTFLAGS, C(55, 1), C(52, 1), C(54, 1), C(50, 1), C(53, 1))
#define F_TESTFLAGS4 FLD(K_TESTFLAGS4, C(55, 1), C(52, 1), C(54, 1), C(53, 1))
#define F_ROT   FLD(K_ROT, C(0, 7), C(14, 6), C(20, 1), C(36, 2), C(38, 5))

/* emit: the opcode bits around end (50), src0 ext (51) and the sideband */
#define EMIT_M (M(63, 56) | B(53) | B(52) | M(47, 46) | B(40))


/* The instruction families, one file each (forms/README.md): their kinds and
 * field macros here, their entries in the table below. */
#define USSE_PART_DEFS
#include "forms/float.inc"
#include "forms/memctl.inc"
#include "forms/intpack.inc"
#include "forms/misc.inc"
#undef USSE_PART_DEFS

/* A form leaves dflt out unless it needs one (see usse_form.h). */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
const usse_form usse_forms[] = {
    /* ---- class 31 moves: limm and pclink -------------------------------- */
    { "{0}mov{1}{2}{3} {4}, #{5}", M(63, 56) | B(53) | B(52), 0xFCull << 56 | B(53),
      { FLD(PRED_ALL, C(41, 3)), FLD(F_SKIPINV, C(55, 1)), FLD(F_NOSCHED, C(54, 1)),
        FLD(F_END, C(50, 1)), F_DST, F_LIMM } },
    /* ---- class 5 mov ----------------------------------------------------- */
    { "{0}mov{1}{2}{3}{4} {5}{6}, {7}", CLSM | M(42, 40) | B(53), CLS(5),
      { FLD(PRED_ALL, C(56, 3)), FLD(F_SKIPINV, C(55, 1)), FLD(F_SYNCS, C(52, 1)),
        FLD(F_NOSCHED, C(43, 1)), FLD(F_END, C(50, 1)), F_DST, FLD(WMASK, C(44, 4)),
        F_SRC1H }, UNUSED_SRC2 },
    { "{0}mov{1}{2}{3}{4}{5} {6}, {7}", CLSM | M(42, 40) | B(53), CLS(5) | B(53),
      { FLD(PRED_ALL, C(56, 3)), FLD(F_SKIPINV, C(55, 1)), FLD(F_SYNCS, C(52, 1)),
        FLD(F_NOSCHED, C(43, 1)), FLD(F_END, C(50, 1)), FLD(REPEAT, C(44, 4)), F_DST,
        F_SRC1H }, UNUSED_SRC2 },
    { "mov pclink, {0}", ~M(13, 7), 0xF80000C000000000ull, { FLD(K_TEMP, C(7, 7)) } },
    { "mov {0}, pclink", ~M(27, 21), 0xF800010000000000ull, { FLD(K_TEMP, C(21, 7)) } },

    /* ---- class 31 specials ---------------------------------------------- */
    { "nop{0}{1}{2}{3}{4}", M(63, 56) | M(54, 51) | M(49, 44) | M(42, 38),
      0xF800014000000000ull,
      { FLD(F_SYNCS, C(55, 1)), FLD(F_NOSCHED, C(43, 1)), FLD(F_END, C(50, 1)),
        FLD(F_TOG, C(0, 1)), FLD(F_TRIGGER, C(1, 1)) } },
    { "idf drc{0}, bif", ~B(32), 0xF820000000000000ull, { FLD(K_DEC, C(32, 1)) } },
    { "wdf drc{0}", ~B(32), 0xF920000000000000ull, { FLD(K_DEC, C(32, 1)) } },
    { "phas{0} #{1}, #{2}, {3}, {4}, {5}", M(63, 50) & ~B(51), 0xFA44000000000000ull,
      { FLD(F_END, C(51, 1)), FLD(K_DEC, C(0, 18)), FLD(K_X4, C(32, 8)),
        FLD(PHAS_RATE, C(43, 2)), FLD(PHAS_WAIT, C(40, 3)), FLD(PHAS_MODE, C(45, 1)) } },
    { "phas{0}{1} {2}, {3}", M(63, 50) & ~B(51), 0xFA40000000000000ull,
      { FLD(F_NOSCHED, C(43, 1)), FLD(F_END, C(51, 1)), F_SRC1D, F_SRC2D } },
    { "emitpix1{0}{1}{2} #{3} /* incp */, {4}, {5}",
      EMIT_M, 0xFB20000000000000ull | B(40),
      { FLD(F_NOSCHED, C(43, 1)), FLD(F_END, C(50, 1)), FLD(F_FREEP, C(21, 1)),
        FLD(K_DEC, C(32, 2), C(41, 1)), F_SRC0, F_SRC1D } },
    { "emitpix2{0}{1}{2} #{3} /* incp */, {4}, {5}, {6}, #{7}",
      EMIT_M, 0xFB20000000000000ull,
      { FLD(F_NOSCHED, C(43, 1)), FLD(F_END, C(50, 1)), FLD(F_FREEP, C(21, 1)),
        FLD(K_DEC, C(32, 2), C(41, 1)), F_SRC0, F_SRC1D, F_SRC2D,
        FLD(K_HEX, C(22, 6), C(35, 6), C(54, 2)) } },

    /* ---- class 31 flow control: ba / br / bexception ---------------------- */
    { "{0}ba{1} #{2}", CLSM | M(54, 51) | M(40, 38), CLS(31),
      { FLD(PRED_ALL, C(56, 3)), F_BRFLAGS, FLD(K_HEX, C(0, 18)) } },
    { "{0}br{1} {2}", CLSM | M(54, 51) | M(40, 38), CLS(31) | B(38),
      { FLD(PRED_ALL, C(56, 3)), F_BRFLAGS, FLD(K_BR, C(0, 18)) } },
    { "bexception{0}", CLSM | M(54, 51) | M(40, 39), CLS(31) | B(51),
      { FLD(F_NOSCHED, C(43, 1)) } },

    /* ---- the bitwise group: classes 10-13 --------------------------------- *
     * and/or (10), xor (11), shl/rol (12), shr/asr (13): one layout, with
     * the operation in enc[35] and the class's low bit. Source 2 is a rotated
     * 16-bit immediate when its bank reads as an immediate. With enc[53] set,
     * the destination mask field is a repeat count instead. */
#define BITWISE(hi, ops, pat, m, v, f4, src2) \
    { pat, M(63, 60) | B(53) | (m), (uint64_t)(hi) << 60 | (v), \
      { FLD(PRED_ALL, C(56, 3)), FLD(ops, C(35, 1), C(59, 1)), F_ALUFLAGS, F_DST, f4, \
        F_SRC1D, FLD(F_INV, C(43, 1)), src2 } }
#define BITWISE4(hi, ops) \
    BITWISE(hi, ops, "{0}{1}{2} {3}{4}, {5}, {6}#{7}", B(48) | M(29, 28), B(48) | B(29), \
            FLD(WMASK, C(44, 4)), F_ROT), \
    BITWISE(hi, ops, "{0}{1}{2}{4} {3}, {5}, {6}#{7}", B(48) | M(29, 28), \
            B(53) | B(48) | B(29), FLD(REPEAT, C(44, 4)), F_ROT), \
    BITWISE(hi, ops, "{0}{1}{2} {3}{4}, {5}, {6}{7}", 0, 0, FLD(WMASK, C(44, 4)), F_SRC2D), \
    BITWISE(hi, ops, "{0}{1}{2}{4} {3}, {5}, {6}{7}", 0, B(53), FLD(REPEAT, C(44, 4)), F_SRC2D)
    BITWISE4(5, OP_BW_ANDXOR),
    BITWISE4(6, OP_BW_SHIFT),
#undef BITWISE4
#undef BITWISE

    /* ---- the test group: class 9 ------------------------------------------- *
     * An ALU operation (enc[19:14]) whose result is tested into predicate
     * p<enc[35:34]>; enc[20] clear disables the register write ("!" before
     * the destination). One-source operations read source 1. The bitwise
     * operations print a source-1 immediate in hex, the others in decimal.
     * Only they read enc[50] as .partial; the others are left with it clear. */
#define TEST(ops, m, flags, src, s1, ...) \
    { "{0}{1}{2}.{3} {4}{5}{6}, p{7}, {8}" src, CLSM | (m), CLS(9), \
      { FLD(PRED_ALL, C(56, 3)), FLD(ops, C(14, 6)), flags, FLD(K_TEST, C(36, 8)), \
        FLD(F_WRITE, C(20, 1)), F_DST, FLD(WMASK, C(44, 4)), FLD(K_DEC, C(34, 2)), s1, \
        __VA_ARGS__ } }
    TEST(TESTOP_BW, 0, F_TESTFLAGS, ", {9}", F_SRC1H, F_SRC2D),
    TEST(TESTOP_2, B(50), F_TESTFLAGS4, ", {9}", F_SRC1D, F_SRC2D),
    TEST(TESTOP_1, B(50), F_TESTFLAGS4, "", F_SRC1D),
#undef TEST

    /* ---- integer multiply-add: imae (21), ima16 (20), ima32 (26) ---------- *
     * Destination, a source-0 operand (r or pa, plus o and sa for ima32) and
     * the usual sources 1 and 2. Source and carry formats other than the
     * plain ones (imae u32, ima16 u16, no carry or extra operand) are left
     * undecoded: those bits are fixed to their plain values. */
#define F_MULFLAGS FLD(K_MULFLAGS, C(55, 1), C(54, 1), C(50, 1), C(44, 3))
#define F_MSRC0    FLD(K_SRC0, C(14, 7), C(34, 1))
    { "{0}imae{1}.{2}{3} {4}, {5}.{6}, {7}.{8}, {9}, u32",
      CLSM | B(47) | M(41, 38), CLS(21) | B(39),
      { FLD(PRED_MUL, C(57, 2)), F_MULFLAGS, FLD(SIGNSAT, C(42, 1), C(43, 1)),
        FLD(RS, C(35, 3)), F_DST, F_MSRC0, FLD(LOWHIGH, C(56, 1)), F_SRC1D,
        FLD(LOWHIGH, C(53, 1)), F_SRC2D } },
    { "{0}ima16{1}.{2}{3} {4}{5}, {6}, {7}, {8}{9}, u16, u16",
      CLSM | B(47) | M(41, 37), CLS(20),
      { FLD(PRED_MUL, C(57, 2)), F_MULFLAGS, FLD(SIGNSAT, C(42, 1), C(43, 1)),
        FLD(RS, C(35, 2)), F_DST, FLD(F_ABS, C(56, 1)), F_MSRC0, F_SRC1D, F_SRC2D,
        FLD(F_NEG, C(53, 1)) } },
    { "{0}ima32{1}.{2} {3}, {4}, {5}{6}, {7}{8}", CLSM | M(53, 52) | M(43, 42) | B(38),
      CLS(26),
      { FLD(PRED_ALL, C(56, 3)), F_MULFLAGS, FLD(SU, C(41, 1)), F_DST,
        FLD(K_SRC0, C(14, 7), C(34, 1), C(47, 1)), F_SRC1D, FLD(F_NEG, C(40, 1)), F_SRC2D,
        FLD(F_NEG, C(39, 1)) } },
#undef F_MSRC0

    /* ---- load / store (classes 29, 30) ------------------------------------ *
     * ld/st + address mode (a/l/t) + data type (d/w/b). The base is a source-0
     * operand and the offset a source-1 operand; enc[41:40] picks plain
     * (+/-), pre-increment (++/--) or post-increment (++/-- after it). A load
     * with enc[38] set names a range operand (source 2).
     *
     *
     * The cache mode is enc[33] | enc[51] << 1 on the SGX545 (.bpcache,
     * .fcfill, .bypassl1) and the two bits are swapped on the SGX540, whose
     * corpus oracle_check.py also checks: see usse_set_core(). */
#define LDST(cls, pat, m, v, flags, ...) \
    { pat, CLSM | (m), CLS(cls) | (v), { FLD(PRED_ALL, C(56, 3)), \
      FLD(AMDT, C(36, 2), C(42, 2)), flags, __VA_ARGS__ }, UNUSED_SRC2 }
#define F_LDFLAGS FLD(K_LDFLAGS, C(55, 1), C(52, 1), C(33, 1), C(51, 1), C(53, 1), C(44, 4))
#define F_STFLAGS FLD(K_STFLAGS, C(55, 1), C(52, 1), C(54, 1), C(33, 1), C(51, 1), C(32, 1), \
                      C(38, 1), C(53, 1), C(44, 4))
#define F_BASE    FLD(K_SRC0, C(14, 7), C(34, 1), C(50, 1))
#define F_RANGE   FLD(K_RANGE, C(0, 7), C(28, 2), C(48, 1), C(38, 1))
#define F_DRC     FLD(K_DEC, C(32, 1))
    LDST(29, "{0}ld{1}{2} {3}, [{4},{5}{6}{7}]{8}, drc{9}", B(54), 0, F_LDFLAGS, F_LSDST,
         F_BASE, FLD(IMODE_PLAIN, C(40, 2)), FLD(F_SIGN, C(35, 1)), F_SRC1D, F_RANGE, F_DRC),
    LDST(29, "{0}ld{1}{2} {3}, [{4},{5}{6}]{7}, drc{8}", B(54) | M(41, 40), B(40), F_LDFLAGS,
         F_LSDST, F_BASE, FLD(F_SIGN2, C(35, 1)), F_SRC1D, F_RANGE, F_DRC),
    LDST(29, "{0}ld{1}{2} {3}, [{4},{6}{5}]{7}, drc{8}", B(54) | M(41, 40), B(41), F_LDFLAGS,
         F_LSDST, F_BASE, FLD(F_SIGN2, C(35, 1)), F_SRC1D, F_RANGE, F_DRC),
    LDST(30, "{0}st{1}{2} [{3},{4}{5}{6}], {7}", 0, 0, F_STFLAGS,
         F_BASE, FLD(IMODE_PLAIN, C(40, 2)), FLD(F_SIGN, C(35, 1)), F_SRC1D, F_SRC2D),
    LDST(30, "{0}st{1}{2} [{3},{4}{5}], {6}", M(41, 40), B(40), F_STFLAGS,
         F_BASE, FLD(F_SIGN2, C(35, 1)), F_SRC1D, F_SRC2D),
    LDST(30, "{0}st{1}{2} [{3},{5}{4}], {6}", M(41, 40), B(41), F_STFLAGS,
         F_BASE, FLD(F_SIGN2, C(35, 1)), F_SRC1D, F_SRC2D),
#undef LDST

    /* ---- class 31 control: ldr / str / smlsi / emitpds -------------------- */
    /* ldr/str: a register index in source 2 (an immediate takes 14 bits) */
#define LDST_R(m, v) M(63, 56) | M(54, 51) | (m), 0xFE20000000000000ull | (v)
#define F_LDRFLAGS FLD(K_LDRFLAGS, C(55, 1), C(43, 1))
#define F_IDX14    FLD(K_DEC, C(0, 7), C(14, 7))
#define S2_IMM     B(48) | M(29, 28), B(48) | B(29)
    { "ldr{0} {1}, #{2}, drc{3}", LDST_R(B(48) | M(29, 28), B(48) | B(29)),
      { F_LDRFLAGS, F_LSDST, F_IDX14, FLD(K_DEC, C(32, 2)) } },
    { "ldr{0} {1}, {2}, drc{3}", LDST_R(0, 0),
      { F_LDRFLAGS, F_LSDST, F_SRC2D, FLD(K_DEC, C(32, 2)) } },
    { "str{0} #{1}, {2}", LDST_R(B(48) | M(29, 28), B(51) | B(48) | B(29)),
      { F_LDRFLAGS, F_IDX14, F_SRC1D } },
    { "str{0} {1}, {2}", LDST_R(0, B(51)), { F_LDRFLAGS, F_SRC2D, F_SRC1D } },
#undef S2_IMM
#undef F_IDX14
#undef LDST_R

    /* ---- the instruction families (forms/) --------------------------------- */
#define USSE_PART_FORMS
#include "forms/float.inc"
#include "forms/memctl.inc"
#include "forms/intpack.inc"
#include "forms/misc.inc"
#undef USSE_PART_FORMS

};
#pragma GCC diagnostic pop
const size_t usse_nforms = sizeof usse_forms / sizeof usse_forms[0];
const usse_table usse_table_main = { usse_forms, sizeof usse_forms / sizeof usse_forms[0], NULL };

void usse_decode(uint64_t e, uint32_t pc, usse_insn *o) {
    (void)pc;
    o->enc = e;
    if (usse_form_decode(e, o->text, sizeof o->text)) { o->valid = 1; return; }
    /* Not yet decoded: readable class hint (invalid -> regression ignores it). */
    const char *base = usse_class_name((unsigned)(e >> 59));
    o->valid = 0;
    if (base) snprintf(o->text, sizeof o->text, "%-8s; TODO operands", base);
    else      snprintf(o->text, sizeof o->text, ".long 0x%016llX", (unsigned long long)e);
}
