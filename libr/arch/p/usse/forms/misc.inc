/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2026 Josep Torra */
/* forms/misc.inc — the misc family of USSE forms, included twice by usse.c:
 * with USSE_PART_DEFS for this family's operand kinds and field macros (name
 * them with a family prefix), and with USSE_PART_FORMS for its table entries.
 * Clean-room like the rest of the table: layouts come from probing the
 * refdisasm545 binary and are held to 0 wrong by random_oracle_check.py. */
#ifdef USSE_PART_DEFS
#include <string.h>

/* ---- class 5: movc / movmsk --------------------------------------------- *
 * enc[42:40] is the class-5 type: 0 the plain mov (usse.c), 1-5 movc with
 * data type i8, i16, i32, flt, i10, 6 movmsk and 7 movmsk.smsk (which adds
 * a source). enc[39] | enc[54] << 1 is the movc test and the movmsk format;
 * u8 is the one movmsk format printed after .smsk and the repeat count. */
ENUM(MSC_MOVC_T, 8, NULL, ".i8", ".i16", ".i32", ".flt", ".i10", NULL, NULL);
ENUM(MSC_MOVC_TR, 8, NULL, NULL, ".i16", ".i32", ".flt", ".i10", NULL, NULL);
ENUM(MSC_MOVC_TEST, 4, ".tz", ".tnz", ".tn", ".tp|z");
ENUM(MSC_MOVMSK_F, 4, ".mask", NULL, ".flt16", ".flt");
/* the component of movmsk's last source, enc[38:37] */
ENUM(MSC_COMP, 4, "", ".1", ".2", ".3");

#define MSC_F_SRC0 FLD(K_SRC0, C(14, 7), C(34, 1))
#define MSC_F_SRC2 F_SRC2D
static const char *const MSC_C5FLAGS_T[] = { ".skipinv", ".syncs", ".nosched", ".end" };
static const usse_kind K_MSC_C5FLAGS = { k_flags_print, NULL, MSC_C5FLAGS_T };
#define MSC_C5FLAGS FLD(K_MSC_C5FLAGS, C(55, 1), C(52, 1), C(43, 1), C(50, 1))

/* ---- classes 9 and 15: the test group ---------------------------------- *
 * Class 9 tests the result into a predicate, class 15 into a mask (b, w or
 * d, enc[37:36]; enc[38] and the predicate number enc[35:34] are ignored).
 * usse.c decodes class 9 with enc[50] clear and the bitwise operations; the
 * forms here add enc[50] set for the others: .sat on the 8-bit integer
 * operations, nothing on the 16- and 32-bit ones, and a per-operand format on
 * the float operations: bit 6 of the operand number selects .flt16 (number
 * [5:1], component [0], printed .2 when set) or, for fpmul8/fpadd8/fpsub8,
 * .c10 (number [5:0]). Constants and immediates keep their 7-bit numbers. */

/* Class 15 test: v = mask type[1:0] (enc[37:36]) | rest[6:2] (enc[43:39]:
 * all-or-any, zero test, sign test, as in K_TEST). */
static int k_msc_testmsk_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    static const char *const SIGN[4] = { "t", "n", "p", NULL };
    static const char *const ZERO[4] = { "t", "z", "nz", NULL };
    static const char *const MSK[4] = { "bmsk", "wmsk", "dmsk", NULL };
    (void)k;
    if (!SIGN[v >> 5] || !ZERO[v >> 3 & 3] || !MSK[v & 3]) return 0;
    snprintf(out, n, "test%s%s%s.%s", SIGN[v >> 5], (v & 4) ? "a" : "o", ZERO[v >> 3 & 3],
             MSK[v & 3]);
    return 1;
}
static const usse_kind K_MSC_TESTMSK = { k_msc_testmsk_print, NULL, NULL };

/* A float operand with enc[50] set: v = number[6:0] | bank[8:7] | ext[9],
 * banks numbered as for K_DST (dst) or K_SRCD. Temporaries past r59 (r29
 * for .flt16) print as i0-i3; an indexed operand takes a 6-bit index
 * ([5:4] bank, [3] il/ih, [2:0] offset) and no component. */
typedef struct { uint8_t dst, mode; } msc_fop;
enum { MSC_FLT16, MSC_FLT16_0, MSC_C10 };   /* MSC_FLT16_0: a source prints .0 */
static int k_msc_fop_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    static const char *const SB[8] = { "r", "o", "pa", "sa", "[", "c", "#", "i" };
    static const char *const DB[8] = { "r", "o", "pa", "[", "sa", "c", "i.", "i" };
    static const char *const IB[4] = { "r", "o", "pa", "sa" };
    const msc_fop *a = k->arg;
    const char *b = (a->dst ? DB : SB)[v >> 7];
    unsigned r = v & 0x7f, fmt = r >> 6, n6 = r & 63, h = fmt && a->mode != MSC_C10;
    unsigned num = h ? n6 >> 1 : n6, comp = h && (n6 & 1) && b[0] != '[', lim = h ? 30 : 60;
    int at;
    if (b[0] == 'c') return print_const(out, n, r);
    if (b[0] == '#') { snprintf(out, n, "#%u", r); return 1; }
    if (b[1] == '.') return k_dst_print(&K_DST, 6u << 7 | r, out, n);
    if (b[0] == '[')
        at = snprintf(out, n, "%s[%s + #%u]", IB[n6 >> 4], (n6 & 8) ? "ih" : "il", n6 & 7);
    else if (b[0] == 'r' && num >= lim)
        at = snprintf(out, n, "i%u", num - lim);
    else
        at = snprintf(out, n, "%s%u", b, num);
    if (!fmt || at < 0 || (size_t)at >= n) return 1;
    if (a->mode == MSC_C10) snprintf(out + at, n - (size_t)at, ".c10");
    else snprintf(out + at, n - (size_t)at, ".flt16%s",
                  comp ? ".2" : (!a->dst && a->mode == MSC_FLT16_0) ? ".0" : "");
    return 1;
}
static const msc_fop MSC_FOP_A[] = { { 1, MSC_FLT16 }, { 0, MSC_FLT16 }, { 0, MSC_FLT16_0 },
                                     { 1, MSC_C10 }, { 0, MSC_C10 } };
static const usse_kind K_MSC_FDST = { k_msc_fop_print, NULL, &MSC_FOP_A[0] };
static const usse_kind K_MSC_FSRC = { k_msc_fop_print, NULL, &MSC_FOP_A[1] };
static const usse_kind K_MSC_FSRC0 = { k_msc_fop_print, NULL, &MSC_FOP_A[2] };
static const usse_kind K_MSC_CDST = { k_msc_fop_print, NULL, &MSC_FOP_A[3] };
static const usse_kind K_MSC_CSRC = { k_msc_fop_print, NULL, &MSC_FOP_A[4] };
#define MSC_DST(k)  FLD(k, C(21, 7), C(32, 2), C(51, 1))
#define MSC_SRC1(k) FLD(k, C(7, 7), C(30, 2), C(49, 1))
#define MSC_SRC2(k) FLD(k, C(0, 7), C(28, 2), C(48, 1))

/* Test-group operations enc[19:14], grouped by how they read enc[50] set. */
ENUM(MSC_TOP_I, 64, [22] = "iadd16", [23] = "isub16", [24] = "imul16", [25] = "iaddu16",
     [26] = "isubu16", [27] = "imulu16", [28] = "iadd32", [29] = "iaddu32");
ENUM(MSC_TOP_I8, 64, [32] = "iadd8", [33] = "isub8", [34] = "iaddu8", [35] = "isubu8",
     [36] = "imul8", [38] = "imulu8");
ENUM(MSC_TOP_F2, 64, [0] = "fadd", [3] = "fsubflr", [13] = "fmul", [14] = "fsub");
ENUM(MSC_TOP_F2Z, 64, [8] = "fdp", [9] = "fmin", [10] = "fmax", [11] = "fdsx", [12] = "fdsy");
ENUM(MSC_TOP_C10, 64, [37] = "fpmul8", [39] = "fpadd8", [40] = "fpsub8");

/* ---- classes 22 and 23: adif, adifsum, bilin, firv, firh ---------------- *
 * Class 22 selects the operation with enc[53:52] (0 adif, or adifsum with
 * enc[38]; 2 bilin; 3 firv); class 23 is firh. All take the multiply flags
 * (skipinv, nosched, end, repeat count) and a 2-bit predicate enc[58:57].
 * firv and firh read their second operand's number from enc[20:14] with
 * source 1's bank. */
ENUM(MSC_FMT8, 4, "u8", "s8", "o8", NULL);
ENUM(MSC_BILIN_L, 2, "planar", "interleaved");
ENUM(MSC_BILIN_SEL, 4, "src01, dst01", "src23, dst01", "src01, dst23", "src23, dst23");
ENUM(MSC_RND, 2, "", ", rnd");
static const char *const MSC_FIRV_T[] = { ", +src2.2", ", iadd", ", scale" };
static const usse_kind K_MSC_FIRV = { k_flags_print, NULL, MSC_FIRV_T };

/* firh: v = edge mode[1:0] | filter coefficient set[4:2] */
static int k_msc_firh_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    static const char *const EDGE[4] = { "rep", "msc", "mdc", "reserved" };
    (void)k;
    snprintf(out, n, "%s, fcs%u", EDGE[v & 3], v >> 2);
    return 1;
}
static const usse_kind K_MSC_FIRH = { k_msc_firh_print, NULL, NULL };

/* A 5-bit two's-complement number. */
static int k_msc_s5_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    snprintf(out, n, "%d", (int)v - (v & 16 ? 32 : 0));
    return 1;
}
static const usse_kind K_MSC_S5 = { k_msc_s5_print, NULL, NULL };

/* firv/firh operands 2 and 3: v = number[6:0] (enc[20:14]) | source-1
 * number[13:7] | the shared bank[16:14], printed as two K_SRCD operands.
 * One field, so that the assembler cannot pick two different banks; it
 * parses the pair by searching the bank and both numbers. */
static int k_msc_pair_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    uint32_t bank = v >> 14 << 7;
    size_t at;
    (void)k;
    k_src_print(&K_SRCD, bank | (v & 0x7f), out, n);
    at = strlen(out);
    if (at + 2 >= n) return 0;
    out[at++] = ',';
    out[at++] = ' ';
    return k_src_print(&K_SRCD, bank | (v >> 7 & 0x7f), out + at, n - at);
}

/* Match printed operand x at s, blanks in either side being free; the
 * operand must end at a comma or the end. Return the end of the match. */
static const char *msc_operand(const char *x, const char *s) {
    for (;;) {
        while (*x == ' ') x++;
        while (*s == ' ' || *s == '\t') s++;
        if (!*x) return (*s == ',' || !*s) ? s : NULL;
        if (*s++ != *x++) return NULL;
    }
}

static int k_msc_pair_parse(const usse_kind *k, const char *s, const char **end, uint32_t *v) {
    char buf[32];
    (void)k;
    for (uint32_t bank = 0; bank < 8; bank++)
        for (uint32_t a = 0; a < 128; a++) {
            const char *q;
            k_src_print(&K_SRCD, bank << 7 | a, buf, sizeof buf);
            if (!(q = msc_operand(buf, s)) || *q != ',') continue;
            for (uint32_t b = 0; b < 128; b++) {
                const char *r;
                k_src_print(&K_SRCD, bank << 7 | b, buf, sizeof buf);
                if ((r = msc_operand(buf, q + 1))) {
                    *end = r;
                    *v = a | b << 7 | bank << 14;
                    return 1;
                }
            }
        }
    return 0;
}
static const usse_kind K_MSC_PAIR = { k_msc_pair_print, k_msc_pair_parse, NULL };

#define MSC_MULFLAGS(rw) FLD(K_MULFLAGS, C(55, 1), C(54, 1), C(50, 1), C(44, rw))
#define MSC_F_PAIR FLD(K_MSC_PAIR, C(14, 7), C(7, 7), C(30, 2), C(49, 1))

#endif
#ifdef USSE_PART_FORMS
    /* ---- class 5: movc, movmsk --------------------------------------------- */
    { "{0}movc{1}{2}{3} {4}{5}, {6}, {7}, {8}", CLSM | B(53), CLS(5),
      { FLD(PRED_ALL, C(56, 3)), MSC_C5FLAGS, FLD(MSC_MOVC_T, C(40, 3)),
        FLD(MSC_MOVC_TEST, C(39, 1), C(54, 1)), F_DST, FLD(WMASK, C(44, 4)), MSC_F_SRC0,
        F_SRC1D, MSC_F_SRC2 } },
    /* with a repeat count: it prints before i8 and after the other types */
    { "{0}movc{1}{2}{3}{4} {5}, {6}, {7}, {8}", CLSM | B(53), CLS(5) | B(53),
      { FLD(PRED_ALL, C(56, 3)), MSC_C5FLAGS, FLD(MSC_MOVC_TR, C(40, 3)),
        FLD(REPEAT, C(44, 4)), FLD(MSC_MOVC_TEST, C(39, 1), C(54, 1)), F_DST,
        MSC_F_SRC0, F_SRC1D, MSC_F_SRC2 } },
    { "{0}movc{1}{2}.i8{3} {4}, {5}, {6}, {7}", CLSM | B(53) | M(42, 40),
      CLS(5) | B(53) | B(40),
      { FLD(PRED_ALL, C(56, 3)), MSC_C5FLAGS, FLD(REPEAT, C(44, 4)),
        FLD(MSC_MOVC_TEST, C(39, 1), C(54, 1)), F_DST, MSC_F_SRC0, F_SRC1D, MSC_F_SRC2 } },
    /* movmsk: masked format, without and with .smsk (enc[40]) */
#define MSC_MOVMSK(pat, m, v, f, ...) \
    { pat, CLSM | M(42, 41) | (m), CLS(5) | M(42, 41) | (v), \
      { FLD(PRED_ALL, C(56, 3)), MSC_C5FLAGS, f, F_DST, __VA_ARGS__ } }
#define MSC_FMT FLD(MSC_MOVMSK_F, C(39, 1), C(54, 1))
#define MSC_LAST FLD(K_SRCD, C(0, 7), C(28, 2), C(48, 1)), FLD(MSC_COMP, C(37, 2))
    MSC_MOVMSK("{0}movmsk{1}{2} {3}{4}, {5}, {6}{7}", B(53) | B(40), 0, MSC_FMT,
               FLD(WMASK, C(44, 4)), F_SRC1D, MSC_LAST),
    MSC_MOVMSK("{0}movmsk{1}{2}{4} {3}, {5}, {6}{7}", B(53) | B(40), B(53), MSC_FMT,
               FLD(REPEAT, C(44, 4)), F_SRC1D, MSC_LAST),
    MSC_MOVMSK("{0}movmsk{1}{2}.smsk {3}{4}, {5}, {6}, {7}{8}", B(53) | B(40), B(40),
               MSC_FMT, FLD(WMASK, C(44, 4)), MSC_F_SRC0, F_SRC1D, MSC_LAST),
    MSC_MOVMSK("{0}movmsk{1}{2}.smsk{4} {3}, {5}, {6}, {7}{8}", B(53) | B(40),
               B(53) | B(40), MSC_FMT, FLD(REPEAT, C(44, 4)), MSC_F_SRC0, F_SRC1D, MSC_LAST),
    /* u8 prints after .smsk and the repeat count */
    MSC_MOVMSK("{0}movmsk{1}.u8 {3}{2}, {4}, {5}{6}", B(53) | B(40) | B(54) | B(39),
               B(39), FLD(WMASK, C(44, 4)), F_SRC1D, MSC_LAST),
    MSC_MOVMSK("{0}movmsk{1}{2}.u8 {3}, {4}, {5}{6}", B(53) | B(40) | B(54) | B(39),
               B(53) | B(39), FLD(REPEAT, C(44, 4)), F_SRC1D, MSC_LAST),
    MSC_MOVMSK("{0}movmsk{1}.smsk.u8 {3}{2}, {4}, {5}, {6}{7}",
               B(53) | B(40) | B(54) | B(39), B(40) | B(39), FLD(WMASK, C(44, 4)), MSC_F_SRC0,
               F_SRC1D, MSC_LAST),
    MSC_MOVMSK("{0}movmsk{1}.smsk{2}.u8 {3}, {4}, {5}, {6}{7}",
               B(53) | B(40) | B(54) | B(39), B(53) | B(40) | B(39), FLD(REPEAT, C(44, 4)),
               MSC_F_SRC0, F_SRC1D, MSC_LAST),
#undef MSC_LAST
#undef MSC_FMT
#undef MSC_MOVMSK

    /* ---- classes 9 and 15: the test group ----------------------------------- */
#define MSC_TEST9(ops, m, v, flags, sat, src, d, ...) \
    { "{0}{1}{2}" sat ".{3} {4}{5}{6}, p{7}, {8}" src, CLSM | (m), CLS(9) | (v), \
      { FLD(PRED_ALL, C(56, 3)), FLD(ops, C(14, 6)), flags, FLD(K_TEST, C(36, 8)), \
        FLD(F_WRITE, C(20, 1)), d, FLD(WMASK, C(44, 4)), FLD(K_DEC, C(34, 2)), __VA_ARGS__ } }
#define MSC_TEST15(ops, m, v, flags, sat, src, d, ...) \
    { "{0}{1}{2}" sat ".{3} {4}{5}{6}, {7}" src, CLSM | (m), CLS(15) | (v), \
      { FLD(PRED_ALL, C(56, 3)), FLD(ops, C(14, 6)), flags, \
        FLD(K_MSC_TESTMSK, C(36, 2), C(39, 5)), FLD(F_WRITE, C(20, 1)), d, \
        FLD(WMASK, C(44, 4)), __VA_ARGS__ } }
    /* enc[50] set (both classes) */
#define MSC_TESTS50(T, s2) \
    T(MSC_TOP_I, B(50), B(50), F_TESTFLAGS4, "", s2, F_DST, F_SRC1D, F_SRC2D), \
    T(MSC_TOP_I8, B(50), B(50), F_TESTFLAGS4, ".sat", s2, F_DST, F_SRC1D, F_SRC2D), \
    T(MSC_TOP_F2, B(50), B(50), F_TESTFLAGS4, "", s2, MSC_DST(K_MSC_FDST), \
      MSC_SRC1(K_MSC_FSRC), MSC_SRC2(K_MSC_FSRC)), \
    T(MSC_TOP_F2Z, B(50), B(50), F_TESTFLAGS4, "", s2, MSC_DST(K_MSC_FDST), \
      MSC_SRC1(K_MSC_FSRC0), MSC_SRC2(K_MSC_FSRC0)), \
    T(TESTOP_1, B(50), B(50), F_TESTFLAGS4, "", "", MSC_DST(K_MSC_FDST), \
      MSC_SRC1(K_MSC_FSRC0)), \
    T(MSC_TOP_C10, B(50), B(50), F_TESTFLAGS4, "", s2, MSC_DST(K_MSC_CDST), \
      MSC_SRC1(K_MSC_CSRC), MSC_SRC2(K_MSC_CSRC))
    MSC_TESTS50(MSC_TEST9, ", {9}"),
    /* class 15 with enc[50] clear and the bitwise operations, as usse.c's class
     * 9, except that a bitwise operation prints a source-2 immediate in hex
     * and a source-1 one in decimal */
    MSC_TEST15(TESTOP_BW, 0, 0, F_TESTFLAGS, "", ", {8}", F_DST, F_SRC1D,
               FLD(K_SRCH, C(0, 7), C(28, 2), C(48, 1))),
    MSC_TEST15(TESTOP_2, B(50), 0, F_TESTFLAGS4, "", ", {8}", F_DST, F_SRC1D, F_SRC2D),
    MSC_TEST15(TESTOP_1, B(50), 0, F_TESTFLAGS4, "", "", F_DST, F_SRC1D),
    MSC_TESTS50(MSC_TEST15, ", {8}"),
#undef MSC_TESTS50
#undef MSC_TEST15
#undef MSC_TEST9

    /* ---- classes 22 and 23: adif, adifsum, bilin, firv, firh --------------- */
    { "{0}adif{1} {2}, {3}, {4}", CLSM | M(53, 52) | B(38), CLS(22),
      { FLD(PRED_MUL, C(57, 2)), MSC_MULFLAGS(3), F_DST, F_SRC1D, F_SRC2D } },
    { "{0}adifsum{1} {2}, {3}.{4}, {5}, {6}", CLSM | M(53, 52) | B(38), CLS(22) | B(38),
      { FLD(PRED_MUL, C(57, 2)), MSC_MULFLAGS(3), F_DST, MSC_F_SRC0, FLD(LOWHIGH, C(47, 1)),
        F_SRC1D, F_SRC2D } },
    { "{0}bilin{1} {2}, {3}, {4}, {5}, {6}, {7}, {8}{9}", CLSM | M(53, 52), CLS(22) | B(53),
      { FLD(PRED_MUL, C(57, 2)), MSC_MULFLAGS(3), F_DST, MSC_F_SRC0, F_SRC1D, F_SRC2D,
        FLD(MSC_FMT8, C(40, 2)), FLD(MSC_BILIN_L, C(56, 1)),
        FLD(MSC_BILIN_SEL, C(43, 1), C(42, 1)), FLD(MSC_RND, C(47, 1)) } },
    { "{0}firv{1} {2}{3}, {4}, {5}, {6}{7}", CLSM | M(53, 52), CLS(22) | M(53, 52),
      { FLD(PRED_MUL, C(57, 2)), MSC_MULFLAGS(3), FLD(F_WRITE, C(47, 1)), F_DST,
        MSC_F_PAIR, F_SRC2D, FLD(MSC_FMT8, C(40, 2)),
        FLD(K_MSC_FIRV, C(56, 1), C(39, 1), C(42, 1)) } },
    { "{0}firh{1} {2}, {3}, {4}, {5}, {6}, #{7}, #{8}", CLSM, CLS(23),
      { FLD(PRED_MUL, C(57, 2)), MSC_MULFLAGS(2), F_DST, MSC_F_PAIR, F_SRC2D,
        FLD(MSC_FMT8, C(40, 2)), FLD(K_MSC_FIRH, C(38, 2), C(35, 3)),
        FLD(K_MSC_S5, C(42, 2), C(46, 2), C(56, 1)), FLD(K_DEC, C(52, 2)) } },
#endif
