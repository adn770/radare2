/* SPDX-License-Identifier: MIT */
/* SPDX-FileCopyrightText: 2026 Josep Torra */
/* forms/memctl.inc — the memctl family of USSE forms, included twice by usse.c:
 * with USSE_PART_DEFS for this family's operand kinds and field macros (name
 * them with a family prefix), and with USSE_PART_FORMS for its table entries.
 * Clean-room like the rest of the table: layouts come from probing the
 * refdisasm545 binary and are held to 0 wrong by random_oracle_check.py. */
#ifdef USSE_PART_DEFS

/* A sequence of small enumerations in one field, printed one after another:
 * the field's chunks, LSB first, are the subfields in print order, so a run of
 * flags and modes costs a single field. A NULL name marks an invalid value. */
typedef struct { uint8_t w; const char *const *t; } mem_sub;
typedef struct { const mem_sub *s; unsigned n; } mem_seq;

static int mem_k_seq_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    const mem_seq *q = k->arg;
    size_t at = 0;
    out[0] = '\0';
    for (unsigned i = 0; i < q->n; i++) {
        const char *s = q->s[i].t[v & ((1u << q->s[i].w) - 1)];
        if (!s) return 0;
        at += (size_t)snprintf(out + at, at < n ? n - at : 0, "%s", s);
        v >>= q->s[i].w;
    }
    return at < n;
}

#define MEM_SEQ(name, ...) \
    static const mem_sub name##_S[] = { __VA_ARGS__ }; \
    static const mem_seq name##_Q = { name##_S, sizeof name##_S / sizeof name##_S[0] }; \
    static const usse_kind name = { mem_k_seq_print, NULL, &name##_Q }
#define MEM_SUB(w, ...) { w, (const char *const[1u << (w)]){ __VA_ARGS__ } }

/* ---- class 28: texture sampling ------------------------------------------
 * Probed by single-bit flips and field sweeps of random class-28 words: the
 * dimension enc[43:42] (1d, 2d, 3d) and the LOD mode enc[41:40] (none, bias,
 * replace, grad; dimension 3 prints invalid_smp_lod_mode); the flags skipinv
 * enc[55], syncs enc[52], nosched enc[54], PCF enc[38:37] and SRD enc[47:46];
 * the coordinate format enc[36:35]. The value 3 of PCF, SRD and the format is
 * invalid (invalid_smp_pcf_mode, _srd_mode, _data_type). */
MEM_SEQ(MEM_K_SMP0, MEM_SUB(2, "1d", "2d", "3d", NULL), MEM_SUB(2, "", NULL, NULL, NULL));
MEM_SEQ(MEM_K_SMPL, MEM_SUB(2, "1d", "2d", "3d", NULL),
        MEM_SUB(2, NULL, "bias", "replace", "grad"));
MEM_SEQ(MEM_K_SMPFLAGS, MEM_SUB(1, "", ".skipinv"), MEM_SUB(1, "", ".syncs"),
        MEM_SUB(1, "", ".nosched"), MEM_SUB(2, "", ".pcf", ".pcff16", NULL),
        MEM_SUB(2, "", ".sinf", ".rsd", NULL));
MEM_SEQ(MEM_K_SMPFMT, MEM_SUB(2, "", ".flt16", ".c10", NULL));

/* ---- class 29 with enc[54] set: eldd / eldq --------------------------------
 * Probed like the samplers: every bit of the word is read. The flags are
 * skipinv enc[55], syncs enc[52], the cache mode enc[33] | enc[53] << 1 and
 * the fetch count enc[47:44] (count + 1, nothing for 0). */
MEM_SEQ(MEM_K_ELDFLAGS, MEM_SUB(1, "", ".skipinv"), MEM_SUB(1, "", ".syncs"),
        MEM_SUB(2, "", ".bpcache", ".fcfill", ".bypassl1"),
        MEM_SUB(4, "", ".fetch2", ".fetch3", ".fetch4", ".fetch5", ".fetch6", ".fetch7",
                ".fetch8", ".fetch9", ".fetch10", ".fetch11", ".fetch12", ".fetch13",
                ".fetch14", ".fetch15", ".fetch16"));
ENUM(MEM_ELDTYPE, 2, "d", "q");

/* Signed decimal of arg's width (a usse_num whose mul is the width). */
static int mem_k_snum_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    unsigned w = ((const usse_num *)k->arg)->mul;
    int32_t x = (v & 1u << (w - 1)) ? (int32_t)v - (int32_t)(1u << w) : (int32_t)v;
    snprintf(out, n, "%d", (int)x);
    return 1;
}

static int mem_parse_int(const char *s, const char **end, int64_t *x) {
    uint64_t u;
    int neg = *s == '-';
    if (!usse_parse_uint(s + neg, end, &u)) return 0;
    *x = neg ? -(int64_t)u : (int64_t)u;
    return 1;
}

static int mem_k_snum_parse(const usse_kind *k, const char *s, const char **end, uint32_t *v) {
    unsigned w = ((const usse_num *)k->arg)->mul;
    int64_t x;
    if (!mem_parse_int(s, end, &x) || x < -(1ll << (w - 1)) || x >= 1ll << (w - 1)) return 0;
    *v = (uint32_t)x & ((1u << w) - 1);
    return 1;
}

static const usse_num MEM_W10 = { NULL, 10, 0 };
static const usse_kind MEM_K_S10 = { mem_k_snum_print, mem_k_snum_parse, &MEM_W10 };

/* imo's 12-bit immediates print as unsigned while bit 6 is clear and as the
 * sign-extended 7-bit value -64..-1 when it is set (the bits above it do not
 * show then; the encoder writes them as 0). */
static int mem_k_imo_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    if (v & 0x40u) snprintf(out, n, "%d", (int)(v & 0x7fu) - 128);
    else           snprintf(out, n, "%u", v);
    return 1;
}

static int mem_k_imo_parse(const usse_kind *k, const char *s, const char **end, uint32_t *v) {
    int64_t x;
    (void)k;
    if (!mem_parse_int(s, end, &x) || x < -64 || x >= 4096 || (x >= 0 && (x & 0x40))) return 0;
    *v = x < 0 ? (uint32_t)(x + 128) : (uint32_t)x;
    return 1;
}
static const usse_kind MEM_K_IMO = { mem_k_imo_print, mem_k_imo_parse, NULL };

/* smlsi operand: v = value[7:0] | swizzle mode[8]: a signed increment, or
 * four 2-bit components, x first in the low bits. */
static int mem_k_smlsi_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    static const char XYZW[] = "xyzw";
    (void)k;
    if (v >> 8)
        snprintf(out, n, "swizzle(%c%c%c%c)", XYZW[v & 3], XYZW[v >> 2 & 3], XYZW[v >> 4 & 3],
                 XYZW[v >> 6 & 3]);
    else
        snprintf(out, n, "#%d", (v & 0x80) ? (int)v - 256 : (int)v);
    return 1;
}
static const usse_kind MEM_K_SMLSI = { mem_k_smlsi_print, NULL, NULL };
#define MEM_SMLSIMODE MEM_SUB(1, ", incrementmode", ", swizzlemode")
MEM_SEQ(MEM_K_SMLSIMODES, MEM_SMLSIMODE, MEM_SMLSIMODE, MEM_SMLSIMODE, MEM_SMLSIMODE);
#undef MEM_SMLSIMODE

/* ---- class 31, enc[53:52] = 1: the MOE group, operation enc[58:56] -------- */
ENUM(MEM_SMOAMODE, 4, "none", "repeat", "clamp", "mirror");
ENUM(MEM_MOEST, 16, "0 /* SMOA low data */", "1 /* SMOA high data */",
     "2 /* SMLSI low data */", "3 /* SMLSI high data */", "4 /* SMBO low data */",
     "5 /* SMBO high data */", "6 /* SMR low data */", "7 /* SMR high data */",
     "8 /* Index data */", "9 /* Reserved */", "10 /* Reserved */", "11 /* Reserved */",
     "12 /* Reserved */", "13 /* Reserved */", "14 /* Reserved */", "15 /* Reserved */");

/* ---- class 31, enc[53:52] = 2: the other group ---------------------------- */
ENUM(MEM_IDFMODE, 4, "bif", "pixelbe", "reserved(=2)", "reserved(=3)");
ENUM(MEM_LOCK, 2, "lock", "release");
ENUM(MEM_F_TWOPART, 2, "", ".twopart");
ENUM(MEM_F_THREEPART, 2, "", ".threepart");
ENUM(MEM_F_CUT, 2, "", ".cut");
ENUM(MEM_F_TASKS, 2, "", ".tasks");
ENUM(MEM_F_TASKE, 2, "", ".taske");

/* ---- class 31, enc[53:52] = 3: the visibility test group ------------------- */
MEM_SEQ(MEM_K_VISFLAGS, MEM_SUB(1, "", ".syncs"), MEM_SUB(1, "", ".nosched"),
        MEM_SUB(1, "", ".end"), MEM_SUB(1, "", ".c10"));
ENUM(MEM_TWOSIDED, 2, ", ", ", twosided, ");
ENUM(MEM_VISMODE, 4, "fb", "nfb", "optdwd", "optdwd");

/* ---- class 31, enc[54:52] = 4: cache control ------------------------------- */
ENUM(MEM_CFOP, 4, NULL, "ci", "cf", "cfi");
MEM_SEQ(MEM_K_CFFLAGS, MEM_SUB(1, "", ".nosched"), MEM_SUB(1, "", ".global"),
        MEM_SUB(1, "", ".dm_nomatch"));
ENUM(MEM_CFLEVEL, 4, "0 /* Reserved */", "1 /* L0 and L1 */", "2 /* L2 */",
     "3 /* L0, L1 and L2 */");

#endif
#ifdef USSE_PART_FORMS

    /* ---- class 28: smp1d/smp2d/smp3d[bias|replace|grad] -------------------- *
     * The destination is r or pa (enc[39]) with a 2-bit write mask enc[45:44],
     * or with enc[53] set a repeat count in the same bits. The coordinates are
     * a source-0 operand (bank enc[34] | enc[50] << 1) with their format, the
     * state a source-1 operand, and a LOD mode other than none adds its value
     * as a source-2 operand (whose bits are otherwise ignored). */
#define MEM_SMP(pat, v, op, cnt, ...) \
    { pat, CLSM | B(53), CLS(28) | (v), \
      { FLD(PRED_ALL, C(56, 3)), FLD(op, C(42, 2), C(40, 2)), \
        FLD(MEM_K_SMPFLAGS, C(55, 1), C(52, 1), C(54, 1), C(37, 2), C(46, 2)), cnt, \
        F_LSDST, FLD(K_SRC0, C(14, 7), C(34, 1), C(50, 1)), FLD(MEM_K_SMPFMT, C(35, 2)), \
        F_SRC1D, __VA_ARGS__ } }
    MEM_SMP("{0}smp{1}{2} {4}{3}, {5}{6}, {7}, drc{8}", 0, MEM_K_SMP0,
            FLD(WMASK, C(44, 2)), FLD(K_DEC, C(32, 2))),
    MEM_SMP("{0}smp{1}{2}{3} {4}, {5}{6}, {7}, drc{8}", B(53), MEM_K_SMP0,
            FLD(REPEAT, C(44, 2)), FLD(K_DEC, C(32, 2))),
    MEM_SMP("{0}smp{1}{2} {4}{3}, {5}{6}, {7}, {8}, drc{9}", 0, MEM_K_SMPL,
            FLD(WMASK, C(44, 2)), F_SRC2D, FLD(K_DEC, C(32, 2))),
    MEM_SMP("{0}smp{1}{2}{3} {4}, {5}{6}, {7}, {8}, drc{9}", B(53), MEM_K_SMPL,
            FLD(REPEAT, C(44, 2)), F_SRC2D, FLD(K_DEC, C(32, 2))),
#undef MEM_SMP

    /* ---- class 29 with enc[54] set: eldd / eldq ---------------------------- *
     * eld + d/q (enc[35]): an r/pa destination (enc[36]), then the base, a
     * source-1-like operand of the r, o, pa or sa bank (enc[31:30]), an r/pa
     * index (enc[34]) and an 11-bit immediate offset enc[43:37] | enc[51:48] << 7,
     * then a source-2-like operand of the same four banks (enc[29:28]) and a
     * 1-bit DRC. The SGX540 oracle reads these words as ld; the SGX540 corpus
     * has none. */
    { "{0}eld{1}{2} {3}, [{4}, {5}, #{6}], {7}, drc{8}", CLSM | B(54), CLS(29) | B(54),
      { FLD(PRED_ALL, C(56, 3)), FLD(MEM_ELDTYPE, C(35, 1)),
        FLD(MEM_K_ELDFLAGS, C(55, 1), C(52, 1), C(33, 1), C(53, 1), C(44, 4)),
        FLD(K_LSDST, C(21, 7), C(36, 1)), FLD(K_SRCD, C(7, 7), C(30, 2)),
        FLD(K_SRC0, C(14, 7), C(34, 1)), FLD(K_DEC, C(37, 7), C(48, 4)),
        FLD(K_SRCD, C(0, 7), C(28, 2)), FLD(K_DEC, C(32, 1)) } },

    /* ---- class 31 flow control (enc[54:52] = 0): lapc, mov pclink, nop ----- *
     * enc[40:38] picks the operation as for ba (0) and br (1): lapc (2), a
     * move to pclink from a source-1 operand (3), a move from pclink to a
     * destination (4) and nop (5), which prints no predicate. lapc reads
     * nosched and the sync flags as the branches do; the other bits these
     * forms leave out are ignored. */
#define MEM_FLOW(op) CLSM | M(54, 52) | M(40, 38), CLS(31) | (uint64_t)(op) << 38
    { "{0}lapc{1}", MEM_FLOW(2),
      { FLD(PRED_ALL, C(56, 3)), FLD(K_BRFLAGS, C(43, 1), C(55, 1), C(44, 1)) } },
    { "{0}mov{1} pclink, {2}", MEM_FLOW(3),
      { FLD(PRED_ALL, C(56, 3)), FLD(F_NOSCHED, C(43, 1)), F_SRC1H } },
    { "{0}mov{1} {2}, pclink", MEM_FLOW(4),
      { FLD(PRED_ALL, C(56, 3)), FLD(F_NOSCHED, C(43, 1)), F_DST } },
    { "nop{0}{1}{2}{3}{4}", MEM_FLOW(5),
      { FLD(F_SYNCS, C(55, 1)), FLD(F_NOSCHED, C(43, 1)), FLD(F_END, C(50, 1)),
        FLD(F_TOG, C(0, 1)), FLD(F_TRIGGER, C(1, 1)) } },
#undef MEM_FLOW

    /* ---- class 31 MOE group (enc[53:52] = 1, operation enc[58:56]) --------- *
     * No predicate; nosched is enc[50] throughout. smoa, smr, smlsi and smbo
     * take two source operands with enc[51] set, or immediates with it clear:
     * smoa four signed 10-bit offsets and four 2-bit address modes, smr and
     * smbo four 12-bit values, smlsi four 8-bit operands (an increment or a
     * swizzle, by the mode bits enc[35:32]) and three 4-bit values times 4.
     * imo (enc[51] ignored) takes four 12-bit immediates, setfc two bits,
     * moest a destination and a 4-bit selector the oracle names. */
#define MEM_MOE(op, m, v) CLSM | M(58, 56) | M(53, 52) | (m), \
                          CLS(31) | (uint64_t)(op) << 56 | B(52) | (v)
#define MEM_MOEREG(name, op) \
    { name "{0} {1}, {2}", MEM_MOE(op, B(51), B(51)), \
      { FLD(F_NOSCHED, C(50, 1)), F_SRC1D, F_SRC2D } }
    MEM_MOEREG("smoa", 0), MEM_MOEREG("smr", 1), MEM_MOEREG("smlsi", 2), MEM_MOEREG("smbo", 3),
#undef MEM_MOEREG
    { "smoa{0} #{1}, #{2}, #{3}, #{4}, {5}, {6}, {7}, {8}", MEM_MOE(0, B(51), 0),
      { FLD(F_NOSCHED, C(50, 1)), FLD(MEM_K_S10, C(30, 10)), FLD(MEM_K_S10, C(20, 10)),
        FLD(MEM_K_S10, C(10, 10)), FLD(MEM_K_S10, C(0, 10)), FLD(MEM_SMOAMODE, C(46, 2)),
        FLD(MEM_SMOAMODE, C(44, 2)), FLD(MEM_SMOAMODE, C(42, 2)),
        FLD(MEM_SMOAMODE, C(40, 2)) } },
#define MEM_MOE12(name, op) \
    { name "{0} #{1}, #{2}, #{3}, #{4}", MEM_MOE(op, B(51), 0), \
      { FLD(F_NOSCHED, C(50, 1)), FLD(K_DEC, C(36, 12)), FLD(K_DEC, C(24, 12)), \
        FLD(K_DEC, C(12, 12)), FLD(K_DEC, C(0, 12)) } }
    MEM_MOE12("smr", 1), MEM_MOE12("smbo", 3),
#undef MEM_MOE12
    { "smlsi{0} {1}, {2}, {3}, {4}{5}, #{6}, #{7}, #{8}", MEM_MOE(2, B(51), 0),
      { FLD(F_NOSCHED, C(50, 1)), FLD(MEM_K_SMLSI, C(24, 8), C(35, 1)),
        FLD(MEM_K_SMLSI, C(16, 8), C(34, 1)), FLD(MEM_K_SMLSI, C(8, 8), C(33, 1)),
        FLD(MEM_K_SMLSI, C(0, 8), C(32, 1)),
        FLD(MEM_K_SMLSIMODES, C(35, 1), C(34, 1), C(33, 1), C(32, 1)),
        FLD(K_X4, C(44, 4)), FLD(K_X4, C(40, 4)), FLD(K_X4, C(36, 4)) } },
    { "imo{0} #{1}, #{2}, #{3}, #{4}", MEM_MOE(4, 0, 0),
      { FLD(F_NOSCHED, C(50, 1)), FLD(MEM_K_IMO, C(36, 12)), FLD(MEM_K_IMO, C(24, 12)),
        FLD(MEM_K_IMO, C(12, 12)), FLD(MEM_K_IMO, C(0, 12)) } },
    { "setfc{0} #{1}, #{2}", MEM_MOE(5, 0, 0),
      { FLD(F_NOSCHED, C(50, 1)), FLD(K_DEC, C(0, 1)), FLD(K_DEC, C(8, 1)) } },
    { "moest{0}{1} {2}, #{3}", MEM_MOE(6, 0, 0),
      { FLD(F_SKIPINV, C(55, 1)), FLD(F_NOSCHED, C(50, 1)), F_DST, FLD(MEM_MOEST, C(43, 4)) } },
#undef MEM_MOE

    /* ---- class 31 other group (enc[53:52] = 2, operation enc[58:56]) ------- *
     * No predicate; nosched is enc[43]. idf (0) and wdf (1) name a 2-bit DRC
     * and idf a 2-bit mode, setm (2) and wop (7) a small number (wop with
     * twopart enc[3]), lock/release (5, by enc[0]) a 3-bit mutex number
     * enc[6:4] (enc[7] set is invalid_mutex_number). ldr/str (6, by enc[51])
     * read the same fields as the forms above them, which fix the ignored
     * enc[54] and enc[50]. The emits (3) are picked by enc[47:46] and enc[44]:
     * emitpds has the layout of emitpix2 with tasks/taske flags; the
     * emitmt and emitvcb forms take two or one source operands and a parts
     * flag enc[42] (emitmtevtx also cut, enc[45]). */
#define MEM_OTH(op, m, v) CLSM | M(58, 56) | M(53, 52) | (m), \
                          CLS(31) | (uint64_t)(op) << 56 | B(53) | (v)
    { "idf{0} drc{1}, {2}", MEM_OTH(0, 0, 0),
      { FLD(F_NOSCHED, C(43, 1)), FLD(K_DEC, C(32, 2)), FLD(MEM_IDFMODE, C(46, 2)) } },
    { "wdf{0} drc{1}", MEM_OTH(1, 0, 0), { FLD(F_NOSCHED, C(43, 1)), FLD(K_DEC, C(32, 2)) } },
    { "setm{0} #{1}", MEM_OTH(2, 0, 0), { FLD(F_NOSCHED, C(43, 1)), FLD(K_DEC, C(0, 4)) } },
    { "wop{0}{1} #{2}", MEM_OTH(7, 0, 0),
      { FLD(F_NOSCHED, C(43, 1)), FLD(MEM_F_TWOPART, C(3, 1)), FLD(K_DEC, C(0, 3)) } },
    { "{0}{1} #{2}", MEM_OTH(5, B(7), 0),
      { FLD(MEM_LOCK, C(0, 1)), FLD(F_NOSCHED, C(43, 1)), FLD(K_DEC, C(4, 3)) } },
#define MEM_LDSTR(m, v) MEM_OTH(6, B(51) | (m), v)
#define MEM_LDRFLAGS FLD(K_LDRFLAGS, C(55, 1), C(43, 1))
#define MEM_IDX14 FLD(K_DEC, C(0, 7), C(14, 7))
    { "ldr{0} {1}, #{2}, drc{3}", MEM_LDSTR(B(48) | M(29, 28), B(48) | B(29)),
      { MEM_LDRFLAGS, F_LSDST, MEM_IDX14, FLD(K_DEC, C(32, 2)) } },
    { "ldr{0} {1}, {2}, drc{3}", MEM_LDSTR(0, 0),
      { MEM_LDRFLAGS, F_LSDST, F_SRC2D, FLD(K_DEC, C(32, 2)) } },
    { "str{0} #{1}, {2}", MEM_LDSTR(B(48) | M(29, 28), B(51) | B(48) | B(29)),
      { MEM_LDRFLAGS, MEM_IDX14, F_SRC1D } },
    { "str{0} {1}, {2}", MEM_LDSTR(0, B(51)), { MEM_LDRFLAGS, F_SRC2D, F_SRC1D } },
#undef MEM_IDX14
#undef MEM_LDRFLAGS
#undef MEM_LDSTR
#define MEM_EMIT(m, v) MEM_OTH(3, M(47, 46) | (m), v)
/* The closed compilers' vertex and state programs write the operand an emit does
 * not print as immediate 0 (bank 2 with the extension bit): src1 of emitvcbst and
 * emitvcbvtx, the extension bit of src0 for emitmtest (the 3D captures,
 * design/sgx545_3d.md 9.2). The encoder prefers that. */
#define EMIT_UNUSED_SRC1 (B(49) | B(31))
#define EMIT_UNUSED_SRC0 B(51)
    { "emitpds{0}{1}{2}{3}{4} #{5} /* incp */, {6}, {7}, {8}, #{9}", MEM_EMIT(0, B(47)),
      { FLD(F_NOSCHED, C(43, 1)), FLD(F_END, C(50, 1)), FLD(MEM_F_TASKS, C(45, 1)),
        FLD(MEM_F_TASKE, C(44, 1)), FLD(F_FREEP, C(21, 1)), FLD(K_DEC, C(32, 2), C(41, 1)),
        F_SRC0, F_SRC1D, F_SRC2D, FLD(K_HEX, C(22, 6), C(35, 6), C(54, 2)) } },
    { "emitmtest{0}{1}{2}{3} #{4} /* incp */, {5}, {6}", MEM_EMIT(B(44), B(46)),
      { FLD(F_NOSCHED, C(43, 1)), FLD(F_END, C(50, 1)), FLD(MEM_F_THREEPART, C(42, 1)),
        FLD(F_FREEP, C(21, 1)), FLD(K_DEC, C(32, 2), C(41, 1)), F_SRC1D, F_SRC2D },
      EMIT_UNUSED_SRC0 },
    { "emitmtevtx{0}{1}{2}{3}{4} #{5} /* incp */, {6}, {7}", MEM_EMIT(B(44), B(46) | B(44)),
      { FLD(F_NOSCHED, C(43, 1)), FLD(F_END, C(50, 1)), FLD(MEM_F_TWOPART, C(42, 1)),
        FLD(MEM_F_CUT, C(45, 1)), FLD(F_FREEP, C(21, 1)), FLD(K_DEC, C(32, 2), C(41, 1)),
        F_SRC1D, F_SRC2D } },
    { "emitvcbst{0}{1}{2}{3} #{4} /* incp */, {5}", MEM_EMIT(B(44), B(47) | B(46)),
      { FLD(F_NOSCHED, C(43, 1)), FLD(F_END, C(50, 1)), FLD(MEM_F_THREEPART, C(42, 1)),
        FLD(F_FREEP, C(21, 1)), FLD(K_DEC, C(32, 2), C(41, 1)), F_SRC2D },
      EMIT_UNUSED_SRC1 },
    { "emitvcbvtx{0}{1}{2}{3} #{4} /* incp */, {5}", MEM_EMIT(B(44), B(47) | B(46) | B(44)),
      { FLD(F_NOSCHED, C(43, 1)), FLD(F_END, C(50, 1)), FLD(MEM_F_TWOPART, C(42, 1)),
        FLD(F_FREEP, C(21, 1)), FLD(K_DEC, C(32, 2), C(41, 1)), F_SRC2D },
      EMIT_UNUSED_SRC1 },
#undef MEM_EMIT
#undef EMIT_UNUSED_SRC1
#undef EMIT_UNUSED_SRC0
#undef MEM_OTH

    /* ---- class 31 visibility test group (enc[53:52] = 3) ------------------- *
     * pcoeff and ptoff (operation 0, by enc[47]) print no predicate; atst8 (1)
     * and depthf (3) a 2-bit one at enc[42:41]. atst8 writes a destination and
     * a predicate p<enc[40:39]> (enc[38] clear prints "!"), with c10 at enc[54].
     * Both test source 0, 1 and 2 with twosided enc[37] and the feedback mode
     * enc[36:35] (fb, nfb, optdwd twice). */
#define MEM_VIS(op, m, v) CLSM | M(58, 56) | M(53, 52) | (m), \
                          CLS(31) | (uint64_t)(op) << 56 | M(53, 52) | (v)
    { "pcoeff{0}{1} {2}, {3}, {4}", MEM_VIS(0, B(47), 0),
      { FLD(F_NOSCHED, C(43, 1)), FLD(F_END, C(50, 1)), F_SRC0, F_SRC1D, F_SRC2D } },
    { "ptoff{0}{1}", MEM_VIS(0, B(47), B(47)),
      { FLD(F_NOSCHED, C(43, 1)), FLD(F_END, C(50, 1)) } },
    { "{0}atst8{1} {2}, {3}p{4}, {5}, {6}, {7}{8}{9}", MEM_VIS(1, 0, 0),
      { FLD(PRED_MUL, C(41, 2)), FLD(MEM_K_VISFLAGS, C(55, 1), C(43, 1), C(50, 1), C(54, 1)),
        FLD(K_DST, C(21, 7), C(32, 2)), FLD(F_WRITE, C(38, 1)), FLD(K_DEC, C(39, 2)), F_SRC0,
        F_SRC1D, F_SRC2D, FLD(MEM_TWOSIDED, C(37, 1)), FLD(MEM_VISMODE, C(35, 2)) } },
    { "{0}depthf{1} {2}, {3}, {4}{5}{6}", MEM_VIS(3, 0, 0),
      { FLD(PRED_MUL, C(41, 2)), FLD(MEM_K_VISFLAGS, C(55, 1), C(43, 1), C(50, 1)), F_SRC0,
        F_SRC1D, F_SRC2D, FLD(MEM_TWOSIDED, C(37, 1)), FLD(MEM_VISMODE, C(35, 2)) } },
#undef MEM_VIS

    /* ---- class 31 enc[54:52] = 4: cache control and phas ------------------- *
     * Operation 0 is ci, cf or cfi by enc[45:44] (0 is invalid_cfi_mode), with
     * nosched enc[43], global enc[47], dm_nomatch enc[46], two sources and the
     * cache levels enc[41:40]. Operation 2 is phas; the older phas forms fix
     * enc[55], which it ignores. */
#define MEM_OT2(op, m, v) CLSM | M(58, 56) | M(54, 52) | (m), \
                          CLS(31) | (uint64_t)(op) << 56 | B(54) | (v)
    { "{0}{1} {2}, {3}, #{4}", MEM_OT2(0, 0, 0),
      { FLD(MEM_CFOP, C(44, 2)), FLD(MEM_K_CFFLAGS, C(43, 1), C(47, 1), C(46, 1)), F_SRC1D,
        F_SRC2D, FLD(MEM_CFLEVEL, C(40, 2)) } },
    { "phas{0} #{1}, #{2}, {3}, {4}, {5}", MEM_OT2(2, B(50), B(50)),
      { FLD(F_END, C(51, 1)), FLD(K_DEC, C(0, 18)), FLD(K_X4, C(32, 8)),
        FLD(PHAS_RATE, C(43, 2)), FLD(PHAS_WAIT, C(40, 3)), FLD(PHAS_MODE, C(45, 1)) } },
    { "phas{0}{1} {2}, {3}", MEM_OT2(2, B(50), 0),
      { FLD(F_NOSCHED, C(43, 1)), FLD(F_END, C(51, 1)), F_SRC1D, F_SRC2D } },
#undef MEM_OT2

#endif
