/* forms/intpack.inc — the intpack family of USSE forms, included twice by usse.c:
 * with USSE_PART_DEFS for this family's operand kinds and field macros (name
 * them with a family prefix), and with USSE_PART_FORMS for its table entries.
 * Clean-room like the rest of the table: layouts come from probing the
 * refdisasm545 binary and are held to 0 wrong by random_oracle_check.py. */
#ifdef USSE_PART_DEFS

/* A source operand with a component (byte or half) select after it:
 * v = operand[9:0] | select[11:10]. With a non-NULL arg, select 0 prints
 * nothing. */
static int k_int_srcc_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    char op[48];
    if (!k_src_print(&K_SRCD, v & 0x3ff, op, sizeof op)) return 0;
    if (k->arg && !(v >> 10)) snprintf(out, n, "%s", op);
    else                      snprintf(out, n, "%s.%u", op, v >> 10 & 3);
    return 1;
}
static const usse_kind K_INT_SRCC = { k_int_srcc_print, NULL, NULL };
static const usse_kind K_INT_SRCC0 = { k_int_srcc_print, NULL, "" };

/* ---- class 8: pack / unpack ----------------------------------------------
 * enc[43:38] names the destination and source formats together (value 8 is
 * statomic, whose component selects print nothing for 0). enc[37:34] is the
 * destination byte mask (all four bytes print nothing), enc[20:19] the
 * rounding mode, enc[18] .scale, enc[17:16] and enc[15:14] the source
 * components. */
ENUM(INT_PCKFMT, 64,
     "unpcku8u8", "unpcku8s8", NULL, "unpcku16u8", "unpcks16u8", "unpckf16u8", "unpckf32u8",
     NULL, NULL, NULL, NULL, "unpcku16s8", "unpcks16s8", "unpckf16s8", "unpckf32s8", NULL,
     NULL, NULL, NULL, "unpcku16o8", "unpcks16o8", "unpckf16o8", "unpckf32o8", NULL,
     "pcku8u16", "pcks8u16", "pcko8u16", "pcku16u16", "pcks16u16", "pckf16u16",
     "unpckf32u16", "pckc10u16",
     "pcku8s16", "pcks8s16", "pcko8s16", "pcku16s16", "pcks16s16", "pckf16s16",
     "unpckf32s16", "pckc10s16",
     "pcku8f16", "pcks8f16", "pcko8f16", "pcku16f16", "pcks16f16", "pckf16f16",
     "unpckf32f16", "pckc10f16",
     "pcku8f32", "pcks8f32", "pcko8f32", "pcku16f32", "pcks16f32", "pckf16f32",
     "unpckf32f32", "pckc10f32",
     NULL, NULL, NULL, "unpcku16c10", "unpcks16c10", "unpckf16c10", "unpckf32c10",
     "unpckc10c10");
ENUM(INT_BYTEMASK, 16, ".bytemask0000", ".bytemask0001", ".bytemask0010", ".bytemask0011",
     ".bytemask0100", ".bytemask0101", ".bytemask0110", ".bytemask0111", ".bytemask1000",
     ".bytemask1001", ".bytemask1010", ".bytemask1011", ".bytemask1100", ".bytemask1101",
     ".bytemask1110", "");
ENUM(INT_ROUND, 4, "nearest", "down", "up", "zero");

/* The operation and its flags: v = format[5:0] | skipinv | syncs << 1 |
 * nosched << 2 | end << 3 | enc[18] << 4, which reads .renable for the
 * float-to-float conversions and .scale for the others. */
static int k_int_pckop_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    static const char *const F[] = { ".skipinv", ".syncs", ".nosched", ".end" };
    const char *const *name = k->arg;
    unsigned fmt = v & 63;
    size_t at;
    if (!name[fmt]) return 0;
    at = (size_t)snprintf(out, n, "%s", name[fmt]);
    for (unsigned i = 0; i < 4; i++)
        if (v >> (6 + i) & 1) at += (size_t)snprintf(out + at, at < n ? n - at : 0, "%s", F[i]);
    if (v >> 10 & 1) {
        int ff = fmt == 45 || fmt == 46 || fmt == 53 || fmt == 54;
        at += (size_t)snprintf(out + at, at < n ? n - at : 0, "%s", ff ? ".renable" : ".scale");
    }
    return at < n;
}
static const char *const INT_STATOMIC_T[64] = { [8] = "statomic" };
static const usse_kind K_INT_PCKOP = { k_int_pckop_print, NULL, INT_PCKFMT_T };
static const usse_kind K_INT_STATOMIC = { k_int_pckop_print, NULL, INT_STATOMIC_T };
#define INT_PCKOP(k) FLD(k, C(38, 6), C(55, 1), C(52, 1), C(54, 1), C(50, 1), C(18, 1))
#define INT_S1C(k) FLD(k, C(7, 7), C(30, 2), C(49, 1), C(16, 2))
#define INT_S2C(k) FLD(k, C(0, 7), C(28, 2), C(48, 1), C(14, 2))

/* ---- classes 16-19, 24: sop2, sop3, lrp, sop2wm, ima8, dot products -------
 * These name registers with six bits and a seventh, .c10, after the name:
 * temporaries r0-r59 then i0-i3, indexed [5:4] bank, [3] il/ih, [2:0]
 * offset. Constants, immediates and i.l/i.h keep all seven bits. arg[0] is
 * the bank numbering: that of K_DST ('d'), K_SRCD ('s') or a source 0 of r
 * and pa ('0'). arg[1], if any, names a modifier bit above the operand
 * (bit 8 for a source 0, 10 otherwise), printed before .c10: 'n' .neg,
 * 'c' .comp. */
static int k_int_c10_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    static const char *const D[8] = { NULL, "o", "pa", NULL, "sa", NULL, NULL, "i" };
    static const char *const S[8] = { NULL, "o", "pa", "sa", NULL, NULL, NULL, "i" };
    static const char *const IB[4] = { "r", "o", "pa", "sa" };
    static const char *const Z[8] = { NULL, "pa" };
    const char *arg = k->arg;
    char kind = arg[0], base[48];
    int dst = kind == 'd';
    unsigned nb = kind == '0' ? 8 : 10, op = v & ((1u << nb) - 1), mod = v >> nb & 1;
    unsigned b = op >> 7, r = op & 63, c10 = op >> 6 & 1;
    const char *name = (dst ? D : kind == 's' ? S : Z)[b];
    if (kind != '0' && (b == 5 || b == 6)) {
        if (dst) k_dst_print(k, op, base, sizeof base);
        else     k_src_print(&K_SRCD, op, base, sizeof base);
        c10 = 0;
    } else if (b == 0) {
        snprintf(base, sizeof base, r < 60 ? "r%u" : "i%u", r < 60 ? r : r - 60);
    } else if (kind != '0' && b == (dst ? 3u : 4u)) {
        snprintf(base, sizeof base, "%s[%s + #%u]", IB[r >> 4], (r & 8) ? "ih" : "il", r & 7);
    } else {
        snprintf(base, sizeof base, "%s%u", name, r);
    }
    snprintf(out, n, "%s%s%s", base, mod ? (arg[1] == 'n' ? ".neg" : ".comp") : "",
             c10 ? ".c10" : "");
    return 1;
}
static const usse_kind K_INT_D10 = { k_int_c10_print, NULL, "d" };
static const usse_kind K_INT_S10 = { k_int_c10_print, NULL, "s" };
#define F_INT_D10  FLD(K_INT_D10, C(21, 7), C(32, 2), C(51, 1))
#define F_INT_S1_10 FLD(K_INT_S10, C(7, 7), C(30, 2), C(49, 1))
#define F_INT_S2_10 FLD(K_INT_S10, C(0, 7), C(28, 2), C(48, 1))

/* A blend selection: a list of items printed ", "-separated, each a
 * selector (w bits, its names in t) followed by its complement bit when comp
 * is set (".comp"). v = [complement-all] | items in order | [neg]; pre adds a
 * leading bit printed as "comp, ", neg a trailing one printed as ", neg". */
typedef struct { const char *const *t; uint8_t w, comp; } int_item;
typedef struct { uint8_t pre, neg, n; int_item it[6]; } int_sel;
static int k_int_sel_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    const int_sel *a = k->arg;
    size_t at = 0;
    unsigned sh = 0;
    out[0] = '\0';
    if (a->pre && (v >> sh++ & 1)) at += (size_t)snprintf(out, n, "comp, ");
    for (unsigned i = 0; i < a->n; i++) {
        const int_item *it = &a->it[i];
        const char *name = it->t[v >> sh & ((1u << it->w) - 1)];
        int c = it->comp && (v >> (sh + it->w) & 1);
        if (!name) return 0;
        sh += it->w + it->comp;
        at += (size_t)snprintf(out + at, at < n ? n - at : 0, "%s%s%s", i ? ", " : "", name,
                               c ? ".comp" : "");
    }
    if (a->neg && (v >> sh & 1)) at += (size_t)snprintf(out + at, at < n ? n - at : 0, ", neg");
    return at < n;
}
#define INT_SELK(name, ...) \
    static const int_sel name##_S = { __VA_ARGS__ }; \
    static const usse_kind name = { k_int_sel_print, NULL, &name##_S }
static const char *const INT_OP4_T[4] = { "add", "sub", "min", "max" };
static const char *const INT_OP2_T[2] = { "add", "sub" };
/* sop2 */
static const char *const INT_SOP2C1_T[8] = { "zero", "s1", "s2", "s1a", "s2a", "asat", "s2scale",
                                             NULL };
static const char *const INT_SOP2C2_T[8] = { "zero", "s1", "s2", "s1a", "s2a", "asat", "zeros",
                                             NULL };
static const char *const INT_SOP2A1_T[4] = { "zero", "s1a", "s2a", "s2scale" };
static const char *const INT_SOP2A2_T[4] = { "zero", "s1a", "s2a", "zeros" };
INT_SELK(K_INT_SOP2C, 1, 0, 3, { { INT_SOP2C1_T, 3, 1 },
                               { INT_SOP2C2_T, 3, 1 }, { INT_OP4_T, 2, 0 } });
INT_SELK(K_INT_SOP2A, 1, 1, 3, { { INT_SOP2A1_T, 2, 1 },
                               { INT_SOP2A2_T, 2, 1 }, { INT_OP4_T, 2, 0 } });
/* sop3 and lrp */
static const char *const INT_SEL3_T[8] = { "zero", "asat", "s1", "s1a", "s0", "s0a", "s2", "s2a" };
static const char *const INT_ASEL_T[4] = { "zero", "s0a", "s1a", "s2a" };
static const char *const INT_Z1A_T[2] = { "zero", "s1a" };
static const char *const INT_Z2A_T[2] = { "zero", "s2a" };
static const char *const INT_Z1_T[2] = { "zero", "s1" };
static const char *const INT_Z2_T[2] = { "zero", "s2" };
static const char *const INT_S0_T[2] = { "s0", "s0a" };
static const char *const INT_LRP2_T[4] = { "s1, s2", "s1, s2.comp", "one, s2", "s1.comp, s2" };
INT_SELK(K_INT_SOP3C, 0, 0, 3, { { INT_SEL3_T, 3, 1 }, { INT_SEL3_T, 3, 1 }, { INT_OP2_T, 1, 0 } });
INT_SELK(K_INT_SOP3CN, 0, 1, 3, { { INT_SEL3_T, 3, 1 },
                                { INT_SEL3_T, 3, 1 }, { INT_OP2_T, 1, 0 } });
INT_SELK(K_INT_ASOP, 0, 0, 3, { { INT_ASEL_T, 2, 1 }, { INT_SEL3_T, 3, 1 }, { INT_OP2_T, 1, 0 } });
INT_SELK(K_INT_ARSOP, 0, 0, 2, { { INT_ASEL_T, 2, 1 }, { INT_OP2_T, 1, 0 } });
INT_SELK(K_INT_ALRP, 0, 0, 2, { { INT_Z1A_T, 1, 1 }, { INT_Z2A_T, 1, 1 } });
INT_SELK(K_INT_LRP1C, 0, 0, 3, { { INT_Z1_T, 1, 1 }, { INT_Z2_T, 1, 1 }, { INT_S0_T, 1, 0 } });
INT_SELK(K_INT_LRP1A, 0, 0, 3, { { INT_SEL3_T, 3, 1 }, { INT_SEL3_T, 3, 1 }, { INT_OP2_T, 1, 0 } });
INT_SELK(K_INT_LRP2C, 0, 0, 3, { { INT_SEL3_T, 3, 1 },
                               { INT_SEL3_T, 3, 1 }, { INT_LRP2_T, 2, 0 } });
/* sop2wm */
static const char *const INT_SELWM_T[8] = { "zero", "asat", "s1", "s1a", NULL, NULL, "s2", "s2a" };
INT_SELK(K_INT_SOPWM, 0, 0, 4, { { INT_SELWM_T, 3, 1 }, { INT_SELWM_T, 3, 1 }, { INT_OP4_T, 2, 0 },
                                 { INT_OP4_T, 2, 0 } });
ENUM(INT_BYTEMASK4, 16, ".bytemask0000", ".bytemask0001", ".bytemask0010", ".bytemask0011",
     ".bytemask0100", ".bytemask0101", ".bytemask0110", ".bytemask0111", ".bytemask1000",
     ".bytemask1001", ".bytemask1010", ".bytemask1011", ".bytemask1100", ".bytemask1101",
     ".bytemask1110", ".bytemask1111");
#define F_INT_SEL3PAIR C(38, 3), C(56, 1), C(35, 3), C(47, 1)
#define F_INT_ALRP FLD(K_INT_ALRP, C(45, 1), C(41, 1), C(44, 1), C(46, 1))
#define F_INT_FLAGS3 FLD(K_MULFLAGS, C(55, 1), C(54, 1), C(50, 1))
static const usse_kind K_INT_S0_10 = { k_int_c10_print, NULL, "0" };
#define F_INT_S0_10 FLD(K_INT_S0_10, C(14, 7), C(34, 1))
#define F_INT_MULFLAGS FLD(K_MULFLAGS, C(55, 1), C(54, 1), C(50, 1), C(44, 3))

/* ---- integer multiply-add: ima8 (19), ima16 (20), imae (21), ima32/idiv (26)
 * The older forms in usse.c decode the plain formats; these take the rest. */

/* A source with a suffix: v = operand | neg << nb | low/high << (nb + 1),
 * where the operand (nb bits) is a source 0 (arg "0") or source 1/2 (arg
 * "s"); arg[1] says which suffixes exist ('n' neg, 'l' low/high, 'b' both). */
static int k_int_srcx_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    const char *arg = k->arg;
    unsigned nb = arg[0] == '0' ? 8 : 10;
    int hasneg = arg[1] == 'n' || arg[1] == 'b', haslh = arg[1] == 'l' || arg[1] == 'b';
    uint32_t op = v & ((1u << nb) - 1), rest = v >> nb;
    unsigned neg = hasneg ? rest & 1 : 0, lh = haslh ? rest >> hasneg & 1 : 0;
    char buf[48];
    if (arg[0] == '0') k_src0_print(&K_SRC0, op, buf, sizeof buf);
    else               k_src_print(&K_SRCD, op, buf, sizeof buf);
    snprintf(out, n, "%s%s%s", buf, neg ? ".neg" : "", haslh ? (lh ? ".high" : ".low") : "");
    return 1;
}
static const usse_kind K_INT_S0LH = { k_int_srcx_print, NULL, "0l" };
static const usse_kind K_INT_SLH  = { k_int_srcx_print, NULL, "sl" };
static const usse_kind K_INT_SNEG = { k_int_srcx_print, NULL, "sn" };
static const usse_kind K_INT_SNLH = { k_int_srcx_print, NULL, "sb" };

/* ima16 source formats: v = format 1 [1:0] | format 2 [3:2]; arg bit i set
 * means format i+1 is an 8-bit one (u8, s8, o8), clear that it is u16. */
static int k_int_fmt16_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    static const char *const F[4] = { "u16", "u8", "s8", "o8" };
    unsigned want = *(const uint8_t *)k->arg, f1 = v & 3, f2 = v >> 2 & 3;
    if ((f1 != 0) != (want & 1) || (f2 != 0) != (want >> 1 & 1)) return 0;
    snprintf(out, n, "%s, %s", F[f1], F[f2]);
    return 1;
}
static const uint8_t INT_FMT16_W[4] = { 0, 1, 2, 3 };
static const usse_kind K_INT_FMT16[4] = {
    { k_int_fmt16_print, NULL, &INT_FMT16_W[0] }, { k_int_fmt16_print, NULL, &INT_FMT16_W[1] },
    { k_int_fmt16_print, NULL, &INT_FMT16_W[2] }, { k_int_fmt16_print, NULL, &INT_FMT16_W[3] },
};

/* imae source-2 type and carries: v = type[1:0] | coe | cie | register; the
 * carry register prints when either carry is used. */
static int k_int_imaec_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    static const char *const T[4] = { "z16", "u16", "u32", NULL };
    char reg[8] = "";
    (void)k;
    if (!T[v & 3]) return 0;
    if (v & 12) snprintf(reg, sizeof reg, ", i%u", v >> 4 & 1);
    snprintf(out, n, "%s%s%s%s", T[v & 3], (v & 4) ? ", coe" : "", (v & 8) ? ", cie" : "", reg);
    return 1;
}
static const usse_kind K_INT_IMAEC = { k_int_imaec_print, NULL, NULL };

/* ima32 carry-in: 0 none, else register i(v-1). */
static int k_int_cie32_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    if (v) snprintf(out, n, ", cie, i%u", v - 1);
    else   out[0] = '\0';
    return 1;
}
static const usse_kind K_INT_CIE32 = { k_int_cie32_print, NULL, NULL };
/* ima32 extra operand after the destination: v = present | register << 1. */
static int k_int_ima32x_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    if (v & 1) snprintf(out, n, ", i%u", v >> 1);
    else       out[0] = '\0';
    return 1;
}
static const usse_kind K_INT_IMA32X = { k_int_ima32x_print, NULL, NULL };

/* ima8: six selectors */
static const char *const INT_I8A_T[4] = { "s0", "s1", "s0a", "s1a" };
static const char *const INT_I8B_T[2] = { "s1", "s1a" };
static const char *const INT_I8C_T[2] = { "s2", "s2a" };
static const char *const INT_I8D_T[2] = { "s0a", "s1a" };
static const char *const INT_I8E_T[1] = { "s1a" };
static const char *const INT_I8F_T[1] = { "s2a" };
INT_SELK(K_INT_IMA8SEL, 0, 0, 6, { { INT_I8A_T, 2, 1 }, { INT_I8B_T, 1, 1 }, { INT_I8C_T, 1, 1 },
                                   { INT_I8D_T, 1, 1 }, { INT_I8E_T, 0, 1 }, { INT_I8F_T, 0, 1 } });
ENUM(INT_SAT, 2, "", ".sat");
static const usse_kind K_INT_S0N_10 = { k_int_c10_print, NULL, "0n" };
static const usse_kind K_INT_SC10 = { k_int_c10_print, NULL, "sc" };
#define F_INT_MSRC0 FLD(K_SRC0, C(14, 7), C(34, 1))

/* ---- class 24: u8dot3, u8dot4, u16dot3, u16dot4 (and their off forms) */
ENUM(INT_DOTFMT, 4, "u8", "u8", "u8", "u16");      /* enc[53:52] */
ENUM(INT_X4, 4, "1", "2", "4", "8");
ENUM(INT_OFF, 2, "", "off");
ENUM(INT_NOT3, 4, "", "", "", NULL);
ENUM(INT_AADD, 2, "aadd", "asub");
ENUM(INT_AINTRP, 2, "aintrp1", "aintrp2");
static const char *const INT_DOTSEL_T[4] = { "zero", "s1a", "s2a", NULL };
static const char *const INT_S1A_T[1] = { "s1a" };
static const char *const INT_S2A_T[1] = { "s2a" };
INT_SELK(K_INT_DOTADD, 0, 0, 4, { { INT_DOTSEL_T, 2, 1 }, { INT_S1A_T, 0, 1 },
                                  { INT_DOTSEL_T, 2, 1 }, { INT_S2A_T, 0, 0 } });
INT_SELK(K_INT_DOTINTRP, 0, 0, 2, { { INT_DOTSEL_T, 2, 0 }, { INT_DOTSEL_T, 2, 1 } });

#endif
#ifdef USSE_PART_FORMS

    /* ---- class 8: pack / unpack, statomic -------------------------------- */
#define INT_PCK(op, srcc) \
    { "{0}{1} {3}{4}{2}, {5}, {6}, {7}", CLSM | B(53), CLS(8), \
      { FLD(PRED_ALL, C(56, 3)), INT_PCKOP(op), FLD(WMASK, C(44, 4)), F_DST, \
        FLD(INT_BYTEMASK, C(34, 4)), INT_S1C(srcc), INT_S2C(srcc), \
        FLD(INT_ROUND, C(19, 2)) } }, \
    { "{0}{1}{2} {3}{4}, {5}, {6}, {7}", CLSM | B(53), CLS(8) | B(53), \
      { FLD(PRED_ALL, C(56, 3)), INT_PCKOP(op), FLD(REPEAT, C(44, 4)), F_DST, \
        FLD(INT_BYTEMASK, C(34, 4)), INT_S1C(srcc), INT_S2C(srcc), \
        FLD(INT_ROUND, C(19, 2)) } }
    INT_PCK(K_INT_PCKOP, K_INT_SRCC),
    INT_PCK(K_INT_STATOMIC, K_INT_SRCC0),
#undef INT_PCK

    /* ---- class 16: sop2 ---------------------------------------------------
     * Colour selectors enc[40:38] and enc[37:35] (complemented by enc[56] and
     * enc[47], the whole colour by enc[20]) and operation enc[19:18]; alpha
     * selectors enc[53:52], enc[42:41] (enc[43], enc[34], enc[15]),
     * operation enc[17:16] and enc[14] neg. */
    { "{0}sop2{1} {2}, {3}, {4}, {5}+asop2 {6}", CLSM, CLS(16),
      { FLD(PRED_MUL, C(57, 2)), F_INT_MULFLAGS, F_INT_D10, F_INT_S1_10, F_INT_S2_10,
        FLD(K_INT_SOP2C, C(20, 1), C(38, 3), C(56, 1), C(35, 3), C(47, 1), C(18, 2)),
        FLD(K_INT_SOP2A, C(15, 1), C(52, 2), C(43, 1), C(41, 2), C(34, 1), C(16, 2),
            C(14, 1)) } },

    /* ---- class 17: sop3, lrp1, lrp2 ------------------------------------------
     * enc[53] picks sop3 or lrp, enc[43:42] the alpha operation. The pair of
     * 3-bit selectors enc[40:38], enc[37:35] (complements enc[56], enc[47])
     * is the colour of sop3 and lrp2 and the alpha of lrp1; the sop3 asop
     * alpha repeats the second colour selector. */
#define INT_SOP3(pat, m, v, col, alpha) \
    { pat, CLSM | B(53) | (m), CLS(17) | (v), \
      { FLD(PRED_MUL, C(57, 2)), F_INT_FLAGS3, F_INT_D10, F_INT_S0_10, F_INT_S1_10, \
        F_INT_S2_10, col, alpha } }
    INT_SOP3("{0}sop3{1} {2}, {3}, {4}, {5}, {6}+asop {7}", M(43, 42), 0,
             FLD(K_INT_SOP3C, F_INT_SEL3PAIR, C(52, 1)),
             FLD(K_INT_ASOP, C(44, 2), C(46, 1), C(35, 3), C(47, 1), C(41, 1))),
    INT_SOP3("{0}sop3{1} {2}, {3}, {4}, {5}, {6}+arsop {7}", M(43, 42), B(43),
             FLD(K_INT_SOP3C, F_INT_SEL3PAIR, C(52, 1)),
             FLD(K_INT_ARSOP, C(44, 2), C(46, 1), C(41, 1))),
    INT_SOP3("{0}sop3{1} {2}, {3}, {4}, {5}, {6}+alrp {7}", B(42), B(42),
             FLD(K_INT_SOP3CN, F_INT_SEL3PAIR, C(52, 1), C(43, 1)), F_INT_ALRP),
    INT_SOP3("{0}lrp1{1} {2}, {3}, {4}, {5}, {6}+asop {7}", B(42), B(53),
             FLD(K_INT_LRP1C, C(45, 1), C(52, 1), C(44, 1), C(46, 1), C(43, 1)),
             FLD(K_INT_LRP1A, F_INT_SEL3PAIR, C(41, 1))),
    INT_SOP3("{0}lrp2{1} {2}, {3}, {4}, {5}, {6}+alrp {7}", B(42), B(53) | B(42),
             FLD(K_INT_LRP2C, F_INT_SEL3PAIR, C(43, 1), C(52, 1)), F_INT_ALRP),
#undef INT_SOP3

    /* ---- class 18: sop2wm ------------------------------------------------
     * The selector pair of sop3 (values 4 and 5 invalid), the colour and
     * alpha operations enc[53:52] and enc[42:41], and a byte mask in
     * enc[46:44] (bits 0-2) and enc[43] (bit 3), always printed. The oracle
     * reads none of enc[20:14] and enc[34]. */
    { "{0}sop2wm{1} {2}{3}, {4}, {5}, {6}", CLSM, CLS(18),
      { FLD(PRED_MUL, C(57, 2)), F_INT_FLAGS3, F_INT_D10,
        FLD(INT_BYTEMASK4, C(44, 3), C(43, 1)), F_INT_S1_10, F_INT_S2_10,
        FLD(K_INT_SOPWM, F_INT_SEL3PAIR, C(52, 2), C(41, 2)) } },

    /* ---- class 19: ima8 ---------------------------------------------------
     * Source 0 with .neg (enc[35]); six selectors: enc[53:52], enc[37],
     * enc[36], enc[41] and two fixed ones, complemented by enc[42], enc[56],
     * enc[47], enc[38], enc[39], enc[40]; .sat is enc[43]. */
    { "{0}ima8{1}{2} {3}, {4}, {5}, {6}, {7}", CLSM, CLS(19),
      { FLD(PRED_MUL, C(57, 2)), F_INT_MULFLAGS, FLD(INT_SAT, C(43, 1)), F_INT_D10,
        FLD(K_INT_S0N_10, C(14, 7), C(34, 1), C(35, 1)), F_INT_S1_10, F_INT_S2_10,
        FLD(K_INT_IMA8SEL, C(52, 2), C(42, 1), C(37, 1), C(56, 1), C(36, 1), C(47, 1),
            C(41, 1), C(38, 1), C(39, 1), C(40, 1)) } },

    /* ---- class 20: ima16 with every source format ------------------------
     * Formats enc[39:38] (source 1) and enc[41:40] (source 2): u16, u8, s8,
     * o8. An 8-bit source prints its half: enc[52] for source 1, enc[37] for
     * source 2. The oracle reads neither enc[47] nor, for a u16 source 2,
     * enc[37]. */
#define INT_IMA16(m, s1, s2, f) \
    { "{0}ima16{1}.{2}{3} {4}{5}, {6}, {7}, {8}, {9}", CLSM | (m), CLS(20), \
      { FLD(PRED_MUL, C(57, 2)), F_INT_MULFLAGS, FLD(SIGNSAT, C(42, 1), C(43, 1)), \
        FLD(RS, C(35, 2)), F_DST, FLD(F_ABS, C(56, 1)), F_INT_MSRC0, s1, s2, \
        FLD(K_INT_FMT16[f], C(38, 4)) } }
#define INT_S16_1 FLD(K_SRCD, C(7, 7), C(30, 2), C(49, 1))
#define INT_S8_1  FLD(K_INT_SLH, C(7, 7), C(30, 2), C(49, 1), C(52, 1))
#define INT_S16_2 FLD(K_INT_SNEG, C(0, 7), C(28, 2), C(48, 1), C(53, 1))
#define INT_S8_2  FLD(K_INT_SNLH, C(0, 7), C(28, 2), C(48, 1), C(53, 1), C(37, 1))
    INT_IMA16(M(41, 38), INT_S16_1, INT_S16_2, 0),
    INT_IMA16(M(41, 40), INT_S8_1, INT_S16_2, 1),
    INT_IMA16(M(39, 38), INT_S16_1, INT_S8_2, 2),
    INT_IMA16(0, INT_S8_1, INT_S8_2, 3),
#undef INT_S16_1
#undef INT_S8_1
#undef INT_S16_2
#undef INT_S8_2
#undef INT_IMA16

    /* ---- class 21: imae with every source-2 type and carry ----------------
     * Source-2 type enc[39:38] (z16, u16, u32; the 16-bit ones print the
     * half in enc[52]), carry out enc[40], carry in enc[41] and the carry
     * register enc[47]. */
#define INT_IMAE(m, v, s2) \
    { "{0}imae{1}.{2}{3} {4}, {5}, {6}, {7}, {8}", CLSM | (m), CLS(21) | (v), \
      { FLD(PRED_MUL, C(57, 2)), F_INT_MULFLAGS, FLD(SIGNSAT, C(42, 1), C(43, 1)), \
        FLD(RS, C(35, 3)), F_DST, FLD(K_INT_S0LH, C(14, 7), C(34, 1), C(56, 1)), \
        FLD(K_INT_SLH, C(7, 7), C(30, 2), C(49, 1), C(53, 1)), s2, \
        FLD(K_INT_IMAEC, C(38, 2), C(40, 2), C(47, 1)) } }
    INT_IMAE(B(39), B(39), F_SRC2D),
    INT_IMAE(B(39), 0, FLD(K_INT_SLH, C(0, 7), C(28, 2), C(48, 1), C(52, 1))),
#undef INT_IMAE

    /* ---- class 26: ima32 with carry and extra operand, idiv ---------------
     * ima32: enc[38] adds the operand i<enc[37:36]> after the destination,
     * enc[43:42] the carry in (i0-i2). idiv (enc[52]): destination r or pa
     * (enc[39]), sources 1 and 2, drc enc[32]. */
    { "{0}ima32{1}.{2} {3}{4}, {5}, {6}, {7}{8}", CLSM | M(53, 52), CLS(26),
      { FLD(PRED_ALL, C(56, 3)), F_INT_MULFLAGS, FLD(SU, C(41, 1)), F_DST,
        FLD(K_INT_IMA32X, C(38, 1), C(36, 2)), FLD(K_SRC0, C(14, 7), C(34, 1), C(47, 1)),
        FLD(K_INT_SNEG, C(7, 7), C(30, 2), C(49, 1), C(40, 1)),
        FLD(K_INT_SNEG, C(0, 7), C(28, 2), C(48, 1), C(39, 1)),
        FLD(K_INT_CIE32, C(42, 2)) } },
    { "{0}idiv{1} {2}, {3}, {4}, drc{5}", CLSM | M(53, 52), CLS(26) | B(52),
      { FLD(PRED_ALL, C(56, 3)), F_INT_MULFLAGS, F_LSDST, F_SRC1D, F_SRC2D,
        FLD(K_DEC, C(32, 1)) } },

    /* ---- class 24: dot products ---------------------------------------------
     * enc[56] dot4, enc[38] off, Cx enc[40:39] and Ax enc[17:16] (1, 2, 4,
     * 8), sources 1 and 2 complemented by enc[43] and enc[47]. A dot3 has an
     * alpha operation unless enc[53:52] (u16) or enc[42:41] is 3; then, as
     * for dot4, Ax follows Cx. The u8dot3 alpha: aadd/asub (enc[37] clear,
     * enc[36]) with Ax and four selectors, or aintrp1/2 with a source-0
     * operand and two; selectors enc[53:52], enc[42:41]. */
#define INT_DOT(pat, m, v, ...) \
    { pat, CLSM | (m), CLS(24) | (v), \
      { FLD(PRED_MUL, C(57, 2)), __VA_ARGS__ } }
#define INT_DOTOPS FLD(INT_OFF, C(38, 1)), F_INT_MULFLAGS, F_INT_D10, FLD(INT_X4, C(39, 2))
#define INT_DOTSRC FLD(K_INT_SC10, C(7, 7), C(30, 2), C(49, 1), C(43, 1)), \
                   FLD(K_INT_SC10, C(0, 7), C(28, 2), C(48, 1), C(47, 1))
    INT_DOT("{0}{1}dot4{2}{3} {4}, Cx{5}, Ax{6}, {7}, {8}", B(56), B(56),
            FLD(INT_DOTFMT, C(52, 2)), INT_DOTOPS, FLD(INT_X4, C(16, 2)), INT_DOTSRC),
    INT_DOT("{0}{1}dot3{2}{3} {4}, Cx{5}, Ax{6}, {7}, {8}", B(56) | M(42, 41), M(42, 41),
            FLD(INT_DOTFMT, C(52, 2)), INT_DOTOPS, FLD(INT_X4, C(16, 2)), INT_DOTSRC),
    INT_DOT("{0}u16dot3{1}{2} {3}, Cx{4}, {5}, {6}{7}", B(56) | M(53, 52), M(53, 52),
            INT_DOTOPS, INT_DOTSRC, FLD(INT_NOT3, C(41, 2))),
    INT_DOT("{0}u8dot3{1}{2} {3}, Cx{4}, {5}, {6}+{7} Ax{8}, {9}", B(56) | B(37), 0,
            INT_DOTOPS, INT_DOTSRC, FLD(INT_AADD, C(36, 1)), FLD(INT_X4, C(16, 2)),
            FLD(K_INT_DOTADD, C(52, 2), C(34, 1), C(15, 1), C(41, 2), C(35, 1))),
    INT_DOT("{0}u8dot3{1}{2} {3}, Cx{4}, {5}, {6}+{7} {8}, {9}", B(56) | B(37), B(37),
            INT_DOTOPS, INT_DOTSRC, FLD(INT_AINTRP, C(36, 1)), F_INT_S0_10,
            FLD(K_INT_DOTINTRP, C(52, 2), C(41, 2), C(35, 1))),
#undef INT_DOTSRC
#undef INT_DOTOPS
#undef INT_DOT

    /* ---- class 14: rlp -------------------------------------------------------
     * The bitwise-group flags, a write mask or (enc[53]) a repeat count, a
     * source 1 and p<enc[20:14]>; the oracle reads no source 2. */
    { "{0}rlp{1} {2}{3}, {4}, p{5}", CLSM | B(53), CLS(14),
      { FLD(PRED_ALL, C(56, 3)), F_ALUFLAGS, F_DST, FLD(WMASK, C(44, 4)), F_SRC1D,
        FLD(K_DEC, C(14, 7)) } },
    { "{0}rlp{1}{2} {3}, {4}, p{5}", CLSM | B(53), CLS(14) | B(53),
      { FLD(PRED_ALL, C(56, 3)), F_ALUFLAGS, FLD(REPEAT, C(44, 4)), F_DST, F_SRC1D,
        FLD(K_DEC, C(14, 7)) } },

#endif
