/* usse.c — SGX Series-5 USSE decoder core. Field layouts derived from the
 * SGX540 oracle disassembly by bit-correlation (solve.py). Each instruction
 * group is a `decode_fn` returning 1 (and writing the exact oracle mnemonic)
 * or 0 (defer); usse_decode tries them in order. Invariant: a decoder that
 * returns 1 must match the oracle — never a guess (see oracle_check.py). */
#include "usse.h"
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
    uint32_t raw = cbits(e, 19, 0);            /* 20-bit PC field (SGX545) */
    *is_call = cbit(e, 41) ? 1 : 0;
    *is_cond = cbits(e, 58, 56) ? 1 : 0;
    *is_rel  = (op2 == 1u) ? 1 : 0;            /* br is pc-relative */
    *off_words = (op2 == 1u && (raw & 0x80000u)) ? (int32_t)raw - (1 << 20) : (int32_t)raw;
    return 1;
}

static inline uint32_t bit(uint64_t e, unsigned n) { return (uint32_t)((e >> n) & 1u); }
static inline uint32_t bits(uint64_t e, unsigned hi, unsigned lo) {
    return (uint32_t)((e >> lo) & ((1ull << (hi - lo + 1)) - 1));
}

/* A group decoder: return 1 and write the exact mnemonic into out, or 0. */
typedef int (*decode_fn)(uint64_t e, char *out, size_t n);


/* ---- control/special no/trivial-operand ops (class 0x1F) -------------------
 * nop is a single fixed encoding; idf/wdf are a fixed signature plus a
 * 1-bit DRC selector at enc[32]. Branches (ba/br) stay deferred: the oracle's
 * targets are all <=7, so the target field above bit 2 is unexercised. */
static int decode_special(uint64_t e, char *out, size_t n) {
    if (e == 0xF800014000000000ull) { snprintf(out, n, "nop");  return 1; }
    uint64_t no_drc = e & ~(1ull << 32);
    unsigned drc = (unsigned)((e >> 32) & 1u);
    if (no_drc == 0xF820000000000000ull) { snprintf(out, n, "idf drc%u, bif", drc); return 1; }
    if (no_drc == 0xF920000000000000ull) { snprintf(out, n, "wdf drc%u", drc); return 1; }
    return 0;
}


/* ===== group: alu_logic (RE fan-out) ===== */
/* ---- alu_logic group: and/or/xor (classes 10/11 simple form) and the
 *      class-9 .test*.chan* predicate-setting form for and/or/xor/isub16/
 *      isubu16/iaddu32. ---------------------------------------------------- */

static uint32_t alu_logic_rol32(uint32_t x, unsigned r)
{
    r &= 31u;
    return r ? ((x << r) | (x >> (32u - r))) : x;
}

/* Decode the rotated immediate used by the class-10/11 simple form.
 * mantissa = enc[6:0] | enc[19:14]<<7 | enc[20]<<13 | enc[37:36]<<14
 * rot      = enc[42:38]
 * imm      = rol32(mantissa, rot). (bit43 is the invert flag, handled by caller) */
static uint32_t alu_logic_decode_imm(uint64_t e)
{
    uint32_t lo  = (uint32_t)(e & 0x7Fu);
    uint32_t mid = (uint32_t)((e >> 14) & 0x3Fu);
    uint32_t b20 = (uint32_t)((e >> 20) & 0x1u);
    uint32_t hi  = (uint32_t)((e >> 36) & 0xFFu);   /* bit43 = invert, 42:38 rot, 37:36 man */
    uint32_t manhi = hi & 0x3u;
    uint32_t rot   = (hi >> 2) & 0x1Fu;
    uint32_t mant  = lo | (mid << 7) | (b20 << 13) | (manhi << 14);
    return alu_logic_rol32(mant, rot);
}

/* predicate prefix from enc[58:56]: 0 none, 1 p0, 2 p1, 3 p2, 5 !p0, 6 !p1.
 * Writes the prefix (with trailing space) to buf; returns bytes written, or
 * -1 if the field value is not one we understand. */
static int alu_logic_pred(uint64_t e, char *buf, size_t n)
{
    unsigned p = (unsigned)((e >> 56) & 0x7u);
    switch (p) {
    case 0: buf[0] = '\0'; return 0;
    case 1: return snprintf(buf, n, "p0 ");
    case 2: return snprintf(buf, n, "p1 ");
    case 3: return snprintf(buf, n, "p2 ");
    case 4: return snprintf(buf, n, "p3 ");
    case 5: return snprintf(buf, n, "!p0 ");
    case 6: return snprintf(buf, n, "!p1 ");
    case 7: return snprintf(buf, n, "!p2 ");
    default: return -1;
    }
}

/* Class-9 test flag from enc[43:36]; returns the name or NULL if unknown. */
static const char *alu_logic_testflag(uint64_t e)
{
    switch ((unsigned)((e >> 36) & 0xFFu)) {
    case 0x18: return "testtaz";
    case 0x28: return "testtanz";
    case 0x48: return "testnat";
    case 0x88: return "testpat";
    default:   return NULL;
    }
}

static int decode_alu_logic(uint64_t e, char *out, size_t n)
{
    unsigned cls = (unsigned)((e >> 59) & 0x1Fu);

    /* ---- Simple 3-operand form: classes 10 (and/or) and 11 (xor). -------- */
    if (cls == 10 || cls == 11) {
        const char *op;
        if (cls == 11) {
            op = "xor";
        } else {
            /* class 10: bit35 selects and(0)/or(1) */
            op = ((e >> 35) & 1u) ? "or" : "and";
        }

        char pred[8];
        if (alu_logic_pred(e, pred, sizeof pred) < 0)
            return 0;

        unsigned dst = (unsigned)((e >> 21) & 0x1Fu);
        unsigned s1n = (unsigned)((e >> 7) & 0x1Fu);
        unsigned s1pa = (unsigned)((e >> 31) & 1u);   /* 1 => pa bank */
        /* src1 bank bits other than 31 must be clear for a plain r/pa. */
        if ((e >> 30) & 1u)
            return 0;

        /* src1 string */
        char s1[8];
        if (s1pa) {
            /* pa number: only pa0/pa1 observed; number field in low bits */
            snprintf(s1, sizeof s1, "pa%u", s1n);
        } else {
            snprintf(s1, sizeof s1, "r%u", s1n);
        }

        unsigned inv = (unsigned)((e >> 43) & 1u);
        unsigned isimm = (unsigned)((e >> 29) & 1u);

        char s2[24];
        if (isimm) {
            uint32_t imm = alu_logic_decode_imm(e);
            if (inv)
                snprintf(s2, sizeof s2, "~#0x%08X", imm);
            else
                snprintf(s2, sizeof s2, "#0x%08X", imm);
        } else {
            /* register src2.  Only the 'r' bank is safely decodable here:
             * guard against the g/other banks (bits 6,28,48) and any imm. */
            if (((e >> 6) & 1u) || ((e >> 26) & 0xFu) || ((e >> 48) & 1u))
                return 0;
            unsigned s2n = (unsigned)(e & 0x1Fu);
            if (inv)
                snprintf(s2, sizeof s2, "~r%u", s2n);
            else
                snprintf(s2, sizeof s2, "r%u", s2n);
        }

        snprintf(out, n, "%s%s r%u, %s, %s", pred, op, dst, s1, s2);
        return 1;
    }

    /* ---- Class 9: predicate-setting .test*.chan* form. ------------------- *
     * Four observed sub-forms, each with a distinct constant "frame" of bits
     * that we require to match so we never fire on an encoding whose
     * unexplained bits differ from ground truth.                            */
    if (cls == 9) {
        char pred[8];
        if (alu_logic_pred(e, pred, sizeof pred) < 0)
            return 0;

        const char *test = alu_logic_testflag(e);
        unsigned pg  = (unsigned)((e >> 34) & 0x3u);
        unsigned s1n = (unsigned)((e >> 7) & 0x1Fu);
        unsigned s2n = (unsigned)(e & 0x1Fu);
        unsigned dst = (unsigned)((e >> 21) & 0x1Fu);

        /* ---- Form A: and/or/xor.TEST.chan0 !c0, pG, src1, src2 ---------- *
         * src2 is a register (bit29=0) or a small decimal imm (bit29=1,
         * value in enc[6:0]).                                             */
        {
            const uint64_t FRAME_MASK = 0xF8FEF0035FFF3000ULL;
            const uint64_t FRAME_VAL  = 0x48081001000C0000ULL;
            if ((e & FRAME_MASK) == FRAME_VAL && test) {
                const char *op;
                unsigned b14 = (unsigned)((e >> 14) & 1u);
                unsigned b15 = (unsigned)((e >> 15) & 1u);
                if (b15 && !b14)       op = "xor";
                else if (b14 && !b15)  op = "or";
                else if (!b14 && !b15) op = "and";
                else return 0;

                /* src1: r bank only (bit31 must be 0). */
                if ((e >> 31) & 1u)
                    return 0;

                unsigned isimm = (unsigned)((e >> 29) & 1u);
                char s2[16];
                if (isimm)
                    snprintf(s2, sizeof s2, "#%u", (unsigned)(e & 0x7Fu));
                else
                    snprintf(s2, sizeof s2, "r%u", s2n);

                snprintf(out, n, "%s%s.%s.chan0 !c0, p%u, r%u, %s",
                         pred, op, test, pg, s1n, s2);
                return 1;
            }
        }

        /* ---- isub16/isubu16.TEST.chan0 rN, pG, src1, #imm -------------- *
         * dest==src1 always; imm in enc[6:0]. op bits 16/17 select. ------ */
        {
            const uint64_t FRAME_MASK = 0xF8FFF003FC1C3000ULL;
            const uint64_t FRAME_VAL  = 0x4801100020140000ULL;
            if ((e & FRAME_MASK) == FRAME_VAL && test) {
                unsigned b16 = (unsigned)((e >> 16) & 1u);
                unsigned b17 = (unsigned)((e >> 17) & 1u);
                const char *op;
                if (b16 && !b17)      op = "isub16";
                else if (!b16 && b17) op = "isubu16";
                else return 0;
                snprintf(out, n, "%s%s.%s.chan0 r%u, p%u, r%u, #%u",
                         pred, op, test, dst, pg, s1n, (unsigned)(e & 0x7Fu));
                return 1;
            }
        }

        /* ---- iaddu32.TEST.chan0 rN, pG, #imm, src2 -------------------- *
         * dest==src2 always; imm always 1 in corpus (frame-pinned). ----- */
        {
            const uint64_t FRAME_MASK = 0xF8FFF003FC1FFFE0ULL;
            const uint64_t FRAME_VAL  = 0x4802100080174080ULL;
            if ((e & FRAME_MASK) == FRAME_VAL && test) {
                snprintf(out, n, "%siaddu32.%s.chan0 r%u, p%u, #1, r%u",
                         pred, test, dst, pg, s2n);
                return 1;
            }
        }

        /* ---- isub16.TEST.chan0 !c0, pG, src1, src2 (predicate dest) ---- */
        {
            const uint64_t FRAME_MASK = 0xF8FFF003DFFC3060ULL;
            const uint64_t FRAME_VAL  = 0x4808100100040000ULL;
            if ((e & FRAME_MASK) == FRAME_VAL && test) {
                /* only isub16 observed in this form */
                snprintf(out, n, "%sisub16.%s.chan0 !c0, p%u, r%u, r%u",
                         pred, test, pg, s1n, s2n);
                return 1;
            }
        }

        return 0;
    }

    return 0;
}

/* ===== group: alu_shift (RE fan-out) ===== */
static inline uint32_t alu_shift_bits(uint64_t e, int hi, int lo)
{
    return (uint32_t)((e >> lo) & ((1ULL << (hi - lo + 1)) - 1ULL));
}

/* Decode predicate prefix from bits[58:56] (valid only within shift classes).
 * Returns pointer to a static string ("", "p0 ", ...) or NULL if the code is
 * one not observed in the oracle for these classes (defer). */
static const char *alu_shift_pred(uint64_t e)
{
    switch (alu_shift_bits(e, 58, 56)) {
    case 0: return "";
    case 1: return "p0 ";
    case 2: return "p1 ";
    case 5: return "!p0 ";
    case 6: return "!p1 ";
    default: return NULL;
    }
}

static int decode_alu_shift(uint64_t e, char *out, size_t n)
{
    unsigned cls = (unsigned)((e >> 59) & 0x1f);

    /* Standard register,register,#imm form: class 12 (shl/rol), 13 (shr). */
    if (cls == 12 || cls == 13) {
        const char *pred = alu_shift_pred(e);
        if (!pred)
            return 0;

        /* Source-format selectors: only the rr_imm form (src1 register,
         * src2 immediate) is determined by the oracle. */
        if (((e >> 44) & 1) != 1) return 0;
        if (((e >> 48) & 1) != 1) return 0;
        if (((e >> 49) & 1) != 0) return 0;
        if (((e >> 29) & 1) != 1) return 0;
        if (((e >> 30) & 1) != 0) return 0;

        unsigned b35 = (unsigned)((e >> 35) & 1);
        const char *op;
        if (cls == 12) {
            op = b35 ? "rol" : "shl";
        } else { /* cls == 13 */
            if (b35) return 0;
            op = "shr";
        }

        /* Enforce the full constant template: any encoding bit not belonging
         * to a known field must match the canonical fixed value, else defer. */
        uint64_t accounted = 0;
        for (int b = 56; b <= 58; b++) accounted |= (1ULL << b); /* pred  */
        for (int b = 21; b <= 25; b++) accounted |= (1ULL << b); /* dst   */
        for (int b = 7;  b <= 11; b++) accounted |= (1ULL << b); /* src1  */
        for (int b = 0;  b <= 4;  b++) accounted |= (1ULL << b); /* imm   */
        accounted |= (1ULL << 35);                               /* op    */
        for (int b = 59; b <= 63; b++) accounted |= (1ULL << b); /* class */

        static const int fixed1[] = {29, 44, 48};
        uint64_t rest = e & ~accounted;
        for (unsigned i = 0; i < sizeof(fixed1) / sizeof(fixed1[0]); i++)
            rest &= ~(1ULL << fixed1[i]);
        if (rest != 0)
            return 0;
        for (unsigned i = 0; i < sizeof(fixed1) / sizeof(fixed1[0]); i++)
            if (!((e >> fixed1[i]) & 1))
                return 0;

        unsigned dst  = alu_shift_bits(e, 25, 21);
        unsigned src1 = alu_shift_bits(e, 11, 7);
        unsigned imm  = alu_shift_bits(e, 4, 0);

        snprintf(out, n, "%s%s r%u, r%u, #0x%08X", pred, op, dst, src1, imm);
        return 1;
    }

    /* Test form: class 9, "shl.testnat|testpat.chan0 !c0, pN, rM, #imm". */
    if (cls == 9) {
        const char *pred = alu_shift_pred(e);
        if (!pred)
            return 0;

        unsigned tsel = alu_shift_bits(e, 43, 42);
        const char *test;
        if (tsel == 1)      test = "testnat";
        else if (tsel == 2) test = "testpat";
        else                return 0;

        uint64_t accounted = 0;
        for (int b = 56; b <= 58; b++) accounted |= (1ULL << b); /* pred     */
        for (int b = 42; b <= 43; b++) accounted |= (1ULL << b); /* testsel  */
        for (int b = 34; b <= 35; b++) accounted |= (1ULL << b); /* pN       */
        for (int b = 7;  b <= 10; b++) accounted |= (1ULL << b); /* rM       */
        for (int b = 0;  b <= 4;  b++) accounted |= (1ULL << b); /* imm      */
        for (int b = 59; b <= 63; b++) accounted |= (1ULL << b); /* class    */

        static const int fixed1[] = {14, 15, 18, 19, 29, 32, 39, 44, 48, 51};
        uint64_t rest = e & ~accounted;
        for (unsigned i = 0; i < sizeof(fixed1) / sizeof(fixed1[0]); i++)
            rest &= ~(1ULL << fixed1[i]);
        if (rest != 0)
            return 0;
        for (unsigned i = 0; i < sizeof(fixed1) / sizeof(fixed1[0]); i++)
            if (!((e >> fixed1[i]) & 1))
                return 0;

        unsigned pN  = alu_shift_bits(e, 35, 34);
        unsigned rM  = alu_shift_bits(e, 10, 7);
        unsigned imm = alu_shift_bits(e, 4, 0);

        snprintf(out, n, "%sshl.%s.chan0 !c0, p%u, r%u, #%u",
                 pred, test, pN, rM, imm);
        return 1;
    }

    return 0;
}

/* ===== group: alu_mul (RE fan-out) ===== */
/* alu_mul group: imae (class 21), ima16 (class 20) integer multiply-accumulate.
 * Field layout derived from oracle:
 *   class   = e[63:59]  (20=ima16, 21=imae)
 *   pred    = e[58:57]  (0=none,1=p0,2=p1,3=!p0)
 *   su      = e[43]     (0=.u, 1=.s)
 *   dst     = e[25:21]  (r bank)
 *   src1    = e[18:14]  (r bank); imae adds .low/.high from e[56]
 *   src2    = e[12:7]   reg (6 bits) unless e[49]==1 -> immediate e[13:7] (7 bits)
 *   src3    = e[4:0]    reg unless e[48]==1 -> imm e[6:0], or e[28]==1 -> sa e[4:0]
 *   imae trailer: ", u32"; src2 printed with ".low"
 *   ima16 trailer: src3 printed with ".neg", ", u16, u16"
 *
 * Guard masks (bits that are structurally constant in the oracle for each form)
 * reject anything outside the observed envelope -> never emit wrong.
 */

#define ALU_MUL_IMAE_REQ1 0xA800008000000000ULL
#define ALU_MUL_IMAE_REQ0 0x50FCF77F4C182000ULL
#define ALU_MUL_IMA16_REQ1 0xA022080080000080ULL
#define ALU_MUL_IMA16_REQ0 0x5FDCF7FF5D9B3F6CULL

static const char *alu_mul_pred(uint64_t e)
{
    switch ((e >> 57) & 3) {
    case 0: return "";
    case 1: return "p0 ";
    case 2: return "p1 ";
    default: return "!p0 ";
    }
}

static int decode_alu_mul(uint64_t e, char *out, size_t n)
{
    unsigned cls = (e >> 59) & 0x1f;
    const char *pred = alu_mul_pred(e);
    char su = ((e >> 43) & 1) ? 's' : 'u';
    unsigned dst = (e >> 21) & 0x1f;
    unsigned s1 = (e >> 14) & 0x1f;

    if (cls == 21) {
        if ((e & ALU_MUL_IMAE_REQ1) != ALU_MUL_IMAE_REQ1) return 0;
        if ((e & ALU_MUL_IMAE_REQ0) != 0) return 0;

        const char *s1m = ((e >> 56) & 1) ? "high" : "low";
        char s2[24], s3[24];

        if ((e >> 49) & 1)
            snprintf(s2, sizeof s2, "#%u.low", (unsigned)((e >> 7) & 0x7f));
        else
            snprintf(s2, sizeof s2, "r%u.low", (unsigned)((e >> 7) & 0x3f));

        if ((e >> 48) & 1)
            snprintf(s3, sizeof s3, "#%u", (unsigned)(e & 0x7f));
        else if ((e >> 28) & 1)
            snprintf(s3, sizeof s3, "sa%u", (unsigned)(e & 0x1f));
        else
            snprintf(s3, sizeof s3, "r%u", (unsigned)(e & 0x1f));

        snprintf(out, n, "%simae.%c r%u, r%u.%s, %s, %s, u32",
                 pred, su, dst, s1, s1m, s2, s3);
        return 1;
    } else if (cls == 20) {
        if ((e & ALU_MUL_IMA16_REQ1) != ALU_MUL_IMA16_REQ1) return 0;
        if ((e & ALU_MUL_IMA16_REQ0) != 0) return 0;

        char s2[24], s3[24];

        if ((e >> 49) & 1)
            snprintf(s2, sizeof s2, "#%u", (unsigned)((e >> 7) & 0x7f));
        else
            snprintf(s2, sizeof s2, "r%u", (unsigned)((e >> 7) & 0x3f));

        if ((e >> 48) & 1)
            snprintf(s3, sizeof s3, "#%u", (unsigned)(e & 0x7f));
        else
            snprintf(s3, sizeof s3, "r%u", (unsigned)(e & 0x1f));

        snprintf(out, n, "%sima16.%c r%u, r%u, %s, %s.neg, u16, u16",
                 pred, su, dst, s1, s2, s3);
        return 1;
    }
    return 0;
}




/* ===== group: ctrl_rest (RE fan-out) ===== */
/* ctrl_rest group: str, ldr (class 31, enc[63:59]==31).
 *
 * Derived field layouts (little-endian 64-bit word):
 *   10-bit "value A" field: enc[6:0] | (enc[16:14] << 7)
 *   7-bit  "value B" field: enc[13:7]
 *   5-bit  dest reg (ldr):  enc[25:21]
 *   drc bit (ldr):          enc[32]
 *
 * Form discriminator = enc[63:48] (top 16 bits), with enc[47:33]==0 and the
 * remaining non-field bits fixed per form (captured by FIXED masks below).
 *
 *   ldr r,r,drc    0xFE20  src reg = enc[6:0]
 *   ldr r,#imm,drc 0xFE21  imm = valueA, dest = enc[25:21], drc = enc[32]
 *   str #imm,rN    0xFE29  imm = valueA, reg = enc[13:7]
 *   str rN,#imm    0xFE2A  reg = valueA, imm = enc[13:7]
 *   str #imm,#imm  0xFE2B  imm1 = valueA, imm2 = enc[13:7]
 *
 * smlsi and emitpds have too few oracle samples to fix their operand fields,
 * so they are deferred.
 */

static uint32_t ctrl_rest_valA(uint64_t e)
{
    return (uint32_t)((e & 0x7f) | (((e >> 14) & 0x7) << 7));
}

static int decode_ctrl_rest(uint64_t e, char *out, size_t n)
{
    /* Must be class 31 */
    if (((e >> 59) & 0x1f) != 31)
        return 0;

    /* ldr r,r,drc : FE20 */
    if ((e & 0xFFFFFFFEFC1FFF80ULL) == 0xFE20000000000000ULL) {
        unsigned dst = (unsigned)((e >> 21) & 0x1f);
        unsigned src = (unsigned)(e & 0x7f);
        unsigned drc = (unsigned)((e >> 32) & 1);
        snprintf(out, n, "ldr r%u, r%u, drc%u", dst, src, drc);
        return 1;
    }

    /* ldr r,#imm,drc : FE21 */
    if ((e & 0xFFFFFFFEFC1E3F80ULL) == 0xFE21000020000000ULL) {
        unsigned dst = (unsigned)((e >> 21) & 0x1f);
        unsigned imm = ctrl_rest_valA(e);
        unsigned drc = (unsigned)((e >> 32) & 1);
        snprintf(out, n, "ldr r%u, #%u, drc%u", dst, imm, drc);
        return 1;
    }

    /* str #imm, rN : FE29 */
    if ((e & 0xFFFFFFFFFFFE0000ULL) == 0xFE29000020000000ULL) {
        unsigned imm = ctrl_rest_valA(e);
        unsigned reg = (unsigned)((e >> 7) & 0x7f);
        snprintf(out, n, "str #%u, r%u", imm, reg);
        return 1;
    }

    /* str rN, #imm : FE2A */
    if ((e & 0xFFFFFFFFFFFE0000ULL) == 0xFE2A000080000000ULL) {
        unsigned reg = ctrl_rest_valA(e);
        unsigned imm = (unsigned)((e >> 7) & 0x7f);
        snprintf(out, n, "str r%u, #%u", reg, imm);
        return 1;
    }

    /* str #imm, #imm : FE2B */
    if ((e & 0xFFFFFFFFFFFE0000ULL) == 0xFE2B0000A0000000ULL) {
        unsigned imm1 = ctrl_rest_valA(e);
        unsigned imm2 = (unsigned)((e >> 7) & 0x7f);
        snprintf(out, n, "str #%u, #%u", imm1, imm2);
        return 1;
    }

    return 0;
}

/* ===== group: mov (wave2, replaces limm+mov5) ===== */
/* ===== group: mov (RE fan-out) =============================================
 * Comprehensive mov decoder covering every mov form the SGX540 oracle proves:
 *
 *   (A) limm  — long-immediate load, class 31, byte7 0xFC
 *         signature  e[63:54]==0x3F0, e[53]==1
 *         pred       e[43:41]  0=none,1=p0,2=p1,3=p2,5=!p0,6=!p1
 *         dst bank   e[52:51]  0=r, 1=sa   (+ indexed dst sa[il+#0] via e[35:26])
 *         dst reg #  e[25:21]
 *         imm32      e[20:0] | e[40:36]<<21 | e[49:44]<<26
 *       Direct dst requires e[35:26]==0; the indexed sa[il+#0] dst is the single
 *       marker 0x0C3 at e[35:26] (only the #0 offset is attested — do not
 *       generalise the offset).
 *
 *   (B) reg-to-reg — class 5 (bytes 0x28/0x29/0x2A/0x2B/0x2D)
 *         pred       e[58:56]  0=none,1=p0,2=p1,3=p2,5=!p0,6=!p1
 *         dst reg #  e[27:21], src reg # e[13:7]
 *         form       = e masked of pred/dst/src selects the operand template.
 *
 *   (C) special-register mov — class 31, byte7 0xF8 (pclink)
 *         mov pclink, rN   form 0xF80000C000000000, src e[13:7]
 *         mov rN, pclink   form 0xF800010000000000, dst e[27:21]
 *
 * Every field above was derived by bit-correlation over the oracle (see
 * movs.txt analysis); under-determined cases (unseen pred values, nonzero il
 * offset, other special regs) are deferred by returning 0. */

/* Predicate prefix shared by limm (e[43:41]) and class-5 (e[58:56]); the 3-bit
 * value encodes the same table in both. Returns 0 on an unattested value. */
static int mov_pred(unsigned p, char *out, size_t n, size_t *len) {
    const char *s;
    switch (p) {
        case 0: s = "";     break;
        case 1: s = "p0 ";  break;
        case 2: s = "p1 ";  break;
        case 3: s = "p2 ";  break;
        case 5: s = "!p0 "; break;
        case 6: s = "!p1 "; break;
        default: return 0; /* values 4,7 never observed -> defer */
    }
    int w = snprintf(out, n, "%s", s);
    if (w < 0 || (size_t)w >= n) return 0;
    *len = (size_t)w;
    return 1;
}

/* form mask for class-5: exclude pred[58:56], dst[27:21], src[13:7]. */
#define MOV5_FORM_MASK (~(((uint64_t)0x7f << 21) | ((uint64_t)0x7f << 7) \
                          | ((uint64_t)0x7 << 56)))

static int mov_limm(uint64_t e, char *out, size_t n) {
    if (bits(e, 63, 54) != 0x3F0u || !bit(e, 53)) return 0;

    size_t len = 0;
    if (!mov_pred(bits(e, 43, 41), out, n, &len)) return 0;
    char *o = out + len; size_t rem = n - len;

    uint32_t reg  = bits(e, 25, 21);
    uint32_t imm  = bits(e, 20, 0) | (bits(e, 40, 36) << 21) | (bits(e, 49, 44) << 26);
    uint32_t bank = bits(e, 52, 51);
    uint32_t didx = bits(e, 35, 26);
    int w = -1;

    if (didx == 0) {
        if (bank == 0)      w = snprintf(o, rem, "mov r%u, #0x%08X", reg, imm);
        else if (bank == 1) w = snprintf(o, rem, "mov sa%u, #0x%08X", reg, imm);
        else return 0; /* banks 2/3 not attested */
    } else if (didx == 0x0C3u && bank == 0 && reg == 0) {
        /* indexed sa dst; only sa[il + #0] attested */
        w = snprintf(o, rem, "mov sa[il + #0], #0x%08X", imm);
    } else {
        return 0; /* other indexed dst forms under-determined */
    }
    if (w < 0 || (size_t)w >= rem) return 0;
    return 1;
}

static int mov_class5(uint64_t e, char *out, size_t n) {
    if (((e >> 59) & 0x1f) != 5) return 0;

    unsigned dnum = (unsigned)((e >> 21) & 0x7f);
    unsigned snum = (unsigned)((e >> 7)  & 0x7f);
    uint64_t f = e & MOV5_FORM_MASK;

    size_t len = 0;
    if (!mov_pred((unsigned)((e >> 56) & 0x7), out, n, &len)) return 0;
    char *o = out + len; size_t rem = n - len;
    int w = -1;

    switch (f) {
        case 0x2801100020000000ULL: w = snprintf(o, rem, "mov r%u, r%u", dnum, snum); break;
        case 0x2805100020000000ULL: w = snprintf(o, rem, "mov.end r%u, r%u", dnum, snum); break;
        case 0x28011000E0000000ULL: w = snprintf(o, rem, "mov r%u, sa%u", dnum, snum); break;
        case 0x2809100020000000ULL: w = snprintf(o, rem, "mov sa%u, r%u", dnum, snum); break;
        case 0x2801100220000000ULL: w = snprintf(o, rem, "mov pa%u, r%u", dnum, snum); break;
        case 0x2809100220000000ULL: w = snprintf(o, rem, "mov i.l, r%u", snum); break;
        case 0x2803100020000000ULL: w = snprintf(o, rem, "mov r%u, sa[il + #0]", dnum); break;
        case 0x2801100320000000ULL: w = snprintf(o, rem, "mov sa[il + #0], r%u", snum); break;
        default: return 0;
    }
    if (w < 0 || (size_t)w >= rem) return 0;
    return 1;
}

static int mov_special(uint64_t e, char *out, size_t n) {
    unsigned dnum = (unsigned)((e >> 21) & 0x7f);
    unsigned snum = (unsigned)((e >> 7)  & 0x7f);
    uint64_t f = e & ~(((uint64_t)0x7f << 21) | ((uint64_t)0x7f << 7));
    int w = -1;

    if (f == 0xF80000C000000000ULL)      w = snprintf(out, n, "mov pclink, r%u", snum);
    else if (f == 0xF800010000000000ULL) w = snprintf(out, n, "mov r%u, pclink", dnum);
    else return 0;

    if (w < 0 || (size_t)w >= n) return 0;
    return 1;
}

static int decode_mov(uint64_t e, char *out, size_t n) {
    if (mov_limm(e, out, n))    return 1;
    if (mov_class5(e, out, n))  return 1;
    if (mov_special(e, out, n)) return 1;
    return 0;
}

/* ===== group: alu_ext (wave2) ===== */
/* ===== group: alu_ext (RE fan-out) ===== *
 * Additional integer ALU/shift operand banks and forms that the primary
 * alu_logic / alu_shift decoders defer.  Runs AFTER them, so it only ever
 * sees encodings those two declined.  Field layouts are derived from the
 * SGX540 oracle:
 *   - cls12/13 shift: extra src1 banks (g / immediate) and register src2.
 *   - cls11/10 logic: g-bank src2.
 *   - cls9 test:  pa-bank src1 (form A), register destination + imm src2,
 *                 and the all-immediate (imm src1 + imm src2) form.
 * Every sub-form is frame-pinned: non-field bits must equal the oracle's
 * canonical constant, so the decoder can never emit a confident-but-wrong
 * line (see oracle_check.py — WRONG must stay 0). */

/* predicate prefix from enc[58:56], shared encoding with alu_logic_pred. */
static int alu_ext_pred(uint64_t e, char *buf, size_t n)
{
    switch ((unsigned)((e >> 56) & 0x7u)) {
    case 0: buf[0] = '\0'; return 0;
    case 1: return snprintf(buf, n, "p0 ");
    case 2: return snprintf(buf, n, "p1 ");
    case 3: return snprintf(buf, n, "p2 ");
    case 4: return snprintf(buf, n, "p3 ");
    case 5: return snprintf(buf, n, "!p0 ");
    case 6: return snprintf(buf, n, "!p1 ");
    case 7: return snprintf(buf, n, "!p2 ");
    default: return -1;
    }
}

/* Reuse class-9 test-flag mapping (enc[43:36]). */
static const char *alu_ext_testflag(uint64_t e)
{
    switch ((unsigned)((e >> 36) & 0xFFu)) {
    case 0x18: return "testtaz";
    case 0x28: return "testtanz";
    case 0x48: return "testnat";
    case 0x88: return "testpat";
    default:   return NULL;
    }
}

static int decode_alu_ext(uint64_t e, char *out, size_t n)
{
    unsigned cls = (unsigned)((e >> 59) & 0x1Fu);

    /* ---- cls12/13 shift: src1 g-bank / immediate, register src2. --------- *
     * Source-format selectors (derived over all 540 class-12/13 lines):
     *   src1 immediate  iff  bit49==1 && bit48==0  -> "#<dec>", value = e[11:7]
     *   else src1 register, bank g iff bit30==1    -> r/g<e[11:7]>
     *   src2 immediate  iff  bit48==1 && bit29==1  -> "#0x%08X", value = e[4:0]
     *   src2 register   iff  bit48==0 && bit29==0  -> bank g iff bit28==1       */
    if (cls == 12 || cls == 13) {
        char pred[8];
        if (alu_ext_pred(e, pred, sizeof pred) < 0)
            return 0;

        unsigned b35 = (unsigned)((e >> 35) & 1u);
        const char *op;
        if (cls == 12) {
            op = b35 ? "rol" : "shl";
        } else {
            if (b35) return 0;
            op = "shr";
        }

        /* Canonical shift frame: these bits are structurally constant for all
         * observed class-12/13 shift forms; anything else -> defer.          */
        const uint64_t FRAME_MASK = 0x00FCFFF70C1FD060ULL;
        const uint64_t FRAME_VAL  = 0x0000100000000000ULL;
        if ((e & FRAME_MASK) != FRAME_VAL)
            return 0;

        unsigned dst = (unsigned)((e >> 21) & 0x1Fu);

        /* src1 */
        char s1[12];
        unsigned s1imm = ((e >> 49) & 1u) && !((e >> 48) & 1u);
        if (s1imm) {
            snprintf(s1, sizeof s1, "#%u", (unsigned)((e >> 7) & 0x1Fu));
        } else {
            const char *bank = ((e >> 30) & 1u) ? "g" : "r";
            snprintf(s1, sizeof s1, "%s%u", bank, (unsigned)((e >> 7) & 0x1Fu));
        }

        /* src2 */
        char s2[16];
        unsigned s2imm = ((e >> 48) & 1u) && ((e >> 29) & 1u);
        unsigned s2reg = !((e >> 48) & 1u) && !((e >> 29) & 1u);
        if (s2imm) {
            snprintf(s2, sizeof s2, "#0x%08X", (unsigned)(e & 0x1Fu));
        } else if (s2reg) {
            const char *bank = ((e >> 28) & 1u) ? "g" : "r";
            snprintf(s2, sizeof s2, "%s%u", bank, (unsigned)(e & 0x1Fu));
        } else {
            return 0;
        }

        snprintf(out, n, "%s%s r%u, %s, %s", pred, op, dst, s1, s2);
        return 1;
    }

    /* ---- cls11/10 logic: g-bank src2 (and/or/xor). ----------------------- *
     * Identical to the alu_logic register-src2 form but src2 lives in the g
     * bank (selector bit28=1, bit48=1, bit6=1).  Field layout (dst e[25:21],
     * src1 e[11:7], src2 number e[4:0], invert e[43], op from class/bit35) is
     * the layout proven by the 1000+ class-10/11 register lines; the g-bank
     * marker bits plus the surrounding frame are pinned to the oracle.       */
    if (cls == 10 || cls == 11) {
        char pred[8];
        if (alu_ext_pred(e, pred, sizeof pred) < 0)
            return 0;

        const char *op;
        if (cls == 11) op = "xor";
        else           op = ((e >> 35) & 1u) ? "or" : "and";

        /* g-bank src2 frame.  Free fields: dst[25:21], src1[11:7], src2[4:0],
         * op bit35, invert bit43, pred[58:56], class[63:59]. */
        const uint64_t FRAME_MASK = 0x00FFF7F7FC1FF060ULL;
        const uint64_t FRAME_VAL  = 0x0001100010000040ULL;
        if ((e & FRAME_MASK) != FRAME_VAL)
            return 0;

        unsigned dst = (unsigned)((e >> 21) & 0x1Fu);
        unsigned s1  = (unsigned)((e >> 7) & 0x1Fu);
        unsigned s2  = (unsigned)(e & 0x1Fu);
        const char *inv = ((e >> 43) & 1u) ? "~" : "";

        snprintf(out, n, "%s%s r%u, r%u, %sg%u", pred, op, dst, s1, inv, s2);
        return 1;
    }

    /* ---- cls9 test forms the alu_logic decoder defers. ------------------- */
    if (cls == 9) {
        char pred[8];
        if (alu_ext_pred(e, pred, sizeof pred) < 0)
            return 0;
        const char *test = alu_ext_testflag(e);
        if (!test)
            return 0;

        /* Form A (and/or/xor.TEST.chan0 !c0, pG, src1, src2) with pa-bank
         * src1: exactly the alu_logic form-A frame plus bit31=1.  src1 number
         * from e[11:7], src2 register e[4:0].  All non-field bits pinned.    */
        {
            const uint64_t FM = 0xF8FEF0035FFF3000ULL;
            const uint64_t FV = 0x48081001000C0000ULL;
            if ((e & FM) == FV && ((e >> 31) & 1u)) {
                const char *op;
                unsigned b14 = (unsigned)((e >> 14) & 1u);
                unsigned b15 = (unsigned)((e >> 15) & 1u);
                if (b15 && !b14)       op = "xor";
                else if (b14 && !b15)  op = "or";
                else if (!b14 && !b15) op = "and";
                else return 0;
                if ((e >> 29) & 1u)     /* src2 register only in this form */
                    return 0;
                unsigned pg  = (unsigned)((e >> 34) & 0x3u);
                unsigned s1n = (unsigned)((e >> 7) & 0x1Fu);
                unsigned s2n = (unsigned)(e & 0x1Fu);
                snprintf(out, n, "%s%s.%s.chan0 !c0, p%u, pa%u, r%u",
                         pred, op, test, pg, s1n, s2n);
                return 1;
            }
        }

        /* Register-destination form with immediate src2:
         *   op.TEST.chan0 rDST, pG, rSRC1, #imm       (imm = e[6:0], dst==src1)
         * The imm field position (e[6:0]) is the one proven by the 100+ !c0
         * immediate test lines; every other bit is pinned to the oracle so we
         * only ever fire on this exact frame family.                         */
        {
            const uint64_t FM = 0xFFFFFFFFFFFFFF80ULL;
            const uint64_t FV = 0x48011180203C0080ULL;
            if ((e & FM) == FV) {
                unsigned dst = (unsigned)((e >> 21) & 0x1Fu);
                unsigned s1n = (unsigned)((e >> 7) & 0x1Fu);
                unsigned pg  = (unsigned)((e >> 34) & 0x3u);
                snprintf(out, n, "%sand.%s.chan0 r%u, p%u, r%u, #%u",
                         pred, test, dst, pg, s1n, (unsigned)(e & 0x7Fu));
                return 1;
            }
        }

        return 0;
    }

    return 0;
}

/* Register decode_alu_ext in DECODERS[] immediately after decode_alu_shift:
 *     decode_alu_logic,
 *     decode_alu_shift,
 *     decode_alu_ext,
 */

/* ===== group: ctrl_ext (wave2) ===== */
/* ===== group: ctrl_ext (class-31 special-register moves) ===== */
/*
 * Group: ctrl_ext  (class 31, enc[63:59]==31). Non-branch control/special ops.
 *
 * Findings from the oracle (all four disasm files):
 *   - The only class-31 control forms present beyond those owned by other
 *     groups (ba/br, ldr/str, idf/wdf/nop, the FC2x "mov rN,#imm"
 *     immediates) or deferred (emitpds, smlsi, lapc, lock, ci/cfi, phas) are
 *     the two special-register moves to/from the pclink register:
 *
 *       mov rX, pclink : base 0xF800010000000000, dst = enc[25:21] (5 bits)
 *       mov pclink, rX : base 0xF80000C000000000, src = enc[13:7]  (7 bits)
 *
 *     Both field layouts are fully determined across every witnessing sample
 *     (dst 0..23, src 0..23), with all remaining bits fixed and no predicate
 *     prefix ever observed on these forms. Masking out the register field and
 *     comparing against the base reproduces the exact oracle mnemonic for all
 *     occurrences, and collides with NO other class-31 encoding in the oracle.
 *   - No lock / release / wop / link (non-pclink) special-register control ops
 *     appear anywhere in the oracle, so none can be derived; deferred.
 */

static int decode_ctrl_ext(uint64_t e, char *out, size_t n)
{
    /* Must be class 31 */
    if (((e >> 59) & 0x1f) != 31)
        return 0;

    /* mov rX, pclink : F800_0100.... with dst in enc[25:21] */
    if ((e & ~(uint64_t)(0x1full << 21)) == 0xF800010000000000ULL) {
        unsigned dst = (unsigned)((e >> 21) & 0x1f);
        snprintf(out, n, "mov r%u, pclink", dst);
        return 1;
    }

    /* mov pclink, rX : F80000C0.... with src in enc[13:7] */
    if ((e & ~(uint64_t)(0x7full << 7)) == 0xF80000C000000000ULL) {
        unsigned src = (unsigned)((e >> 7) & 0x7f);
        snprintf(out, n, "mov pclink, r%u", src);
        return 1;
    }

    return 0;
}


/* ===== group: ldst (wave3, replaces load+store) ===== */
/* ===== group: ldst (RE fan-out) ===== */
/* ---- USSE load/store group: ldad/ldaw/stad/staw (major class 29=LD, 30=ST) ----
 *
 * Replaces the earlier decode_load/decode_store. Field layout is taken straight
 * from PVR_PSP2's ref_usse_disasm.c / sgxdefs.h (EURASIA_USE1_LDST_*). The USE1 fields
 * live in the upper 32-bit word, so a shift of N in the hwdefs header maps to bit
 * (N+32) of the full 64-bit instruction word; USE0 fields map directly.
 *
 *   op class      enc[63:59]            29 = LD, 30 = ST        (USE1 OP_SHIFT 27)
 *   predicate     enc[58:56]            EPRED: 0 none,1 p0,2 p1,3 p2,5 !p0,6 !p1
 *   skipinv       enc[55]               ".skipinv"              (USE1 bit23)
 *   moe_expand     enc[53]               0 => fetch-enable        (USE1 bit21)
 *   amode         enc[43:42]            0 absolute only         (USE1 AMODE_SHIFT 10)
 *   dtype         enc[37:36]            0 d(32b) 1 w(16b) 2 b(8b)(USE1 DTYPE_SHIFT 4)
 *   incsgn        enc[35]               offset sign 1 => '-'     (USE1 bit3)
 *   drcsel        enc[32]               drc number (LD)          (USE1 bit0)
 *   rmskcnt       enc[47:44]            fetchN = count+1        (USE1 RMSKCNT_SHIFT12)
 *   imode         enc[41:40]            0 none, 2 post (1 pre)   (USE1 IMODE_SHIFT 8)
 *   cache bits    enc[51] & enc[33]     see below
 *   base (src0)   reg enc[18:14]; bank enc[34](S0BANK bit2)+enc[50](S0BEXT bit18):
 *                                       {bext,bank} {0,0}=r {1,1}=sa {0,1}=pa
 *   dest  (LD)    reg enc[25:21]; bank enc[39] (DBANK bit7) primattr=>pa else r
 *   offset(src1)  enc[13:7]; bank enc[31:30](S1BANK)+enc[49](S1BEXT bit17):
 *                                       immediate {bext=1,bank=2}; reg-temp {0,0}
 *   src   (ST)    enc[6:0]; bank enc[29:28](S2BANK)+enc[48](S2BEXT bit16):
 *                                       immediate {1,2} => #n ; reg-temp {0,0} => rN
 *
 * Cache flag: SGX540 (non-extended) uses enc[51]=BPCACHE, enc[33]=FCLFILL; SGX545
 * (extended cache modes) swaps the two — enc[51]=DCCTLEXT, enc[33]=DCCTL — so there
 * ".bpcache" is enc[33]=1 and ".fcfill" is enc[51]=1. Both targets therefore agree
 * that exactly one of {enc[51],enc[33]} set spells ".bpcache", and that neither set
 * is plain, apart from one ".fcfill" load per target (the swapped bit), which this
 * decoder also prints as ".bpcache".
 *
 * Deferred (return 0): local/tiled address modes, dtype 3, pre-increment, negative
 * post-/register offsets (no sample), non-temp register offset/source banks and the
 * indexed special-register store source ("sa[il + #n]"). */

static unsigned ldst_bits(uint64_t e, int lo, int w)
{
    return (unsigned)((e >> lo) & ((1u << w) - 1u));
}

static int ldst_pred(uint64_t e, char *out, size_t n)
{
    switch (ldst_bits(e, 56, 3)) {
    case 0: out[0] = '\0';            return 1;
    case 1: snprintf(out, n, "p0 ");  return 1;
    case 2: snprintf(out, n, "p1 ");  return 1;
    case 3: snprintf(out, n, "p2 ");  return 1;
    case 5: snprintf(out, n, "!p0 "); return 1;
    case 6: snprintf(out, n, "!p1 "); return 1;
    default: return 0;                /* p3 / pNmod4: not in corpus */
    }
}

static int decode_ldst(uint64_t e, char *out, size_t n)
{
    unsigned op = ldst_bits(e, 59, 5);
    if (op != 29 && op != 30)           /* 29 = LD, 30 = ST */
        return 0;
    int is_store = (op == 30);

    /* Absolute address mode only (ldad/stad/ldaw/staw); local/tiled deferred. */
    if (ldst_bits(e, 42, 2) != 0)
        return 0;

    /* Data type -> mnemonic suffix d/w/b (reserved deferred). */
    const char *suf;
    switch (ldst_bits(e, 36, 2)) {
    case 0: suf = "d"; break;
    case 1: suf = "w"; break;
    case 2: suf = "b"; break;
    default: return 0;
    }
    char mnem[8];
    snprintf(mnem, sizeof mnem, "%s%s", is_store ? "sta" : "lda", suf);

    char pfx[8];
    if (!ldst_pred(e, pfx, sizeof pfx))
        return 0;

    /* Cache flag (see header): exactly one of enc[51]/enc[33] => .bpcache,
     * neither => plain. */
    unsigned b51 = ldst_bits(e, 51, 1);
    unsigned b33 = ldst_bits(e, 33, 1);
    if (b51 && b33)                     /* unseen combination */
        return 0;
    const char *cache = (b51 || b33) ? ".bpcache" : "";

    /* Flag suffix: .skipinv, cache, .fetchN. */
    char flags[32];
    size_t fp = 0;
    flags[0] = '\0';
    if (ldst_bits(e, 55, 1)) {          /* SKIPINV */
        int w = snprintf(flags + fp, sizeof flags - fp, ".skipinv");
        if (w < 0) return 0;
        fp += (size_t)w;
    }
    {
        int w = snprintf(flags + fp, sizeof flags - fp, "%s", cache);
        if (w < 0) return 0;
        fp += (size_t)w;
    }
    if (ldst_bits(e, 53, 1) == 0) {     /* MOEEXPAND clear => fetch enabled */
        unsigned nfetch = ldst_bits(e, 44, 4) + 1u;    /* RMSKCNT + 1 */
        int w = snprintf(flags + fp, sizeof flags - fp, ".fetch%u", nfetch);
        if (w < 0) return 0;
        fp += (size_t)w;
    }

    /* Base register (src0) + bank. */
    unsigned basen  = ldst_bits(e, 14, 5);
    unsigned s0bank = ldst_bits(e, 34, 1);
    unsigned s0bext = ldst_bits(e, 50, 1);
    const char *bbank;
    if (s0bext == 1 && s0bank == 1)      bbank = "sa";
    else if (s0bext == 0 && s0bank == 0) bbank = "r";
    else if (s0bext == 0 && s0bank == 1) bbank = "pa";
    else return 0;

    /* Offset (src1): immediate (+#n / -#n / #n++) or register ([b,+rN]). */
    unsigned imode  = ldst_bits(e, 40, 2);
    unsigned sgnbit = ldst_bits(e, 35, 1);         /* INCSGN */
    unsigned s1     = ldst_bits(e, 7, 7);
    unsigned s1bank = ldst_bits(e, 30, 2);
    unsigned s1ext  = ldst_bits(e, 49, 1);

    char addr[48];
    if (s1ext == 1 && s1bank == 2) {               /* immediate offset */
        if (imode == 2) {                          /* post-increment [b,#n++] */
            if (sgnbit) return 0;                  /* negative post-inc: no sample */
            snprintf(addr, sizeof addr, "[%s%u,#%u++]", bbank, basen, s1);
        } else if (imode == 0) {                   /* plain [b,+#n] / [b,-#n] */
            snprintf(addr, sizeof addr, "[%s%u,%c#%u]",
                     bbank, basen, sgnbit ? '-' : '+', s1);
        } else {
            return 0;                              /* pre-increment: no sample */
        }
    } else if (s1ext == 0 && s1bank == 0) {        /* register offset [b,+rN] */
        if (imode != 0 || sgnbit) return 0;        /* only +rN attested */
        snprintf(addr, sizeof addr, "[%s%u,+r%u]", bbank, basen, s1 & 0x1fu);
    } else {
        return 0;                                  /* other offset banks deferred */
    }

    if (!is_store) {
        /* Load: dest, addr, drc. */
        unsigned dst = ldst_bits(e, 21, 5);
        const char *dbank = ldst_bits(e, 39, 1) ? "pa" : "r";
        unsigned drc = ldst_bits(e, 32, 1);
        snprintf(out, n, "%s%s%s %s%u, %s, drc%u",
                 pfx, mnem, flags, dbank, dst, addr, drc);
        return 1;
    }

    /* Store: addr, source (register or immediate). */
    unsigned s2     = ldst_bits(e, 0, 7);
    unsigned s2bank = ldst_bits(e, 28, 2);
    unsigned s2ext  = ldst_bits(e, 48, 1);
    char src[24];
    if (s2ext == 1 && s2bank == 2)                 /* immediate source #n */
        snprintf(src, sizeof src, "#%u", s2);
    else if (s2ext == 0 && s2bank == 0)            /* register source rN */
        snprintf(src, sizeof src, "r%u", s2 & 0x1fu);
    else
        return 0;                                  /* other source banks deferred */
    snprintf(out, n, "%s%s%s %s, %s", pfx, mnem, flags, addr, src);
    return 1;
}

/* ===== group: rest (wave3) ===== */
/* Shared register-field extractors for the class-26 IMA32 form. */
static unsigned rest_ima32_dst(uint64_t e)  { return (unsigned)((e >> 21) & 0x7f); }
static unsigned rest_ima32_src0(uint64_t e) { return (unsigned)((e >> 14) & 0x7f); }
static unsigned rest_ima32_src1(uint64_t e) { return (unsigned)((e >> 7)  & 0x7f); }
static unsigned rest_ima32_src2(uint64_t e) { return (unsigned)(e & 0x7f); }

static int decode_rest(uint64_t e, char *out, size_t n)
{
    unsigned cls = (unsigned)((e >> 59) & 0x1f);
    uint32_t i1  = (uint32_t)(e >> 32);

    /* ---- (A) ima32 : class 26, OP2==IMA32 ------------------------------- */
    if (cls == 26) {
        /* OP2 field = word1[21:20]; only IMA32 (0) is implemented. */
        if (((i1 >> 20) & 3u) != 0u)
            return 0;

        /* Defer every form beyond the plain temp-bank MAD the ukernel uses:
         *   - any register bank != temp (D1 bank word1[1:0], S0 bank bit2 /
         *     S0BEXT bit15, S1 bank enc[31:30], S2 bank enc[29:28])
         *   - GPI-write destination (bit6), carry-in (bits[11:10])
         *   - source negate (NEGS1 bit8 / NEGS2 bit7)
         *   - repeat count (bits[14:12]) != 0, skipinv/end/nosched
         *   - any predicate (bits[26:24]) */
        unsigned d1bank  = i1 & 3u;
        unsigned s0bank  = (i1 >> 2) & 1u;
        unsigned s0bext  = (i1 >> 15) & 1u;
        unsigned s1bank  = (unsigned)((e >> 30) & 3u);
        unsigned s2bank  = (unsigned)((e >> 28) & 3u);
        unsigned gpiwen  = (i1 >> 6) & 1u;
        unsigned cien    = (i1 >> 10) & 3u;
        unsigned negs1   = (i1 >> 8) & 1u;
        unsigned negs2   = (i1 >> 7) & 1u;
        unsigned rcount  = (i1 >> 12) & 7u;
        unsigned skipinv = (i1 >> 23) & 1u;
        unsigned endf    = (i1 >> 18) & 1u;
        unsigned nosched = (i1 >> 22) & 1u;
        unsigned epred   = (i1 >> 24) & 7u;

        if (d1bank != 0u || s0bank != 0u || s0bext != 0u ||
            s1bank != 0u || s2bank != 0u)
            return 0;                 /* non-temp bank: defer */
        if (gpiwen || cien || negs1 || negs2)
            return 0;                 /* GPI / carry / negate: defer */
        if (rcount || skipinv || endf || nosched || epred)
            return 0;                 /* repeat / modifier / predicate: defer */

        unsigned sgn = (i1 >> 9) & 1u;   /* use_1_ima32_sgn */
        snprintf(out, n, "ima32.%c r%u, r%u, r%u, r%u",
                 sgn ? 's' : 'u',
                 rest_ima32_dst(e), rest_ima32_src0(e),
                 rest_ima32_src1(e), rest_ima32_src2(e));
        return 1;
    }

    /* ---- (B) nop.end / nop.nosched : class 31 FLOWCTRL NOP --------------- */
    if (cls == 31) {
        /* op_category == FLOWCTRL (word1[21:20]==0) and OP2 == NOP(5) (word1[8:6]). */
        if (((i1 >> 20) & 3u) != 0u) return 0;
        if (((i1 >> 6) & 7u) != 5u)  return 0;

        unsigned endf    = (i1 >> 18) & 1u;  /* use_1_end     */
        unsigned nosched = (i1 >> 11) & 1u;  /* use_1_nosched */

        uint32_t i0 = (uint32_t)(e & 0xffffffffu);
        uint32_t base = i1;
        if (endf)    base &= ~(1u << 18);
        if (nosched) base &= ~(1u << 11);
        if (base != 0xF8000140u || i0 != 0u)
            return 0;
        if (!endf && !nosched)
            return 0;                 /* bare nop handled by decode_special */

        /* Flag print order per ref_usse_disasm op_flags_1: .nosched before .end. */
        if (nosched && endf)      snprintf(out, n, "nop.nosched.end");
        else if (nosched)         snprintf(out, n, "nop.nosched");
        else                      snprintf(out, n, "nop.end");
        return 1;
    }

    return 0;
}

/* Append decode_rest to DECODERS[] as the final entry. */

/* ===== branch (ba/br, authoritative 20-bit offset per PVR ref_usse_disasm) ===== */
static const char *branch_pred(uint64_t e){
    static const char *P[8]={"","p0 ","p1 ","p2 ","p3 ","!p0 ","!p1 ","!p2 "};
    return P[(unsigned)((e>>56)&7u)];
}
static int decode_branch(uint64_t e, char *out, size_t n){
    if(((e>>59)&0x1fu)!=31u) return 0;      /* SPECIAL */
    if(((e>>52)&0x3u)!=0u)   return 0;       /* op_category==FLOWCTRL */
    if((e>>54)&1u)           return 0;       /* not OTHER2 */
    unsigned op2=(unsigned)((e>>38)&0x7u);
    const char *pre=branch_pred(e), *link=((e>>41)&1u)?".savelink":"";
    uint32_t off=(uint32_t)(e & 0xFFFFFu);   /* 20-bit PC field (SGX545) */
    if(op2==0u){ snprintf(out,n,"%sba%s #0x%08X",pre,link,off); return 1; }
    if(op2==1u){
        if(off & 0x80000u){ uint32_t mag=(1u<<20)-off; snprintf(out,n,"%sbr%s -#0x%08X",pre,link,mag); }
        else snprintf(out,n,"%sbr%s #0x%08X",pre,link,off);
        return 1;
    }
    return 0;
}

/* ---- INTEGRATION POINT -----------------------------------------------------
 * Verified group decoders produced by the RE fan-out get pasted above this
 * line and listed in DECODERS below. Order matters only for disambiguation;
 * the global regression (oracle_check.py) guarantees no decoder lies. */

static const decode_fn DECODERS[] = {
    decode_mov,
    decode_special,
    decode_branch,
    decode_alu_logic,
    decode_alu_ext,
    decode_alu_shift,
    decode_alu_mul,
    decode_ldst,
    decode_ctrl_rest,
    decode_ctrl_ext,
    decode_rest,
};

void usse_decode(uint64_t e, uint32_t pc, usse_insn *o) {
    (void)pc;
    o->enc = e;
    for (size_t i = 0; i < sizeof DECODERS / sizeof DECODERS[0]; i++) {
        if (DECODERS[i](e, o->text, sizeof o->text)) { o->valid = 1; return; }
    }
    /* Not yet decoded: readable class hint (invalid -> regression ignores it). */
    const char *base = usse_class_name((unsigned)(e >> 59));
    o->valid = 0;
    if (base) snprintf(o->text, sizeof o->text, "%-8s; TODO operands", base);
    else      snprintf(o->text, sizeof o->text, ".long 0x%016llX", (unsigned long long)e);
}
