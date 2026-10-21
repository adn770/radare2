/* forms/float.inc — the float family of USSE forms, included twice by usse.c:
 * with USSE_PART_DEFS for this family's operand kinds and field macros (name
 * them with a family prefix), and with USSE_PART_FORMS for its table entries.
 * Clean-room like the rest of the table: layouts come from probing the
 * refdisasm545 binary and are held to 0 wrong by random_oracle_check.py. */
#ifdef USSE_PART_DEFS
#include <stdlib.h>
#include <string.h>

/* ==== float operands =======================================================
 * A float source is a register operand plus .neg/.abs and, with the
 * instruction's f16 bit (enc[54] in the multiply-add group) set, a half-float
 * reading of the register number: numbers 64-127 then name a half of a
 * 32-bit register, (n - 64) >> 1, printed with a component suffix chosen by
 * n & 1 (".flt16.0"/".flt16.2", or ".flt16"/".flt16.2" for fsubflr). The
 * temporaries reach r0-r29 and then i0-i1. Indexed operands read the f16 bit
 * too: the bank is n[5:4], il/ih n[3] and the offset n[2:0], with the
 * first-component suffix when n[6] is set. Constants and immediates are not
 * affected. Swept bank by bank and number by number through refdisasm545. */
typedef struct {
    const char *imm;          /* format of the immediate bank */
    int f16;                  /* the half-float reading */
    const char *comp[2];      /* its component suffixes */
} flt_srcarg;

static size_t flt_put(char *out, size_t n, size_t at, const char *s) {
    int k = snprintf(out + (at < n ? at : n), at < n ? n - at : 0, "%s", s);
    return at + (size_t)k;
}

/* bank: the source-1/2 bank code (0 r, 1 o, 2 pa, 3 sa, 4 indexed, 5 c/g,
 * 6 immediate, 7 i). Return 1 when the text fits. */
static int flt_src(const flt_srcarg *a, unsigned bank, unsigned r, int neg, int abs,
                   char *out, size_t n) {
    int f16 = a->f16;
    static const char *const NAME[8] = { "r", "o", "pa", "sa", NULL, NULL, NULL, "i" };
    static const char *const IDX[4] = { "r", "o", "pa", "sa" };
    const char *suffix = "";
    int at;
    if (f16 && bank == 0 && r >= 60 && r < 64) {
        at = snprintf(out, n, "i%u", r - 60);
    } else if (!f16 || bank == 5 || bank == 6 || (bank != 4 && r < 64)) {
        if (bank == 6) at = snprintf(out, n, a->imm, r);
        else           { k_src_print(&K_SRCD, r | bank << 7, out, n); at = (int)strlen(out); }
    } else if (bank == 4) {
        at = snprintf(out, n, "%s[%s + #%u]", IDX[r >> 4 & 3], (r & 8) ? "ih" : "il", r & 7);
        if (r >= 64) suffix = a->comp[0];
    } else {
        unsigned m = (r - 64) >> 1;
        if (bank == 0 && m >= 30) at = snprintf(out, n, "i%u", m - 30);
        else                      at = snprintf(out, n, "%s%u", NAME[bank], m);
        suffix = a->comp[r & 1];
    }
    if (at < 0) return 0;
    size_t p = (size_t)at;
    if (neg) p = flt_put(out, n, p, ".neg");
    if (abs) p = flt_put(out, n, p, ".abs");
    p = flt_put(out, n, p, suffix);
    return p < n;
}

/* The encoder's side of an operand kind: rather than searching the field's
 * values for each try of each form (thousands of prints, again on every
 * backtrack), look the operand up in a table of every text the kind prints,
 * built on first use, each with its smallest value. The operand is read up
 * to a delimiter (',', '+', '=', a blank or the end; blanks inside brackets
 * collapse to one), so a kind with a parse must be followed by one in every
 * pattern that uses it. */
#define FLT_TAB_VALUES 8192u      /* wider than every kind that uses it */

/* Operand text compares in either case, as the form engine's literals do
 * (radare2 lowercases what it assembles): tables and tokens are lowercased. */
static void flt_lower(char *t) {
    for (; *t; t++) *t = (char)tolower((unsigned char)*t);
}
static int flt_ncaseeq(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return 0;
    return 1;
}
static const char *flt_casestr(const char *s, const char *pat) {
    size_t l = strlen(pat);
    for (; *s; s++)
        if (flt_ncaseeq(s, pat, l)) return s;
    return NULL;
}
typedef struct { char *t; uint32_t v; } flt_ent;
typedef struct { const usse_kind *k; flt_ent *e; size_t n; } flt_tab;

static int flt_ent_cmp(const void *a, const void *b) {
    const flt_ent *x = a, *y = b;
    int c = strcmp(x->t, y->t);
    return c ? c : (x->v > y->v) - (x->v < y->v);
}

static const flt_tab *flt_tab_get(const usse_kind *k) {
    static flt_tab tabs[64];
    static size_t ntabs;
    for (size_t i = 0; i < ntabs; i++)
        if (tabs[i].k == k) return &tabs[i];
    if (ntabs == sizeof tabs / sizeof tabs[0]) return NULL;
    flt_ent *e = malloc(FLT_TAB_VALUES * sizeof *e);
    size_t n = 0, m = 0;
    if (!e) return NULL;
    for (uint32_t v = 0; v < FLT_TAB_VALUES; v++) {
        char buf[64];
        size_t l;
        if (!k->print(k, v, buf, sizeof buf)) continue;
        flt_lower(buf);
        l = strlen(buf) + 1;               /* (no strdup: the core builds as plain C11) */
        if (!(e[n].t = malloc(l))) continue;
        memcpy(e[n].t, buf, l);
        e[n++].v = v;
    }
    qsort(e, n, sizeof *e, flt_ent_cmp);
    for (size_t i = 0; i < n; i++) {          /* keep the smallest value of each text */
        if (m && !strcmp(e[m - 1].t, e[i].t)) { free(e[i].t); continue; }
        e[m++] = e[i];
    }
    tabs[ntabs] = (flt_tab){ k, e, m };
    return &tabs[ntabs++];
}

/* Copy the operand at s into tok; return its end. */
static const char *flt_token(const char *s, char *tok, size_t size) {
    size_t n = 0;
    int br = 0;
    while (*s && n + 1 < size) {
        if (*s == '[') br = 1;
        else if (*s == ']') br = 0;
        if (!br && (*s == ',' || *s == '+' || *s == '=' || isspace((unsigned char)*s))) break;
        if (isspace((unsigned char)*s)) {
            while (isspace((unsigned char)s[1])) s++;
            tok[n++] = ' ';
            s++;
            continue;
        }
        tok[n++] = *s++;
    }
    tok[n] = '\0';
    return s;
}

static int k_flt_tab_parse(const usse_kind *k, const char *s, const char **end, uint32_t *v) {
    const flt_tab *t = flt_tab_get(k);
    char tok[64];
    if (!t) return 0;
    s = flt_token(s, tok, sizeof tok);
    flt_lower(tok);
    flt_ent key = { tok, 0 };
    size_t lo = 0, hi = t->n;              /* the first entry not below the text */
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        if (flt_ent_cmp(&t->e[mid], &key) < 0) lo = mid + 1;
        else hi = mid;
    }
    if (lo == t->n || strcmp(t->e[lo].t, tok)) return 0;
    *v = t->e[lo].v;
    *end = s;
    return 1;
}

/* The f16 bit is fixed by each form (the encoder cannot share a bit between
 * fields), so a kind is either the plain or the half-float reading. */

/* Source 1 or 2: v = number[6:0] | bank[9:7] | neg[10] | abs[11]. */
static int k_flt_src_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    return flt_src(k->arg, v >> 7 & 7, v & 0x7f, v >> 10 & 1, v >> 11 & 1, out, n);
}

/* Source 0: v = number[6:0] | pa[7] | abs[8]. */
static int k_flt_src0_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    return flt_src(k->arg, (v >> 7 & 1) ? 2 : 0, v & 0x7f, 0, v >> 8 & 1, out, n);
}

/* .incsXYZ: v = off[0] (enc[53], set: nothing printed) | enc[40] << 1 |
 * enc[46] << 2 | enc[47] << 3, printed as enc[47] enc[46] enc[40]. */
static int k_flt_incs_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    if (v & 1) out[0] = '\0';
    else       snprintf(out, n, ".incs%u%u%u", v >> 3 & 1, v >> 2 & 1, v >> 1 & 1);
    return 1;
}

static const flt_srcarg FLT_ARG_32  = { "#%u", 0, { "", "" } };
static const flt_srcarg FLT_ARG_MAD = { "#%u", 1, { ".flt16.0", ".flt16.2" } };
static const flt_srcarg FLT_ARG_FLR = { "#%u", 1, { ".flt16", ".flt16.2" } };
static const usse_kind K_FLT_SRC     = { k_flt_src_print, k_flt_tab_parse, &FLT_ARG_32 };
static const usse_kind K_FLT_SRC0    = { k_flt_src0_print, k_flt_tab_parse, &FLT_ARG_32 };
static const usse_kind K_FLT_SRC0_NP = { k_flt_src0_print, NULL, &FLT_ARG_32 };
static const usse_kind K_FLT_SRC_MAD16  = { k_flt_src_print, k_flt_tab_parse, &FLT_ARG_MAD };
static const usse_kind K_FLT_SRC0_MAD16 = { k_flt_src0_print, k_flt_tab_parse, &FLT_ARG_MAD };
static const usse_kind K_FLT_SRC_FLR16  = { k_flt_src_print, k_flt_tab_parse, &FLT_ARG_FLR };
static const usse_kind K_FLT_SRC0_FLR16 = { k_flt_src0_print, k_flt_tab_parse, &FLT_ARG_FLR };
static const usse_kind K_FLT_INCS = { k_flt_incs_print, NULL, NULL };
static const char *const FLT_FLAGS_T[] = { ".skipinv", ".syncs", ".nosched", ".end" };
/* The flags of every float form. The SGX540 reads these classes differently
 * (a write mask, source-0 negation, no .incs), so the float forms are the
 * SGX545's only: on the 540 the flags refuse to print and the word stays
 * undecoded. */
static int k_flt_flags_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    return core != 540 && k_flags_print(k, v, out, n);
}
static const usse_kind K_FLT_FLAGS = { k_flt_flags_print, NULL, FLT_FLAGS_T };

ENUM(FLT_OP_MAD, 4, "fmad", "fadm", "fmsa", NULL);          /* enc[42:41] */
ENUM(FLT_OP_MINMAX, 4, "fmaxmin", "fminmax", NULL, NULL);
ENUM(FLT_OP_DS, 4, "fdsx", "fdsy", NULL, NULL);
ENUM(FLT_REPEAT4, 4, "", ".repeat2", ".repeat3", ".repeat4");

#define F_FLT_FLAGS  FLD(K_FLT_FLAGS, C(55, 1), C(52, 1), C(43, 1), C(50, 1))
#define F_FLT_REP2   FLD(FLT_REPEAT4, C(44, 2))
#define F_FLT_INCS   FLD(K_FLT_INCS, C(53, 1), C(40, 1), C(46, 2))
#define F_FLT_SRC0(k) FLD(k, C(14, 7), C(34, 1), C(39, 1))
#define F_FLT_SRC1(k) FLD(k, C(7, 7), C(30, 2), C(49, 1), C(37, 1), C(38, 1))
#define F_FLT_SRC2(k) FLD(k, C(0, 7), C(28, 2), C(48, 1), C(35, 1), C(36, 1))
/* ... the same operands without the modifier bits (which the kinds read as 0) */
#define F_FLT_SRC0P(k) FLD(k, C(14, 7), C(34, 1))
#define F_FLT_SRC1P(k) FLD(k, C(7, 7), C(30, 2), C(49, 1))
#define F_FLT_SRC2P(k) FLD(k, C(0, 7), C(28, 2), C(48, 1))
/* a destination without the bank extension bit (enc[51] used otherwise) */
#define F_FLT_DST9   FLD(K_FLT_DST, C(21, 7), C(32, 2))
/* the shared destination with a parse (followed by a delimiter) */
#define F_FLT_DST    FLD(K_FLT_DST, C(21, 7), C(32, 2), C(51, 1))
static const usse_kind K_FLT_DST = { k_dst_print, k_flt_tab_parse, NULL };

/* ==== class 1: single-source transcendentals ================================
 * The source modifiers: v = neg[0] | abs[1] | data type[3:2] | component[5:4]
 * (enc[37], enc[38], enc[40:39], enc[36:35]). Type 1 is a half float, its
 * component enc[35] printed as 0 or 2; type 2 a c10 value with the 2-bit
 * component; type 3 is invalid. */
static int k_flt_mods1_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    unsigned t = v >> 2 & 3, c = v >> 4 & 3;
    (void)k;
    if (t == 3) return 0;
    size_t p = flt_put(out, n, 0, (v & 1) ? ".neg" : "");
    if (v & 2) p = flt_put(out, n, p, ".abs");
    if (t == 1) p += (size_t)snprintf(out + p, p < n ? n - p : 0, ".flt16.%u", (c & 1) * 2);
    if (t == 2) p += (size_t)snprintf(out + p, p < n ? n - p : 0, ".c10.%u", c);
    return p < n;
}
static const usse_kind K_FLT_MODS1 = { k_flt_mods1_print, NULL, NULL };
static const char *const FLT_FLAGS1_T[] = { ".skipinv", ".syncs", ".nosched", ".end", ".tpres" };
static const usse_kind K_FLT_FLAGS1 = { k_flt_flags_print, NULL, FLT_FLAGS1_T };
ENUM(FLT_OP_SC, 8, "frcp", "frsq", "flog", "fexp", "fsqrt", "fsin", "fcos", NULL);
#define F_FLT_FLAGS1 FLD(K_FLT_FLAGS1, C(55, 1), C(52, 1), C(43, 1), C(50, 1), C(34, 1))
#define F_FLT_MODS1  FLD(K_FLT_MODS1, C(37, 2), C(39, 2), C(35, 2))

/* ==== class 6: fmad16 =======================================================
 * Source modifiers: v = neg[0] | abs[1] | swizzle[3:2] (arg NULL), or, for
 * source 0, v = abs[0] | swizzle[2:1] (arg non-NULL: no neg bit). */
static int k_flt_m16_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    static const char *const SWZ[4] = { "", ".swzll", ".swzhh", ".swzf32" };
    if (k->arg) v <<= 1;
    size_t p = flt_put(out, n, 0, (v & 1) ? ".neg" : "");
    if (v & 2) p = flt_put(out, n, p, ".abs");
    p = flt_put(out, n, p, SWZ[v >> 2 & 3]);
    return p < n;
}
/* fmad16's repeat: v = repeat2[0] | enc[40] << 1 | enc[46] << 2 | enc[47] << 3;
 * the .incs field prints only with the repeat. */
static int k_flt_rep16_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    if (!(v & 1)) out[0] = '\0';
    else snprintf(out, n, ".repeat2.incs%u%u%u", v >> 3 & 1, v >> 2 & 1, v >> 1 & 1);
    return 1;
}
static const usse_kind K_FLT_M16  = { k_flt_m16_print, NULL, NULL };
static const usse_kind K_FLT_M16A = { k_flt_m16_print, NULL, "" };
static const usse_kind K_FLT_REP16 = { k_flt_rep16_print, NULL, NULL };
static const char *const FLT_FLAGS3_T[] = { ".skipinv", ".syncs", ".nosched" };
static const usse_kind K_FLT_FLAGS3 = { k_flt_flags_print, NULL, FLT_FLAGS3_T };

/* ==== class 7: efo ==========================================================
 * The sources print both readings, "plain/half", whenever the half-float
 * reading (as in fmad's .flt16.0/.flt16.2) differs from the plain one, each
 * with its .neg. */
static int flt_efo_src(unsigned bank, unsigned r, int neg, char *out, size_t n) {
    char a[48], b[48];
    if (!flt_src(&FLT_ARG_32, bank, r, neg, 0, a, sizeof a) ||
        !flt_src(&FLT_ARG_MAD, bank, r, neg, 0, b, sizeof b)) return 0;
    int k = strcmp(a, b) ? snprintf(out, n, "%s/%s", a, b) : snprintf(out, n, "%s", a);
    return k >= 0 && (size_t)k < n;
}
/* Source 2: v = number[6:0] | bank[9:7] | neg[10]. */
static int k_flt_efo_s2_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    return flt_efo_src(v >> 7 & 7, v & 0x7f, v >> 10 & 1, out, n);
}
/* Sources 0 and 1: v = number[6:0] | bank[8:7] | neg[9]; arg maps the bank
 * to the source-1/2 code. */
static int k_flt_efo_s01_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    const unsigned char *map = k->arg;
    return flt_efo_src(map[v >> 7 & 3], v & 0x7f, v >> 9 & 1, out, n);
}
/* v = skipinv | nosched << 1 | gpiext << 2 | repeat-1 << 3 (2 bits) */
static int k_flt_efo_flags_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    if (core == 540) return 0;
    int at = snprintf(out, n, "%s%s%s", (v & 1) ? ".skipinv" : "", (v & 2) ? ".nosched" : "",
                      (v & 4) ? ".gpiext" : "");
    if (v >> 3 && at >= 0 && (size_t)at < n) snprintf(out + at, n - at, ".repeat%u", (v >> 3) + 1);
    return 1;
}
/* The internal-register writes: v = select[1:0] (enc[51:50]) | i0 write[2]
 * (enc[42]) | i1 write[3] (enc[41]); a clear write bit prints "!". */
static int k_flt_efo_iw_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    static const char *const SEL[4][2] = { { "a0", "a1" }, { "a1", "a0" }, { "m0", "m1" },
                                           { "a0", "m1" } };
    (void)k;
    snprintf(out, n, "%si0 = %s, %si1 = %s", (v & 4) ? "" : "!", SEL[v & 3][0],
             (v & 8) ? "" : "!", SEL[v & 3][1]);
    return 1;
}
/* The adders: v = select[1:0] (enc[49:48]) | a1 negate[2] (enc[54]) |
 * a0 subtract[3] (enc[58]). Select 3 prints no comma between the two. */
static int k_flt_efo_add_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    static const char *const A[4][4] = { { "m0", "m1", "i1", "i0" }, { "m0", "src0", "i1", "i0" },
                                         { "m0", "i0", "i1", "m1" },
                                         { "src0", "src2", "src1", "src2" } };
    const char *const *a = A[v & 3];
    (void)k;
    snprintf(out, n, "a0=%s%c%s%s a1=%s%s+%s", a[0], (v & 8) ? '-' : '+', a[1],
             (v & 3) == 3 ? "" : ",", (v & 4) ? "-" : "", a[2], a[3]);
    return 1;
}
static const unsigned char FLT_EFO_S0MAP[4] = { 0, 2, 1, 3 };   /* r, pa, o, sa */
static const unsigned char FLT_EFO_S1MAP[4] = { 0, 1, 2, 3 };   /* r, o, pa, sa */
static const usse_kind K_FLT_EFO_S0 = { k_flt_efo_s01_print, k_flt_tab_parse, FLT_EFO_S0MAP };
static const usse_kind K_FLT_EFO_S1 = { k_flt_efo_s01_print, k_flt_tab_parse, FLT_EFO_S1MAP };
static const usse_kind K_FLT_EFO_S2 = { k_flt_efo_s2_print, k_flt_tab_parse, NULL };
static const usse_kind K_FLT_EFO_FLAGS = { k_flt_efo_flags_print, NULL, NULL };
static const usse_kind K_FLT_EFO_IW = { k_flt_efo_iw_print, NULL, NULL };
static const usse_kind K_FLT_EFO_ADD = { k_flt_efo_add_print, NULL, NULL };
ENUM(FLT_EFO_DSEL, 4, "i0", "i1", "a0", "a1");                 /* enc[53:52] */
ENUM(FLT_EFO_MSEL, 4, "m0=src0*src2, m1=src1*src2", "m0=src2*src1, m1=src2*src2",
     "m0=src1*src0, m1=src2*src2", "m0=src1*i0, m1=src2*i1");  /* enc[47:46] */

/* ==== class 25: fpma ========================================================
 * Operands read as c10 values: number bit 6 adds .c10 (after .neg) to the
 * register n & 63 (temporaries r0-r59, then i0-i3); indexed operands take
 * the bank from n[5:4], il/ih from n[3] and the offset from n[2:0], as in the
 * half-float reading. Constants, immediates and the destination's i.l/i.h
 * names are not affected. bank: the source-1/2 code, or 8 for i.l/i.h. */
static int flt_c10(unsigned bank, unsigned r, int neg, char *out, size_t n) {
    static const char *const NAME[8] = { "r", "o", "pa", "sa", NULL, NULL, NULL, "i" };
    static const char *const IDX[4] = { "r", "o", "pa", "sa" };
    unsigned m = r & 63;
    int at;
    if (bank == 8) return k_dst_print(&K_DST, 6u << 7 | r, out, n);
    if (bank == 5 || bank == 6) return k_src_print(&K_SRCD, bank << 7 | r, out, n);
    if (bank == 4)
        at = snprintf(out, n, "%s[%s + #%u]", IDX[r >> 4 & 3], (r & 8) ? "ih" : "il", r & 7);
    else if (bank == 0 && m >= 60)
        at = snprintf(out, n, "i%u", m - 60);
    else
        at = snprintf(out, n, "%s%u", NAME[bank], m);
    if (at < 0) return 0;
    size_t p = (size_t)at;
    if (neg) p = flt_put(out, n, p, ".neg");
    if (r & 64) p = flt_put(out, n, p, ".c10");
    return p < n;
}
/* Destination: v = number[6:0] | bank[9:7], the K_DST banks. */
static int k_flt_c10_dst_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    static const unsigned char MAP[8] = { 0, 1, 2, 4, 3, 5, 8, 7 };
    (void)k;
    return flt_c10(MAP[v >> 7 & 7], v & 0x7f, 0, out, n);
}
/* Source 0: v = number[6:0] | pa[7] | neg[8]. */
static int k_flt_c10_s0_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    return flt_c10((v >> 7 & 1) ? 2 : 0, v & 0x7f, v >> 8 & 1, out, n);
}
/* Sources 1 and 2: v = number[6:0] | bank[9:7]. */
static int k_flt_c10_src_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    return flt_c10(v >> 7 & 7, v & 0x7f, 0, out, n);
}
/* v = skipinv | nosched << 1 | end << 2 | repeat-1 << 3 (3 bits) | sat << 6 */
static int k_flt_pma_flags_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    if (core == 540) return 0;
    int at = snprintf(out, n, "%s%s%s", (v & 1) ? ".skipinv" : "", (v & 2) ? ".nosched" : "",
                      (v & 4) ? ".end" : "");
    if (v >> 3 & 7) at += snprintf(out + at, n - at, ".repeat%u", (v >> 3 & 7) + 1);
    snprintf(out + at, n - at, "%s", (v & 64) ? ".sat" : "");
    return 1;
}
/* The colour selections: v = sel0[1:0] (enc[53:52]: s0 s1 s0a s1a) |
 * comp0[2] (enc[42]) | sel1[3] (enc[37]: s1 s1a) | comp1[4] (enc[56]) |
 * sel2[5] (enc[36]: s2 s2a) | comp2[6] (enc[47]). */
static int k_flt_pma_csel_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    static const char *const S0[4] = { "s0", "s1", "s0a", "s1a" };
    (void)k;
    snprintf(out, n, "%s%s, %s%s, %s%s", S0[v & 3], (v & 4) ? ".comp" : "",
             (v & 8) ? "s1a" : "s1", (v & 16) ? ".comp" : "", (v & 32) ? "s2a" : "s2",
             (v & 64) ? ".comp" : "");
    return 1;
}
/* The alpha selections: v = sel0[0] (enc[41]: s0a s1a) | comp0[1] (enc[38]) |
 * comp1[2] (enc[39]) | comp2[3] (enc[40]). */
static int k_flt_pma_asel_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    (void)k;
    snprintf(out, n, "%s%s, s1a%s, s2a%s", (v & 1) ? "s1a" : "s0a", (v & 2) ? ".comp" : "",
             (v & 4) ? ".comp" : "", (v & 8) ? ".comp" : "");
    return 1;
}
static const usse_kind K_FLT_C10_DST = { k_flt_c10_dst_print, k_flt_tab_parse, NULL };
static const usse_kind K_FLT_C10_S0 = { k_flt_c10_s0_print, k_flt_tab_parse, NULL };
static const usse_kind K_FLT_C10_SRC = { k_flt_c10_src_print, k_flt_tab_parse, NULL };
static const usse_kind K_FLT_PMA_FLAGS = { k_flt_pma_flags_print, NULL, NULL };
static const usse_kind K_FLT_PMA_CSEL = { k_flt_pma_csel_print, NULL, NULL };
static const usse_kind K_FLT_PMA_ASEL = { k_flt_pma_asel_print, NULL, NULL };

/* ==== class 27: dual issue ==================================================
 * (mov, primary or secondary, prints a source immediate in hex) */
static const flt_srcarg FLT_ARG_32H  = { "#0x%08X", 0, { "", "" } };
static const flt_srcarg FLT_ARG_FLRH = { "#0x%08X", 1, { ".flt16", ".flt16.2" } };
static const usse_kind K_FLT_SRCH       = { k_flt_src_print, k_flt_tab_parse, &FLT_ARG_32H };
static const usse_kind K_FLT_SRC_FLR16H = { k_flt_src_print, k_flt_tab_parse, &FLT_ARG_FLRH };
/*
 * A primary operation (enc[51:50] | enc[58] << 2) on the usual operands, then
 * "+" and a secondary operation (enc[41:38]) on internal registers. A
 * secondary operand is i<sel> for a 2-bit selection, and selection 3 names the
 * primary's source of the same position (its register, without .neg). */
typedef struct {
    const flt_srcarg *st;     /* the half-float reading of the reference */
    unsigned char w;          /* width of the register bits: 8 (source 0) or 10 */
    signed char sel;          /* mov: the fixed selection; -1: v carries it */
    unsigned char twice;      /* source 0: the destination shares the selection */
} flt_refarg;

/* v = the referenced register (w bits) | selection (2 bits), or for mov the
 * enc[53] bit that picks the primary's source over i<sel>. */
static int k_flt_ref_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    const flt_refarg *a = k->arg;
    uint32_t r = v & ((1u << a->w) - 1), s = v >> a->w;
    unsigned bank = a->w == 8 ? ((r >> 7 & 1) ? 2 : 0) : r >> 7 & 7;
    char ref[48];
    int at;
    if (a->sel >= 0) {
        if (!(s & 1)) at = snprintf(out, n, "i%d", a->sel);
        else return flt_src(a->st, bank, r & 0x7f, 0, 0, out, n);
    } else if (s < 3) {
        at = a->twice ? snprintf(out, n, "i%u, i%u", s, s) : snprintf(out, n, "i%u", s);
    } else {
        if (!flt_src(a->st, bank, r & 0x7f, 0, 0, ref, sizeof ref)) return 0;
        at = snprintf(out, n, a->twice ? "i0, %s" : "%s", ref);
    }
    return at >= 0 && (size_t)at < n;
}
/* The encoder's side: a selection i<n> leaves the register bits 0 (the
 * primary's source field writes them afterwards), and a register is found
 * by trying the register values in order. Searching the whole field instead
 * would walk every don't-care register value of an i<n> selection. */
static int flt_ref_at(const flt_refarg *a, uint32_t v, const char *s, const char **end) {
    char buf[64];
    if (!k_flt_ref_print(&(usse_kind){ k_flt_ref_print, NULL, a }, v, buf, sizeof buf)) return 0;
    size_t l = strlen(buf);
    if (!flt_ncaseeq(s, buf, l) || (s[l] && s[l] != ',' && !isspace((unsigned char)s[l])))
        return 0;
    *end = s + l;
    return 1;
}
static int k_flt_ref_parse(const usse_kind *k, const char *s, const char **end, uint32_t *v) {
    const flt_refarg *a = k->arg;
    uint32_t ref = a->sel >= 0 ? 1u << a->w : 3u << a->w;
    if (a->sel >= 0) {
        if (flt_ref_at(a, 0, s, end)) { *v = 0; return 1; }
    } else {
        for (uint32_t sel = 0; sel < 3; sel++)
            if (flt_ref_at(a, sel << a->w, s, end)) { *v = sel << a->w; return 1; }
    }
    for (uint32_t r = 0; r < 1u << a->w; r++)
        if (flt_ref_at(a, ref | r, s, end)) { *v = ref | r; return 1; }
    return 0;
}
#define FLT_REF_K(a) { k_flt_ref_print, k_flt_ref_parse, &a }
#define FLT_REFS(st, arg) \
    static const flt_refarg FLT_REF_S0_##st##_A = { &arg, 8, -1, 1 }; \
    static const flt_refarg FLT_REF_S1_##st##_A = { &arg, 10, -1, 0 }; \
    static const flt_refarg FLT_REF_S2_##st##_A = { &arg, 10, -1, 0 }; \
    static const flt_refarg FLT_REF_M0_##st##_A = { &arg, 8, 0, 0 }; \
    static const flt_refarg FLT_REF_M1_##st##_A = { &arg, 10, 1, 0 }; \
    static const flt_refarg FLT_REF_M2_##st##_A = { &arg, 10, 2, 0 }; \
    static const usse_kind K_FLT_REF_S0_##st = FLT_REF_K(FLT_REF_S0_##st##_A); \
    static const usse_kind K_FLT_REF_S1_##st = FLT_REF_K(FLT_REF_S1_##st##_A); \
    static const usse_kind K_FLT_REF_S2_##st = FLT_REF_K(FLT_REF_S2_##st##_A); \
    static const usse_kind K_FLT_REF_M0_##st = FLT_REF_K(FLT_REF_M0_##st##_A); \
    static const usse_kind K_FLT_REF_M1_##st = FLT_REF_K(FLT_REF_M1_##st##_A); \
    static const usse_kind K_FLT_REF_M2_##st = FLT_REF_K(FLT_REF_M2_##st##_A)
FLT_REFS(32, FLT_ARG_32);
FLT_REFS(MAD, FLT_ARG_MAD);
FLT_REFS(FLR, FLT_ARG_FLR);
FLT_REFS(32H, FLT_ARG_32H);
FLT_REFS(FLRH, FLT_ARG_FLRH);
#undef FLT_REFS
#undef FLT_REF_K

/* The primary operation and the flags: v = operation[2:0] | skipinv[3] |
 * syncs[4] | nosched[5] | repeat2[6]; arg names the operations a form takes. */
static int k_flt_pop_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    const char *const *name = k->arg;
    if (core == 540 || !name[v & 7]) return 0;
    snprintf(out, n, "%s%s%s%s%s", name[v & 7], (v & 8) ? ".skipinv" : "",
             (v & 16) ? ".syncs" : "", (v & 32) ? ".nosched" : "", (v & 64) ? ".repeat2" : "");
    return 1;
}
static const char *const FLT_POP4_T[8] = { "fmad", NULL, "fadm", "fmsa", NULL, "fminmax", "ima32" };
static const char *const FLT_POP4M_T[8] = { "fmad", NULL, "fadm", "fmsa", NULL, "fminmax" };
static const char *const FLT_POP4F_T[8] = { [6] = "ima32" };
static const char *const FLT_POPMOV_T[8] = { [1] = "mov" };
static const char *const FLT_POPDDP_T[8] = { [4] = "fddp" };
static const char *const FLT_POPSSQ_T[8] = { [7] = "fssq" };
static const usse_kind K_FLT_POP4 = { k_flt_pop_print, NULL, FLT_POP4_T };
static const usse_kind K_FLT_POP4M = { k_flt_pop_print, NULL, FLT_POP4M_T };
static const usse_kind K_FLT_POP4F = { k_flt_pop_print, NULL, FLT_POP4F_T };
static const usse_kind K_FLT_POPMOV = { k_flt_pop_print, NULL, FLT_POPMOV_T };
static const usse_kind K_FLT_POPDDP = { k_flt_pop_print, NULL, FLT_POPDDP_T };
static const usse_kind K_FLT_POPSSQ = { k_flt_pop_print, NULL, FLT_POPSSQ_T };

/* The secondary operations, by operand shape and half-float reading. */
ENUM(FLT_SOP4, 16, [0] = "fmad", [1] = "fmad16", [2] = "fmsa", [4] = "fmaxmin", [14] = "ima32");
ENUM(FLT_SOP4M, 16, [0] = "fmad", [1] = "fmad16", [2] = "fmsa", [4] = "fmaxmin");
ENUM(FLT_SOP4F, 16, [14] = "ima32");
ENUM(FLT_SOP3, 16, [3] = "fsubflr", [11] = "fadd", [12] = "fsub", [13] = "fmul");
ENUM(FLT_SOP2, 16, [5] = "frcp", [6] = "frsq", [7] = "fexp", [8] = "flog", [9] = "fsin",
     [10] = "fcos");
ENUM(FLT_SOPMOV, 16, [15] = "mov");
ENUM(FLT_SDST, 4, "i0", "i1", "i2", "i0");                       /* enc[37] | enc[45] << 1 */

/* The secondary mov names the primary's source <sel> (fixed per form) when
 * its source is not i<sel>. The encoder's engine writes the reference's bits
 * and then the primary's source over them without comparing the two texts, so
 * a form with the wrong selection would be taken for a text whose reference
 * names another source. The primary's source kinds of those forms therefore
 * look ahead in the text and refuse a reference that is neither i<sel> nor
 * their own register as the reference prints it. Printing is the base
 * kind's. */
typedef struct {
    const usse_kind *base;
    unsigned sel;
    const flt_srcarg *ref;    /* the reference's reading */
    int src0;                 /* the base kind is a source-0 kind */
} flt_lookarg;
static int k_flt_look_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    const flt_lookarg *a = k->arg;
    return a->base->print(a->base, v, out, n);
}
static int k_flt_look_parse(const usse_kind *k, const char *s, const char **end, uint32_t *v) {
    const flt_lookarg *a = k->arg;
    const char *m = flt_casestr(s, "+mov ");
    char own[64], ref[64], isel[8];
    if (!a->base->parse(a->base, s, end, v)) return 0;
    if (!m || !(m = strchr(m, ','))) return 1;          /* not this form's text: fails later */
    for (m++; isspace((unsigned char)*m); m++) continue;
    flt_token(m, ref, sizeof ref);
    flt_lower(ref);
    snprintf(isel, sizeof isel, "i%u", a->sel);
    if (!strcmp(ref, isel)) return 1;
    unsigned bank = a->src0 ? ((*v >> 7 & 1) ? 2 : 0) : *v >> 7 & 7;
    if (!flt_src(a->ref, bank, *v & 0x7f, 0, 0, own, sizeof own)) return 0;
    flt_lower(own);
    return !strcmp(own, ref);
}
#define FLT_LOOK(base, sel, ref, src0) \
    static const flt_lookarg base##_L##sel##_A = { &base, sel, &ref, src0 }; \
    static const usse_kind base##_L##sel = \
        { k_flt_look_print, k_flt_look_parse, &base##_L##sel##_A }
FLT_LOOK(K_FLT_SRC0, 0, FLT_ARG_32H, 1);
FLT_LOOK(K_FLT_SRC, 1, FLT_ARG_32H, 0);
FLT_LOOK(K_FLT_SRC, 2, FLT_ARG_32H, 0);
FLT_LOOK(K_FLT_SRCH, 1, FLT_ARG_32H, 0);
FLT_LOOK(K_FLT_SRC0_MAD16, 0, FLT_ARG_FLRH, 1);
FLT_LOOK(K_FLT_SRC_MAD16, 1, FLT_ARG_FLRH, 0);
FLT_LOOK(K_FLT_SRC_MAD16, 2, FLT_ARG_FLRH, 0);
FLT_LOOK(K_FLT_SRC0_FLR16, 0, FLT_ARG_FLRH, 1);
FLT_LOOK(K_FLT_SRC_FLR16, 1, FLT_ARG_FLRH, 0);
FLT_LOOK(K_FLT_SRC_FLR16, 2, FLT_ARG_FLRH, 0);
FLT_LOOK(K_FLT_SRC_FLR16H, 1, FLT_ARG_FLRH, 0);
#undef FLT_LOOK

/* Secondary fields (first, so that the primary's sources are written last). */
#define FD_SOP(e)     FLD(e, C(38, 4))
#define FD_SDST       FLD(FLT_SDST, C(37, 1), C(45, 1))
#define FD_R0(st)     FLD(K_FLT_REF_S0_##st, C(14, 7), C(34, 1), C(37, 1), C(45, 1))
#define FD_R1(st)     FLD(K_FLT_REF_S1_##st, C(7, 7), C(30, 2), C(49, 1), C(46, 2))
#define FD_R2(st)     FLD(K_FLT_REF_S2_##st, C(0, 7), C(28, 2), C(48, 1), C(42, 1), C(53, 1))
#define FD_RM0(st)    FLD(K_FLT_REF_M0_##st, C(14, 7), C(34, 1), C(53, 1))
#define FD_RM1(st)    FLD(K_FLT_REF_M1_##st, C(7, 7), C(30, 2), C(49, 1), C(53, 1))
#define FD_RM2(st)    FLD(K_FLT_REF_M2_##st, C(0, 7), C(28, 2), C(48, 1), C(53, 1))
/* Primary fields */
#define FD_PRED       FLD(PRED_MUL, C(56, 2))
#define FD_MOVM       (CLSM | B(54) | M(47, 46))      /* secondary mov: a fixed selection */
#define FD_POP(k)     FLD(k, C(50, 2), C(58, 1), C(55, 1), C(52, 1), C(43, 1), C(44, 1))
#define FD_PS0(k)     FLD(k, C(14, 7), C(34, 1))
#define FD_PS1(k)     FLD(k, C(7, 7), C(30, 2), C(49, 1), C(36, 1))
#define FD_PS2(k)     FLD(k, C(0, 7), C(28, 2), C(48, 1), C(35, 1))

#endif
#ifdef USSE_PART_FORMS
    /* ---- class 0: the float multiply-add group ---------------------------- *
     * fmad/fadm/fmsa (enc[42:41] 0-2) read three sources, fsubflr (3) two.
     * enc[54] reads the sources as half floats; enc[53] clear adds .incs. */
#define FLT_MAD(f16, s0, s, sf) \
    { "{0}{1}{2}{3}{4} {5}, {6}, {7}, {8}", CLSM | B(54), CLS(0) | (f16), \
      { FLD(PRED_ALL, C(56, 3)), FLD(FLT_OP_MAD, C(41, 2)), F_FLT_FLAGS, F_FLT_REP2, \
        F_FLT_INCS, F_FLT_DST, F_FLT_SRC0(s0), F_FLT_SRC1(s), F_FLT_SRC2(s) }, B(53) }, \
    { "{0}fsubflr{1}{2}{3} {4}, {5}, {6}", CLSM | B(54) | M(42, 41), CLS(0) | (f16) | M(42, 41), \
      { FLD(PRED_ALL, C(56, 3)), F_FLT_FLAGS, F_FLT_REP2, F_FLT_INCS, F_FLT_DST, \
        F_FLT_SRC1(sf), F_FLT_SRC2(sf) }, B(53) }
    FLT_MAD(0, K_FLT_SRC0, K_FLT_SRC, K_FLT_SRC),
    FLT_MAD(B(54), K_FLT_SRC0_MAD16, K_FLT_SRC_MAD16, K_FLT_SRC_FLR16),
#undef FLT_MAD
    /* ---- class 1: frcp frsq flog fexp fsqrt fsin fcos --------------------- *
     * The operation is enc[42:41] | enc[48] << 2; source 1 is the operand.
     * enc[53] clear: a destination write mask in enc[47:44]; set: a repeat
     * count there. */
    { "{0}{1}{2} {3}{4}, {5}{6}", CLSM | B(53), CLS(1),
      { FLD(PRED_ALL, C(56, 3)), FLD(FLT_OP_SC, C(41, 2), C(48, 1)), F_FLT_FLAGS1, F_DST,
        FLD(WMASK, C(44, 4)), F_SRC1D, F_FLT_MODS1 } },
    { "{0}{1}{2}{3} {4}, {5}{6}", CLSM | B(53), CLS(1) | B(53),
      { FLD(PRED_ALL, C(56, 3)), FLD(FLT_OP_SC, C(41, 2), C(48, 1)), F_FLT_FLAGS1,
        FLD(REPEAT, C(44, 4)), F_DST, F_SRC1D, F_FLT_MODS1 } },
    /* ---- class 2: the dot products ----------------------------------------- *
     * enc[42:41]: fdp (0; enc[14] set makes it fdpc, with a cp operand in
     * enc[17:15]), fddp (1), fddpc (2); 3 is invalid. fddp/fddpc name an
     * internal register i<enc[51]> and so lose the destination's bank
     * extension; fddpc's two cp operands take the source modifier bits and
     * enc[40], and it has no .incs. enc[54] reads the sources as half floats:
     * fdp prints the first component as .flt16.0, the others as .flt16. */
#define FLT_DP(f16, s0f, sm, sf) \
    { "{0}fdp{1}{2}{3} {4}, {5}, {6}", CLSM | M(42, 41) | B(54) | B(14), CLS(2) | (f16), \
      { FLD(PRED_ALL, C(56, 3)), F_FLT_FLAGS, F_FLT_REP2, F_FLT_INCS, F_FLT_DST, F_FLT_SRC1(sm), \
        F_FLT_SRC2(sm) }, B(53) }, \
    { "{0}fdpc{1}{2}{3} {4}, cp{5}, {6}, {7}", CLSM | M(42, 41) | B(54) | B(14), \
      CLS(2) | (f16) | B(14), \
      { FLD(PRED_ALL, C(56, 3)), F_FLT_FLAGS, F_FLT_REP2, F_FLT_INCS, F_FLT_DST, \
        FLD(K_DEC, C(15, 3)), F_FLT_SRC1(sf), F_FLT_SRC2(sf) }, B(53) }, \
    { "{0}fddp{1}{2}{3} {4}, i{5}, {6}, {7}, {8}", CLSM | M(42, 41) | B(54), \
      CLS(2) | (f16) | B(41), \
      { FLD(PRED_ALL, C(56, 3)), F_FLT_FLAGS, F_FLT_REP2, F_FLT_INCS, F_FLT_DST9, \
        FLD(K_DEC, C(51, 1)), F_FLT_SRC0(s0f), F_FLT_SRC1(sf), F_FLT_SRC2(sf) }, B(53) }, \
    { "{0}fddpc{1}{2} {3}, i{4}, cp{5}, cp{6}, {7}, {8}, {9}", CLSM | M(42, 41) | B(54), \
      CLS(2) | (f16) | B(42), \
      { FLD(PRED_ALL, C(56, 3)), F_FLT_FLAGS, F_FLT_REP2, F_FLT_DST9, FLD(K_DEC, C(51, 1)), \
        FLD(K_DEC, C(35, 3)), FLD(K_DEC, C(38, 3)), F_FLT_SRC0P(s0f), F_FLT_SRC1P(sf), \
        F_FLT_SRC2P(sf) } }
    FLT_DP(0, K_FLT_SRC0, K_FLT_SRC, K_FLT_SRC),
    FLT_DP(B(54), K_FLT_SRC0_FLR16, K_FLT_SRC_MAD16, K_FLT_SRC_FLR16),
#undef FLT_DP
    /* ---- class 3: fmaxmin / fminmax ---------------------------------------- *
     * The class-0 layout, with the operation in enc[41] (enc[42] invalid). */
    { "{0}{1}{2}{3}{4} {5}, {6}, {7}, {8}", CLSM | B(54), CLS(3),
      { FLD(PRED_ALL, C(56, 3)), FLD(FLT_OP_MINMAX, C(41, 2)), F_FLT_FLAGS, F_FLT_REP2,
        F_FLT_INCS, F_FLT_DST, F_FLT_SRC0(K_FLT_SRC0), F_FLT_SRC1(K_FLT_SRC),
        F_FLT_SRC2(K_FLT_SRC) }, B(53) },
    { "{0}{1}{2}{3}{4} {5}, {6}, {7}, {8}", CLSM | B(54), CLS(3) | B(54),
      { FLD(PRED_ALL, C(56, 3)), FLD(FLT_OP_MINMAX, C(41, 2)), F_FLT_FLAGS, F_FLT_REP2,
        F_FLT_INCS, F_FLT_DST, F_FLT_SRC0(K_FLT_SRC0_MAD16), F_FLT_SRC1(K_FLT_SRC_MAD16),
        F_FLT_SRC2(K_FLT_SRC_MAD16) }, B(53) },
    /* ---- class 4: fdsx / fdsy ---------------------------------------------- *
     * Two sources (1 and 2) in the class-0 layout, the operation in enc[41]. */
#define FLT_DS(f16, s) \
    { "{0}{1}{2}{3}{4} {5}, {6}, {7}", CLSM | B(54), CLS(4) | (f16), \
      { FLD(PRED_ALL, C(56, 3)), FLD(FLT_OP_DS, C(41, 2)), F_FLT_FLAGS, F_FLT_REP2, \
        F_FLT_INCS, F_FLT_DST, F_FLT_SRC1(s), F_FLT_SRC2(s) }, B(53) }
    FLT_DS(0, K_FLT_SRC),
    FLT_DS(B(54), K_FLT_SRC_MAD16),
#undef FLT_DS
    /* ---- class 6: fmad16 --------------------------------------------------- *
     * Three sources, each with a swizzle (source 0 in enc[42:41], 1 in
     * enc[45] | enc[50] << 1, 2 in enc[54:53]); enc[44] is a repeat of 2,
     * which brings the .incs field. No .end. */
    { "{0}fmad16{1}{2} {3}, {4}{5}, {6}{7}, {8}{9}", CLSM, CLS(6),
      { FLD(PRED_ALL, C(56, 3)), FLD(K_FLT_FLAGS3, C(55, 1), C(52, 1), C(43, 1)),
        FLD(K_FLT_REP16, C(44, 1), C(40, 1), C(46, 2)), F_DST, F_FLT_SRC0P(K_FLT_SRC0_NP),
        FLD(K_FLT_M16A, C(39, 1), C(41, 2)), F_SRC1D,
        FLD(K_FLT_M16, C(37, 2), C(45, 1), C(50, 1)), F_SRC2D,
        FLD(K_FLT_M16, C(35, 2), C(53, 2)) } },
    /* ---- class 7: efo ------------------------------------------------------ *
     * Every bit is a field: the destination (no bank extension) takes one of
     * i0/i1/a0/a1, the two multipliers, two adders and the internal-register
     * writes are selections, and the three sources have a .neg each. */
    { "{0}efo{1} {2}= {3}, {4}, {5}, {6}, {7}, {8}, {9}", CLSM, CLS(7),
      { FLD(PRED_MUL, C(56, 2)),
        FLD(K_FLT_EFO_FLAGS, C(55, 1), C(43, 1), C(40, 1), C(44, 2)), F_FLT_DST9,
        FLD(FLT_EFO_DSEL, C(52, 2)), FLD(K_FLT_EFO_IW, C(50, 2), C(42, 1), C(41, 1)),
        FLD(K_FLT_EFO_ADD, C(48, 2), C(54, 1), C(58, 1)), FLD(FLT_EFO_MSEL, C(46, 2)),
        FLD(K_FLT_EFO_S0, C(14, 7), C(34, 1), C(38, 1), C(37, 1)),
        FLD(K_FLT_EFO_S1, C(7, 7), C(30, 2), C(36, 1)),
        FLD(K_FLT_EFO_S2, C(0, 7), C(28, 2), C(39, 1), C(35, 1)) } },
    /* ---- class 25: fpma ----------------------------------------------------- *
     * Destination and three sources in the c10 reading, then the colour and
     * alpha source selections with their complement (.comp) bits. */
    { "{0}fpma{1} {2}, {3}, {4}, {5}, {6}, {7}", CLSM, CLS(25),
      { FLD(PRED_MUL, C(57, 2)),
        FLD(K_FLT_PMA_FLAGS, C(55, 1), C(54, 1), C(50, 1), C(44, 3), C(43, 1)),
        FLD(K_FLT_C10_DST, C(21, 7), C(32, 2), C(51, 1)),
        FLD(K_FLT_C10_S0, C(14, 7), C(34, 1), C(35, 1)),
        FLD(K_FLT_C10_SRC, C(7, 7), C(30, 2), C(49, 1)),
        FLD(K_FLT_C10_SRC, C(0, 7), C(28, 2), C(48, 1)),
        FLD(K_FLT_PMA_CSEL, C(52, 2), C(42, 1), C(37, 1), C(56, 1), C(36, 1), C(47, 1)),
        FLD(K_FLT_PMA_ASEL, C(41, 1), C(38, 3)) } },
    /* ---- class 27: the dual-issue group ------------------------------------ *
     * One form per primary and secondary operand shape and half-float
     * reading (enc[54]); the primary's operation and flags print as one
     * field. The secondary mov's source is i<sel> or, with enc[53] set, the
     * primary's source <sel> (selection 3 is invalid), so it takes one form
     * per selection. */
    { "{4}{5} {6}, {7}, {8}, {9}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27),
      { FD_SOP(FLT_SOP4), FD_R0(32), FD_R1(32), FD_R2(32), FD_PRED, FD_POP(K_FLT_POP4), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0), FD_PS1(K_FLT_SRC), FD_PS2(K_FLT_SRC) } },
    { "{4}{5} {6}, {7}, {8}, {9}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27),
      { FD_SOP(FLT_SOP3), FD_SDST, FD_R1(32), FD_R2(32), FD_PRED, FD_POP(K_FLT_POP4), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0), FD_PS1(K_FLT_SRC), FD_PS2(K_FLT_SRC) } },
    { "{3}{4} {5}, {6}, {7}, {8}+{0} {1}, {2}", CLSM | B(54), CLS(27),
      { FD_SOP(FLT_SOP2), FD_SDST, FD_R1(32), FD_PRED, FD_POP(K_FLT_POP4), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0), FD_PS1(K_FLT_SRC), FD_PS2(K_FLT_SRC) } },
    { "{3}{4} {5}, {6}, {7}, {8}+{0} {1}, {2}", FD_MOVM, CLS(27),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM0(32H), FD_PRED, FD_POP(K_FLT_POP4), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0_L0), FD_PS1(K_FLT_SRC), FD_PS2(K_FLT_SRC) } },
    { "{3}{4} {5}, {6}, {7}, {8}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(46),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM1(32H), FD_PRED, FD_POP(K_FLT_POP4), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0), FD_PS1(K_FLT_SRC_L1), FD_PS2(K_FLT_SRC) } },
    { "{3}{4} {5}, {6}, {7}, {8}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(47),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM2(32H), FD_PRED, FD_POP(K_FLT_POP4), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0), FD_PS1(K_FLT_SRC), FD_PS2(K_FLT_SRC_L2) } },
    { "{4}{5} {6}, {7}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27),
      { FD_SOP(FLT_SOP4), FD_R0(32), FD_R1(32), FD_R2(32), FD_PRED, FD_POP(K_FLT_POPMOV),
        F_FLT_DST9, FD_PS1(K_FLT_SRCH) } },
    { "{4}{5} {6}, {7}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27),
      { FD_SOP(FLT_SOP3), FD_SDST, FD_R1(32), FD_R2(32), FD_PRED, FD_POP(K_FLT_POPMOV), F_FLT_DST9,
        FD_PS1(K_FLT_SRCH) } },
    { "{3}{4} {5}, {6}+{0} {1}, {2}", CLSM | B(54), CLS(27),
      { FD_SOP(FLT_SOP2), FD_SDST, FD_R1(32), FD_PRED, FD_POP(K_FLT_POPMOV), F_FLT_DST9,
        FD_PS1(K_FLT_SRCH) } },
    { "{3}{4} {5}, {6}+{0} {1}, {2}", FD_MOVM, CLS(27),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM0(32H), FD_PRED, FD_POP(K_FLT_POPMOV), F_FLT_DST9,
        FD_PS1(K_FLT_SRCH) } },
    { "{3}{4} {5}, {6}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(46),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM1(32H), FD_PRED, FD_POP(K_FLT_POPMOV), F_FLT_DST9,
        FD_PS1(K_FLT_SRCH_L1) } },
    { "{3}{4} {5}, {6}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(47),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM2(32H), FD_PRED, FD_POP(K_FLT_POPMOV), F_FLT_DST9,
        FD_PS1(K_FLT_SRCH) } },
    { "{4}{5} {6}, i0, {7}, {8}, {9}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27),
      { FD_SOP(FLT_SOP4), FD_R0(32), FD_R1(32), FD_R2(32), FD_PRED, FD_POP(K_FLT_POPDDP),
        F_FLT_DST9, FD_PS0(K_FLT_SRC0), FD_PS1(K_FLT_SRC), FD_PS2(K_FLT_SRC) } },
    { "{4}{5} {6}, i0, {7}, {8}, {9}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27),
      { FD_SOP(FLT_SOP3), FD_SDST, FD_R1(32), FD_R2(32), FD_PRED, FD_POP(K_FLT_POPDDP), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0), FD_PS1(K_FLT_SRC), FD_PS2(K_FLT_SRC) } },
    { "{3}{4} {5}, i0, {6}, {7}, {8}+{0} {1}, {2}", CLSM | B(54), CLS(27),
      { FD_SOP(FLT_SOP2), FD_SDST, FD_R1(32), FD_PRED, FD_POP(K_FLT_POPDDP), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0), FD_PS1(K_FLT_SRC), FD_PS2(K_FLT_SRC) } },
    { "{3}{4} {5}, i0, {6}, {7}, {8}+{0} {1}, {2}", FD_MOVM, CLS(27),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM0(32H), FD_PRED, FD_POP(K_FLT_POPDDP), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0_L0), FD_PS1(K_FLT_SRC), FD_PS2(K_FLT_SRC) } },
    { "{3}{4} {5}, i0, {6}, {7}, {8}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(46),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM1(32H), FD_PRED, FD_POP(K_FLT_POPDDP), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0), FD_PS1(K_FLT_SRC_L1), FD_PS2(K_FLT_SRC) } },
    { "{3}{4} {5}, i0, {6}, {7}, {8}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(47),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM2(32H), FD_PRED, FD_POP(K_FLT_POPDDP), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0), FD_PS1(K_FLT_SRC), FD_PS2(K_FLT_SRC_L2) } },
    { "{4}{5} {6}, {7}, {8}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27),
      { FD_SOP(FLT_SOP4), FD_R0(32), FD_R1(32), FD_R2(32), FD_PRED, FD_POP(K_FLT_POPSSQ),
        F_FLT_DST9, FD_PS1(K_FLT_SRC), FD_PS2(K_FLT_SRC) } },
    { "{4}{5} {6}, {7}, {8}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27),
      { FD_SOP(FLT_SOP3), FD_SDST, FD_R1(32), FD_R2(32), FD_PRED, FD_POP(K_FLT_POPSSQ), F_FLT_DST9,
        FD_PS1(K_FLT_SRC), FD_PS2(K_FLT_SRC) } },
    { "{3}{4} {5}, {6}, {7}+{0} {1}, {2}", CLSM | B(54), CLS(27),
      { FD_SOP(FLT_SOP2), FD_SDST, FD_R1(32), FD_PRED, FD_POP(K_FLT_POPSSQ), F_FLT_DST9,
        FD_PS1(K_FLT_SRC), FD_PS2(K_FLT_SRC) } },
    { "{3}{4} {5}, {6}, {7}+{0} {1}, {2}", FD_MOVM, CLS(27),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM0(32H), FD_PRED, FD_POP(K_FLT_POPSSQ), F_FLT_DST9,
        FD_PS1(K_FLT_SRC), FD_PS2(K_FLT_SRC) } },
    { "{3}{4} {5}, {6}, {7}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(46),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM1(32H), FD_PRED, FD_POP(K_FLT_POPSSQ), F_FLT_DST9,
        FD_PS1(K_FLT_SRC_L1), FD_PS2(K_FLT_SRC) } },
    { "{3}{4} {5}, {6}, {7}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(47),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM2(32H), FD_PRED, FD_POP(K_FLT_POPSSQ), F_FLT_DST9,
        FD_PS1(K_FLT_SRC), FD_PS2(K_FLT_SRC_L2) } },
    { "{4}{5} {6}, {7}, {8}, {9}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP4M), FD_R0(MAD), FD_R1(MAD), FD_R2(MAD), FD_PRED, FD_POP(K_FLT_POP4M),
        F_FLT_DST9, FD_PS0(K_FLT_SRC0_MAD16), FD_PS1(K_FLT_SRC_MAD16), FD_PS2(K_FLT_SRC_MAD16) } },
    { "{4}{5} {6}, {7}, {8}, {9}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP4F), FD_R0(FLR), FD_R1(FLR), FD_R2(FLR), FD_PRED, FD_POP(K_FLT_POP4M),
        F_FLT_DST9, FD_PS0(K_FLT_SRC0_MAD16), FD_PS1(K_FLT_SRC_MAD16), FD_PS2(K_FLT_SRC_MAD16) } },
    { "{4}{5} {6}, {7}, {8}, {9}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP3), FD_SDST, FD_R1(FLR), FD_R2(FLR), FD_PRED, FD_POP(K_FLT_POP4M),
        F_FLT_DST9, FD_PS0(K_FLT_SRC0_MAD16), FD_PS1(K_FLT_SRC_MAD16), FD_PS2(K_FLT_SRC_MAD16) } },
    { "{3}{4} {5}, {6}, {7}, {8}+{0} {1}, {2}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP2), FD_SDST, FD_R1(MAD), FD_PRED, FD_POP(K_FLT_POP4M), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0_MAD16), FD_PS1(K_FLT_SRC_MAD16), FD_PS2(K_FLT_SRC_MAD16) } },
    { "{3}{4} {5}, {6}, {7}, {8}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(54),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM0(FLRH), FD_PRED, FD_POP(K_FLT_POP4M), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0_MAD16_L0), FD_PS1(K_FLT_SRC_MAD16), FD_PS2(K_FLT_SRC_MAD16) } },
    { "{3}{4} {5}, {6}, {7}, {8}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(54) | B(46),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM1(FLRH), FD_PRED, FD_POP(K_FLT_POP4M), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0_MAD16), FD_PS1(K_FLT_SRC_MAD16_L1), FD_PS2(K_FLT_SRC_MAD16) } },
    { "{3}{4} {5}, {6}, {7}, {8}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(54) | B(47),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM2(FLRH), FD_PRED, FD_POP(K_FLT_POP4M), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0_MAD16), FD_PS1(K_FLT_SRC_MAD16), FD_PS2(K_FLT_SRC_MAD16_L2) } },
    { "{4}{5} {6}, {7}, {8}, {9}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP4M), FD_R0(MAD), FD_R1(MAD), FD_R2(MAD), FD_PRED, FD_POP(K_FLT_POP4F),
        F_FLT_DST9, FD_PS0(K_FLT_SRC0_FLR16), FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{4}{5} {6}, {7}, {8}, {9}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP4F), FD_R0(FLR), FD_R1(FLR), FD_R2(FLR), FD_PRED, FD_POP(K_FLT_POP4F),
        F_FLT_DST9, FD_PS0(K_FLT_SRC0_FLR16), FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{4}{5} {6}, {7}, {8}, {9}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP3), FD_SDST, FD_R1(FLR), FD_R2(FLR), FD_PRED, FD_POP(K_FLT_POP4F),
        F_FLT_DST9, FD_PS0(K_FLT_SRC0_FLR16), FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{3}{4} {5}, {6}, {7}, {8}+{0} {1}, {2}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP2), FD_SDST, FD_R1(MAD), FD_PRED, FD_POP(K_FLT_POP4F), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0_FLR16), FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{3}{4} {5}, {6}, {7}, {8}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(54),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM0(FLRH), FD_PRED, FD_POP(K_FLT_POP4F), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0_FLR16_L0), FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{3}{4} {5}, {6}, {7}, {8}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(54) | B(46),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM1(FLRH), FD_PRED, FD_POP(K_FLT_POP4F), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0_FLR16), FD_PS1(K_FLT_SRC_FLR16_L1), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{3}{4} {5}, {6}, {7}, {8}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(54) | B(47),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM2(FLRH), FD_PRED, FD_POP(K_FLT_POP4F), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0_FLR16), FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16_L2) } },
    { "{4}{5} {6}, {7}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP4M), FD_R0(MAD), FD_R1(MAD), FD_R2(MAD), FD_PRED, FD_POP(K_FLT_POPMOV),
        F_FLT_DST9, FD_PS1(K_FLT_SRC_FLR16H) } },
    { "{4}{5} {6}, {7}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP4F), FD_R0(FLR), FD_R1(FLR), FD_R2(FLR), FD_PRED, FD_POP(K_FLT_POPMOV),
        F_FLT_DST9, FD_PS1(K_FLT_SRC_FLR16H) } },
    { "{4}{5} {6}, {7}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP3), FD_SDST, FD_R1(FLR), FD_R2(FLR), FD_PRED, FD_POP(K_FLT_POPMOV),
        F_FLT_DST9, FD_PS1(K_FLT_SRC_FLR16H) } },
    { "{3}{4} {5}, {6}+{0} {1}, {2}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP2), FD_SDST, FD_R1(MAD), FD_PRED, FD_POP(K_FLT_POPMOV), F_FLT_DST9,
        FD_PS1(K_FLT_SRC_FLR16H) } },
    { "{3}{4} {5}, {6}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(54),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM0(FLRH), FD_PRED, FD_POP(K_FLT_POPMOV), F_FLT_DST9,
        FD_PS1(K_FLT_SRC_FLR16H) } },
    { "{3}{4} {5}, {6}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(54) | B(46),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM1(FLRH), FD_PRED, FD_POP(K_FLT_POPMOV), F_FLT_DST9,
        FD_PS1(K_FLT_SRC_FLR16H_L1) } },
    { "{3}{4} {5}, {6}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(54) | B(47),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM2(FLRH), FD_PRED, FD_POP(K_FLT_POPMOV), F_FLT_DST9,
        FD_PS1(K_FLT_SRC_FLR16H) } },
    { "{4}{5} {6}, i0, {7}, {8}, {9}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP4M), FD_R0(MAD), FD_R1(MAD), FD_R2(MAD), FD_PRED, FD_POP(K_FLT_POPDDP),
        F_FLT_DST9, FD_PS0(K_FLT_SRC0_FLR16), FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{4}{5} {6}, i0, {7}, {8}, {9}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP4F), FD_R0(FLR), FD_R1(FLR), FD_R2(FLR), FD_PRED, FD_POP(K_FLT_POPDDP),
        F_FLT_DST9, FD_PS0(K_FLT_SRC0_FLR16), FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{4}{5} {6}, i0, {7}, {8}, {9}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP3), FD_SDST, FD_R1(FLR), FD_R2(FLR), FD_PRED, FD_POP(K_FLT_POPDDP),
        F_FLT_DST9, FD_PS0(K_FLT_SRC0_FLR16), FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{3}{4} {5}, i0, {6}, {7}, {8}+{0} {1}, {2}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP2), FD_SDST, FD_R1(MAD), FD_PRED, FD_POP(K_FLT_POPDDP), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0_FLR16), FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{3}{4} {5}, i0, {6}, {7}, {8}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(54),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM0(FLRH), FD_PRED, FD_POP(K_FLT_POPDDP), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0_FLR16_L0), FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{3}{4} {5}, i0, {6}, {7}, {8}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(54) | B(46),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM1(FLRH), FD_PRED, FD_POP(K_FLT_POPDDP), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0_FLR16), FD_PS1(K_FLT_SRC_FLR16_L1), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{3}{4} {5}, i0, {6}, {7}, {8}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(54) | B(47),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM2(FLRH), FD_PRED, FD_POP(K_FLT_POPDDP), F_FLT_DST9,
        FD_PS0(K_FLT_SRC0_FLR16), FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16_L2) } },
    { "{4}{5} {6}, {7}, {8}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP4M), FD_R0(MAD), FD_R1(MAD), FD_R2(MAD), FD_PRED, FD_POP(K_FLT_POPSSQ),
        F_FLT_DST9, FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{4}{5} {6}, {7}, {8}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP4F), FD_R0(FLR), FD_R1(FLR), FD_R2(FLR), FD_PRED, FD_POP(K_FLT_POPSSQ),
        F_FLT_DST9, FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{4}{5} {6}, {7}, {8}+{0} {1}, {2}, {3}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP3), FD_SDST, FD_R1(FLR), FD_R2(FLR), FD_PRED, FD_POP(K_FLT_POPSSQ),
        F_FLT_DST9, FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{3}{4} {5}, {6}, {7}+{0} {1}, {2}", CLSM | B(54), CLS(27) | B(54),
      { FD_SOP(FLT_SOP2), FD_SDST, FD_R1(MAD), FD_PRED, FD_POP(K_FLT_POPSSQ), F_FLT_DST9,
        FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{3}{4} {5}, {6}, {7}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(54),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM0(FLRH), FD_PRED, FD_POP(K_FLT_POPSSQ), F_FLT_DST9,
        FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{3}{4} {5}, {6}, {7}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(54) | B(46),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM1(FLRH), FD_PRED, FD_POP(K_FLT_POPSSQ), F_FLT_DST9,
        FD_PS1(K_FLT_SRC_FLR16_L1), FD_PS2(K_FLT_SRC_FLR16) } },
    { "{3}{4} {5}, {6}, {7}+{0} {1}, {2}", FD_MOVM, CLS(27) | B(54) | B(47),
      { FD_SOP(FLT_SOPMOV), FD_SDST, FD_RM2(FLRH), FD_PRED, FD_POP(K_FLT_POPSSQ), F_FLT_DST9,
        FD_PS1(K_FLT_SRC_FLR16), FD_PS2(K_FLT_SRC_FLR16_L2) } },
#endif
