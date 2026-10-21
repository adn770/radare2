/* radare2 RArch plugin for the PowerVR SGX Series-5 USSE instruction set.
 *
 * Decoding lives in the standalone clean-room core (usse.c / usse.h), validated
 * against ground truth by oracle_check.py. This file adapts it to radare2:
 * mnemonic, op type, branch targets, a register profile, op metadata and ESIL.
 * The ESIL/metadata are layered on top by parsing the decoded mnemonic text, so
 * the disassembly output stays byte-identical to the core. 64-bit little-endian,
 * fixed 8-byte instructions.
 */
#include <r_arch.h>
#include <r_lib.h>
#include <r_util.h>
#include <stdlib.h>
#include "usse.h"
#include "usse_form.h"
#include "memop.h"

/* ---- register profile ---------------------------------------------------- */
static const char usse_profile[] =
#include "regs.h"
;

static char *regs(RArchSession *s) {
	return strdup (usse_profile);
}

/* Is r a register of the profile? ESIL must only name registers r2 knows. */
static bool reg_ok(const char *r) {
	char pat[24];
	if (!*r || strlen (r) > 16) {
		return false;
	}
	snprintf (pat, sizeof pat, "\t%s\t", r);
	return strstr (usse_profile, pat) != NULL;
}

/* ---- text-operand analysis (metadata + ESIL) ----------------------------- *
 * We parse our own regular mnemonic text (never the raw bits) into predicate +
 * base-op + args, then fill op->val / op->direction and, for the modelled
 * subset, op->esil. Conservative: an instruction gets ESIL only when every
 * operand is a profile register or an immediate with modifiers whose meaning is
 * pinned, and every flag is a scheduling flag (skipinv, syncs, nosched, end)
 * that does not change what a single instance computes. Repeats (but plain
 * mov.repeatN between disjoint ranges), partial and once-only forms, write
 * masks, the index registers, half/fixed-point formats, the p sign test and
 * the multi-channel tests are left without ESIL. Loads/stores follow memop.h,
 * including the fetch forms' extra element and the post-increment writeback;
 * ldr/str reach the SGX register file in a window above 4 GiB.
 * Floats are IEEE binary32 held in the 32-bit registers and computed through
 * ESIL's double ops (F2D ... D2F). */

static bool simple_tok(const char *t) {
	if (!t || !*t) {
		return false;
	}
	if (*t == '#') { /* immediate */
		return true;
	}
	/* a plain bank register: letters then digits, nothing else */
	const char *p = t;
	while (*p >= 'a' && *p <= 'z') {
		p++;
	}
	if (p == t) {
		return false;
	}
	while (*p >= '0' && *p <= '9') {
		p++;
	}
	return *p == '\0' && reg_ok (t);
}

/* ESIL token for a reg or #imm operand (strip the '#'). */
static const char *esil_tok(const char *t) {
	return (*t == '#') ? t + 1 : t;
}

/* ---- ALU operands --------------------------------------------------------- */

/* A source operand: [~](reg|#imm) followed by .neg/.abs/.low/.high. */
typedef struct {
	char tok[24];    /* register name or immediate text without '#' */
	bool imm;
	ut64 val;        /* immediate value */
	bool inv, neg, abs, low, high;
} UsseSrc;

static bool src_parse(const char *t, UsseSrc *s) {
	memset (s, 0, sizeof (*s));
	if (*t == '~') {
		s->inv = true;
		t++;
	}
	const char *dot = strchr (t, '.');
	size_t n = dot ? (size_t) (dot - t) : strlen (t);
	if (!n || n >= sizeof (s->tok)) {
		return false;
	}
	if (*t == '#') {
		char *end = NULL;
		if (n < 2 || t[1] < '0' || t[1] > '9') {
			return false;
		}
		s->imm = true;
		s->val = strtoull (t + 1, &end, 0);
		if (end != t + n) {
			return false;
		}
		memcpy (s->tok, t + 1, n - 1);
	} else {
		memcpy (s->tok, t, n);
		if (!simple_tok (s->tok)) {
			return false;
		}
	}
	while (dot) {
		const char *m = dot + 1;
		dot = strchr (m, '.');
		n = dot ? (size_t) (dot - m) : strlen (m);
		if (n == 3 && !strncmp (m, "neg", 3)) {
			s->neg = true;
		} else if (n == 3 && !strncmp (m, "abs", 3)) {
			s->abs = true;
		} else if (n == 3 && !strncmp (m, "low", 3)) {
			s->low = true;
		} else if (n == 4 && !strncmp (m, "high", 4)) {
			s->high = true;
		} else {
			return false;
		}
	}
	return true;
}

static bool src_plain(const UsseSrc *s) {
	return !s->inv && !s->neg && !s->abs && !s->low && !s->high;
}

/* A destination: a plain profile register (*nowrite set for a "!reg" test
 * destination, which computes without writing). */
static bool dst_ok(const char *t, bool *nowrite) {
	*nowrite = *t == '!';
	if (*nowrite) {
		t++;
	}
	return *t != '#' && simple_tok (t);
}

/* Every flag of the op word is a scheduling flag or one of extra (NULL-ended).
 * *test / *chan receive the test group's "test..." and "chan..." flags. */
static bool flags_ok(const char *opw, const char * const *extra, char *test, char *chan) {
	static const char * const sched[] = { "skipinv", "syncs", "nosched", "end", NULL };
	const char *f = strchr (opw, '.');
	if (test) {
		*test = 0;
	}
	if (chan) {
		*chan = 0;
	}
	while (f) {
		f++;
		const char *e = strchr (f, '.');
		size_t n = e ? (size_t) (e - f) : strlen (f);
		bool ok = false;
		int i;
		for (i = 0; sched[i] && !ok; i++) {
			ok = strlen (sched[i]) == n && !strncmp (f, sched[i], n);
		}
		for (i = 0; extra && extra[i] && !ok; i++) {
			ok = strlen (extra[i]) == n && !strncmp (f, extra[i], n);
		}
		if (!ok && test && !*test && n < 12 && !strncmp (f, "test", 4)) {
			memcpy (test, f, n);
			test[n] = 0;
			ok = true;
		} else if (!ok && chan && !*chan && n < 12 && !strncmp (f, "chan", 4)) {
			memcpy (chan, f, n);
			chan[n] = 0;
			ok = true;
		}
		if (!ok) {
			return false;
		}
		f = e;
	}
	return true;
}

static bool has_flag(const char *opw, const char *flag) {
	const size_t n = strlen (flag);
	const char *f = strchr (opw, '.');
	while (f) {
		f++;
		if (!strncmp (f, flag, n) && (f[n] == '.' || !f[n])) {
			return true;
		}
		f = strchr (f, '.');
	}
	return false;
}

/* Integer value of a source, inverted if it carries '~'. */
static void src_int(RStrBuf *sb, const UsseSrc *s) {
	if (s->inv) {
		r_strbuf_appendf (sb, "%s,0xffffffff,^", s->tok);
	} else {
		r_strbuf_append (sb, s->tok);
	}
}

/* 32-bit result of a two-source integer op (bitwise group, test group adds),
 * or false when its semantics are not pinned for these operands. Shift and
 * rotate amounts must be immediates below 32; only src2 may be inverted. */
static bool alu_val(RStrBuf *sb, const char *op, const UsseSrc *a, const UsseSrc *b) {
	if (a->inv || a->neg || a->abs || a->low || a->high || b->neg || b->abs || b->low || b->high) {
		return false;
	}
	const char *bw = !strcmp (op, "and") ? "&" : !strcmp (op, "or") ? "|" : !strcmp (op, "xor") ? "^" : NULL;
	if (bw) {
		src_int (sb, b);
		r_strbuf_appendf (sb, ",%s,%s", a->tok, bw);
		return true;
	}
	if (!strcmp (op, "iadd32") || !strcmp (op, "iaddu32")) {
		if (b->inv) {
			return false;
		}
		r_strbuf_appendf (sb, "%s,%s,+,0xffffffff,&", b->tok, a->tok);
		return true;
	}
	if (b->inv || !b->imm || b->val > 31) {
		return false;
	}
	const unsigned n = (unsigned) b->val;
	if (!strcmp (op, "shl")) {
		r_strbuf_appendf (sb, "%s,%s,<<,0xffffffff,&", b->tok, a->tok);
	} else if (!strcmp (op, "shr")) {
		r_strbuf_appendf (sb, "%s,%s,>>", b->tok, a->tok);
	} else if (!strcmp (op, "rol")) {
		if (n) {
			r_strbuf_appendf (sb, "%u,%s,<<,%u,%s,>>,|,0xffffffff,&", n, a->tok, 32 - n, a->tok);
		} else {
			r_strbuf_append (sb, a->tok);
		}
	} else if (!strcmp (op, "asr")) {
		/* ASR sign-extends a 32-bit register or literal (asm.bits=32) */
		r_strbuf_appendf (sb, "%u,%s,ASR,0xffffffff,&", n, a->tok);
	} else {
		return false;
	}
	return true;
}

/* Test group: "<op>.test<S><a|o><Z>.chan0 dst, pN, src1, src2" computes the
 * 32-bit result, sets pN from it and writes dst unless it is "!reg". The sign
 * test S is t (none) or n (bit 31: the firmware tests bits by shifting them to
 * the top, "shl.testnat #25"); Z is t, z or nz; a/o join them. Not modelled:
 * the p sign test (positive: > 0 or >= 0 is not pinned), a/o with a t side
 * (whether t is "true" or "not tested" matters there), sign tests of the adds,
 * channels other than chan0 and every 8/16-bit and float operation. */
static bool test_esil(RStrBuf *sb, const char *base, const char *opw, char **args, int argc) {
	static const char * const sign_ops[] = { "and", "or", "xor", "shl", "shr", "rol", "asr", NULL };
	char test[12], chan[12];
	bool nowrite, signok = false;
	UsseSrc a, b;
	int i;
	if (argc != 4 || !flags_ok (opw, NULL, test, chan) || !*test || strcmp (chan, "chan0")) {
		return false;
	}
	for (i = 0; sign_ops[i]; i++) {
		signok |= !strcmp (base, sign_ops[i]);
	}
	if (!signok && strcmp (base, "iadd32") && strcmp (base, "iaddu32")) {
		return false;
	}
	/* test<S><a|o><Z> */
	const char *t = test + 4;
	const char sgn = *t++;
	const char join = *t++;
	const char *zero = t;
	if ((sgn != 't' && sgn != 'n') || (join != 'a' && join != 'o')) {
		return false;
	}
	if (strcmp (zero, "t") && strcmp (zero, "z") && strcmp (zero, "nz")) {
		return false;
	}
	const bool st = sgn == 't', zt = !strcmp (zero, "t");
	if ((st && zt) || (join == 'o' && (st || zt)) || (!st && !signok)) {
		return false;
	}
	if (!dst_ok (args[0], &nowrite) || strlen (args[1]) != 2 || args[1][0] != 'p'
			|| args[1][1] < '0' || args[1][1] > '3') {
		return false;
	}
	if (!src_parse (args[2], &a) || !src_parse (args[3], &b)) {
		return false;
	}
	RStrBuf *v = r_strbuf_new ("");
	if (!alu_val (v, base, &a, &b)) {
		r_strbuf_free (v);
		return false;
	}
	const char *val = r_strbuf_get (v);
	if (!st) {
		r_strbuf_appendf (sb, "31,%s,>>", val);
	}
	if (!zt) {
		r_strbuf_appendf (sb, "%s%s,!%s", st ? "" : ",", val, strcmp (zero, "z") ? ",!" : "");
	}
	if (!st && !zt) {
		r_strbuf_append (sb, join == 'a' ? ",&" : ",|");
	}
	r_strbuf_appendf (sb, ",%s,=", args[1]);
	if (!nowrite) {
		r_strbuf_appendf (sb, ",%s,%s,=", val, args[0]);
	}
	r_strbuf_free (v);
	return true;
}

/* One 16-bit half of an imae source, zero- or sign-extended. */
static void src_half(RStrBuf *sb, const UsseSrc *s, bool sign) {
	if (s->imm) {
		ut64 h = (s->high ? s->val >> 16 : s->val) & 0xffff;
		if (sign && (h & 0x8000)) {
			r_strbuf_appendf (sb, "0x%"PFMT64x, h | ~(ut64)0xffff);
		} else {
			r_strbuf_appendf (sb, "%"PFMT64u, h);
		}
		return;
	}
	if (sign) {
		r_strbuf_append (sb, "16,");
	}
	if (s->high) {
		r_strbuf_appendf (sb, "16,%s,>>,0xffff,&", s->tok);
	} else {
		r_strbuf_appendf (sb, "%s,0xffff,&", s->tok);
	}
	if (sign) {
		r_strbuf_append (sb, ",~");
	}
}

/* imae.{u,s} d, a.{low,high}, b.{low,high}, c, u32: d = a16 * b16 + c, the
 * halves zero- (u) or sign-extended (s). The firmware adds with it
 * ("imae.u r2, r4.low, #1.low, r2, u32"). Saturating, carry, rs and 16-bit
 * src2 variants are not modelled. ima32.{u,s} d, a, b, c: d = a * b + c, the
 * low 32 bits (the same for either signedness). */
static bool imul_esil(RStrBuf *sb, const char *base, const char *opw, char **args, int argc) {
	static const char * const us[] = { "u", NULL };
	static const char * const ss[] = { "s", NULL };
	const bool sign = has_flag (opw, "s");
	bool nowrite;
	UsseSrc a, b, c;
	if (sign == has_flag (opw, "u") || !flags_ok (opw, sign ? ss : us, NULL, NULL)) {
		return false;
	}
	if (!strcmp (base, "imae")) {
		if (argc != 5 || strcmp (args[4], "u32")) {
			return false;
		}
	} else if (argc != 4) {
		return false;
	}
	if (!dst_ok (args[0], &nowrite) || nowrite || !src_parse (args[1], &a)
			|| !src_parse (args[2], &b) || !src_parse (args[3], &c) || !src_plain (&c)) {
		return false;
	}
	r_strbuf_appendf (sb, "%s,", c.tok);
	if (!strcmp (base, "imae")) {
		if (a.inv || a.neg || a.abs || b.inv || b.neg || b.abs || a.low == a.high || b.low == b.high) {
			return false;
		}
		src_half (sb, &b, sign);
		r_strbuf_append (sb, ",");
		src_half (sb, &a, sign);
	} else {
		if (!src_plain (&a) || !src_plain (&b)) {
			return false;
		}
		r_strbuf_appendf (sb, "%s,%s", b.tok, a.tok);
	}
	r_strbuf_appendf (sb, ",*,+,%s,=", args[0]);
	return true;
}

/* A float source as a double on the ESIL stack; .abs and .neg act on the sign
 * bit (.neg.abs is -|x|). Float immediates are not modelled. */
static bool src_flt(RStrBuf *sb, const char *t) {
	UsseSrc s;
	if (!src_parse (t, &s) || s.imm || s.inv || s.low || s.high) {
		return false;
	}
	if (s.neg && s.abs) {
		r_strbuf_appendf (sb, "32,0x80000000,%s,|,F2D", s.tok);
	} else if (s.neg) {
		r_strbuf_appendf (sb, "32,0x80000000,%s,^,F2D", s.tok);
	} else if (s.abs) {
		r_strbuf_appendf (sb, "32,0x7fffffff,%s,&,F2D", s.tok);
	} else {
		r_strbuf_appendf (sb, "32,%s,F2D", s.tok);
	}
	return true;
}

/* fmad d, a, b, c (a * b + c), frcp, frsq and fsqrt, in IEEE binary32 through
 * ESIL's doubles. Not modelled: repeats and source increments other than
 * incs000, .tpres, write masks, f16/fixed-point sources (.flt16, .c10, swizzles),
 * immediates, fexp/flog/fsin/fcos (no ESIL op), the dual-issue and the test
 * group forms. */
static bool flt_esil(RStrBuf *sb, const char *base, const char *opw, char **args, int argc) {
	static const char * const incs[] = { "incs000", NULL };
	bool nowrite;
	if (!dst_ok (args[0], &nowrite) || nowrite) {
		return false;
	}
	RStrBuf *t = r_strbuf_new ("32,");
	bool ok = false;
	if (!strcmp (base, "fmad")) {
		ok = argc == 4 && flags_ok (opw, incs, NULL, NULL) && src_flt (t, args[3])
			&& r_strbuf_append (t, ",") && src_flt (t, args[2])
			&& r_strbuf_append (t, ",") && src_flt (t, args[1])
			&& r_strbuf_append (t, ",F*,F+");
	} else if (!strcmp (base, "frcp") || !strcmp (base, "frsq") || !strcmp (base, "fsqrt")) {
		ok = argc == 2 && flags_ok (opw, NULL, NULL, NULL) && src_flt (t, args[1]);
		if (ok) {
			r_strbuf_append (t, !strcmp (base, "frcp") ? ",1,I2D,F/"
				: !strcmp (base, "frsq") ? ",SQRT,1,I2D,F/" : ",SQRT");
		}
	}
	if (ok) {
		r_strbuf_appendf (sb, "%s,D2F,%s,=", r_strbuf_get (t), args[0]);
	}
	r_strbuf_free (t);
	return ok;
}

/* The SGX register file as ESIL sees it. ldr/str take a dword register
 * index, from an immediate or a register: register offset = index * 4 (the
 * hardware returns CORE_ID for "ldr rD, #7" and the firmware programs its
 * registers this way). The registers are not in the USSE's 32-bit address
 * space, so the emulation places them in a window just above it, at
 * USSE_CR_ESIL_BASE + index * 4; map memory there ("o malloc://0x10000
 * 0x100000000") to emulate them. The window is plain memory: registers with
 * side effects (status, clear-on-read) and the drc wait of ldr are not
 * modelled, and register-supplied indexes are not masked to 14 bits. */
#define USSE_CR_ESIL_BASE 0x100000000ULL

static bool cr_index(RStrBuf *sb, const char *t) {
	if (*t == '#') {
		char *end = NULL;
		const ut64 idx = strtoull (t + 1, &end, 0);
		if (end == t + 1 || *end || idx > 0x3fff) {
			return false;
		}
		r_strbuf_appendf (sb, "0x%"PFMT64x, USSE_CR_ESIL_BASE + idx * 4);
		return true;
	}
	if (!simple_tok (t)) {
		return false;
	}
	r_strbuf_appendf (sb, "2,%s,<<,0x%"PFMT64x",+", t, USSE_CR_ESIL_BASE);
	return true;
}

/* "ldr rD, idx, drcN" and "str idx, src" (src a register or an immediate). */
static bool cr_esil(RStrBuf *sb, const char *base, const char *opw, char **args, int argc) {
	bool nowrite;
	if (!flags_ok (opw, NULL, NULL, NULL)) {
		return false;
	}
	if (!strcmp (base, "ldr")) {
		if (argc != 3 || strncmp (args[2], "drc", 3) || !dst_ok (args[0], &nowrite) || nowrite
				|| !cr_index (sb, args[1])) {
			return false;
		}
		r_strbuf_appendf (sb, ",[4],%s,=", args[0]);
		return true;
	}
	if (argc != 2 || !simple_tok (args[1])) {
		return false;
	}
	r_strbuf_appendf (sb, "%s,", esil_tok (args[1]));
	return cr_index (sb, args[0]) && r_strbuf_append (sb, ",=[4]");
}

/* Split a profile register into its bank and number ("pa12" -> "pa", 12). */
static bool reg_split(const char *t, char *bank, size_t bn, int *num) {
	const char *p = t;
	while (*p >= 'a' && *p <= 'z') {
		p++;
	}
	if (p == t || (size_t) (p - t) >= bn || *p < '0' || *p > '9') {
		return false;
	}
	memcpy (bank, t, p - t);
	bank[p - t] = 0;
	*num = atoi (p);
	return true;
}

/* mov.repeatN d, s: N moves d+i = s+i, the task's starting increments (one
 * register per iteration), as our vertex and state-copy programs use them on
 * the hardware ("mov.skipinv.repeat4 o0, pa0" copies the position to o0-o3).
 * Only between register ranges that do not overlap, so the order of the
 * iterations does not matter, every register is in the profile, and without
 * a predicate (per-iteration predicates are not pinned). The increments that
 * smlsi/smoa/smbo set are not tracked. */
static bool mov_repeat_esil(RStrBuf *sb, const char *opw, char **args, int argc) {
	static const char * const rep[] = { "repeat2", "repeat3", "repeat4", "repeat5", "repeat6",
		"repeat7", "repeat8", "repeat9", "repeat10", "repeat11", "repeat12", "repeat13",
		"repeat14", "repeat15", "repeat16", NULL };
	char db[8], sbk[8], reg[24];
	int d, s, n = 0, i;
	if (argc != 2 || !flags_ok (opw, rep, NULL, NULL)) {
		return false;
	}
	for (i = 0; rep[i]; i++) {
		if (has_flag (opw, rep[i])) {
			n = i + 2;
		}
	}
	if (!n || !simple_tok (args[0]) || !simple_tok (args[1]) || *args[0] == '#' || *args[1] == '#'
			|| !reg_split (args[0], db, sizeof db, &d) || !reg_split (args[1], sbk, sizeof sbk, &s)) {
		return false;
	}
	if (!strcmp (db, sbk) && d < s + n && s < d + n) {
		return false;
	}
	for (i = 0; i < n; i++) {
		snprintf (reg, sizeof reg, "%s%d", db, d + i);
		if (!reg_ok (reg)) {
			return false;
		}
		snprintf (reg, sizeof reg, "%s%d", sbk, s + i);
		if (!reg_ok (reg)) {
			return false;
		}
	}
	for (i = 0; i < n; i++) {
		r_strbuf_appendf (sb, "%s%s%d,%s%d,=", i ? "," : "", sbk, s + i, db, d + i);
	}
	return true;
}

/* ESIL for a load/store whose addresses are fully known (memop.h). */
static bool mem_esil(const UsseMemOp *m, RStrBuf *sb) {
	if (!usse_memop_modelled (m) || (m->load && *m->data == '#')) {
		return false;
	}
	const int s = m->size;
	const int n = m->fetch ? m->fetch : 1;
	bool wneg;
	const ut64 wb = usse_memop_writeback (m, &wneg);
	char reg[24];
	int i;
	if (!reg_ok (m->base)) {
		return false;
	}
	for (i = 0; i < n; i++) {
		if (!usse_reg_nth (m->data, i, reg, sizeof reg) || (*reg != '#' && !reg_ok (reg))) {
			return false;
		}
	}
	if (m->load) {
		/* a destination that is also the base would be clobbered mid-sequence */
		for (i = 0; i < n; i++) {
			if (!usse_reg_nth (m->data, i, reg, sizeof reg)) {
				return false;
			}
			if (!strcmp (reg, m->base) && (wb || i < n - 1)) {
				return false;
			}
		}
	}
	if (!m->fetch && m->mode == USSE_AM_PRE) {
		r_strbuf_appendf (sb, "%"PFMT64u",%s,%s=,", m->k * s, m->base, m->neg ? "-" : "+");
	}
	for (i = 0; i < n; i++) {
		char addr[48];
		if (m->fetch) {
			snprintf (addr, sizeof addr, "%"PFMT64u",%s,+", usse_memop_elem (m, i) * s, m->base);
		} else if (m->mode == USSE_AM_NONE) {
			snprintf (addr, sizeof addr, "%"PFMT64u",%s,%s", m->k * s, m->base, m->neg ? "-" : "+");
		} else {
			snprintf (addr, sizeof addr, "%s", m->base);
		}
		if (!usse_reg_nth (m->data, i, reg, sizeof reg)) {
			return false;
		}
		const char *src = (*reg == '#') ? reg + 1 : reg;
		if (m->load) {
			r_strbuf_appendf (sb, "%s%s,[%d],%s,=", i ? "," : "", addr, s, reg);
		} else {
			r_strbuf_appendf (sb, "%s%s,%s,=[%d]", i ? "," : "", src, addr, s);
		}
	}
	if (wb && (m->fetch || m->mode == USSE_AM_POST)) {
		r_strbuf_appendf (sb, ",%"PFMT64u",%s,%s=", wb * s, m->base, wneg ? "-" : "+");
	}
	return true;
}

static void usse_analyze(RAnalOp *op, const char *text, RArchDecodeMask mask) {
	char *s = strdup (text);
	if (!s) {
		return;
	}
	char *body = s;
	char cond[4] = {0};
	int neg = 0;
	if (body[0] == 'p' && body[1] >= '0' && body[1] <= '3' && body[2] == ' ') {
		cond[0] = 'p'; cond[1] = body[1]; body += 3;
	} else if (body[0] == '!' && body[1] == 'p' && body[2] >= '0' && body[2] <= '3' && body[3] == ' ') {
		neg = 1; cond[0] = 'p'; cond[1] = body[2]; body += 4;
	}

	char *sp = strchr (body, ' ');
	char *opw = body;
	char *args[8] = {0};
	int argc = 0;
	if (sp) {
		*sp = 0;
		char *p = sp + 1;
		while (p && argc < 8) {
			args[argc++] = p;
			char *c = strstr (p, ", ");
			if (!c) {
				break;
			}
			*c = 0;
			p = c + 2;
		}
	}
	char base[16];
	const char *dot = strchr (opw, '.');
	size_t bn = dot ? (size_t) (dot - opw) : strlen (opw);
	if (bn >= sizeof base) {
		bn = sizeof base - 1;
	}
	memcpy (base, opw, bn);
	base[bn] = 0;

	/* op->val: first immediate operand */
	int i;
	for (i = 0; i < argc; i++) {
		if (args[i][0] == '#') {
			op->val = (ut64) strtoull (args[i] + 1, NULL, 0);
			break;
		}
	}
	/* op->direction for memory ops */
	if (!strcmp (base, "ldad") || !strcmp (base, "ldaw")) {
		op->direction = R_ANAL_OP_DIR_READ;
	} else if (!strcmp (base, "stad") || !strcmp (base, "staw") || !strcmp (base, "str")) {
		op->direction = R_ANAL_OP_DIR_WRITE;
	}
	if (!strcmp (base, "ldr")) {
		op->direction = R_ANAL_OP_DIR_READ;
	}

	if (!(mask & R_ARCH_OP_MASK_ESIL)) {
		free (s);
		return;
	}

	char e[192];
	e[0] = 0;
	const bool sched = flags_ok (opw, NULL, NULL, NULL);
	const bool bitwise = !strcmp (base, "and") || !strcmp (base, "or") || !strcmp (base, "xor");
	const bool shift = !strcmp (base, "shl") || !strcmp (base, "shr");
	if (!strcmp (base, "mov") && sched && argc == 2 && simple_tok (args[0]) && simple_tok (args[1])) {
		snprintf (e, sizeof e, "%s,%s,=", esil_tok (args[1]), args[0]);
	} else if (bitwise && sched && argc == 3 && simple_tok (args[0]) && simple_tok (args[1]) && simple_tok (args[2])) {
		const char *sym = !strcmp (base, "and") ? "&" : !strcmp (base, "or") ? "|" : "^";
		snprintf (e, sizeof e, "%s,%s,%s,%s,=", esil_tok (args[2]), esil_tok (args[1]), sym, args[0]);
	} else if (shift && sched && argc == 3 && simple_tok (args[0]) && simple_tok (args[1]) && simple_tok (args[2])) {
		const char *sym = !strcmp (base, "shl") ? "<<" : ">>";
		snprintf (e, sizeof e, "%s,%s,%s,%s,=", esil_tok (args[2]), esil_tok (args[1]), sym, args[0]);
	} else if ((!strcmp (base, "ba") || !strcmp (base, "br")) && argc == 1) {
		/* pclink holds an instruction index (the firmware returns through
		 * "mov r15, #0x5C2" ... "mov pclink, r15"); ESIL's pc has already
		 * moved to the next instruction, the return address */
		if (strstr (opw, "savelink")) {
			snprintf (e, sizeof e, "3,pc,>>,pclink,=,0x%"PFMT64x",pc,=", op->jump);
		} else {
			snprintf (e, sizeof e, "0x%"PFMT64x",pc,=", op->jump);
		}
	} else if (!strcmp (opw, "lapc") && argc == 0) {
		snprintf (e, sizeof e, "3,pclink,<<,pc,=");
	}

	/* the wider ALU subset (test group, rotates, inverted sources, multiply-adds, floats) */
	RStrBuf *ab = NULL;
	if (!e[0] && argc >= 2) {
		bool ok = false;
		UsseSrc sa, sb;
		bool nowrite;
		ab = r_strbuf_new ("");
		if (strstr (opw, ".test")) {
			ok = test_esil (ab, base, opw, args, argc);
		} else if ((bitwise || !strcmp (base, "rol") || !strcmp (base, "asr")) && sched && argc == 3
				&& dst_ok (args[0], &nowrite) && !nowrite
				&& src_parse (args[1], &sa) && src_parse (args[2], &sb)) {
			ok = alu_val (ab, base, &sa, &sb) && r_strbuf_appendf (ab, ",%s,=", args[0]);
		} else if (!strcmp (base, "imae") || !strcmp (base, "ima32")) {
			ok = imul_esil (ab, base, opw, args, argc);
		} else if (*base == 'f') {
			ok = flt_esil (ab, base, opw, args, argc);
		} else if (!strcmp (base, "ldr") || !strcmp (base, "str")) {
			ok = cr_esil (ab, base, opw, args, argc);
		} else if (!strcmp (base, "mov") && !cond[0]) {
			ok = mov_repeat_esil (ab, opw, args, argc);
		}
		if (!ok) {
			r_strbuf_free (ab);
			ab = NULL;
		}
	}

	UsseMemOp mo;
	RStrBuf *mb = NULL;
	if (!e[0] && !ab && argc >= 2 && usse_memop_parse (opw, args[0], args[1], &mo)) {
		mb = r_strbuf_new ("");
		if (!mem_esil (&mo, mb)) {
			r_strbuf_free (mb);
			mb = NULL;
		}
	}
	const char *body_esil = mb ? r_strbuf_get (mb) : ab ? r_strbuf_get (ab) : e;
	if (body_esil[0]) {
		if (cond[0]) {
			r_strbuf_setf (&op->esil, "%s,%s?{,%s,}", cond, neg ? "!," : "", body_esil);
		} else {
			r_strbuf_set (&op->esil, body_esil);
		}
	}
	r_strbuf_free (mb);
	r_strbuf_free (ab);
	free (s);
}

static bool usse_decode_cb(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	if (!op || !op->bytes || op->size < 8) {
		return false;
	}
	ut64 e = r_read_le64 (op->bytes);
	op->size = 8;

	switch (usse_classify (e)) {
	case USSE_T_MOV:   op->type = R_ANAL_OP_TYPE_MOV;   break;
	case USSE_T_ALU:   op->type = R_ANAL_OP_TYPE_ADD;   break; /* generic int ALU */
	case USSE_T_MUL:   op->type = R_ANAL_OP_TYPE_MUL;   break;
	case USSE_T_LOAD:  op->type = R_ANAL_OP_TYPE_LOAD;  break;
	case USSE_T_STORE: op->type = R_ANAL_OP_TYPE_STORE; break;
	case USSE_T_JMP:   op->type = R_ANAL_OP_TYPE_JMP;   break;
	case USSE_T_CJMP:  op->type = R_ANAL_OP_TYPE_CJMP;  break;
	case USSE_T_CALL:  op->type = R_ANAL_OP_TYPE_CALL;  break;
	case USSE_T_NOP:   op->type = R_ANAL_OP_TYPE_NOP;   break;
	case USSE_T_SYNC:  op->type = R_ANAL_OP_TYPE_SYNC;  break;
	case USSE_T_RET:   op->type = R_ANAL_OP_TYPE_RET;   break; /* lapc */
	case USSE_T_CRET:
		op->type = R_ANAL_OP_TYPE_CRET;
		op->fail = op->addr + 8;
		break;
	default:           op->type = R_ANAL_OP_TYPE_UNK;   break;
	}

	int is_call, is_cond, is_rel; st32 off;
	if (usse_branch (e, &is_call, &is_cond, &is_rel, &off)) {
		ut64 byteoff = (ut64) ((st64) off * 8); /* PC field is in 8-byte insns */
		op->jump = is_rel ? (op->addr + byteoff) : byteoff;
		if (is_cond) {
			op->fail = op->addr + 8;
		}
	}

	/* decode text once; feed both the mnemonic and the text-based analysis */
	usse_insn in;
	usse_decode (e, (ut32) (op->addr / 8), &in);
	if (in.valid) {
		usse_analyze (op, in.text, mask);
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		op->mnemonic = strdup (in.valid ? in.text : "invalid");
	}
	return true;
}

static int archinfo(RArchSession *as, ut32 q) {
	switch (q) {
	case R_ARCH_INFO_MINOP_SIZE:
	case R_ARCH_INFO_MAXOP_SIZE:
	case R_ARCH_INFO_INVOP_SIZE:
	case R_ARCH_INFO_CODE_ALIGN:
		return 8;
	}
	return 8;
}

/* The inverse of decode, on the same form table: any text the decoder prints
 * assembles back (rasm2 -a usse, pa, wa). */
static bool usse_encode_cb(RArchSession *as, RAnalOp *op, RArchEncodeMask mask) {
	uint64_t e;
	ut8 *buf;

	if (!op->mnemonic || !usse_form_encode (op->mnemonic, &e)) {
		return false;
	}
	buf = malloc (8);
	if (!buf) {
		return false;
	}
	r_write_le64 (buf, e);
	free (op->bytes);
	op->bytes = buf;
	op->size = 8;
	return true;
}

const RArchPlugin r_arch_plugin_usse = {
	.meta = {
		.name = "usse",
		.desc = "PowerVR SGX Series-5 USSE (clean-room)",
		.author = "SGXhumation",
		.license = "LGPL-3.0-only",
	},
	.arch = "usse",
	.bits = R_SYS_BITS_PACK1 (32),
	.endian = R_SYS_ENDIAN_LITTLE,
	.info = archinfo,
	.regs = regs,
	.decode = usse_decode_cb,
	.encode = usse_encode_cb,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_usse,
	.version = R2_VERSION
};
#endif
