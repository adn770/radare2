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
	/* measured: i3 reads as i0 and drops writes; the text cannot tell bank 0's
	 * i3 from bank 7's, so neither is modelled */
	if (!strcmp (r, "i3")) {
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
 * that does not change what a single instance computes. Repeats other than
 * those of mov, fmad, fminmax/fmaxmin and fdp/fddp, partial and once-only
 * forms, half-float and c10 operands and the multi-channel tests are left
 * without ESIL; a write mask is a repeat of four with gaps (measured). The
 * 8-bit colour operations, integer dot products, fpma, efo, fadm/fmsa/
 * fsubflr and statomic follow the third round of probes. The
 * semantics follow the hardware probes (sgxhumation tools/usse-asm/probe.py).
 * Loads/stores follow memop.h,
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
 * or false when its semantics are not pinned for these operands; only src2
 * may be inverted. Measured on the hardware (tools/usse-asm/probe.py):
 * iadd32/iaddu32 add src1's low half, sign- or zero-extended, to the 32-bit
 * src2; shl/shr by a register amount of 32 and over give 0, asr fills the
 * sign and rol takes the amount mod 32. Immediate amounts stay below 32. */
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
		const bool sx = op[4] == '3';
		if (b->inv) {
			return false;
		}
		if (a->imm) {
			ut32 v = (ut32) a->val & 0xffff;
			if (sx && (v & 0x8000)) {
				v |= 0xffff0000;
			}
			r_strbuf_appendf (sb, v > 0xffff ? "%s,0x%x,+,0xffffffff,&" : "%s,%u,+,0xffffffff,&",
				b->tok, v);
		} else {
			r_strbuf_appendf (sb, "%s,%s%s,0xffff,&%s,+,0xffffffff,&", b->tok,
				sx ? "16," : "", a->tok, sx ? ",~" : "");
		}
		return true;
	}
	if (b->inv) {
		return false;
	}
	if (!b->imm) {
		/* a register amount: any 32-bit value */
		const char *x = a->tok, *y = b->tok;
		if (!strcmp (op, "shl")) {
			r_strbuf_appendf (sb, "0xffffffe0,%s,&,!,31,%s,&,%s,<<,0xffffffff,&,*", y, y, x);
		} else if (!strcmp (op, "shr")) {
			r_strbuf_appendf (sb, "0xffffffe0,%s,&,!,31,%s,&,%s,>>,*", y, y, x);
		} else if (!strcmp (op, "rol")) {
			r_strbuf_appendf (sb, "31,%s,&,%s,<<,31,%s,&,32,-,%s,>>,|,0xffffffff,&", y, x, y, x);
		} else if (!strcmp (op, "asr")) {
			r_strbuf_appendf (sb, "0xffffffe0,%s,&,!,!,31,*,31,%s,&,|,%s,ASR,0xffffffff,&", y, y, x);
		} else {
			return false;
		}
		return true;
	}
	if (b->val > 31) {
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

/* One 16-bit lane of a source: an immediate is in both lanes, a register
 * gives its low or high half. */
static void src_lane(RStrBuf *sb, const UsseSrc *s, bool high) {
	if (s->imm) {
		r_strbuf_appendf (sb, "0x%"PFMT64x, s->val & 0xffff);
	} else if (high) {
		r_strbuf_appendf (sb, "16,%s,>>", s->tok);
	} else {
		r_strbuf_appendf (sb, "%s,0xffff,&", s->tok);
	}
}

/* isub16/isubu16: both 16-bit lanes a - b, wrapping (measured: no
 * saturation, an immediate subtracted from both lanes). */
static bool lane_sub(RStrBuf *sb, const UsseSrc *a, const UsseSrc *b) {
	if (!src_plain (a) || !src_plain (b) || a->imm) {
		return false;
	}
	int h;
	for (h = 0; h < 2; h++) {
		if (h) {
			r_strbuf_append (sb, ",");
		}
		src_lane (sb, b, h);
		r_strbuf_append (sb, ",");
		src_lane (sb, a, h);
		r_strbuf_append (sb, h ? ",-,0xffff,&,0x10000,*,|" : ",-,0xffff,&");
	}
	return true;
}

/* Test group: "<op>.test<S><a|o><Z>.chan0 dst, pN, src1, src2" computes the
 * result, sets pN from it and writes dst unless it is "!reg". As measured on
 * the hardware: the sign test S is t (true), n (the sign bit) or p (its
 * complement, >= 0); Z is t (true), z or nz; a/o join them, so an o join with
 * a t side is always true. The bitwise group, the shifts and iadd32 test the
 * 32-bit result; iaddu32 is unsigned (n never, p always true); isub16 and
 * isubu16 test their low lane (chan0), and isubu16's sign tests are not
 * modelled. Other channels (measured to clear pN for z) and the 8-bit and
 * float tests are not modelled. */
static bool test_esil(RStrBuf *sb, const char *base, const char *opw, char **args, int argc) {
	static const char * const ops[] = { "and", "or", "xor", "shl", "shr", "rol", "asr",
		"iadd32", "iaddu32", "isub16", "isubu16", NULL };
	char test[12], chan[12];
	bool nowrite, known = false;
	UsseSrc a, b;
	int i;
	if (argc != 4 || !flags_ok (opw, NULL, test, chan) || !*test || strcmp (chan, "chan0")) {
		return false;
	}
	for (i = 0; ops[i]; i++) {
		known |= !strcmp (base, ops[i]);
	}
	if (!known) {
		return false;
	}
	const bool lanes = !strncmp (base, "isub", 4), uns = !strcmp (base, "iaddu32");
	/* test<S><a|o><Z> */
	const char *t = test + 4;
	const char sgn = *t++;
	const char join = *t++;
	const char *zero = t;
	if ((sgn != 't' && sgn != 'n' && sgn != 'p') || (join != 'a' && join != 'o')) {
		return false;
	}
	if (strcmp (zero, "t") && strcmp (zero, "z") && strcmp (zero, "nz")) {
		return false;
	}
	if (!strcmp (base, "isubu16") && sgn != 't') {
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
	if (!(lanes ? lane_sub (v, &a, &b) : alu_val (v, base, &a, &b))) {
		r_strbuf_free (v);
		return false;
	}
	const char *val = r_strbuf_get (v);
	/* the tested value: the result, or the low lane of a 16-bit op */
	char *tv = lanes ? r_str_newf ("%s,0xffff,&", val) : strdup (val);
	const int top = lanes ? 15 : 31;
	char *sx = NULL, *zx = NULL;      /* NULL: true */
	if (sgn == 'n') {
		sx = uns ? strdup ("0") : r_str_newf ("%d,%s,>>", top, tv);
	} else if (sgn == 'p' && !uns) {
		sx = r_str_newf ("%d,%s,>>,!", top, tv);
	}
	if (!strcmp (zero, "z")) {
		zx = r_str_newf ("%s,!", tv);
	} else if (!strcmp (zero, "nz")) {
		zx = r_str_newf ("%s,!,!", tv);
	}
	if (join == 'o' && (!sx || !zx)) {
		r_strbuf_append (sb, "1");
	} else if (!sx && !zx) {
		r_strbuf_append (sb, "1");
	} else if (!sx || !zx) {
		r_strbuf_append (sb, sx ? sx : zx);
	} else {
		r_strbuf_appendf (sb, "%s,%s,%s", sx, zx, join == 'a' ? "&" : "|");
	}
	r_strbuf_appendf (sb, ",%s,=", args[1]);
	if (!nowrite) {
		r_strbuf_appendf (sb, ",%s,%s,=", val, args[0]);
	}
	free (sx);
	free (zx);
	free (tv);
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

/* ima16.{s,u} d, a, b, c[.neg], u16, u16: in each 16-bit lane a * b + c (or
 * - c), wrapping; an immediate b or c is in both lanes (measured; the low 16
 * bits of the product are the same signed or unsigned). The other formats
 * are not modelled. */
static bool ima16_esil(RStrBuf *sb, const char *opw, char **args, int argc) {
	static const char * const us[] = { "u", NULL };
	static const char * const ss[] = { "s", NULL };
	const bool sign = has_flag (opw, "s");
	bool nowrite;
	UsseSrc a, b, c;
	int h;
	if (argc != 6 || strcmp (args[4], "u16") || strcmp (args[5], "u16")
			|| sign == has_flag (opw, "u") || !flags_ok (opw, sign ? ss : us, NULL, NULL)) {
		return false;
	}
	if (!dst_ok (args[0], &nowrite) || nowrite || !src_parse (args[1], &a)
			|| !src_parse (args[2], &b) || !src_parse (args[3], &c)) {
		return false;
	}
	if (!src_plain (&a) || a.imm || !src_plain (&b) || c.inv || c.abs || c.low || c.high) {
		return false;
	}
	for (h = 0; h < 2; h++) {
		if (h) {
			r_strbuf_append (sb, ",");
		}
		src_lane (sb, &c, h);
		r_strbuf_append (sb, ",");
		src_lane (sb, &b, h);
		r_strbuf_append (sb, ",");
		src_lane (sb, &a, h);
		r_strbuf_appendf (sb, ",*,%s,0xffff,&%s", c.neg ? "-" : "+", h ? ",0x10000,*,|" : "");
	}
	r_strbuf_appendf (sb, ",%s,=", args[0]);
	return true;
}

/* Flush a binary32 on the stack to zero when it is a denormal, keeping its
 * sign: the hardware does so with fmad's inputs, product and result and with
 * frcp's input (measured). */
#define FLT_FLUSH "DUP,0x7f800000,&,!,!,0x7fffffff,*,0x80000000,|,&"

/* A float source's binary32 bits, flushed, on the ESIL stack; .abs and .neg
 * act on the sign bit (.neg.abs is -|x|). Float immediates are not modelled. */
static bool src_bits(RStrBuf *sb, const char *t) {
	UsseSrc s;
	if (!src_parse (t, &s) || s.imm || s.inv || s.low || s.high) {
		return false;
	}
	if (s.neg && s.abs) {
		r_strbuf_appendf (sb, "0x80000000,%s,|", s.tok);
	} else if (s.neg) {
		r_strbuf_appendf (sb, "0x80000000,%s,^", s.tok);
	} else if (s.abs) {
		r_strbuf_appendf (sb, "0x7fffffff,%s,&", s.tok);
	} else {
		r_strbuf_append (sb, s.tok);
	}
	r_strbuf_append (sb, ","FLT_FLUSH);
	return true;
}

/* A float source as a double on the ESIL stack. */
static bool src_flt(RStrBuf *sb, const char *t) {
	return r_strbuf_append (sb, "32,") && src_bits (sb, t) && r_strbuf_append (sb, ",F2D");
}

/* fmad d, a, b, c, frcp, frsq and fsqrt, in IEEE binary32 through ESIL's
 * doubles. As measured: fmad rounds the product to binary32, then the sum,
 * both to nearest even (not fused), and flushes denormal inputs, product and
 * result to zero; frcp/frsq/fsqrt are within one ulp of the correctly rounded
 * result the ESIL computes. Repeats and .incsXYZ are in flt_rep_esil, write
 * masks in mask_esil. Not modelled: .tpres, f16/fixed-point sources (.flt16,
 * .c10, swizzles), immediates, fexp/flog/fsin/fcos (no ESIL op), the
 * dual-issue and the test group forms. */
static bool flt_esil(RStrBuf *sb, const char *base, const char *opw, char **args, int argc) {
	static const char * const incs[] = { "incs000", NULL };
	bool nowrite;
	if (!dst_ok (args[0], &nowrite) || nowrite) {
		return false;
	}
	RStrBuf *t = r_strbuf_new ("32,");
	bool ok = false;
	if (!strcmp (base, "fmad")) {
		/* sum = round(round(a * b) + c): two binary32 roundings */
		ok = argc == 4 && flags_ok (opw, incs, NULL, NULL) && src_flt (t, args[3])
			&& r_strbuf_append (t, ",32,32,") && src_flt (t, args[2])
			&& r_strbuf_append (t, ",") && src_flt (t, args[1])
			&& r_strbuf_append (t, ",F*,D2F,"FLT_FLUSH",F2D,F+");
	} else if (!strcmp (base, "frcp") || !strcmp (base, "frsq") || !strcmp (base, "fsqrt")) {
		ok = argc == 2 && flags_ok (opw, NULL, NULL, NULL) && src_flt (t, args[1]);
		if (ok) {
			r_strbuf_append (t, !strcmp (base, "frcp") ? ",1,I2D,F/"
				: !strcmp (base, "frsq") ? ",SQRT,1,I2D,F/" : ",SQRT");
		}
	}
	if (ok) {
		r_strbuf_appendf (sb, "%s,D2F,%s%s,=", r_strbuf_get (t),
			strcmp (base, "fmad") ? "" : FLT_FLUSH",", args[0]);
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
 * modelled. ldr masks a register index to 14 bits (measured: 0x4007,
 * 0x10007 and 0x40007 read CORE_ID); str's register index is not masked. */
#define USSE_CR_ESIL_BASE 0x100000000ULL

static bool cr_index(RStrBuf *sb, const char *t, bool mask) {
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
	if (mask) {
		r_strbuf_appendf (sb, "2,0x3fff,%s,&,<<,0x%"PFMT64x",+", t, USSE_CR_ESIL_BASE);
	} else {
		r_strbuf_appendf (sb, "2,%s,<<,0x%"PFMT64x",+", t, USSE_CR_ESIL_BASE);
	}
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
				|| !cr_index (sb, args[1], true)) {
			return false;
		}
		r_strbuf_appendf (sb, ",[4],%s,=", args[0]);
		return true;
	}
	if (argc != 2 || !simple_tok (args[1])) {
		return false;
	}
	r_strbuf_appendf (sb, "%s,", esil_tok (args[1]));
	return cr_index (sb, args[0], false) && r_strbuf_append (sb, ",=[4]");
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
 * Measured: the iterations run one after the other in ascending order, so
 * overlapping ranges propagate ("mov.repeat3 r2, r1" copies r1 to r2-r4), and
 * a predicate is tested once for the whole instruction. Every register must
 * be in the profile. The increments that smlsi/smoa/smbo set are not tracked
 * (measured: smlsi's first increment is the destination's, its third the
 * source's). */
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

/* Moves through the index register: "mov i.l, src" and "mov d, B[il + #n]" /
 * "mov B[il + #n], s" for the banks r and sa. Measured: the register is
 * B(i.l + n), counted from the bank's first register; bits 10 and up of i.l
 * are ignored. ESIL cannot name a register from a value, so the move is a
 * chain of conditionals over the bank's registers in the profile (r0-r63,
 * sa0-sa31); an index outside them moves nothing. i.h, the o and pa banks
 * and other operations' indexed operands are not modelled. */
static bool idx_parse(const char *t, char *bank, size_t bn, int *n, int *max) {
	const char *br = strchr (t, '[');
	char *end = NULL;
	if (!br || (size_t) (br - t) >= bn || strncmp (br, "[il + #", 7)) {
		return false;
	}
	memcpy (bank, t, br - t);
	bank[br - t] = 0;
	*max = !strcmp (bank, "r") ? 64 : !strcmp (bank, "sa") ? 32 : 0;
	*n = (int) strtol (br + 7, &end, 10);
	return *max && end && end != br + 7 && !strcmp (end, "]");
}

static bool idx_esil(RStrBuf *sb, const char *opw, char **args, int argc) {
	char bank[8], reg[24];
	int n, max, k;
	bool nowrite;
	if (argc != 2 || !flags_ok (opw, NULL, NULL, NULL)) {
		return false;
	}
	if (!strcmp (args[0], "i.l")) {
		if (!simple_tok (args[1])) {
			return false;
		}
		r_strbuf_appendf (sb, "%s,il,=", esil_tok (args[1]));
		return true;
	}
	const bool load = idx_parse (args[1], bank, sizeof bank, &n, &max);
	if (load) {
		if (!dst_ok (args[0], &nowrite) || nowrite) {
			return false;
		}
	} else if (!idx_parse (args[0], bank, sizeof bank, &n, &max) || !simple_tok (args[1])) {
		return false;
	}
	for (k = n; k < max; k++) {
		snprintf (reg, sizeof reg, "%s%d", bank, k);
		r_strbuf_appendf (sb, "%s%d,il,0x3ff,&,-,!,?{,%s,%s,=,}", k > n ? "," : "", k - n,
			load ? reg : esil_tok (args[1]), load ? args[0] : reg);
	}
	return true;
}

/* A load or store with a register offset: "ldad d, [b,+o]", "ldad d, [b,-o]",
 * "ldad.fetchN d, [b,+o]" and "stad [b,+o], s" (dwords). Measured: the offset
 * register holds two unsigned 16-bit halves whose product is the offset in
 * bytes (the firmware ORs 0x00040000 into a dword index), added to the base
 * modulo 2^32; a fetch starts one element after it, as with immediates; a
 * load from an address that is not a multiple of 4 reads those four bytes,
 * a store to one does not land. Word forms, pre/post increments and the
 * negative fetch are not modelled. */
static bool mem_reg_esil(const UsseMemOp *m, RStrBuf *sb) {
	const int n = m->fetch ? m->fetch : 1;
	char reg[24], addr[96];
	int i;
	if (m->imm || m->size != 4 || m->mode != USSE_AM_NONE || (m->fetch && m->neg)
			|| !reg_ok (m->base) || !reg_ok (m->off)) {
		return false;
	}
	for (i = 0; i < n; i++) {
		if (!usse_reg_nth (m->data, i, reg, sizeof reg) || (*reg != '#' && !reg_ok (reg))) {
			return false;
		}
		/* a loaded register that is the base or the offset changes the next address */
		if (m->load && (!strcmp (reg, m->base) || !strcmp (reg, m->off)) && i < n - 1) {
			return false;
		}
	}
	for (i = 0; i < n; i++) {
		char elem[16] = "";
		if (m->fetch) {
			snprintf (elem, sizeof elem, "%d,", 4 * (i + 1));
		}
		snprintf (addr, sizeof addr, "%s0xffff,%s,&,16,%s,>>,*,%s,%s,%s0xffffffff,&",
			elem, m->off, m->off, m->base, m->neg ? "-" : "+", m->fetch ? "+," : "");
		usse_reg_nth (m->data, i, reg, sizeof reg);
		if (m->load) {
			r_strbuf_appendf (sb, "%s%s,[4],%s,=", i ? "," : "", addr, reg);
		} else {
			r_strbuf_appendf (sb, "%s,3,&,!,?{,%s,%s,=[4],}", addr,
				*reg == '#' ? reg + 1 : reg, addr);
		}
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

/* ---- round 1 of the hardware probes: repeats, write masks, dot products,
 * min/max, conditional moves and packs (tools/usse-asm/probe.py) ---------- */

/* A register operand moved k registers on ("r10.neg" + 2 -> "r12.neg"); an
 * operand that is not a bank register (an immediate, a rounding mode) is
 * copied. False when the register leaves the profile. */
static bool reg_offset(const char *t, int k, char *out, size_t n) {
	char base[24], bank[8];
	int num;
	const char *dot = strchr (t, '.');
	const size_t bl = dot ? (size_t) (dot - t) : strlen (t);
	if (bl >= sizeof base) {
		return false;
	}
	memcpy (base, t, bl);
	base[bl] = 0;
	if (*t == '#' || !reg_split (base, bank, sizeof bank, &num)) {
		snprintf (out, n, "%s", t);
		return strlen (t) < n;
	}
	snprintf (base, sizeof base, "%s%d", bank, num + k);
	if (!reg_ok (base)) {
		return false;
	}
	snprintf (out, n, "%s%s", base, dot ? dot : "");
	return true;
}

/* The operands of iteration k of a repeat or a write mask: bit i of adv lets
 * operand i advance by k registers. */
typedef struct {
	char buf[8][48];
	char *v[8];
} UsseArgs;

static bool args_step(char **args, int argc, int k, unsigned adv, UsseArgs *o) {
	int i;
	if (argc > 8) {
		return false;
	}
	for (i = 0; i < argc; i++) {
		o->v[i] = o->buf[i];
		if (!(adv >> i & 1)) {
			if (strlen (args[i]) >= sizeof o->buf[i]) {
				return false;
			}
			strcpy (o->buf[i], args[i]);
		} else if (!reg_offset (args[i], k, o->buf[i], sizeof o->buf[i])) {
			return false;
		}
	}
	return true;
}

/* A destination with a write mask: "r10.xz" -> "r10", 5; "r10." -> mask 0;
 * a pack destination keeps its byte mask ("r10.bytemask0011.y"). False when
 * the destination has no write mask. */
static bool dst_mask(const char *t, char *base, size_t n, int *mask) {
	const char *dot = strrchr (t, '.');
	const char *p;
	int m = 0, last = -1;
	if (!dot || (size_t) (dot - t) >= n) {
		return false;
	}
	for (p = dot + 1; *p; p++) {
		const char *c = strchr ("xyzw", *p);
		if (!c || (int) (c - "xyzw") <= last) {
			return false;
		}
		last = (int) (c - "xyzw");
		m |= 1 << last;
	}
	memcpy (base, t, dot - t);
	base[dot - t] = 0;
	*mask = m;
	return true;
}

/* The repeat count (1 without .repeatN) and the .incsXYZ advance bits (X:
 * source 0 ... Z: source 2; every source advances without .incs). Measured:
 * the destination always advances. */
static int rep_count(const char *opw) {
	int n;
	for (n = 16; n > 1; n--) {
		char f[12];
		snprintf (f, sizeof f, "repeat%d", n);
		if (has_flag (opw, f)) {
			return n;
		}
	}
	return 1;
}

static unsigned incs_bits(const char *opw) {
	unsigned x;
	for (x = 0; x < 8; x++) {
		char f[12];
		snprintf (f, sizeof f, "incs%u%u%u", x >> 2 & 1, x >> 1 & 1, x & 1);
		if (has_flag (opw, f)) {
			return x;
		}
	}
	return 7;
}

static const char * const flt_rep[] = { "repeat2", "repeat3", "repeat4", "incs000", "incs001",
	"incs010", "incs011", "incs100", "incs101", "incs110", "incs111", NULL };

/* The operand advance mask for a float repeat: the destination (operand 0)
 * always, then sources 0-2 (operands first .. first + 2) by .incsXYZ. */
static unsigned flt_adv(const char *opw, int first) {
	const unsigned x = incs_bits (opw);
	return 1 | (x >> 2 & 1) << first | (x >> 1 & 1) << (first + 1) | (x & 1) << (first + 2);
}

/* NaN test, order key and unsigned less-than on binary32 bit patterns (no
 * temporaries in ESIL: each expression is repeated where it is needed). The
 * key orders floats as integers, -0 below +0. */
static char *f_nan(const char *x) {
	return r_str_newf ("63,0x7fffffff,%s,&,0x7f800000,-,>>", x);
}

static char *f_key(const char *x) {
	return r_str_newf ("%s,0x80000000,0x7fffffff,31,%s,>>,*,|,^", x, x);
}

static char *f_lt(const char *x, const char *y) {
	char *kx = f_key (x), *ky = f_key (y);
	char *r = r_str_newf ("63,%s,%s,-,>>", ky, kx);
	free (kx);
	free (ky);
	return r;
}

/* IEEE minNum/maxNum of two flushed binary32 values, as measured for
 * fminmax/fmaxmin: a NaN loses to a number, -0 is below +0. b is chosen
 * when a is a NaN, or b is a number below (above, for max) a. */
static char *f_minmax(const char *a, const char *b, bool max) {
	char *na = f_nan (a), *nb = f_nan (b), *lt = max ? f_lt (a, b) : f_lt (b, a);
	char *c = r_str_newf ("%s,%s,!,%s,&,|", na, nb, lt);
	char *r = r_str_newf ("%s,%s,*,%s,%s,!,*,|", b, c, a, c);
	free (na);
	free (nb);
	free (lt);
	free (c);
	return r;
}

/* fminmax d, a, b, c = min(max(a, b), c); fmaxmin d, a, b, c =
 * max(min(a, c), b) (measured; both clamp a to [b, c]). The first step goes
 * through d, so d must not be the operand the second step reads. */
static bool minmax_one(RStrBuf *sb, const char *base, char **args) {
	const bool fmm = !strcmp (base, "fminmax");
	RStrBuf *x = r_strbuf_new (""), *y = r_strbuf_new (""), *z = r_strbuf_new ("");
	bool nowrite, ok = dst_ok (args[0], &nowrite) && !nowrite && src_bits (x, args[1])
		&& src_bits (y, args[fmm ? 2 : 3]) && src_bits (z, args[fmm ? 3 : 2]);
	char reg[24];
	const char *last = args[fmm ? 3 : 2];
	snprintf (reg, sizeof reg, "%.*s", (int) strcspn (last, "."), last);
	if (ok && !strcmp (reg, args[0])) {
		ok = false;
	}
	if (ok) {
		char *m1 = f_minmax (r_strbuf_get (x), r_strbuf_get (y), fmm);
		char *m2 = f_minmax (args[0], r_strbuf_get (z), !fmm);
		r_strbuf_appendf (sb, "%s,%s,=,%s,%s,=", m1, args[0], m2, args[0]);
		free (m1);
		free (m2);
	}
	r_strbuf_free (x);
	r_strbuf_free (y);
	r_strbuf_free (z);
	return ok;
}

/* One rounded binary32 product a * b, flushed, as bits. */
static bool f_prod(RStrBuf *sb, const char *a, const char *b) {
	return r_strbuf_append (sb, "32,") && src_flt (sb, b) && r_strbuf_append (sb, ",")
		&& src_flt (sb, a) && r_strbuf_append (sb, ",F*,D2F,"FLT_FLUSH);
}

/* The dot product of n terms (a + k) . (b + k), advancing a and b by their
 * adv bits: each product rounded to binary32, then added in order, each sum
 * rounded (measured: like a chain of fmad), flushed. */
static bool f_dot(RStrBuf *sb, const char *a, const char *b, int n, bool adva, bool advb) {
	RStrBuf *acc = r_strbuf_new ("");
	char ak[48], bk[48];
	int k;
	bool ok = true;
	for (k = 0; k < n && ok; k++) {
		RStrBuf *p = r_strbuf_new ("");
		ok = reg_offset (a, adva ? k : 0, ak, sizeof ak) && reg_offset (b, advb ? k : 0, bk, sizeof bk)
			&& f_prod (p, ak, bk);
		if (ok && !k) {
			r_strbuf_set (acc, r_strbuf_get (p));
		} else if (ok) {
			char *s = r_str_newf ("32,32,%s,F2D,32,%s,F2D,F+,D2F,"FLT_FLUSH, r_strbuf_get (p),
				r_strbuf_get (acc));
			r_strbuf_set (acc, s);
			free (s);
		}
		r_strbuf_free (p);
	}
	if (ok) {
		r_strbuf_append (sb, r_strbuf_get (acc));
	}
	r_strbuf_free (acc);
	return ok;
}

/* fdp.repeatN d, a, b writes the N-term dot product to d + N - 1 only;
 * fddp.repeatN d, iM, s0, s1, s2 writes s0 . s1 there and s0 . s2 to iM
 * (measured). .incsXYZ: X source 0, Y source 1, Z source 2. fdpc and fddpc
 * (whose clip-plane result is not located) are not modelled. */
static bool fdp_esil(RStrBuf *sb, const char *base, const char *opw, char **args, int argc) {
	const bool dd = !strcmp (base, "fddp");
	const int n = rep_count (opw);
	const unsigned x = incs_bits (opw);
	char d[48];
	bool nowrite;
	if (argc != (dd ? 5 : 3) || !flags_ok (opw, flt_rep, NULL, NULL) || !dst_ok (args[0], &nowrite)
			|| nowrite || !reg_offset (args[0], n - 1, d, sizeof d)) {
		return false;
	}
	if (!dd) {
		return f_dot (sb, args[1], args[2], n, x >> 1 & 1, x & 1) && r_strbuf_appendf (sb, ",%s,=", d);
	}
	if (strcmp (args[1], "i0") && strcmp (args[1], "i1")) {
		return false;
	}
	/* the second product reads s0 and s2 after d is written */
	int k;
	for (k = 0; k < n; k++) {
		char s0[48], s2[48];
		if (!reg_offset (args[2], (x >> 2 & 1) ? k : 0, s0, sizeof s0)
				|| !reg_offset (args[4], (x & 1) ? k : 0, s2, sizeof s2)) {
			return false;
		}
		s0[strcspn (s0, ".")] = 0;
		s2[strcspn (s2, ".")] = 0;
		if (!strcmp (s0, d) || !strcmp (s2, d)) {
			return false;
		}
	}
	return f_dot (sb, args[2], args[3], n, x >> 2 & 1, x >> 1 & 1) && r_strbuf_appendf (sb, ",%s,=,", d)
		&& f_dot (sb, args[2], args[4], n, x >> 2 & 1, x & 1) && r_strbuf_appendf (sb, ",%s,=", args[1]);
}

/* A movc source 0 lane test: the mask of the lanes that pass, as an ESIL
 * expression. Measured: .i32/.i16/.i8 test each 32/16/8-bit lane, .i10 the
 * three 10-bit lanes at bits 0, 10, 20; tz zero, tnz not zero, tn the lane's
 * sign bit, tp|z its complement; .flt tests the float with denormals and -0
 * as zero, < 0 and >= 0, a NaN failing all but tnz. */
static bool movc_mask(RStrBuf *sb, const char *type, const char *test, const char *s0) {
	const int w = !strcmp (type, "i8") ? 8 : !strcmp (type, "i16") ? 16 : !strcmp (type, "i10") ? 10 : 32;
	const int n = w == 10 ? 3 : 32 / w;
	const ut64 lm = w == 32 ? 0xffffffffULL : (1ULL << w) - 1;
	int k;
	if (!strcmp (type, "flt")) {
		char *nan = f_nan (s0);
		char *z = r_str_newf ("0x7fffffff,%s,"FLT_FLUSH",&,!", s0);
		char *t = !strcmp (test, "tz") ? strdup (z) : !strcmp (test, "tnz") ? r_str_newf ("%s,!", z)
			: !strcmp (test, "tn") ? r_str_newf ("31,%s,>>,%s,!,&,%s,!,&", s0, z, nan)
			: r_str_newf ("31,%s,>>,!,%s,|,%s,!,&", s0, z, nan);
		r_strbuf_appendf (sb, "0xffffffff,%s,*", t);
		free (nan);
		free (z);
		free (t);
		return true;
	}
	for (k = 0; k < n; k++) {
		const int sh = k * w;
		char *lane = r_str_newf ("0x%"PFMT64x",%d,%s,>>,&", lm, sh, s0);
		char *t = !strcmp (test, "tz") ? r_str_newf ("%s,!", lane)
			: !strcmp (test, "tnz") ? r_str_newf ("%s,!,!", lane)
			: !strcmp (test, "tn") ? r_str_newf ("%d,%s,>>", w - 1, lane)
			: r_str_newf ("%d,%s,>>,!", w - 1, lane);
		r_strbuf_appendf (sb, "%s0x%"PFMT64x",%s,*%s", k ? "," : "", lm << sh, t, k ? ",|" : "");
		free (lane);
		free (t);
	}
	return true;
}

/* movc.<type>.<test> d, s0, s1, s2: each lane of d is s1's where the test of
 * s0's lane passes, else s2's; .i10 clears bits 30-31 (measured). */
static bool movc_esil(RStrBuf *sb, const char *opw, char **args, int argc) {
	static const char * const fl[] = { "i8", "i16", "i32", "flt", "i10", "tz", "tnz", "tn", "tp|z", NULL };
	static const char * const types[] = { "i8", "i16", "i32", "flt", "i10", NULL };
	static const char * const tests[] = { "tz", "tnz", "tn", "tp|z", NULL };
	const char *type = NULL, *test = NULL;
	bool nowrite;
	int i;
	if (argc != 4 || !flags_ok (opw, fl, NULL, NULL)) {
		return false;
	}
	for (i = 0; types[i]; i++) {
		type = has_flag (opw, types[i]) ? types[i] : type;
	}
	for (i = 0; tests[i]; i++) {
		test = has_flag (opw, tests[i]) ? tests[i] : test;
	}
	if (!type || !test || !dst_ok (args[0], &nowrite) || nowrite || *args[1] == '#'
			|| !simple_tok (args[1]) || !simple_tok (args[2]) || !simple_tok (args[3])) {
		return false;
	}
	RStrBuf *m = r_strbuf_new ("");
	movc_mask (m, type, test, args[1]);
	const char *mm = r_strbuf_get (m);
	r_strbuf_appendf (sb, "%s,%s,&,%s,%s,%s,^,&,|,%s,=", esil_tok (args[2]), mm, esil_tok (args[3]),
		mm, !strcmp (type, "i10") ? "0x3fffffff" : "0xffffffff", args[0]);
	r_strbuf_free (m);
	return true;
}

/* A source with a component select ("r2.1"): the register and c. */
static bool comp_src(const char *t, char *reg, size_t n, int *c) {
	const char *dot = strchr (t, '.');
	size_t l = dot ? (size_t) (dot - t) : strlen (t);
	*c = 0;
	if (dot && (dot[1] < '0' || dot[1] > '3' || dot[2])) {
		return false;
	}
	if (dot) {
		*c = dot[1] - '0';
	}
	if (l >= n) {
		return false;
	}
	memcpy (reg, t, l);
	reg[l] = 0;
	return *reg != '#' && simple_tok (reg);
}

/* movmsk.<fmt> d, s1, s2.c: s1 is moved into d when s2 passes (measured):
 * .mask bit 0 of byte c, .u8 bit 7 of byte c, .flt s2 >= 0.5 (a NaN fails),
 * .flt16 the half c (bits 0-15, 8-23, 16-31, 16-31) >= 0.5; with .smsk
 * (movmsk.<fmt>.smsk d, s0, s1, s2.c) bit 0 of s0 must be set too, except
 * for .mask. */
static bool movmsk_esil(RStrBuf *sb, const char *opw, char **args, int argc) {
	static const char * const fl[] = { "mask", "flt", "flt16", "u8", "smsk", NULL };
	char reg[24];
	int c, nf = 0, i;
	bool nowrite;
	const bool smsk = has_flag (opw, "smsk");
	for (i = 0; i < 4; i++) {
		nf += has_flag (opw, fl[i]);
	}
	if (argc != 3 + smsk || nf != 1 || !flags_ok (opw, fl, NULL, NULL) || !dst_ok (args[0], &nowrite)
			|| nowrite || (smsk && !simple_tok (args[1])) || !simple_tok (args[1 + smsk])
			|| !comp_src (args[2 + smsk], reg, sizeof reg, &c)) {
		return false;
	}
	/* .smsk: the move also needs bit 0 of source 0, but for .mask (measured) */
	const char *s0 = smsk && !has_flag (opw, "mask") ? esil_tok (args[1]) : NULL;
	args += smsk;
	char *cond = NULL;
	if (has_flag (opw, "mask") || has_flag (opw, "u8")) {
		cond = r_str_newf ("1,%d,%s,>>,&", 8 * c + (has_flag (opw, "u8") ? 7 : 0), reg);
	} else if (has_flag (opw, "flt")) {
		char *nan = f_nan (reg), *lt = f_lt (reg, "0x3f000000");
		cond = r_str_newf ("%s,!,%s,!,&", nan, lt);
		free (nan);
		free (lt);
	} else {
		const int sh = c == 0 ? 0 : c == 1 ? 8 : 16;
		char *hm = r_str_newf ("0x7fff,0xffff,%d,%s,>>,&,&", sh, reg);
		cond = r_str_newf ("15,0xffff,%d,%s,>>,&,>>,!,63,0x3800,%s,-,>>,!,&,63,%s,0x7c00,-,>>,!,&",
			sh, reg, hm, hm);
		free (hm);
	}
	if (s0) {
		r_strbuf_appendf (sb, "1,%s,&,%s,&,?{,%s,%s,=,}", s0, cond, esil_tok (args[1]), args[-1]);
	} else {
		r_strbuf_appendf (sb, "%s,?{,%s,%s,=,}", cond, esil_tok (args[1]), args[smsk ? -1 : 0]);
	}
	free (cond);
	return true;
}

/* ---- pack and unpack ---- */

/* Which source an enabled destination byte takes (0: source 1, 1: source 2),
 * for an 8-bit (lanes 1, 2, 1, 2) or a 16-bit result (halves 1, 2), under a
 * byte mask: measured on every mask (probes pack-u8-bytemask and
 * pack-u16-bytemask). */
static int pack_sel(int mask, int i, bool half) {
	const int b0 = mask & 1, b1 = mask >> 1 & 1, b2 = mask >> 2 & 1;
	if (half) {
		return i < 2 ? 0 : b0;
	}
	return i == 0 ? 0 : i == 1 ? b0 : i == 2 ? (b0 ^ b1) : (b0 | b1 | b2);
}

/* f32 -> integer for a pack: clamped to [lo, hi] (before rounding, the same
 * as after for integer bounds), rounded in the mode, as a two's complement
 * integer. The scaled conversions always round to nearest even. */
static char *pack_int(const char *src, ut64 scale, int lo, int hi, const char *mode) {
	RStrBuf *x = r_strbuf_new ("");
	char *v, *c, *hi_s, *lo_s, *r;
	src_flt (x, src);
	if (scale) {
		r_strbuf_appendf (x, ",%"PFMT64u",I2D,F*", scale);
	}
	lo_s = lo < 0 ? r_str_newf ("%d,0,-,I2D", -lo) : r_str_newf ("%d,I2D", lo);
	hi_s = r_str_newf ("%d,I2D", hi);
	c = r_str_newf ("%s,%s,F<", r_strbuf_get (x), hi_s);
	v = r_str_newf ("%s,%s,*,%s,%s,!,*,|", hi_s, c, r_strbuf_get (x), c);
	free (c);
	c = r_str_newf ("%s,%s,F<", lo_s, v);
	r = r_str_newf ("%s,%s,*,%s,%s,!,*,|", lo_s, c, v, c);
	free (c);
	free (v);
	if (scale || !strcmp (mode, "nearest")) {
		v = r_str_newf ("6755399441055744,I2D,6755399441055744,I2D,%s,F+,F-,D2I", r);
	} else if (!strcmp (mode, "down")) {
		v = r_str_newf ("%s,FLOOR,D2I", r);
	} else if (!strcmp (mode, "up")) {
		v = r_str_newf ("%s,CEIL,D2I", r);
	} else {
		v = r_str_newf ("%s,D2I", r);
	}
	free (r);
	free (lo_s);
	free (hi_s);
	r_strbuf_free (x);
	return v;
}

/* An integer source lane of an unpack: byte c, or the 16 bits from bit 8c
 * (.3 reads nothing), sign-extended for s8/s16. */
static char *unpack_lane(const char *reg, int c, int w, bool sign) {
	if (w == 16 && c == 3) {
		return strdup ("0");
	}
	char *v = r_str_newf ("0x%x,%d,%s,>>,&", w == 8 ? 0xff : 0xffff, 8 * c, reg);
	if (sign) {
		char *s = r_str_newf ("%d,%s,~", w, v);
		free (v);
		return s;
	}
	return v;
}

/* pck<u8|s8|o8|u16|s16|c10>f32[.scale] d[.bytemaskXXXX], s1.c, s2.c, mode and
 * unpck<f32|u8|u16|s16><u8|s8|o8|u16|s16> d[.bytemaskXXXX], s1.c, s2.c, mode,
 * as measured (probes pack-* and unpack-*): see the ISA reference's "Pack
 * and unpack lanes" and "conversions". f16 and c10 sources, f16 results,
 * statomic and .scale on the integer-to-integer forms are not modelled. */
static bool pack_esil(RStrBuf *sb, const char *base, const char *opw, char **args, int argc) {
	static const char * const fl[] = { "scale", NULL };
	static const char * const fmts[] = { "u8", "s8", "o8", "u16", "s16", "f16", "f32", "c10", NULL };
	const bool pck = !strncmp (base, "pck", 3);
	const char *f = base + (pck ? 3 : 5);
	char dfmt[4] = "", sfmt[4] = "", dreg[24], r1[24], r2[24];
	int i, c1, c2, bm = 15;
	bool nowrite;
	for (i = 0; fmts[i]; i++) {
		if (!strncmp (f, fmts[i], strlen (fmts[i]))) {
			const char *g = f + strlen (fmts[i]);
			int j;
			for (j = 0; fmts[j]; j++) {
				if (!strcmp (g, fmts[j]) && strlen (fmts[i]) + strlen (fmts[j]) < 7) {
					strcpy (dfmt, fmts[i]);
					strcpy (sfmt, fmts[j]);
				}
			}
		}
	}
	const bool scale = has_flag (opw, "scale");
	if (!*dfmt || argc != 4 || !flags_ok (opw, fl, NULL, NULL) || !comp_src (args[1], r1, sizeof r1, &c1)
			|| !comp_src (args[2], r2, sizeof r2, &c2)
			|| (strcmp (args[3], "nearest") && strcmp (args[3], "down") && strcmp (args[3], "up")
				&& strcmp (args[3], "zero"))) {
		return false;
	}
	const char *bmt = strstr (args[0], ".bytemask");
	snprintf (dreg, sizeof dreg, "%.*s", bmt ? (int) (bmt - args[0]) : (int) strlen (args[0]), args[0]);
	if (bmt) {
		if (strlen (bmt) != 13) {
			return false;
		}
		bm = 0;
		for (i = 0; i < 4; i++) {
			bm |= (bmt[9 + i] == '1') << (3 - i);
		}
	}
	if (!dst_ok (dreg, &nowrite) || nowrite) {
		return false;
	}
	const bool f32d = !strcmp (dfmt, "f32");
	const int dw = !strcmp (dfmt, "c10") ? 10 : dfmt[1] == '8' ? 8 : 16;
	char *v[2] = { NULL, NULL };
	if (pck) {
		static const struct { const char *f; int lo, hi, off, slo, shi; ut64 k; } pf[] = {
			{ "u8", 0, 255, 0, 0, 255, 255 }, { "s8", -128, 127, 0, -127, 127, 127 },
			{ "o8", -128, 127, 128, -127, 127, 127 }, { "u16", 0, 65535, 0, 0, 65535, 65535 },
			{ "s16", -32768, 32767, 0, -32767, 32767, 32767 }, { "c10", -510, 510, 0, -510, 510, 255 },
		};
		if (strcmp (sfmt, "f32")) {
			return false;
		}
		for (i = 0; i < 6 && strcmp (pf[i].f, dfmt); i++) {
		}
		if (i == 6 || (dw == 10 && bmt)) {
			return false;
		}
		const bool sc = scale || dw == 10;
		int s;
		for (s = 0; s < 2; s++) {
			char *n = pack_int (s ? r2 : r1, sc ? pf[i].k : 0, sc ? pf[i].slo : pf[i].lo,
				sc ? pf[i].shi : pf[i].hi, dw == 10 ? "nearest" : args[3]);
			v[s] = r_str_newf ("0x%x,%d,%s,+,&", dw == 8 ? 0xff : dw == 10 ? 0x3ff : 0xffff, pf[i].off, n);
			free (n);
		}
	} else if (f32d) {
		/* to f32: source 1 only */
		const int sw = sfmt[1] == '8' ? 8 : 16;
		const bool sg = *sfmt == 's';
		static const struct { const char *f; int k, off; } uf[] = {
			{ "u8", 255, 0 }, { "s8", 127, 0 }, { "o8", 127, 128 }, { "u16", 65535, 0 }, { "s16", 32767, 0 },
		};
		for (i = 0; i < 5 && strcmp (uf[i].f, sfmt); i++) {
		}
		if (i == 5) {
			return false;
		}
		char *lane = unpack_lane (r1, c1, sw, sg);
		char *q, *d = uf[i].off ? r_str_newf ("%d,%s,-,I2D", uf[i].off, lane) : r_str_newf ("%s,I2D", lane);
		if (scale) {
			q = r_str_newf ("%d,I2D,%s,F/", uf[i].k, d);
			free (d);
			d = q;
			if (*sfmt != 'u') {
				char *cc = r_str_newf ("1,0,-,I2D,%s,F<", d);
				q = r_str_newf ("1,0,-,I2D,%s,*,%s,%s,!,*,|", cc, d, cc);
				free (cc);
				free (d);
				d = q;
			}
		}
		r_strbuf_appendf (sb, "32,%s,D2F,%s,=", d, dreg);
		free (d);
		free (lane);
		return true;
	} else {
		/* integer to integer, measured: u8 <- s8 makes a negative 0x7f, u16 <- s8 0 */
		if (scale || (strcmp (sfmt, "u8") && strcmp (sfmt, "s8")) || (dw == 8 && strcmp (dfmt, "u8"))
				|| (dw == 8 && strcmp (sfmt, "s8"))) {
			return false;
		}
		int s;
		for (s = 0; s < 2; s++) {
			char *b = unpack_lane (s ? r2 : r1, s ? c2 : c1, 8, false);
			if (!strcmp (sfmt, "u8")) {
				v[s] = strdup (b);
			} else if (!strcmp (dfmt, "u8")) {
				v[s] = r_str_newf ("0x7f,7,%s,>>,*,%s,7,%s,>>,!,*,|", b, b, b);
			} else if (!strcmp (dfmt, "s16")) {
				v[s] = r_str_newf ("0xffff,8,%s,~,&", b);
			} else {
				v[s] = r_str_newf ("%s,7,%s,>>,!,*", b, b);
			}
			free (b);
		}
	}
	/* lay the two values out */
	if (dw == 10) {
		r_strbuf_appendf (sb, "%s,20,%s,<<,|,10,%s,<<,|,%s,=", v[0], v[0], v[1], dreg);
	} else {
		ut32 keep = 0;
		for (i = 0; i < 4; i++) {
			keep |= (bm >> i & 1) ? 0 : 0xffu << (8 * i);
		}
		r_strbuf_appendf (sb, "0x%x,%s,&", keep, dreg);
		for (i = 0; i < 4; i++) {
			if (bm >> i & 1) {
				const int s = pack_sel (bm, i, dw == 16);
				const int sh = dw == 16 ? 8 * (i & 1) : 0;
				r_strbuf_appendf (sb, ",%d,0xff,%d,%s,>>,&,<<,|", 8 * i, sh, v[s]);
			}
		}
		r_strbuf_appendf (sb, ",%s,=", dreg);
	}
	free (v[0]);
	free (v[1]);
	return true;
}

/* fmad, fminmax and fmaxmin repeats with .incsXYZ (measured: X, Y, Z let
 * source 0, 1, 2 advance, the destination always advances, every source
 * without .incs), iterations in ascending order; fdp and fddp. */
static bool flt_rep_esil(RStrBuf *sb, const char *base, const char *opw, char **args, int argc) {
	const bool fmad = !strcmp (base, "fmad");
	int k, n;
	if (!strcmp (base, "fdp") || !strcmp (base, "fddp")) {
		return fdp_esil (sb, base, opw, args, argc);
	}
	if ((!fmad && strcmp (base, "fminmax") && strcmp (base, "fmaxmin")) || argc != 4
			|| !flags_ok (opw, flt_rep, NULL, NULL)) {
		return false;
	}
	n = rep_count (opw);
	for (k = 0; k < n; k++) {
		UsseArgs ga;
		if (k) {
			r_strbuf_append (sb, ",");
		}
		if (!args_step (args, argc, k, flt_adv (opw, 1), &ga)
				|| !(fmad ? flt_esil (sb, base, base, ga.v, argc) : minmax_one (sb, base, ga.v))) {
			return false;
		}
	}
	return true;
}

/* One iteration of the forms a write mask repeats (measured: component k
 * writes d + k from every register source + k): mov, the bitwise group and
 * shifts, frcp/frsq/fsqrt, movc and the packs. */
static bool masked_one(RStrBuf *sb, const char *base, const char *opw, char **args, int argc) {
	bool nowrite;
	UsseSrc a, b;
	if (!strcmp (base, "mov")) {
		if (argc != 2 || !flags_ok (opw, NULL, NULL, NULL) || !simple_tok (args[0]) || !simple_tok (args[1])) {
			return false;
		}
		r_strbuf_appendf (sb, "%s,%s,=", esil_tok (args[1]), args[0]);
		return true;
	}
	if (!strcmp (base, "and") || !strcmp (base, "or") || !strcmp (base, "xor") || !strcmp (base, "shl")
			|| !strcmp (base, "shr") || !strcmp (base, "rol") || !strcmp (base, "asr")) {
		return argc == 3 && flags_ok (opw, NULL, NULL, NULL) && dst_ok (args[0], &nowrite) && !nowrite
			&& src_parse (args[1], &a) && src_parse (args[2], &b) && alu_val (sb, base, &a, &b)
			&& r_strbuf_appendf (sb, ",%s,=", args[0]);
	}
	if (!strcmp (base, "frcp") || !strcmp (base, "frsq") || !strcmp (base, "fsqrt")) {
		return flt_esil (sb, base, opw, args, argc);
	}
	if (!strcmp (base, "movc")) {
		return movc_esil (sb, opw, args, argc);
	}
	if (!strncmp (base, "pck", 3) || !strncmp (base, "unpck", 5)) {
		return pack_esil (sb, base, opw, args, argc);
	}
	return false;
}

static bool mask_esil(RStrBuf *sb, const char *base, const char *opw, char **args, int argc) {
	char db[48];
	int m, k, done = 0;
	if (argc < 2 || !dst_mask (args[0], db, sizeof db, &m) || !m) {
		return false;
	}
	char *saved = args[0];
	args[0] = db;
	for (k = 0; k < 4; k++) {
		UsseArgs ga;
		if (!(m >> k & 1)) {
			continue;
		}
		if (done++) {
			r_strbuf_append (sb, ",");
		}
		if (!args_step (args, argc, k, 0xff, &ga) || !masked_one (sb, base, opw, ga.v, argc)) {
			args[0] = saved;
			return false;
		}
	}
	args[0] = saved;
	return true;
}

/* ---- round 2 of the hardware probes: colour operations, integer dot
 * products, fpma, efo, fadm/fmsa/fsubflr, statomic ----
 * The colour forms work on bytes, byte 3 the alpha, a channel x standing for
 * x / 255 (measured, sgxhumation tools/usse-asm/progs/probes/colour.toml).
 * ESIL has no temporaries, so these helpers build expressions that repeat
 * their operands; every string is kept in the arena and freed at the end. */

typedef struct {
	RList *l;
} EArena;

static const char *ea_put(EArena *a, char *s) {
	if (s) {
		r_list_append (a->l, s);
	}
	return s;
}

#define EA(...) ea_put (ar, r_str_newf (__VA_ARGS__))

/* byte b of a register */
static const char *e_byte(EArena *ar, const char *reg, int b) {
	return b ? EA ("0xff,%d,%s,>>,&", 8 * b, reg) : EA ("0xff,%s,&", reg);
}

/* ESIL keeps the strings it stacks in a ring of 32 bytes per stack slot, so
 * a value must not stay stacked while hundreds of others are pushed: the
 * helpers evaluate each operand once (DUP/SWAP) and the longer one first. */

/* max(x, 0) */
static const char *e_relu(EArena *ar, const char *x) {
	return EA ("%s,DUP,63,SWAP,>>,1,-,*", x);
}

/* the smaller and the larger of two signed values */
static const char *e_min(EArena *ar, const char *a, const char *b) {
	return EA ("%s,DUP,%s,SWAP,-,DUP,63,SWAP,>>,1,-,*,SWAP,-", a, b);
}

static const char *e_max(EArena *ar, const char *a, const char *b) {
	return EA ("%s,DUP,%s,-,DUP,63,SWAP,>>,1,-,*,+", a, b);
}

/* p / q rounded to nearest (halves up) for p >= 0, and capped at hi */
static const char *e_round_cap(EArena *ar, const char *p, int q, int hi) {
	return EA ("%s,2,*,%d,+,%d,SWAP,/,DUP,%d,SWAP,-,DUP,63,SWAP,>>,1,-,*,SWAP,-", p, q, 2 * q, hi);
}

/* d / q rounded to nearest (halves away from zero) and clamped to [lo, hi],
 * for a signed d; lo is 0 or -hi */
static const char *e_rdiv(EArena *ar, const char *d, int q, int hi, bool sgn) {
	const char *pos = e_round_cap (ar, e_relu (ar, d), q, hi);
	if (!sgn) {
		return pos;
	}
	const char *neg = e_round_cap (ar, e_relu (ar, EA ("%s,0,-", d)), q, hi);
	return EA ("%s,%s,-", neg, pos);
}

/* x / 255 rounded and saturated to 0..255 */
static const char *e_sat(EArena *ar, const char *d) {
	return e_rdiv (ar, d, 255, 255, false);
}

/* a colour selector without its .comp, and whether it had one */
static bool sel_split(const char *t, char *n, size_t sz, bool *comp) {
	size_t l = strlen (t);
	*comp = l > 5 && !strcmp (t + l - 5, ".comp");
	if (*comp) {
		l -= 5;
	}
	if (!l || l >= sz) {
		return false;
	}
	memcpy (n, t, l);
	n[l] = 0;
	return true;
}

/* The value of a sop3/lrp/sop2wm selector (also sop2's, but s2scale and
 * zeros) in byte b, b = 3 being the alpha reading: zero, one, the sources'
 * channels and alphas, asat = min(s1a, 1 - s2a) (.comp: min(1 - s1a, s2a)),
 * 1 for an alpha. NULL: not a selector. */
static const char *e_sel(EArena *ar, const char *t, const char *s0, const char *s1, const char *s2, int b) {
	char n[12];
	bool c;
	const char *v = NULL;
	if (!sel_split (t, n, sizeof n, &c)) {
		return NULL;
	}
	if (!strcmp (n, "asat")) {
		if (b == 3) {
			return "255";
		}
		const char *a1 = e_byte (ar, s1, 3), *a2 = e_byte (ar, s2, 3);
		return c ? e_min (ar, EA ("%s,255,-", a1), a2) : e_min (ar, a1, EA ("%s,255,-", a2));
	}
	if (!strcmp (n, "zero")) {
		v = "0";
	} else if (!strcmp (n, "one")) {
		v = "255";
	} else if (n[0] == 's' && n[1] >= '0' && n[1] <= '2' && (!n[2] || (n[2] == 'a' && !n[3]))) {
		const char *r = n[1] == '0' ? s0 : n[1] == '1' ? s1 : s2;
		if (!r) {
			return NULL;
		}
		v = e_byte (ar, r, n[2] ? 3 : b);
	} else {
		return NULL;
	}
	return c ? EA ("%s,255,-", v) : v;
}

/* x1 * f1 op x2 * f2 for add or sub, as a signed sum of products */
static const char *e_addsub(EArena *ar, const char *op, const char *x1, const char *f1, const char *x2,
		const char *f2) {
	if (!strcmp (op, "add")) {
		return EA ("%s,%s,*,%s,%s,*,+", f2, x2, f1, x1);
	}
	return strcmp (op, "sub") ? NULL : EA ("%s,%s,*,%s,%s,*,-", f2, x2, f1, x1);
}

/* The operands of a colour instruction: plain profile registers. */
static bool colour_reg(const char *t) {
	return *t != '#' && simple_tok (t);
}

/* Split "a, b, c" into at most n items (in place). */
static int split_list(char *s, char **out, int n) {
	int k = 0;
	while (s && k < n) {
		out[k++] = s;
		char *c = strstr (s, ", ");
		if (!c) {
			break;
		}
		*c = 0;
		s = c + 2;
	}
	return k;
}

/* Place four byte expressions, or keep a byte of d where mask bit b is clear. */
static void bytes_out(RStrBuf *sb, EArena *ar, const char *v[4], const char *d, int mask) {
	int b;
	for (b = 0; b < 4; b++) {
		const char *x = (mask >> b & 1) ? v[b] : e_byte (ar, d, b);
		if (b) {
			r_strbuf_appendf (sb, ",%s,%d,*,|", x, 1 << (8 * b));
		} else {
			r_strbuf_append (sb, x);
		}
	}
	r_strbuf_appendf (sb, ",%s,=", d);
}

/* sop2 d, s1, s2, [comp, ]f1, f2, op+asop2 [comp, ]g1, g2, aop[, neg] (measured):
 * add/sub sum the exact products, divide by 255 once, round and saturate;
 * min/max compare the sources (factors and comp ignored); s2scale (first
 * factor) doubles the result; zeros (second factor) is 0, .comp 1, and makes
 * s2 signed (s2 - 0.5) in add/sub; comp complements s1 in add/sub; neg
 * negates the alpha before saturating. */
static const char *sop2_byte(EArena *ar, char **c, int n, const char *s1, const char *s2, int b, bool neg) {
	int k = 0;
	const bool comp = n == 4 && !strcmp (c[0], "comp");
	if (n != 3 + comp) {
		return NULL;
	}
	k = comp;
	char n1[12], n2[12];
	bool c1, c2;
	if (!sel_split (c[k], n1, sizeof n1, &c1) || !sel_split (c[k + 1], n2, sizeof n2, &c2)) {
		return NULL;
	}
	const char *op = c[k + 2];
	const char *x1 = e_byte (ar, s1, b), *x2 = e_byte (ar, s2, b);
	const int scale = strcmp (n1, "s2scale") ? 1 : 2;
	const char *f1 = scale == 2 ? (c1 ? EA ("%s,255,-", e_byte (ar, s2, b)) : e_byte (ar, s2, b))
		: (strcmp (n1, "zeros") ? e_sel (ar, c[k], NULL, s1, s2, b) : NULL);
	const char *f2;
	bool zs = false;
	if (!strcmp (n2, "zeros")) {
		f2 = c2 ? "255" : "0";
		zs = true;
	} else {
		f2 = strcmp (n2, "s2scale") ? e_sel (ar, c[k + 1], NULL, s1, s2, b) : NULL;
	}
	if (!f1 || !f2 || ((n1[0] == 's' && n1[1] == '0') || (n2[0] == 's' && n2[1] == '0'))) {
		return NULL;
	}
	const char *d;
	if (!strcmp (op, "min") || !strcmp (op, "max")) {
		const char *m = !strcmp (op, "min") ? e_min (ar, x1, x2) : e_max (ar, x1, x2);
		d = EA ("%d,%s,*", 255 * scale, m);
	} else {
		if (comp) {
			x1 = EA ("%s,255,-", x1);
		}
		if (zs) {
			x2 = EA ("128,%s,-", x2);
		}
		d = e_addsub (ar, op, x1, f1, x2, f2);
		if (d && scale == 2) {
			d = EA ("2,%s,*", d);
		}
	}
	if (d && neg) {
		d = EA ("%s,0,-", d);
	}
	return d ? e_sat (ar, d) : NULL;
}

/* sop3/lrp1/lrp2 colour of byte b < 3 (measured): sop3 = op(s1 f1, s2 f2), its
 * neg form -op(s1 f2, s2 f1); lrp1 = x (1 - t) + y t, t = s0 or s0a; lrp2 =
 * f1 m1 + f2 m2 with (m1, m2) = (s1, s2), (s1, 1 - s2), (1, s2), (1 - s1, s2). */
static const char *sop3_colour(EArena *ar, const char *kind, char **c, int n, const char *s0,
		const char *s1, const char *s2, int b) {
	if (!strcmp (kind, "sop3")) {
		const bool neg = n == 4 && !strcmp (c[3], "neg");
		if (n != 3 + neg) {
			return NULL;
		}
		const char *f1 = e_sel (ar, c[neg ? 1 : 0], s0, s1, s2, b);
		const char *f2 = e_sel (ar, c[neg ? 0 : 1], s0, s1, s2, b);
		const char *d = f1 && f2 ? e_addsub (ar, c[2], e_byte (ar, s1, b), f1, e_byte (ar, s2, b), f2) : NULL;
		return d ? e_sat (ar, neg ? EA ("%s,0,-", d) : d) : NULL;
	}
	if (!strcmp (kind, "lrp1")) {
		char nx[12], ny[12];
		bool cx, cy;
		if (n != 3 || !sel_split (c[0], nx, sizeof nx, &cx) || !sel_split (c[1], ny, sizeof ny, &cy)
				|| (strcmp (nx, "zero") && strcmp (nx, "s1")) || (strcmp (ny, "zero") && strcmp (ny, "s2"))
				|| (strcmp (c[2], "s0") && strcmp (c[2], "s0a"))) {
			return NULL;
		}
		const char *x = e_sel (ar, c[0], s0, s1, s2, b), *y = e_sel (ar, c[1], s0, s1, s2, b);
		const char *t = e_byte (ar, s0, strcmp (c[2], "s0") ? 3 : b);
		return e_sat (ar, EA ("%s,%s,*,%s,255,-,%s,*,+", t, y, t, x));
	}
	if (n != 4) {
		return NULL;
	}
	const char *f1 = e_sel (ar, c[0], s0, s1, s2, b), *f2 = e_sel (ar, c[1], s0, s1, s2, b);
	const char *m1 = !strcmp (c[2], "one") ? "255" : !strcmp (c[2], "s1") ? e_byte (ar, s1, b)
		: !strcmp (c[2], "s1.comp") ? EA ("%s,255,-", e_byte (ar, s1, b)) : NULL;
	const char *m2 = !strcmp (c[3], "s2") ? e_byte (ar, s2, b)
		: !strcmp (c[3], "s2.comp") && !strcmp (c[2], "s1") ? EA ("%s,255,-", e_byte (ar, s2, b)) : NULL;
	if (!f1 || !f2 || !m1 || !m2 || (!strcmp (c[3], "s2.comp") && strcmp (c[2], "s1"))) {
		return NULL;
	}
	return e_sat (ar, EA ("%s,%s,*,%s,%s,*,+", m2, f2, m1, f1));
}

/* the sop3/lrp alpha: asop a, f2, op = op(s1a a, s2a f2); arsop a, op =
 * -op(s1a f2, s2a a), f2 the colour's second selector; alrp a, b =
 * a (1 - s0a) + b s0a */
static const char *sop3_alpha(EArena *ar, const char *akind, char **a, int n, const char *f2c,
		const char *s0, const char *s1, const char *s2) {
	const char *a1 = e_byte (ar, s1, 3), *a2 = e_byte (ar, s2, 3);
	if (!strcmp (akind, "asop") && n == 3) {
		const char *x = e_sel (ar, a[0], s0, s1, s2, 3), *y = e_sel (ar, a[1], s0, s1, s2, 3);
		const char *d = x && y ? e_addsub (ar, a[2], a1, x, a2, y) : NULL;
		return d ? e_sat (ar, d) : NULL;
	}
	if (!strcmp (akind, "arsop") && n == 2 && f2c) {
		const char *x = e_sel (ar, a[0], s0, s1, s2, 3), *y = e_sel (ar, f2c, s0, s1, s2, 3);
		const char *d = x && y ? e_addsub (ar, a[1], a1, y, a2, x) : NULL;
		return d ? e_sat (ar, EA ("%s,0,-", d)) : NULL;
	}
	if (!strcmp (akind, "alrp") && n == 2) {
		const char *x = e_sel (ar, a[0], s0, s1, s2, 3), *y = e_sel (ar, a[1], s0, s1, s2, 3);
		const char *t = e_byte (ar, s0, 3);
		return x && y ? e_sat (ar, EA ("%s,%s,*,%s,255,-,%s,*,+", t, y, t, x)) : NULL;
	}
	return NULL;
}

static bool colour_esil(RStrBuf *sb, const char *base, const char *opw, const char *text) {
	char *s = strdup (text), *plus, *ops[8], *col[6], *al[6];
	EArena a = { r_list_newf (free) }, *ar = &a;
	bool ok = false;
	const char *v[4] = { 0 };
	int no, nc, na = 0, mask = 15, b;
	char *sp = strchr (s, ' ');
	if (!sp || !flags_ok (opw, NULL, NULL, NULL)) {
		goto out;
	}
	plus = strchr (sp, '+');
	char *akind = NULL;
	if (plus) {
		*plus = 0;
		akind = plus + 1;
		char *asp = strchr (akind, ' ');
		if (!asp) {
			goto out;
		}
		*asp = 0;
		na = split_list (asp + 1, al, 6);
	}
	const bool three = strcmp (base, "sop2") && strcmp (base, "sop2wm");
	no = split_list (sp + 1, ops, 8);
	if (no < 3 + three + 2) {
		goto out;
	}
	char d[24];
	snprintf (d, sizeof d, "%s", ops[0]);
	if (!strcmp (base, "sop2wm")) {
		char *m = strstr (d, ".bytemask");
		if (!m || strlen (m) != 13) {
			goto out;
		}
		mask = 0;
		for (b = 0; b < 4; b++) {
			mask |= (m[9 + b] == '1') << (3 - b);
		}
		*m = 0;
	}
	const char *s0 = three ? ops[1] : NULL, *s1 = ops[1 + three], *s2 = ops[2 + three];
	if (!colour_reg (d) || !colour_reg (s1) || !colour_reg (s2) || (s0 && !colour_reg (s0))) {
		goto out;
	}
	nc = no - 3 - three;
	memcpy (col, ops + 3 + three, nc * sizeof (char *));
	if (!strcmp (base, "sop2")) {
		if (!akind || strcmp (akind, "asop2")) {
			goto out;
		}
		const bool neg = na >= 1 && !strcmp (al[na - 1], "neg");
		for (b = 0; b < 4; b++) {
			v[b] = b < 3 ? sop2_byte (ar, col, nc, s1, s2, b, false)
				: sop2_byte (ar, al, na - neg, s1, s2, 3, neg);
		}
	} else if (!strcmp (base, "sop2wm")) {
		if (akind || nc != 4) {
			goto out;
		}
		for (b = 0; b < 4; b++) {
			const char *op = col[b < 3 ? 2 : 3];
			const char *x1 = e_byte (ar, s1, b), *x2 = e_byte (ar, s2, b);
			const char *f1 = e_sel (ar, col[0], NULL, s1, s2, b), *f2 = e_sel (ar, col[1], NULL, s1, s2, b);
			if (!f1 || !f2) {
				goto out;
			}
			v[b] = !strcmp (op, "min") ? e_min (ar, x1, x2) : !strcmp (op, "max") ? e_max (ar, x1, x2) : NULL;
			if (!v[b]) {
				const char *dd = e_addsub (ar, op, x1, f1, x2, f2);
				v[b] = dd ? e_sat (ar, dd) : NULL;
			}
		}
	} else {
		if (!akind) {
			goto out;
		}
		for (b = 0; b < 3; b++) {
			v[b] = sop3_colour (ar, base, col, nc, s0, s1, s2, b);
		}
		v[3] = sop3_alpha (ar, akind, al, na, nc > 1 ? col[1] : NULL, s0, s1, s2);
	}
	for (b = 0; b < 4; b++) {
		if (!v[b]) {
			goto out;
		}
	}
	bytes_out (sb, ar, v, d, mask);
	ok = true;
out:
	r_list_free (a.l);
	free (s);
	return ok;
}

/* u8dot3/u8dot4/u16dot3/u16dot4[off] (measured): S = the sum of the byte
 * products over bytes 0-2 or 0-3 (off: of (x - 128)(y - 128)); u8: S Cx / 255
 * into bytes 0-2, S Ax / 255 (or u8dot3's alpha operation) into byte 3, each
 * rounded and saturated; u16: S Cx 32767 / 255^2 into both halves, saturated
 * to 0x7fff (+-0x7fff with off). */
static bool dot_esil(RStrBuf *sb, const char *base, const char *opw, const char *text) {
	char *s = strdup (text), *ops[8], *al[6];
	EArena a = { r_list_newf (free) }, *ar = &a;
	bool ok = false;
	int na = 0, i;
	const bool u16 = base[1] == '1', off = strstr (base, "off") != NULL;
	const int n = strstr (base, "dot4") ? 4 : 3;
	char *sp = strchr (s, ' '), *plus = sp ? strchr (sp, '+') : NULL, *akind = NULL;
	if (!sp || !flags_ok (opw, NULL, NULL, NULL)) {
		goto out;
	}
	if (plus) {
		*plus = 0;
		akind = plus + 1;
		char *asp = strchr (akind, ' ');
		if (!asp || u16 || n != 3) {
			goto out;
		}
		*asp = 0;
		na = split_list (asp + 1, al, 6);
	}
	int no = split_list (sp + 1, ops, 8);
	const bool hasax = no == 5;
	if (no != 4 + hasax || strncmp (ops[1], "Cx", 2) || (hasax && strncmp (ops[2], "Ax", 2))) {
		goto out;
	}
	const int cx = atoi (ops[1] + 2), ax = hasax ? atoi (ops[2] + 2) : cx;
	char x[24], y[24];
	bool cmx, cmy;
	if (!sel_split (ops[2 + hasax], x, sizeof x, &cmx) || !sel_split (ops[3 + hasax], y, sizeof y, &cmy)
			|| !colour_reg (x) || !colour_reg (y) || !colour_reg (ops[0])) {
		goto out;
	}
	RStrBuf *sum = r_strbuf_new ("0");
	for (i = 0; i < n; i++) {
		const char *bx = e_byte (ar, x, i), *by = e_byte (ar, y, i);
		if (cmx) {
			bx = EA ("%s,255,-", bx);
		}
		if (cmy) {
			by = EA ("%s,255,-", by);
		}
		if (off) {
			bx = EA ("128,%s,-", bx);
			by = EA ("128,%s,-", by);
		}
		r_strbuf_appendf (sum, ",%s,%s,*,+", by, bx);
	}
	const char *S = ea_put (ar, r_strbuf_drain (sum));
	if (u16) {
		const char *h = e_rdiv (ar, EA ("%d,%s,*", 32767 * cx, S), 65025, 0x7fff, off);
		r_strbuf_appendf (sb, "%s,0xffff,&,DUP,65536,*,|,%s,=", h, ops[0]);
		ok = true;
		goto out;
	}
	const char *v[4];
	v[0] = v[1] = v[2] = e_sat (ar, EA ("%d,%s,*", cx, S));
	v[3] = e_sat (ar, EA ("%d,%s,*", ax, S));
	if (akind) {
		const char *a1 = e_byte (ar, x, 3), *a2 = e_byte (ar, y, 3);
		v[3] = NULL;
		if ((!strcmp (akind, "aadd") || !strcmp (akind, "asub")) && na == 5 && !strncmp (al[0], "Ax", 2)) {
			const char *f1 = e_sel (ar, al[1], NULL, x, y, 3), *f2 = e_sel (ar, al[3], NULL, x, y, 3);
			const char *v1 = !strcmp (al[2], "s1a") ? a1 : !strcmp (al[2], "s1a.comp") ? EA ("%s,255,-", a1) : NULL;
			const char *v2 = !strcmp (al[4], "s2a") ? a2 : NULL;
			const char *d = f1 && f2 && v1 && v2 ? e_addsub (ar, akind + 1, v1, f1, v2, f2) : NULL;
			v[3] = d ? e_sat (ar, EA ("%d,%s,*", atoi (al[0] + 2), d)) : NULL;
		} else if ((!strcmp (akind, "aintrp1") || !strcmp (akind, "aintrp2")) && na == 3 && colour_reg (al[0])) {
			const char *p = e_sel (ar, al[1], NULL, x, y, 3), *q = e_sel (ar, al[2], NULL, x, y, 3);
			const char *t = e_byte (ar, al[0], 3);
			if (p && q) {
				if (akind[6] == '2') {
					p = EA ("%s,255,-", p);
				}
				v[3] = e_sat (ar, EA ("%s,%s,*,%s,255,-,%s,*,+", t, q, t, p));
			}
		}
		if (!v[3]) {
			goto out;
		}
	}
	bytes_out (sb, ar, v, ops[0], 15);
	ok = true;
out:
	r_list_free (a.l);
	free (s);
	return ok;
}

/* fpma d, s0, s1, s2, c0, c1, c2, a0, a1, a2 = c0 + c1 c2 per channel (alpha
 * a0 + a1 a2), rounded and saturated (measured); .neg negates s0; .sat
 * changed nothing measured; c10 operands are not modelled. */
static bool fpma_esil(RStrBuf *sb, const char *opw, const char *text) {
	static const char * const sat[] = { "sat", NULL };
	char *s = strdup (text), *ops[12];
	EArena a = { r_list_newf (free) }, *ar = &a;
	bool ok = false;
	int b;
	char *sp = strchr (s, ' ');
	if (!sp || !flags_ok (opw, sat, NULL, NULL) || split_list (sp + 1, ops, 12) != 10) {
		goto out;
	}
	char s0[24];
	snprintf (s0, sizeof s0, "%s", ops[1]);
	const bool neg = strlen (s0) > 4 && !strcmp (s0 + strlen (s0) - 4, ".neg");
	if (neg) {
		s0[strlen (s0) - 4] = 0;
	}
	if (!colour_reg (ops[0]) || !colour_reg (s0) || !colour_reg (ops[2]) || !colour_reg (ops[3])) {
		goto out;
	}
	const char *v[4];
	for (b = 0; b < 4; b++) {
		const char *t[3];
		int k;
		for (k = 0; k < 3; k++) {
			char n[12];
			bool c;
			if (!sel_split (ops[(b < 3 ? 4 : 7) + k], n, sizeof n, &c) || n[0] != 's' || n[1] < '0' || n[1] > '2') {
				goto out;
			}
			const char *r = n[1] == '0' ? s0 : ops[2 + n[1] - '1'];
			const char *x = e_byte (ar, r, (n[2] == 'a') ? 3 : b);
			if (n[1] == '0' && neg) {
				x = EA ("%s,0,-", x);
			}
			t[k] = c ? EA ("%s,255,-", x) : x;
		}
		v[b] = e_sat (ar, EA ("%s,%s,*,255,%s,*,+", t[2], t[1], t[0]));
	}
	bytes_out (sb, ar, v, ops[0], 15);
	ok = true;
out:
	r_list_free (a.l);
	free (s);
	return ok;
}

/* The binary32 sum (or difference) of two binary32 bit expressions, rounded
 * and flushed. */
static const char *f_sum(EArena *ar, const char *x, const char *y, bool sub) {
	return EA ("32,32,%s,F2D,32,%s,F2D,%s,D2F,"FLT_FLUSH, y, x, sub ? "F-" : "F+");
}

static const char *f_mul(EArena *ar, const char *x, const char *y) {
	return EA ("32,32,%s,F2D,32,%s,F2D,F*,D2F,"FLT_FLUSH, y, x);
}

/* A float source's flushed bits (src_bits) in the arena. */
static const char *f_src(EArena *ar, const char *t) {
	RStrBuf *b = r_strbuf_new ("");
	if (!src_bits (b, t)) {
		r_strbuf_free (b);
		return NULL;
	}
	return ea_put (ar, r_strbuf_drain (b));
}

/* fadm d, a, b, c = a.c + b.c, fmsa d, a, b, c = a.a + b.c, each product and
 * the sum rounded; fsubflr d, a, b = a - floor(b) (measured). */
static bool fmisc_esil(RStrBuf *sb, const char *base, const char *opw, char **args, int argc) {
	EArena a = { r_list_newf (free) }, *ar = &a;
	bool nowrite, ok = false;
	if (!flags_ok (opw, NULL, NULL, NULL) || !dst_ok (args[0], &nowrite) || nowrite) {
		goto out;
	}
	if (!strcmp (base, "fsubflr") && argc == 3) {
		const char *x = f_src (ar, args[1]), *y = f_src (ar, args[2]);
		if (x && y) {
			r_strbuf_appendf (sb, "32,32,%s,F2D,FLOOR,32,%s,F2D,F-,D2F,"FLT_FLUSH",%s,=", y, x, args[0]);
			ok = true;
		}
	} else if (argc == 4) {
		const char *x = f_src (ar, args[1]), *y = f_src (ar, args[2]), *z = f_src (ar, args[3]);
		if (x && y && z) {
			const char *p = !strcmp (base, "fadm") ? f_mul (ar, x, z) : f_mul (ar, x, x);
			r_strbuf_appendf (sb, "%s,%s,=", f_sum (ar, p, f_mul (ar, y, z), false), args[0]);
			ok = true;
		}
	}
out:
	r_list_free (a.l);
	return ok;
}

/* efo (measured): m0, m1 multiply the named sources or i0/i1, a0, a1 add or
 * subtract the named values, each rounded to binary32; d takes a0, a1 or the
 * old i0/i1; i0 and i1 are written after (! keeps them). Not modelled:
 * .gpiext (it moves the multipliers' i0/i1 and the writes to i2/i3, but one
 * pixel in four sees another instance's values), sources with a half-float
 * reading ("a/b") and repeats. */
static bool efo_esil(RStrBuf *sb, const char *opw, const char *text) {
	char *s = strdup (text), *it[10];
	EArena a = { r_list_newf (free) }, *ar = &a;
	bool ok = false;
	char *sp = strchr (s, ' '), *eq = sp ? strstr (sp, "= ") : NULL;
	if (!sp || !eq || strchr (s, '/') || !flags_ok (opw, NULL, NULL, NULL)) {
		goto out;
	}
	*eq = 0;
	const char *d = sp + 1;
	/* dsel, i0w, i1w, a0..., a1..., m0..., m1..., s0, s1, s2 ("a0=x+y a1=..." has no comma) */
	int n = split_list (eq + 2, it, 10), k = 0;
	char a0[24], a1[24];
	if (n == 9) {
		char *t = strstr (it[3], " a1=");
		if (!t) {
			goto out;
		}
		*t = 0;
		snprintf (a0, sizeof a0, "%s", it[3]);
		snprintf (a1, sizeof a1, "%s", t + 1);
		k = -1;
	} else if (n == 10) {
		snprintf (a0, sizeof a0, "%s", it[3]);
		snprintf (a1, sizeof a1, "%s", it[4]);
	} else {
		goto out;
	}
	const char *m0t = it[5 + k], *m1t = it[6 + k];
	const char *src[3];
	int i;
	for (i = 0; i < 3; i++) {
		src[i] = f_src (ar, it[7 + k + i]);
		if (!src[i]) {
			goto out;
		}
	}
	bool nowrite;
	if (!dst_ok (d, &nowrite) || nowrite || (strcmp (it[0], "a0") && strcmp (it[0], "a1")
			&& strcmp (it[0], "i0") && strcmp (it[0], "i1"))) {
		goto out;
	}
	/* operands: srcN, i0, i1, flushed as every float input */
	const char *i0f = EA ("i0,"FLT_FLUSH), *i1f = EA ("i1,"FLT_FLUSH);
#define EFO_OPND(t) (!strcmp (t, "src0") ? src[0] : !strcmp (t, "src1") ? src[1] \
		: !strcmp (t, "src2") ? src[2] : !strcmp (t, "i0") ? i0f : !strcmp (t, "i1") ? i1f : NULL)
	const char *m[2];
	const char *mt[2] = { m0t, m1t };
	for (i = 0; i < 2; i++) {
		char x[8], y[8];
		if (sscanf (mt[i], "m%*d=%7[a-z0-9]*%7[a-z0-9]", x, y) != 2 || !EFO_OPND (x) || !EFO_OPND (y)) {
			goto out;
		}
		m[i] = f_mul (ar, EFO_OPND (x), EFO_OPND (y));
	}
	/* a0=X(+|-)Y, a1=[-]X+Y */
	const char *av[2];
	const char *at[2] = { a0, a1 };
	for (i = 0; i < 2; i++) {
		const char *e = at[i] + 3;
		const bool lneg = *e == '-';
		char x[8], y[8], opc;
		if (lneg) {
			e++;
		}
		if (sscanf (e, "%7[a-z0-9]%c%7[a-z0-9]", x, &opc, y) != 3 || (opc != '+' && opc != '-')) {
			goto out;
		}
		const char *vx = !strcmp (x, "m0") ? m[0] : !strcmp (x, "m1") ? m[1] : EFO_OPND (x);
		const char *vy = !strcmp (y, "m0") ? m[0] : !strcmp (y, "m1") ? m[1] : EFO_OPND (y);
		if (!vx || !vy) {
			goto out;
		}
		if (lneg) {
			vx = EA ("0x80000000,%s,^", vx);
		}
		av[i] = f_sum (ar, vx, vy, opc == '-');
	}
#undef EFO_OPND
	const char *val[4] = { av[0], av[1], m[0], m[1] };
	static const char * const vn[4] = { "a0", "a1", "m0", "m1" };
	const char *w[2] = { NULL, NULL };
	for (i = 0; i < 2; i++) {
		char nm[8];
		const char *t = it[1 + i];
		const bool skip = *t == '!';
		if (sscanf (t + skip, "i%*d = %7s", nm) != 1) {
			goto out;
		}
		int j;
		for (j = 0; j < 4 && strcmp (nm, vn[j]); j++) {
		}
		if (j == 4) {
			goto out;
		}
		w[i] = skip ? NULL : val[j];
	}
	/* a register name on the ESIL stack is read when popped: read i0/i1 now */
	const char *dv = !strcmp (it[0], "a0") ? av[0] : !strcmp (it[0], "a1") ? av[1] : EA ("%s,0,|", it[0]);
	/* push d's value and the writes' values first, then assign */
	r_strbuf_appendf (sb, "%s", dv);
	if (w[0]) {
		r_strbuf_appendf (sb, ",%s", w[0]);
	}
	if (w[1]) {
		r_strbuf_appendf (sb, ",%s,i1,=", w[1]);
	}
	if (w[0]) {
		r_strbuf_append (sb, ",i0,=");
	}
	r_strbuf_appendf (sb, ",%s,=", d);
	ok = true;
out:
	r_list_free (a.l);
	free (s);
	return ok;
}

/* statomic d, s1.c, s2.c writes, in both halves, byte c of s1 (low) and of s2
 * (high), each read as a signed byte with negatives made 0 (measured); the
 * rounding mode and .scale change nothing. */
static bool statomic_esil(RStrBuf *sb, const char *opw, char **args, int argc) {
	static const char * const sc[] = { "scale", NULL };
	EArena a = { r_list_newf (free) }, *ar = &a;
	char r1[24], r2[24];
	int c1, c2;
	bool nowrite, ok = false;
	if (argc == 4 && flags_ok (opw, sc, NULL, NULL) && dst_ok (args[0], &nowrite) && !nowrite
			&& comp_src (args[1], r1, sizeof r1, &c1) && comp_src (args[2], r2, sizeof r2, &c2)) {
		const char *x = e_byte (ar, r1, c1), *y = e_byte (ar, r2, c2);
		x = EA ("%s,DUP,7,SWAP,>>,1,-,*", x);
		y = EA ("%s,DUP,7,SWAP,>>,1,-,*", y);
		r_strbuf_appendf (sb, "%s,%s,256,*,|,DUP,65536,*,|,%s,=", x, y, args[0]);
		ok = true;
	}
	r_list_free (a.l);
	return ok;
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

	const char *btext = text + (body - s);
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
	} else if (shift && sched && argc == 3 && simple_tok (args[0]) && simple_tok (args[1]) && *args[2] == '#'
			&& simple_tok (args[2]) && strtoull (args[2] + 1, NULL, 0) < 32) {
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
		char mdb[48];
		int wm;
		ab = r_strbuf_new ("");
		if (!strstr (opw, ".test") && dst_mask (args[0], mdb, sizeof mdb, &wm)) {
			ok = mask_esil (ab, base, opw, args, argc);
		} else if (strstr (opw, ".test")) {
			ok = test_esil (ab, base, opw, args, argc);
		} else if ((bitwise || shift || !strcmp (base, "rol") || !strcmp (base, "asr")) && sched && argc == 3
				&& dst_ok (args[0], &nowrite) && !nowrite
				&& src_parse (args[1], &sa) && src_parse (args[2], &sb)) {
			ok = alu_val (ab, base, &sa, &sb) && r_strbuf_appendf (ab, ",%s,=", args[0]);
		} else if (!strcmp (base, "imae") || !strcmp (base, "ima32")) {
			ok = imul_esil (ab, base, opw, args, argc);
		} else if (!strcmp (base, "ima16")) {
			ok = ima16_esil (ab, opw, args, argc);
		} else if (!strcmp (base, "sop2") || !strcmp (base, "sop3") || !strcmp (base, "lrp1")
				|| !strcmp (base, "lrp2") || !strcmp (base, "sop2wm")) {
			ok = colour_esil (ab, base, opw, btext);
		} else if (strstr (base, "dot") && (base[0] == 'u')) {
			ok = dot_esil (ab, base, opw, btext);
		} else if (!strcmp (base, "fpma")) {
			ok = fpma_esil (ab, opw, btext);
		} else if (!strcmp (base, "efo")) {
			ok = efo_esil (ab, opw, btext);
		} else if (!strcmp (base, "fadm") || !strcmp (base, "fmsa") || !strcmp (base, "fsubflr")) {
			ok = fmisc_esil (ab, base, opw, args, argc);
		} else if (!strcmp (base, "statomic")) {
			ok = statomic_esil (ab, opw, args, argc);
		} else if (*base == 'f') {
			ok = flt_rep_esil (ab, base, opw, args, argc);
			if (!ok) {
				r_strbuf_set (ab, "");
				ok = flt_esil (ab, base, opw, args, argc);
			}
		} else if (!strcmp (base, "movc")) {
			ok = movc_esil (ab, opw, args, argc);
		} else if (!strcmp (base, "movmsk")) {
			ok = movmsk_esil (ab, opw, args, argc);
		} else if (!strncmp (base, "pck", 3) || !strncmp (base, "unpck", 5)) {
			ok = pack_esil (ab, base, opw, args, argc);
		} else if (!strcmp (base, "ldr") || !strcmp (base, "str")) {
			ok = cr_esil (ab, base, opw, args, argc);
		} else if (!strcmp (base, "mov")) {
			ok = (strchr (args[0], '[') || strchr (args[1], '[') || !strcmp (args[0], "i.l"))
				? idx_esil (ab, opw, args, argc) : mov_repeat_esil (ab, opw, args, argc);
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
		if (!(mo.imm ? mem_esil (&mo, mb) : mem_reg_esil (&mo, mb))) {
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
