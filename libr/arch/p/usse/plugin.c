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

/* ---- register profile ---------------------------------------------------- */
static char *regs(RArchSession *s) {
	const char * const p =
#include "regs.h"
	;
	return strdup (p);
}

/* ---- text-operand analysis (metadata + ESIL) ----------------------------- *
 * We parse our own regular mnemonic text (never the raw bits) into predicate +
 * base-op + args, then fill op->val / op->direction and, for the control
 * subset, op->esil. Conservative: only clean reg/#imm operands are modelled;
 * flagged/complex forms (test-predicate, memory ++/reg-offset, fmad, imae, ...)
 * are left without ESIL. */

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
	return *p == '\0';
}

/* ESIL token for a reg or #imm operand (strip the '#'). */
static const char *esil_tok(const char *t) {
	return (*t == '#') ? t + 1 : t;
}

/* Parse "[base,(+)#off]" -> base reg + byte offset (off is in dwords, *4).
 * Rejects register offsets and post-increment ("++"). */
static bool mem_parse(const char *a, char *base, size_t bsz, ut64 *byteoff) {
	if (*a != '[') {
		return false;
	}
	char tmp[64];
	snprintf (tmp, sizeof tmp, "%s", a + 1);
	char *rb = strchr (tmp, ']');
	if (rb) {
		*rb = 0;
	}
	char *comma = strchr (tmp, ',');
	if (!comma) {
		return false;
	}
	*comma = 0;
	char *off = comma + 1;
	if (*off == '+') {
		off++;
	}
	if (*off != '#' || strstr (off, "++")) {
		return false; /* register offset or post-increment: not modelled */
	}
	snprintf (base, bsz, "%s", tmp);
	*byteoff = (ut64) strtoull (off + 1, NULL, 0) * 4;
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
	char *args[4] = {0};
	int argc = 0;
	if (sp) {
		*sp = 0;
		char *p = sp + 1;
		while (p && argc < 4) {
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
	} else if (!strcmp (base, "stad") || !strcmp (base, "staw")) {
		op->direction = R_ANAL_OP_DIR_WRITE;
	}

	if (!(mask & R_ARCH_OP_MASK_ESIL)) {
		free (s);
		return;
	}

	char e[192];
	e[0] = 0;
	char mbase[64];
	ut64 moff;

	if (!strcmp (base, "mov") && argc == 2 && simple_tok (args[0]) && simple_tok (args[1])) {
		snprintf (e, sizeof e, "%s,%s,=", esil_tok (args[1]), args[0]);
	} else if ((!strcmp (base, "and") || !strcmp (base, "or") || !strcmp (base, "xor"))
			&& argc == 3 && simple_tok (args[0]) && simple_tok (args[1]) && simple_tok (args[2])) {
		const char *sym = !strcmp (base, "and") ? "&" : !strcmp (base, "or") ? "|" : "^";
		snprintf (e, sizeof e, "%s,%s,%s,%s,=", esil_tok (args[2]), esil_tok (args[1]), sym, args[0]);
	} else if ((!strcmp (base, "shl") || !strcmp (base, "shr"))
			&& argc == 3 && simple_tok (args[0]) && simple_tok (args[1]) && simple_tok (args[2])) {
		const char *sym = !strcmp (base, "shl") ? "<<" : ">>";
		snprintf (e, sizeof e, "%s,%s,%s,%s,=", esil_tok (args[2]), esil_tok (args[1]), sym, args[0]);
	} else if ((!strcmp (base, "ldad") || !strcmp (base, "ldaw")) && argc >= 2
			&& simple_tok (args[0]) && mem_parse (args[1], mbase, sizeof mbase, &moff)) {
		snprintf (e, sizeof e, "%"PFMT64u",%s,+,[4],%s,=", moff, mbase, args[0]);
	} else if ((!strcmp (base, "stad") || !strcmp (base, "staw")) && argc >= 2
			&& simple_tok (args[1]) && mem_parse (args[0], mbase, sizeof mbase, &moff)) {
		snprintf (e, sizeof e, "%s,%"PFMT64u",%s,+,=[4]", esil_tok (args[1]), moff, mbase);
	} else if ((!strcmp (base, "ba") || !strcmp (base, "br")) && argc == 1) {
		if (strstr (opw, "savelink")) {
			snprintf (e, sizeof e, "8,pc,+,pclink,=,0x%"PFMT64x",pc,=", op->jump);
		} else {
			snprintf (e, sizeof e, "0x%"PFMT64x",pc,=", op->jump);
		}
	}

	if (e[0]) {
		if (cond[0]) {
			r_strbuf_setf (&op->esil, "%s,%s?{,%s,}", cond, neg ? "!," : "", e);
		} else {
			r_strbuf_set (&op->esil, e);
		}
	}
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
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_usse,
	.version = R2_VERSION
};
#endif
