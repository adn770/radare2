/* radare - LGPL-3.0-only - PowerVR SGX Series-5 USSE pseudo syntax */

#include <r_lib.h>
#include <r_util.h>
#include <r_asm.h>

/* Rewrite a decoded USSE instruction into a pseudo-C-ish form, e.g.
 *   mov r0, r1              -> r0 = r1
 *   and r0, r1, r2          -> r0 = r1 & r2
 *   fmad r0, r1, r2, r3     -> r0 = r1 * r2 + r3
 *   imae r0, r1, r2, r3     -> r0 = r1 * r2 + r3
 *   ldad.fcfill r4,[r0,#1++] -> r4 = mem[r0 + 1++]
 *   stad.bpcache [sa1,+#14],r16 -> mem[sa1 + 14] = r16
 *   ba #0x20                -> goto 0x20
 *   ba.savelink #0x20       -> call 0x20
 *   p0 mov r0, r1           -> if (p0) r0 = r1
 * Conservative: only the forms above are rewritten; anything else (test-
 * predicate ALU, smlsi, ci/cfi, ...) is passed through unchanged (return NULL).
 * Memory offsets mirror the disassembly (dword index), not bytes. */

static const char *binop(const char *op) {
	if (!strcmp (op, "and")) return "&";
	if (!strcmp (op, "or"))  return "|";
	if (!strcmp (op, "xor")) return "^";
	if (!strcmp (op, "shl")) return "<<";
	if (!strcmp (op, "shr")) return ">>";
	return NULL;
}

/* "[sa1,+#14]" -> "mem[sa1 + 14]" (prettify, no scaling). */
static char *memref(const char *a) {
	if (*a != '[') {
		return strdup (a);
	}
	char *s = strdup (a + 1);
	char *rb = strchr (s, ']');
	if (rb) {
		*rb = 0;
	}
	s = r_str_replace (s, ",+#", " + ", 1);
	s = r_str_replace (s, ",#", " + ", 1);
	s = r_str_replace (s, ",+", " + ", 1);
	s = r_str_replace (s, ",", " + ", 1);
	s = r_str_replace (s, "#", "", 1);
	char *out = r_str_newf ("mem[%s]", s);
	free (s);
	return out;
}

static char *parse(RAsmPluginSession *aps, const char *data) {
	if (!data || !*data) {
		return NULL;
	}
	char *s = strdup (data);
	if (!s) {
		return NULL;
	}
	char cond[8] = {0};

	/* optional predicate prefix: "p0 ", "!p0 ", ... */
	char *body = s;
	if (body[0] == 'p' || (body[0] == '!' && body[1] == 'p')) {
		char *sp = strchr (body, ' ');
		if (sp) {
			size_t n = (size_t) (sp - body);
			if (n < sizeof (cond)) {
				memcpy (cond, body, n);
				cond[n] = 0;
				body = sp + 1;
			}
		}
	}

	/* split "op arg0, arg1, ..." */
	char *sp = strchr (body, ' ');
	char *op = body;
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
	/* base op = up to first '.' (so ldad.fcfill / stad.bpcache match) */
	char base[16];
	const char *dot = strchr (op, '.');
	size_t bn = dot ? (size_t) (dot - op) : strlen (op);
	if (bn >= sizeof base) {
		bn = sizeof base - 1;
	}
	memcpy (base, op, bn);
	base[bn] = 0;

	RStrBuf *sb = r_strbuf_new ("");
	bool ok = false;
	const char *bo;
	if (!strcmp (op, "mov") && argc == 2) {
		r_strbuf_setf (sb, "%s = %s", args[0], args[1]);
		ok = true;
	} else if ((bo = binop (op)) && argc == 3) {
		r_strbuf_setf (sb, "%s = %s %s %s", args[0], args[1], bo, args[2]);
		ok = true;
	} else if ((!strcmp (op, "fmad") || !strcmp (base, "imae")) && argc == 4) {
		r_strbuf_setf (sb, "%s = %s * %s + %s", args[0], args[1], args[2], args[3]);
		ok = true;
	} else if ((!strcmp (base, "ldad") || !strcmp (base, "ldaw")) && argc >= 2) {
		char *m = memref (args[1]);
		r_strbuf_setf (sb, "%s = %s", args[0], m);
		free (m);
		ok = true;
	} else if ((!strcmp (base, "stad") || !strcmp (base, "staw")) && argc >= 2) {
		char *m = memref (args[0]);
		r_strbuf_setf (sb, "%s = %s", m, args[1]);
		free (m);
		ok = true;
	} else if ((!strcmp (op, "ba") || !strcmp (op, "br")) && argc == 1) {
		r_strbuf_setf (sb, "goto %s", args[0] + (args[0][0] == '#'));
		ok = true;
	} else if ((!strcmp (op, "ba.savelink") || !strcmp (op, "br.savelink")) && argc == 1) {
		r_strbuf_setf (sb, "call %s", args[0] + (args[0][0] == '#'));
		ok = true;
	}

	char *out = NULL;
	if (ok) {
		if (*cond) {
			char *inner = r_strbuf_drain (sb);
			out = r_str_newf ("if (%s) %s", cond, inner);
			free (inner);
		} else {
			out = r_strbuf_drain (sb);
		}
	} else {
		r_strbuf_free (sb);
	}
	free (s);
	return out;
}

RAsmPlugin r_asm_plugin_usse = {
	.meta = {
		.name = "usse",
		.desc = "PowerVR SGX Series-5 USSE pseudo syntax",
		.author = "SGXhumation",
		.license = "LGPL-3.0-only",
	},
	.parse = parse,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_usse,
	.version = R2_VERSION
};
#endif
