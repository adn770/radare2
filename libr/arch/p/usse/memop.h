/* radare - LGPL-3.0-only - PowerVR SGX Series-5 USSE load/store semantics
 *
 * Shared by the arch plugin (ESIL) and the pseudo plugin. Parses our own
 * ldad/ldaw/stad/staw text and says which memory elements an access touches.
 * The printed immediate is the encoded field (identical to Imagination's own
 * disassembler); it is in elements of the data size (4 for d, 2 for w) and its
 * meaning depends on the form:
 *
 *   plain  [b,+#k]   element b+k              [b,-#k] element b-k
 *   plain  [b,++#k]  b += k, then element b   (pre-increment)
 *   plain  [b,#k++]  element b, then b += k   (post-increment)
 *   fetchN [b,+#k]   elements b+k+1 .. b+k+N  (the fetch adds one element)
 *   fetchN [b,#k++]  elements b+k .. b+k+N-1, then b += N
 *
 * fetchN with a pre-increment or a negative offset is not seen in any corpus
 * and is left unmodelled. */

#ifndef USSE_MEMOP_H
#define USSE_MEMOP_H

#include <r_util.h>

enum { USSE_AM_NONE, USSE_AM_PRE, USSE_AM_POST };

typedef struct {
	bool load;
	int size;        /* bytes per element */
	int fetch;       /* fetch count; 0 = plain form */
	int mode;        /* USSE_AM_* */
	bool neg;        /* '-' / '--' */
	bool imm;        /* immediate offset (else register) */
	ut64 k;          /* immediate offset, in elements */
	char base[16];
	char off[16];    /* offset operand text without sign/increment */
	char data[24];   /* load destination or store source */
} UsseMemOp;

/* opw: full op word ("ldad.bpcache.fetch4"); a0/a1: first two operands. */
static inline bool usse_memop_parse(const char *opw, const char *a0, const char *a1, UsseMemOp *m) {
	memset (m, 0, sizeof (*m));
	if (!opw || !a0 || !a1) {
		return false;
	}
	if (!strncmp (opw, "ldad", 4) || !strncmp (opw, "stad", 4)) {
		m->size = 4;
	} else if (!strncmp (opw, "ldaw", 4) || !strncmp (opw, "staw", 4)) {
		m->size = 2;
	} else {
		return false;
	}
	if (opw[4] && opw[4] != '.') {
		return false;
	}
	m->load = opw[0] == 'l';
	if (strstr (opw, ".repeat")) {
		return false;
	}
	const char *f = strstr (opw, ".fetch");
	if (f) {
		m->fetch = atoi (f + 6);
		if (m->fetch < 1 || m->fetch > 16) {
			return false;
		}
	}
	const char *mem = m->load ? a1 : a0;
	const char *dat = m->load ? a0 : a1;
	if (*mem != '[' || strlen (dat) >= sizeof (m->data)) {
		return false;
	}
	snprintf (m->data, sizeof (m->data), "%s", dat);
	char tmp[64];
	snprintf (tmp, sizeof (tmp), "%s", mem + 1);
	char *rb = strchr (tmp, ']');
	if (!rb) {
		return false;
	}
	*rb = 0;
	char *comma = strchr (tmp, ',');
	if (!comma || (size_t)(comma - tmp) >= sizeof (m->base)) {
		return false;
	}
	*comma = 0;
	snprintf (m->base, sizeof (m->base), "%s", tmp);
	char *o = comma + 1;
	size_t ol = strlen (o);
	if (!strncmp (o, "++", 2) || !strncmp (o, "--", 2)) {
		m->mode = USSE_AM_PRE;
		m->neg = *o == '-';
		o += 2;
	} else if (ol > 2 && (!strcmp (o + ol - 2, "++") || !strcmp (o + ol - 2, "--"))) {
		m->mode = USSE_AM_POST;
		m->neg = o[ol - 1] == '-';
		o[ol - 2] = 0;
	} else if (*o == '+' || *o == '-') {
		m->neg = *o == '-';
		o++;
	} else {
		return false;
	}
	if (!*o || strlen (o) >= sizeof (m->off)) {
		return false;
	}
	snprintf (m->off, sizeof (m->off), "%s", o);
	if (*o == '#') {
		char *end = NULL;
		m->imm = true;
		m->k = (ut64) strtoull (o + 1, &end, 0);
		if (!end || *end) {
			return false;
		}
	}
	return true;
}

/* Is the access fully modelled (addresses known from the text alone)? */
static inline bool usse_memop_modelled(const UsseMemOp *m) {
	if (!m->imm) {
		return false;
	}
	if (m->fetch && (m->neg || m->mode == USSE_AM_PRE)) {
		return false;
	}
	return true;
}

/* Element index (relative to the base before the access) of fetched element i.
 * Only for modelled fetch forms. */
static inline ut64 usse_memop_elem(const UsseMemOp *m, int i) {
	return m->k + (m->mode == USSE_AM_NONE ? 1 : 0) + (ut64) i;
}

/* Base register writeback in elements (0 = none); *neg set for a decrement. */
static inline ut64 usse_memop_writeback(const UsseMemOp *m, bool *neg) {
	*neg = m->neg;
	if (m->fetch) {
		*neg = false;
		return m->mode == USSE_AM_POST ? (ut64) m->fetch : 0;
	}
	return m->mode == USSE_AM_NONE ? 0 : m->k;
}

/* i-th register of a consecutive run starting at r ("r5", 2 -> "r7").
 * Immediates are returned unchanged. */
static inline bool usse_reg_nth(const char *r, int i, char *out, size_t n) {
	if (*r == '#') {
		snprintf (out, n, "%s", r);
		return true;
	}
	const char *p = r;
	while (*p >= 'a' && *p <= 'z') {
		p++;
	}
	if (p == r || !*p) {
		return false;
	}
	const char *d = p;
	while (*d >= '0' && *d <= '9') {
		d++;
	}
	if (*d) {
		return false;
	}
	snprintf (out, n, "%.*s%d", (int)(p - r), r, atoi (p) + i);
	return true;
}

#endif
