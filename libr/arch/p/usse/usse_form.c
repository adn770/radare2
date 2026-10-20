/* usse_form.c — decode and encode USSE words with the form table (see
 * usse_form.h). Generic kinds (enumerations and numbers) live here; the
 * USSE-specific operand kinds live with the table in usse.c. */
#include "usse_form.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ---- fields ------------------------------------------------------------- */

unsigned usse_field_width(const usse_field *f) {
    unsigned w = 0;
    for (int i = 0; i < USSE_MAX_CHUNKS && f->c[i].w; i++) w += f->c[i].w;
    return w;
}

uint32_t usse_field_get(const usse_field *f, uint64_t e) {
    uint32_t v = 0;
    unsigned at = 0;
    for (int i = 0; i < USSE_MAX_CHUNKS && f->c[i].w; i++) {
        uint64_t m = (1ull << f->c[i].w) - 1;
        v |= (uint32_t)((e >> f->c[i].lo) & m) << at;
        at += f->c[i].w;
    }
    return v;
}

uint64_t usse_field_put(const usse_field *f, uint64_t e, uint32_t v) {
    for (int i = 0; i < USSE_MAX_CHUNKS && f->c[i].w; i++) {
        uint64_t m = (1ull << f->c[i].w) - 1;
        e = (e & ~(m << f->c[i].lo)) | (((uint64_t)v & m) << f->c[i].lo);
        v >>= f->c[i].w;
    }
    return e;
}

static uint64_t field_bits(const usse_field *f) {
    uint64_t b = 0;
    for (int i = 0; i < USSE_MAX_CHUNKS && f->c[i].w; i++)
        b |= ((1ull << f->c[i].w) - 1) << f->c[i].lo;
    return b;
}

uint64_t usse_form_bits(const usse_form *fm) {
    uint64_t b = fm->mask;
    for (int i = 0; i < USSE_MAX_FIELDS && fm->f[i].k; i++) b |= field_bits(&fm->f[i]);
    return b;
}

/* ---- rendering ---------------------------------------------------------- */

int usse_form_render(const usse_form *fm, uint64_t e, char *out, size_t n) {
    size_t at = 0;
    for (const char *p = fm->pat; *p; ) {
        if (p[0] == '{' && isdigit((unsigned char)p[1]) && p[2] == '}') {
            const usse_field *f = &fm->f[p[1] - '0'];
            char buf[96];
            if (!f->k || !f->k->print(f->k, usse_field_get(f, e), buf, sizeof buf)) return 0;
            size_t l = strlen(buf);
            if (at + l >= n) return 0;
            memcpy(out + at, buf, l);
            at += l;
            p += 3;
        } else {
            if (at + 1 >= n) return 0;
            out[at++] = *p++;
        }
    }
    out[at] = '\0';
    return 1;
}

const usse_form *usse_form_decode_in(const usse_table *t, uint64_t e, char *out, size_t n) {
    for (size_t i = 0; i < t->n; i++) {
        const usse_form *fm = &t->forms[i];
        if ((e & fm->mask) != fm->val) continue;
        if (!fm->pat) return NULL;
        if (usse_form_render(fm, e, out, n)) return fm;
    }
    return NULL;
}

const usse_form *usse_form_decode(uint64_t e, char *out, size_t n) {
    return usse_form_decode_in(&usse_table_main, e, out, n);
}

/* ---- generic kinds ------------------------------------------------------ */

int usse_k_enum_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    const char *const *tab = k->arg;
    if (!tab[v]) return 0;
    snprintf(out, n, "%s", tab[v]);
    return 1;
}

static usse_resolver resolver;
static void *resolver_ctx;

void usse_form_set_resolver(usse_resolver r, void *ctx) {
    resolver = r;
    resolver_ctx = ctx;
}

/* Unsigned number: decimal, hex with a 0x prefix, or a name the resolver knows. */
int usse_parse_uint(const char *s, const char **end, uint64_t *v) {
    const char *p = s;
    uint64_t x = 0;
    if (resolver && (isalpha((unsigned char)*p) || *p == '_')) {
        while (isalnum((unsigned char)*p) || *p == '_' || *p == '.') p++;
        if (!resolver(s, (size_t)(p - s), &x, resolver_ctx) || x > 0xffffffffull) return 0;
        *end = p;
        *v = x;
        return 1;
    }
    if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X') && isxdigit((unsigned char)p[2])) {
        for (p += 2; isxdigit((unsigned char)*p); p++) {
            x = x * 16 + (unsigned)(isdigit((unsigned char)*p) ? *p - '0'
                                    : tolower((unsigned char)*p) - 'a' + 10);
            if (x > 0xffffffffull) return 0;
        }
    } else if (isdigit((unsigned char)*p)) {
        for (; isdigit((unsigned char)*p); p++) {
            x = x * 10 + (unsigned)(*p - '0');
            if (x > 0xffffffffull) return 0;
        }
    } else {
        return 0;
    }
    if (isalnum((unsigned char)*p) || *p == '_') return 0;
    *end = p;
    *v = x;
    return 1;
}

int usse_k_num_print(const usse_kind *k, uint32_t v, char *out, size_t n) {
    const usse_num *a = k->arg;
    snprintf(out, n, a->fmt, (unsigned)(v * a->mul + a->add));
    return 1;
}

int usse_k_num_parse(const usse_kind *k, const char *s, const char **end, uint32_t *v) {
    const usse_num *a = k->arg;
    uint64_t x;
    if (!usse_parse_uint(s, end, &x) || x < a->add || (x - a->add) % a->mul) return 0;
    *v = (uint32_t)((x - a->add) / a->mul);
    return 1;
}

/* ---- encoding ----------------------------------------------------------- */

typedef struct {
    const usse_table *t;
    const usse_form *fm;
    uint32_t v[USSE_MAX_FIELDS];
    uint64_t out;
} match_ctx;

static const char *skip_ws(const char *s) {
    while (isspace((unsigned char)*s)) s++;
    return s;
}

/* Match expected text x (a pattern literal or a printed field) at the start of
 * s: a space in x matches any run of blanks, blanks may precede a comma, a
 * comment in x counts as a blank, and letters match in either case (radare2
 * lowercases what it assembles). Return the end of the match, or NULL. */
static const char *lit(const char *x, size_t len, const char *s) {
    const char *xe = x + len;
    while (x < xe) {
        if (x[0] == '/' && x + 1 < xe && x[1] == '*') {
            const char *c = strstr(x + 2, "*/");
            x = c ? c + 2 : xe;
            s = skip_ws(s);
        } else if (*x == ' ') {
            s = skip_ws(s);
            x++;
        } else if (*x == ',') {
            s = skip_ws(s);
            if (*s != ',') return NULL;
            s++;
            x++;
        } else {
            if (tolower((unsigned char)*s) != tolower((unsigned char)*x)) return NULL;
            s++;
            x++;
        }
    }
    return s;
}

static int finish(match_ctx *c) {
    const usse_form *fm = c->fm;
    uint64_t e = fm->val | (fm->dflt & ~usse_form_bits(fm));
    for (int i = 0; i < USSE_MAX_FIELDS && fm->f[i].k; i++)
        e = usse_field_put(&fm->f[i], e, c->v[i]);
    /* The word must decode with this form's text (an earlier form may claim
     * it, or a field may not print); otherwise keep searching. */
    char want[160], got[160];
    if (!usse_form_render(fm, e, want, sizeof want)) return 0;
    if (c->t->decode) {
        if (!c->t->decode(e, got, sizeof got)) return 0;
    } else if (!usse_form_decode_in(c->t, e, got, sizeof got)) {
        return 0;
    }
    if (strcmp(want, got)) return 0;
    c->out = e;
    return 1;
}

static int match(match_ctx *c, const char *p, const char *s) {
    for (;;) {
        if (!*p) {
            s = skip_ws(s);
            return *s ? 0 : finish(c);
        }
        if (p[0] == '{' && isdigit((unsigned char)p[1]) && p[2] == '}') {
            int i = p[1] - '0';
            const usse_field *f = &c->fm->f[i];
            unsigned w = usse_field_width(f);
            uint32_t lim = w >= 32 ? 0xffffffffu : (1u << w) - 1;
            p += 3;
            if (f->k->parse) {
                const char *end;
                uint32_t v;
                if (!f->k->parse(f->k, s, &end, &v) || v > lim) return 0;
                c->v[i] = v;
                return match(c, p, end);
            }
            /* Search the field's values for one that prints the text, trying
             * the form's preferred value (from dflt) first. */
            uint32_t pref = usse_field_get(f, c->fm->dflt);
            for (uint64_t n = 0; n <= (uint64_t)lim + 1; n++) {
                uint32_t v = n ? (uint32_t)(n - 1) : pref;
                char buf[96];
                if (n && v == pref) continue;
                if (f->k->print(f->k, v, buf, sizeof buf)) {
                    const char *q = lit(buf, strlen(buf), s);
                    if (q) {
                        c->v[i] = v;
                        if (match(c, p, q)) return 1;
                    }
                }
            }
            return 0;
        }
        /* one literal character (or a comment) */
        size_t len = 1;
        if (p[0] == '/' && p[1] == '*') {
            const char *ce = strstr(p + 2, "*/");
            len = ce ? (size_t)(ce + 2 - p) : strlen(p);
        }
        s = lit(p, len, s);
        if (!s) return 0;
        p += len;
    }
}

int usse_form_encode_in(const usse_table *t, const char *text, uint64_t *e) {
    /* Drop comments from the input; the patterns' own comments match blanks. */
    char buf[512];
    size_t n = 0;
    for (const char *s = text; *s && n + 1 < sizeof buf; ) {
        if (s[0] == '/' && s[1] == '*') {
            const char *ce = strstr(s + 2, "*/");
            s = ce ? ce + 2 : s + strlen(s);
            buf[n++] = ' ';
        } else {
            buf[n++] = *s++;
        }
    }
    buf[n] = '\0';
    const char *s = skip_ws(buf);
    for (size_t i = 0; i < t->n; i++) {
        match_ctx c = { .t = t, .fm = &t->forms[i] };
        if (!c.fm->pat) continue;
        if (match(&c, c.fm->pat, s)) {
            *e = c.out;
            return 1;
        }
    }
    return 0;
}

int usse_form_encode(const char *text, uint64_t *e) {
    return usse_form_encode_in(&usse_table_main, text, e);
}
