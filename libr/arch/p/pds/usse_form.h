/* usse_form.h — the USSE instruction-form table, shared by the decoder
 * (usse.c, usse-dis) and the assembler (tools/usse-asm).
 *
 * A form is a text pattern plus the bits that identify it: a word matches when
 * (word & mask) == val, and its text is the pattern with each placeholder {i}
 * replaced by field i, printed by the field's kind. Bits outside the mask and
 * outside every field are ignored by the decoder; the assembler writes them
 * from the form's dflt (0 unless the closed toolchain's own code shows a
 * convention, such as an unused source written as immediate 0), and when
 * several values of a field print the same text it prefers the one in dflt.
 * Forms are tried in table order and the first whose fields all print wins, so
 * decoding and encoding read the same facts: the decoder prints, and the
 * assembler matches the text against the pattern, recovers each field value
 * (by parsing it or by searching the field's values for one that prints the
 * same text) and scatters it back into the word.
 *
 * Every layout here is clean-room: derived by bit-correlation over the oracle
 * corpora and by black-box probing of refdisasm545 (single-bit flips and value
 * sweeps), then checked against it on random words (random_oracle_check.py). */
#ifndef USSE_FORM_H
#define USSE_FORM_H
#include <stddef.h>
#include <stdint.h>

/* A field is up to USSE_MAX_CHUNKS bit ranges of the word, concatenated LSB first. */
typedef struct { uint8_t lo, w; } usse_chunk;

typedef struct usse_kind usse_kind;
struct usse_kind {
    /* Print value v; return 0 if v is not a valid value of this kind. */
    int (*print)(const usse_kind *k, uint32_t v, char *out, size_t n);
    /* Optional: parse a value at s (numbers, wide fields). Return 1 and set
     * *end and *v on success. Kinds without one are inverted by search. */
    int (*parse)(const usse_kind *k, const char *s, const char **end, uint32_t *v);
    const void *arg;
};

#define USSE_MAX_FIELDS 10
#define USSE_MAX_CHUNKS 10
typedef struct {
    const usse_kind *k;
    usse_chunk c[USSE_MAX_CHUNKS];
} usse_field;

typedef struct {
    const char *pat;        /* NULL: a reject entry, the word stays undecoded */
    uint64_t mask, val;
    usse_field f[USSE_MAX_FIELDS];
    uint64_t dflt;          /* the encoder's preference: the bits the form ignores,
                             * and the value tried first for a searched field */
} usse_form;

/* Generic kinds. An enumeration's arg is a table of 2^width names (NULL marks
 * an invalid value); a number's arg is a usse_num, printing v * mul + add. */
typedef struct { const char *fmt; uint32_t mul, add; } usse_num;
int usse_k_enum_print(const usse_kind *k, uint32_t v, char *out, size_t n);
int usse_k_num_print(const usse_kind *k, uint32_t v, char *out, size_t n);
int usse_k_num_parse(const usse_kind *k, const char *s, const char **end, uint32_t *v);
/* Unsigned 32-bit number: decimal, or hex with a 0x prefix. */
int usse_parse_uint(const char *s, const char **end, uint64_t *v);

/* A table of forms. decode is the decoder an encoding must satisfy: NULL
 * means the table itself (the USSE table, whose decoder it is); another
 * instruction set's assembler can check its forms against that set's own
 * decoder (tools/usse-asm does so for PDS). */
typedef struct {
    const usse_form *forms;
    size_t n;
    int (*decode)(uint64_t e, char *out, size_t n);
} usse_table;

/* The USSE table (usse.c). */
extern const usse_form usse_forms[];
extern const size_t usse_nforms;
extern const usse_table usse_table_main;

/* Numeric fields accept a name instead of a number when a resolver is set:
 * it returns 1 and the value for a known name. (The assemblers use it for
 * labels.) Pass NULL to clear it. */
typedef int (*usse_resolver)(const char *name, size_t len, uint64_t *v, void *ctx);
void usse_form_set_resolver(usse_resolver r, void *ctx);

unsigned usse_field_width(const usse_field *f);
uint32_t usse_field_get(const usse_field *f, uint64_t e);
uint64_t usse_field_put(const usse_field *f, uint64_t e, uint32_t v);

/* Bits a form reads: its mask and all its fields. */
uint64_t usse_form_bits(const usse_form *fm);

/* Render word e with form fm. Return 1 if every field printed. */
int usse_form_render(const usse_form *fm, uint64_t e, char *out, size_t n);

/* Decode: the first matching form, or NULL (also for a reject entry). */
const usse_form *usse_form_decode_in(const usse_table *t, uint64_t e, char *out, size_t n);
const usse_form *usse_form_decode(uint64_t e, char *out, size_t n);   /* USSE table */

/* Encode text into *e. The result decodes to the canonical spelling of the
 * text (the same as the input when it is written as the decoder prints it):
 * the first form, in table order, whose pattern matches and whose word the
 * decoder prints with that form's text. Bits outside the fields are 0.
 * Return 1 on success, 0 if no form matches. */
int usse_form_encode_in(const usse_table *t, const char *text, uint64_t *e);
int usse_form_encode(const char *text, uint64_t *e);                   /* USSE table */

#endif /* USSE_FORM_H */
