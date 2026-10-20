/* pds.h — SGX Series-5 PDS (Programmable Data Sequencer) instruction decoder.
 *
 * A PDS program is a data segment (constants, in two banks ds0/ds1) followed by
 * 32-bit little-endian instructions. The EDM is entered through such programs
 * (spec §13.8). Field layouts in pds.c were derived black-box, by probing the
 * reference disassembler with single-bit flips and value sweeps and checking
 * the result against random words (pds_oracle_check.py); no vendor source was
 * used. */
#ifndef PDS_H
#define PDS_H
#include <stdint.h>

/* Decode one PDS instruction into text (oracle-compatible syntax). Returns 1 if
 * decoded; 0 for reserved/unknown encodings, with text set to ".word 0x…". */
int pds_decode(uint32_t w, char *text, unsigned len);

/* Coarse instruction category, for an analysis frontend (e.g. the r2 plugin).
 * PDS_T_IO is a movs/movsa to a dout* port: it issues work to another unit
 * (doutu starts a USSE task, doutd a DMA, douta writes attributes). */
typedef enum {
    PDS_T_UNK = 0, PDS_T_MOV, PDS_T_IO, PDS_T_LOAD, PDS_T_STORE,
    PDS_T_ADD, PDS_T_SUB, PDS_T_MUL, PDS_T_ABS,
    PDS_T_AND, PDS_T_OR, PDS_T_XOR, PDS_T_NOT, PDS_T_NOR, PDS_T_NAND,
    PDS_T_SHL, PDS_T_SHR, PDS_T_CMP,
    PDS_T_JMP, PDS_T_CALL, PDS_T_RET, PDS_T_HALT, PDS_T_NOP, PDS_T_SYNC,
} pds_op_type;

pds_op_type pds_classify(uint32_t w);

/* 1 if w carries an execution predicate (w[26:24] != 7). Always 0 for the groups
 * where those bits are not a predicate (load/store use them as a dword count). */
int pds_predicated(uint32_t w);

/* If w is bra/call, return 1 and set *target to the instruction index it names,
 * counted from the first instruction after the data segment (inferred from the
 * control flow of the captured EDM programs, which only make sense that way). */
int pds_branch(uint32_t w, int *is_call, int *is_cond, uint32_t *target);

#endif /* PDS_H */
