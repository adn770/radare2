/* radare2 RArch plugin for the PowerVR SGX Series-5 PDS (Programmable Data
 * Sequencer) instruction set.
 *
 * A PDS program is a data segment followed by 32-bit little-endian instructions.
 * Decoding lives in the standalone clean-room core (pds.c / pds.h), validated
 * against ground truth by pds_oracle_check.py. This file adapts it to radare2:
 * mnemonic, op type and branch targets. Branch targets are instruction indices
 * from the start of the code, so map the code (not the data segment) at 0.
 */
#include <r_arch.h>
#include <r_lib.h>
#include <r_util.h>
#include "pds.h"

static int op_type(uint32_t w) {
	const int cond = pds_predicated (w);
	switch (pds_classify (w)) {
	case PDS_T_MOV:   return R_ANAL_OP_TYPE_MOV;
	case PDS_T_IO:    return R_ANAL_OP_TYPE_IO;
	case PDS_T_LOAD:  return R_ANAL_OP_TYPE_LOAD;
	case PDS_T_STORE: return R_ANAL_OP_TYPE_STORE;
	case PDS_T_ADD:   return R_ANAL_OP_TYPE_ADD;
	case PDS_T_SUB:   return R_ANAL_OP_TYPE_SUB;
	case PDS_T_MUL:   return R_ANAL_OP_TYPE_MUL;
	case PDS_T_ABS:   return R_ANAL_OP_TYPE_ABS;
	case PDS_T_AND:   return R_ANAL_OP_TYPE_AND;
	case PDS_T_NAND:  return R_ANAL_OP_TYPE_AND;
	case PDS_T_OR:    return R_ANAL_OP_TYPE_OR;
	case PDS_T_XOR:   return R_ANAL_OP_TYPE_XOR;
	case PDS_T_NOT:   return R_ANAL_OP_TYPE_NOT;
	case PDS_T_NOR:   return R_ANAL_OP_TYPE_NOR;
	case PDS_T_SHL:   return R_ANAL_OP_TYPE_SHL;
	case PDS_T_SHR:   return R_ANAL_OP_TYPE_SHR;
	case PDS_T_CMP:   return R_ANAL_OP_TYPE_CMP;
	case PDS_T_JMP:   return cond ? R_ANAL_OP_TYPE_CJMP : R_ANAL_OP_TYPE_JMP;
	case PDS_T_CALL:  return cond ? R_ANAL_OP_TYPE_CCALL : R_ANAL_OP_TYPE_CALL;
	case PDS_T_RET:   /* fallthrough: halt ends the program like a return */
	case PDS_T_HALT:  return cond ? R_ANAL_OP_TYPE_CRET : R_ANAL_OP_TYPE_RET;
	case PDS_T_NOP:   return R_ANAL_OP_TYPE_NOP;
	case PDS_T_SYNC:  return R_ANAL_OP_TYPE_SYNC;
	default:          return R_ANAL_OP_TYPE_UNK;
	}
}

static bool pds_decode_cb(RArchSession *as, RAnalOp *op, RArchDecodeMask mask) {
	if (!op || !op->bytes || op->size < 4) {
		return false;
	}
	const ut32 w = r_read_le32 (op->bytes);
	op->size = 4;
	op->type = op_type (w);

	int is_call, is_cond;
	ut32 target;
	if (pds_branch (w, &is_call, &is_cond, &target)) {
		op->jump = (ut64) target * 4;
		if (is_cond || is_call) {
			op->fail = op->addr + 4;
		}
	}
	if (mask & R_ARCH_OP_MASK_DISASM) {
		char text[128];
		op->mnemonic = strdup (pds_decode (w, text, sizeof text) ? text : "invalid");
	}
	return true;
}

static int archinfo(RArchSession *as, ut32 q) {
	return 4;
}

const RArchPlugin r_arch_plugin_pds = {
	.meta = {
		.name = "pds",
		.desc = "PowerVR SGX Series-5 PDS data sequencer (clean-room)",
		.author = "SGXhumation",
		.license = "LGPL-3.0-only",
	},
	.arch = "pds",
	.bits = R_SYS_BITS_PACK1 (32),
	.endian = R_SYS_ENDIAN_LITTLE,
	.info = archinfo,
	.decode = pds_decode_cb,
};

#ifndef R2_PLUGIN_INCORE
R_API RLibStruct radare_plugin = {
	.type = R_LIB_TYPE_ARCH,
	.data = &r_arch_plugin_pds,
	.version = R2_VERSION
};
#endif
