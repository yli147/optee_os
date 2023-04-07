// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <riscv.h>
#include <assert.h>
#include <kernel/vfp.h>
#include "vfp_private.h"

#define STATUS_FS_BIT_OFFSET	13
#define STATUS_SD_BIT_OFFSET	63
/**
 * @brief csr_sstatus bit13,bit14 indicat float state
 * 0 Off All off
 * 1 Initial None dirty or clean, some on
 * 2 Clean None dirty, some clean
 * 3 Dirty Some dirty
 * @return true 
 * @return false 
 */
bool vfp_is_enabled(void)
{
	return ((read_csr(CSR_SSTATUS) >> STATUS_FS_BIT_OFFSET) & 0x3) ? true : false;
}

void vfp_enable(void)
{
	write_csr(CSR_SSTATUS, read_csr(CSR_SSTATUS) | (1 << STATUS_FS_BIT_OFFSET));
	asm volatile ("fence");
}

void vfp_disable(void)
{
	write_csr(CSR_SSTATUS, read_csr(CSR_SSTATUS) & (~(3 << STATUS_FS_BIT_OFFSET)));
	asm volatile ("fence");
}

void vfp_lazy_save_state_init(struct vfp_state *state)
{
	state->status_fs = read_csr(CSR_SSTATUS) & (0x3 << STATUS_FS_BIT_OFFSET);
	vfp_disable();
}

static int vfp_fs_dirty(void)
{
	return read_csr(CSR_SSTATUS) >> STATUS_SD_BIT_OFFSET;
}

void vfp_lazy_save_state_final(struct vfp_state *state, bool force_save)
{
	if (vfp_fs_dirty() || force_save) {
		assert(!vfp_is_enabled());
		vfp_enable();
		state->fcsr = read_csr(CSR_FCSR);
		vfp_save_extension_regs(state->reg);
		vfp_disable();
	}
}

void vfp_lazy_restore_state(struct vfp_state *state, bool full_state)
{
	if (full_state) {
		vfp_enable();
		write_csr(CSR_FCSR, state->fcsr);
		vfp_restore_extension_regs(state->reg);
	}
	write_csr(CSR_SSTATUS, (read_csr(CSR_SSTATUS) & \
			~(3 << STATUS_FS_BIT_OFFSET)) | state->status_fs);
	asm volatile ("fence");
}
