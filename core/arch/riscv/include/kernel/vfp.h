/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */

#ifndef KERNEL_VFP_H
#define KERNEL_VFP_H

#include <types_ext.h>
#include <compiler.h>

#define VFP_NUM_REGS	U(32)

struct vfp_reg {
	uint64_t v;
};

struct vfp_state {
	struct vfp_reg reg[VFP_NUM_REGS];
	uint32_t status_fs;
	uint32_t fcsr;
};

#ifdef CFG_WITH_VFP
/* vfp_is_enabled() - Returns true if VFP is enabled */
bool vfp_is_enabled(void);

/* vfp_enable() - Enables vfp */
void vfp_enable(void);

/* vfp_disable() - Disables vfp */
void vfp_disable(void);
#else
static inline bool vfp_is_enabled(void)
{
	return false;
}

static inline void vfp_enable(void)
{
}

static inline void vfp_disable(void)
{
}
#endif

/*
 * vfp_lazy_save_state_init() - Saves VFP enable status and disables VFP
 * @state:	VFP state structure to initialize
 */
void vfp_lazy_save_state_init(struct vfp_state *state);

/*
 * vfp_lazy_save_state_final() - Saves rest of VFP state
 * @state:	VFP state to save to
 * @force_save:	Forces saving of state regardless of previous state if true.
 *
 * If VFP was enabled when vfp_lazy_save_state_init() was called or
 * @force_save is true: save rest of state and disable VFP. Otherwise, do
 * nothing.
 */
void vfp_lazy_save_state_final(struct vfp_state *state, bool force_save);

/*
 * vfp_lazy_restore_state() - Lazy restore VFP state
 * @state:		VFP state to restore
 *
 * Restores VFP enable status and also restores rest of VFP state if
 * vfp_lazy_save_state_final() was called on this state.
 */
void vfp_lazy_restore_state(struct vfp_state *state, bool full_state);

#endif /*KERNEL_VFP_H*/
