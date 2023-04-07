/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */

#ifndef VFP_PRIVATE
#define VFP_PRIVATE

#include <kernel/vfp.h>

void vfp_save_extension_regs(struct vfp_reg regs[VFP_NUM_REGS]);
void vfp_restore_extension_regs(struct vfp_reg regs[VFP_NUM_REGS]);

#endif /*VFP_PRIVATE*/
