/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */

#include <asm.S>

/* void vfp_save_extension_regs(struct vfp_reg regs[VFP_NUM_REGS]); */
FUNC vfp_save_extension_regs , :
	fsd f0, 0(a0)
	fsd f1, 1*8(a0)
	fsd f2, 2*8(a0)
	fsd f3, 3*8(a0)
	fsd f4, 4*8(a0)
	fsd f5, 5*8(a0)
	fsd f6, 6*8(a0)
	fsd f7, 7*8(a0)
	fsd f8, 8*8(a0)
	fsd f9, 9*8(a0)
	fsd f10, 10*8(a0)
	fsd f11, 11*8(a0)
	fsd f12, 12*8(a0)
	fsd f13, 13*8(a0)
	fsd f14, 14*8(a0)
	fsd f15, 15*8(a0)
	fsd f16, 16*8(a0)
	fsd f17, 17*8(a0)
	fsd f18, 18*8(a0)
	fsd f19, 19*8(a0)
	fsd f20, 20*8(a0)
	fsd f21, 21*8(a0)
	fsd f22, 22*8(a0)
	fsd f23, 23*8(a0)
	fsd f24, 24*8(a0)
	fsd f25, 25*8(a0)
	fsd f26, 26*8(a0)
	fsd f27, 27*8(a0)
	fsd f28, 28*8(a0)
	fsd f29, 29*8(a0)
	fsd f30, 30*8(a0)
	fsd f31, 31*8(a0)
	ret
END_FUNC vfp_save_extension_regs

/* void vfp_restore_extension_regs(struct vfp_reg regs[VFP_NUM_REGS]); */
FUNC vfp_restore_extension_regs , :
	fld f0, 0(a0)
	fld f1, 1*8(a0)
	fld f2, 2*8(a0)
	fld f3, 3*8(a0)
	fld f4, 4*8(a0)
	fld f5, 5*8(a0)
	fld f6, 6*8(a0)
	fld f7, 7*8(a0)
	fld f8, 8*8(a0)
	fld f9, 9*8(a0)
	fld f10, 10*8(a0)
	fld f11, 11*8(a0)
	fld f12, 12*8(a0)
	fld f13, 13*8(a0)
	fld f14, 14*8(a0)
	fld f15, 15*8(a0)
	fld f16, 16*8(a0)
	fld f17, 17*8(a0)
	fld f18, 18*8(a0)
	fld f19, 19*8(a0)
	fld f20, 20*8(a0)
	fld f21, 21*8(a0)
	fld f22, 22*8(a0)
	fld f23, 23*8(a0)
	fld f24, 24*8(a0)
	fld f25, 25*8(a0)
	fld f26, 26*8(a0)
	fld f27, 27*8(a0)
	fld f28, 28*8(a0)
	fld f29, 29*8(a0)
	fld f30, 30*8(a0)
	fld f31, 31*8(a0)
	ret
END_FUNC vfp_restore_extension_regs
