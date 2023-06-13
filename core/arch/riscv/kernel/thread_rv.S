/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 * Copyright 2023 Nuclei System Technology.
 */

#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <mm/core_mmu.h>
#include <riscv.h>
#include <riscv_macros.S>

.macro save_regs, mode
	addi		sp, sp, -THREAD_TRAP_REGS_SIZE
	store_xregs	sp, THREAD_TRAP_REG_TP, 4, 4
	store_xregs	sp, THREAD_TRAP_REG_GP, 3, 3
.if \mode == TRAP_MODE_USER
	/*
	 * Set the scratch register to 0 such in case of a recursive
	 * exception thread_trap_vect() knows that it is emitted from kernel.
	 */
	csrrw		gp, CSR_XSCRATCH, zero
	store_xregs	sp, THREAD_TRAP_REG_SP, 3, 3
.else
	addi		tp, sp, THREAD_TRAP_REGS_SIZE
	store_xregs	sp, THREAD_TRAP_REG_SP, 4, 4
.endif

.option push
.option norelax
	la		gp, __global_pointer$
.option pop

	store_xregs	sp, THREAD_TRAP_REG_T3, 28, 31
	store_xregs	sp, THREAD_TRAP_REG_A6, 16, 17
	store_xregs	sp, THREAD_TRAP_REG_T0, 5, 7
	store_xregs	sp, THREAD_TRAP_REG_A0, 10, 15
	store_xregs	sp, THREAD_TRAP_REG_S0, 8, 9
	store_xregs	sp, THREAD_TRAP_REG_S2, 18, 27
	store_xregs	sp, THREAD_TRAP_REG_RA, 1, 1

	csrr		t0, CSR_XSTATUS
	store_xregs	sp, THREAD_TRAP_REG_STATUS, 5, 5

	csrr		a0, CSR_XCAUSE
	csrr		a1, CSR_XEPC

	store_xregs	sp, THREAD_TRAP_REG_EPC, 11, 11

	mv		a2, sp

	/* a0 = cause
	 * a1 = epc
	 * a2 = sp
	 * a3 = user
	 * thread_trap_handler(cause, epc, sp, user)
	 */
.endm

.macro restore_regs, mode

	load_xregs	sp, THREAD_TRAP_REG_EPC, 5, 5

	csrw		CSR_XEPC, t0

	load_xregs	sp, THREAD_TRAP_REG_STATUS, 5, 5
	csrw		CSR_XSTATUS, t0

	load_xregs	sp, THREAD_TRAP_REG_RA, 1, 1

	load_xregs	sp, THREAD_TRAP_REG_A0, 10, 15
	load_xregs	sp, THREAD_TRAP_REG_T0, 5, 7

	load_xregs	sp, THREAD_TRAP_REG_A6, 16, 17
	load_xregs	sp, THREAD_TRAP_REG_T3, 28, 31

	load_xregs	sp, THREAD_TRAP_REG_TP, 4, 4

.if \mode == TRAP_MODE_USER
	addi		gp, sp, THREAD_TRAP_REGS_SIZE
	csrw		CSR_XSCRATCH, gp
	load_xregs	sp, THREAD_TRAP_REG_GP, 3, 3
	load_xregs	sp, THREAD_TRAP_REG_SP, 2, 2
.else
	load_xregs	sp, THREAD_TRAP_REG_GP, 3, 3
	addi		sp, sp, THREAD_TRAP_REGS_SIZE
.endif
.endm

FUNC thread_trap_vect , :
	csrrw		sp, CSR_XSCRATCH, sp
	bnez		sp, 0f
	csrrw		sp, CSR_XSCRATCH, sp
	j		trap_from_kernel
0:
	j		trap_from_user
thread_trap_vect_end:
END_FUNC thread_trap_vect

LOCAL_FUNC trap_from_kernel, :
	save_regs	TRAP_MODE_KERNEL
	li		a3, 0
	jal		thread_trap_handler
	restore_regs	TRAP_MODE_KERNEL
	XRET
END_FUNC trap_from_kernel

LOCAL_FUNC trap_from_user, :
	save_regs	TRAP_MODE_USER
	li		a3, 1
	jal		thread_trap_handler
	restore_regs	TRAP_MODE_USER
	XRET
END_FUNC trap_from_user

/*
 * void thread_unwind_user_mode(uint32_t ret, uint32_t exit_status0,
 * 		uint32_t exit_status1);
 * See description in thread.h
 */
FUNC thread_unwind_user_mode , :
	/* Store the exit status,a3,a4,a5 as temp reg
	 * a3 hold thread ctx
	 * a4 hold exit_status0 address
	 * a5 hold exit_status1 address
	 */
	load_xregs	sp, THREAD_USER_MODE_REC_CTX_REGS_PTR, 13, 15

	sw		a1, (a4)
	sw		a2, (a5)

	/* Save user callee registers */
	store_xregs	a3, THREAD_CTX_REG_S0, 8, 9
	store_xregs	a3, THREAD_CTX_REG_S2, 18, 27
	store_xregs	a3, THREAD_CTX_REG_SP, 2, 4

	/* Restore gp registers */
	mv		a1, sp
	load_xregs	a1, THREAD_USER_MODE_REC_RA, 1, 4
	load_xregs	a1, THREAD_USER_MODE_REC_S0, 8, 9
	load_xregs	a1, THREAD_USER_MODE_REC_S2, 18, 27
	add		sp, sp, THREAD_USER_MODE_REC_SIZE

	/*
	 * Zeroize xSCRATCH to indicate to thread_trap_vect() that
	 * we are executing in kernel.
	 */
	csrw		CSR_XSCRATCH, zero

	/* Return from the call of thread_enter_user_mode() */
	ret
END_FUNC thread_unwind_user_mode

/*
 * void thread_exit_user_mode(unsigned long a0, unsigned long a1,
 *                 unsigned long a2, unsigned long a3,
 *                 unsigned long sp, unsigned long pc,
 *                 unsigned long status);
 */

FUNC thread_exit_user_mode , :
    /* Set kernel stack pointer */
    mv  sp, a4

    /* Set xSTATUS */
    csrw    CSR_XSTATUS, a6

    /* Set return address thread_unwind_user_mode() */
    mv  ra, a5
    ret
END_FUNC thread_exit_user_mode

/*
 * uint32_t __thread_enter_user_mode(struct thread_ctx_regs *regs,
 *				     uint32_t *exit_status0,
 *				     uint32_t *exit_status1);
 */
FUNC __thread_enter_user_mode , :
	/*
	 * Create and fill in the struct thread_user_mode_rec
	 * before enter into user mode, save state for tee kernel back
	 */
	addi		sp, sp, -THREAD_USER_MODE_REC_SIZE

	store_xregs	sp, THREAD_USER_MODE_REC_CTX_REGS_PTR, 10, 12
	store_xregs	sp, THREAD_USER_MODE_REC_RA, 1, 4
	store_xregs	sp, THREAD_USER_MODE_REC_S0, 8, 9
	store_xregs	sp, THREAD_USER_MODE_REC_S2, 18, 27

	/*
	 * get pointer to current thread context,
	 * thread_ctx addr is same as thread_ctx_regs
	 */
	mv			tp, a0
	/*
	 * Save kernel stack pointer to ensure that
	 * thread_exit_user_mode() uses correct stack pointer.
	 */

	store_xregs	a0, THREAD_CTX_KERN_SP, 2, 2
	/*
	 * Save the values for a0 and a1 in struct thread_core_local to be
	 * restored later just before the xret.
	 */

	/*
	 * Save kernel stack pointer in xSCRATCH to ensure that
	 * thread_trap_vect() uses correct stack pointer.
	 */

	csrw		CSR_XSCRATCH, sp
	/*
	 * Save kernel thread pointer below of the kernel stack pointer
	 * to enure that thread_trap_vect() uses correct tp when traps
	 * come from user.
	 */

	/*
	 * Initialize xstatus, xepc, and user sp to enter user mode
	 */

	/* Set exception program counter */
	load_xregs	a0, THREAD_CTX_REG_EPC, 8, 8
	csrw		CSR_XEPC, s0

	/* Set user status */
	load_xregs	a0, THREAD_CTX_REG_STATUS, 8, 8
	csrw		CSR_XSTATUS, s0

	/* Set user stack pointer */
	load_xregs	a0, THREAD_CTX_REG_SP, 2, 2

	/* Load the rest of the general purpose registers */
	load_xregs	a0, THREAD_CTX_REG_A1, 11, 15
	load_xregs	a0, THREAD_CTX_REG_T0, 5, 7
	load_xregs	a0, THREAD_CTX_REG_A6, 16, 17
	load_xregs	a0, THREAD_CTX_REG_T3, 28, 31
	load_xregs	a0, THREAD_CTX_REG_A0, 10, 10

	/* zeroize callee registers */
	mv		s0, x0
	mv		s1, x0
	mv		s2, x0
	mv		s3, x0
	mv		s4, x0
	mv		s5, x0
	mv		s6, x0
	mv		s7, x0
	mv		s8, x0
	mv		s9, x0
	mv		s10, x0
	mv		s11, x0

	mv		ra, x0
	mv		gp, x0
	mv		tp, x0

	/* Jump into user mode */
	XRET
END_FUNC __thread_enter_user_mode

/* void thread_resume(struct thread_ctx_regs *regs) */
FUNC thread_resume , :
	load_xregs	a0, THREAD_CTX_REG_EPC, 5, 5
	csrw		sepc, t0
	load_xregs	a0, THREAD_CTX_REG_STATUS, 5, 5
	csrw		sstatus, t0
	load_xregs	a0, THREAD_CTX_REG_SP, 2, 2
	load_xregs	a0, THREAD_CTX_REG_RA, 1, 1
	load_xregs	a0, THREAD_CTX_REG_A1, 11, 15
	load_xregs	a0, THREAD_CTX_REG_T0, 5, 7
	load_xregs	a0, THREAD_CTX_REG_A6, 16, 17
	load_xregs	a0, THREAD_CTX_REG_T3, 28, 31
	load_xregs	a0, THREAD_CTX_REG_S0, 8, 9
	load_xregs	a0, THREAD_CTX_REG_S2, 18, 27
	load_xregs	a0, THREAD_CTX_REG_A0, 10, 10
	sret
END_FUNC thread_resume
