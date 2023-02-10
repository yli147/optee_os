/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 */
#include "tee_syscall_numbers.h"
#include "trace_levels.h"
#include <riscv.h>
#include <riscv_macros.S>
#include <asm.S>
#include <generated/asm-defines.h>
#include <kernel/thread.h>
#include <tee_api_defines.h>

/*
 * uint32_t tee_svc_do_call(struct thread_svc_regs *regs, tee_svc_func func);
 *
 * Called from user_ta_handle_svc()
 */
FUNC tee_svc_do_call , :
	addi	sp, sp, -16

	/* Push return address to stack */
	store_xregs	sp, 0, 1
	/* save s1 */
	store_xregs	sp, 8, 9

	/* Save scall regs to s1 */
	mv	s1, a0

	/* Save func to t0 */
	mv	t0, a1

	/* Load arguments to function */
	load_xregs 	s1, THREAD_SCALL_REG_A0, 10, 17

	/* Call the syscall function */
	jalr	t0

	/* Pop return address from stack */
	load_xregs	sp, 0, 1
	/* restore s1*/
	load_xregs	sp, 8, 9
	addi	sp, sp, 16
	ret
END_FUNC tee_svc_do_call

/*
 * syscall_sys_return() and syscall_panic() are two special cases for syscalls
 * in the way that they do not return to the TA, instead execution is resumed
 * as if __thread_enter_user_mode() had returned to thread_enter_user_mode().
 *
 * In order to do this the functions need a way to get hold of a pointer to
 * the struct thread_svc_regs provided by storing relevant registers on the
 * stack in el0_svc() and later load them into registers again when el0_svc()
 * is returning.
 *
 * tee_svc_do_call() is supplied the pointer to struct thread_svc_regs in
 * x0. This pointer can later be retrieved by chasing x19.
 */

/*
 * User space sees this function as:
 * void syscall_sys_return(uint32_t ret) __noreturn;
 *
 * But internally the function depends on being called from
 * tee_svc_do_call() to be able to chase x19 in order to get hold of a
 * pointer to struct thread_svc_regs.
 *
 * The argument ret is already in x0 so we don't touch that and let it
 * propagate as return value of the called
 * tee_svc_unwind_enter_user_mode().
 */
FUNC syscall_sys_return , :
	li	a1, 0  /* panic = false */
	li	a2, 0  /* panic_code = 0 */
	mv	a3, s1 /* pointer to struct thread_scall_regs */
	j	tee_svc_sys_return_helper
END_FUNC syscall_sys_return

/*
 * User space sees this function as:
 * void syscall_panic(uint32_t code) __noreturn;
 *
 * But internally the function depends on being called from
 * tee_svc_do_call() to be able to chase x19 in order to get hold of a
 * pointer to struct thread_svc_regs.
 */
FUNC syscall_panic , :
	li	a1, 1  /* panic = true */
	mv	a2, a0  /* code */
	li	a0, TEE_ERROR_TARGET_DEAD
	mv	a3, s1 /* pointer to struct thread_scall_regs */
	j	tee_svc_sys_return_helper
END_FUNC syscall_panic
