/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

#include <riscv.h>
#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/thread.h>
#include <sm/optee_smc.h>
#include <sm/teesmc_opteed.h>
#include <sm/teesmc_opteed_macros.h>
#include <riscv_macros.S>

/*
 * If ASLR is configured the identity mapped code may be mapped at two
 * locations, the identity location where virtual and physical address is
 * the same and at the runtime selected location to which OP-TEE has been
 * relocated.  Code executing at a location different compared to the
 * runtime selected location works OK as long as it doesn't do relative
 * addressing outside the identity mapped range. To allow relative
 * addressing this macro jumps to the runtime selected location.
 *
 * Note that the identity mapped range and the runtime selected range can
 * only differ if ASLR is configured.
 */
	.macro readjust_pc
	.endm

LOCAL_FUNC vector_std_smc_entry , : , .identity_map
	readjust_pc
	call	thread_handle_std_smc
	/*
	 * Normally thread_handle_std_smc() should return via
	 * thread_exit(), thread_rpc(), but if thread_handle_std_smc()
	 * hasn't switched stack (error detected) it will do a normal "C"
	 * return.
	 */
	mv	a1, a0
	li	a6, TEESMC_OPTEED_RETURN_CALL_DONE
	li	a7, 0x4F505445
	ecall
	/* ecall should not return */
END_FUNC vector_std_smc_entry

LOCAL_FUNC vector_fast_smc_entry , : , .identity_map
	readjust_pc
	addi	sp, sp, -64
	//store_xregs sp, THREAD_SMC_ARGS_X0, 0, 7
	sd  a0, THREAD_SMC_ARGS_A0(sp)
	sd  a1, THREAD_SMC_ARGS_A1(sp)
	sd  a2, THREAD_SMC_ARGS_A2(sp)
	sd  a3, THREAD_SMC_ARGS_A3(sp)
	sd  a4, THREAD_SMC_ARGS_A4(sp)
	sd  a5, THREAD_SMC_ARGS_A5(sp)
	sd  a6, THREAD_SMC_ARGS_A6(sp)
//	sd  a7, THREAD_SMC_ARGS_A7(sp)	
	mv	a0, sp
	call thread_handle_fast_smc
	//load_xregs sp, THREAD_SMC_ARGS_X0, 1, 8
	ld  a1, THREAD_SMC_ARGS_A0(sp)
	ld  a2, THREAD_SMC_ARGS_A1(sp)
	ld  a3, THREAD_SMC_ARGS_A2(sp)
	ld  a4, THREAD_SMC_ARGS_A3(sp)
	ld  a5, THREAD_SMC_ARGS_A4(sp)
//	ld  a6, THREAD_SMC_ARGS_A5(sp)
//	ld  a7, THREAD_SMC_ARGS_A6(sp)
	addi	sp, sp, 64
	li	a6, TEESMC_OPTEED_RETURN_CALL_DONE
	li	a7, 0x4F505445
	ecall
	/* SMC should not return */
END_FUNC vector_fast_smc_entry

LOCAL_FUNC vector_fiq_entry , : , .identity_map
	/* Secure Monitor received a FIQ and passed control to us. */
	call	thread_check_canaries
	/* optee os should receive FIQ here*/
	li	a6, TEESMC_OPTEED_RETURN_FIQ_DONE
	li	a7, 0x4F505445
	ecall
END_FUNC vector_fiq_entry

LOCAL_FUNC vector_cpu_on_entry , : , .identity_map
	call	cpu_on_handler
	mv	a1, a0
	li	a0, TEESMC_OPTEED_RETURN_ON_DONE
	ecall
	/* SMC should not return */
END_FUNC vector_cpu_on_entry

LOCAL_FUNC vector_cpu_off_entry , : , .identity_map
	readjust_pc
	call	thread_cpu_off_handler
	mv	a1, a0
	li	a0, TEESMC_OPTEED_RETURN_OFF_DONE
	ecall
	/* SMC should not return */
END_FUNC vector_cpu_off_entry

LOCAL_FUNC vector_cpu_suspend_entry , : , .identity_map
	readjust_pc
	call	thread_cpu_suspend_handler
	mv	a1, a0
	li	a0, TEESMC_OPTEED_RETURN_SUSPEND_DONE
	ecall
	/* SMC should not return */
END_FUNC vector_cpu_suspend_entry

LOCAL_FUNC vector_cpu_resume_entry , : , .identity_map
	readjust_pc
	call	thread_cpu_resume_handler
	mv	a1, a0
	li	a0, TEESMC_OPTEED_RETURN_RESUME_DONE
	ecall
	/* SMC should not return */
END_FUNC vector_cpu_resume_entry

LOCAL_FUNC vector_system_off_entry , : , .identity_map
	readjust_pc
	call	thread_system_off_handler
	mv	a1, a0
	li	a0, TEESMC_OPTEED_RETURN_SYSTEM_OFF_DONE
	ecall
	/* SMC should not return */
END_FUNC vector_system_off_entry

LOCAL_FUNC vector_system_reset_entry , : , .identity_map
	readjust_pc
	call	thread_system_reset_handler
	mv	a1, a0
	li	a0, TEESMC_OPTEED_RETURN_SYSTEM_RESET_DONE
	ecall
	/* should not return */
END_FUNC vector_system_reset_entry

/*
 * Vector table supplied to ARM Trusted Firmware (ARM-TF) at
 * initialization.
 *
 * Note that ARM-TF depends on the layout of this vector table, any change
 * in layout has to be synced with ARM-TF.
 */
FUNC thread_vector_table , : , .identity_map, , nobti
	j	vector_std_smc_entry
	j	vector_fast_smc_entry
	j	vector_cpu_on_entry
	j	vector_cpu_off_entry
	j	vector_cpu_resume_entry
	j	vector_cpu_suspend_entry
	j	vector_fiq_entry
	j	vector_system_off_entry
	j	vector_system_reset_entry
END_FUNC thread_vector_table
DECLARE_KEEP_PAGER thread_vector_table

FUNC thread_std_smc_entry , :
	call	__thread_std_smc_entry
	mv	s2, a0	/* Save return value for later */

	/* Mask all maskable exceptions before switching to temporary stack */
	//msr	daifset, #DAIFBIT_ALL
	/* clean riscv SIE of sstatus reg */
	csrci   sstatus,2
	
	call	thread_get_tmp_sp
	mv	sp, a0

	call	thread_state_free

	mv	a1, s2
	li	a2, 0
	li	a3, 0
	li	a4, 0
	li	a6, TEESMC_OPTEED_RETURN_CALL_DONE
	li	a7, 0x4F505445
	ecall
	/* should not return */
END_FUNC thread_std_smc_entry

/* void thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS]) */
FUNC thread_rpc , :
	li a1, 2
	or a1, a1, 32
	or a1, a1, 512
	/*disable all maskable interrupt*/
	csrc sie, a1

	/*read sstatus to a1*/
	csrr a1, sstatus

	addi sp, sp, -(3*8)
	sd ra, 0(sp)
	sd a1, 8(sp)
	sd a0, 16(sp)
	call thread_get_ctx_regs
	ld ra, 0(sp)
	store_xregs a0, THREAD_CTX_REG_RA, 1, 1
	store_xregs a0, THREAD_CTX_REG_S0, 8, 9
	store_xregs a0, THREAD_CTX_REG_S2, 18, 27

	mv t0, a0
	call thread_get_tmp_sp
	ld a1, 8(sp)
	ld t1, 16(sp) /* Get pointer to rv[] */
	addi sp, sp, 2*8
	sd sp, THREAD_CTX_REG_SP(t0)
	mv sp, a0 /* Switch to tmp stack */
	lw t2,0(t1)
	lw t3,4(t1)
	lw t4,8(t1)
	la a2, .thread_rpc_return
	li	a0, THREAD_FLAGS_COPY_ARGS_ON_RETURN
	call	thread_state_suspend
	mv	a4, a0		/* Supply thread index */
	li	a6, TEESMC_OPTEED_RETURN_CALL_DONE
	li	a7, 0x4F505445
	mv	a1, t2
	mv	a2, t3
	mv	a3, t4
	ecall
	/* should not return */

.thread_rpc_return:
	/*
	 * At this point has the stack pointer been restored to the value
	 * stored in THREAD_CTX above.
	 *
	 * Jumps here from thread_resume above when RPC has returned. The
	 * IRQ and FIQ bits are restored to what they where when this
	 * function was originally entered.
	 */
	ld t0, 0(sp)/* Get pointer to rv[] */
	addi sp, sp, (1*8)
	sw a0, (t0)
	sw a1, 4(t0)
	sw a2, 8(t0)
	sw a3, 12(t0)
	ret
END_FUNC thread_rpc
DECLARE_KEEP_PAGER thread_rpc

/*
 * void thread_foreign_intr_exit(uint32_t thread_index)
 *
 * This function is jumped to at the end of macro foreign_intr_handler().
 * The current thread as indicated by @thread_index has just been
 * suspended.  The job here is just to inform normal world the thread id to
 * resume when returning.
 */
FUNC thread_foreign_intr_exit , :
	mv	a4, a0
	li	a6, TEESMC_OPTEED_RETURN_CALL_DONE
	li	a7, 0x4F505445
	li	a1, OPTEE_SMC_RETURN_RPC_FOREIGN_INTR
	li	a2, 0
	li	a3, 0
	ecall
	/* should not return */
END_FUNC thread_foreign_intr_exit
