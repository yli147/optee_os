/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2019, Linaro Limited
 */

//#include <arm64_macros.S>
//#include <arm.h>
#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/thread.h>
#include <sm/optee_smc.h>
#include <sm/teesmc_opteed.h>
#include <sm/teesmc_opteed_macros.h>

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
	li	a0, TEESMC_OPTEED_RETURN_CALL_DONE
	ecall
	/* ecall should not return */
	//panic_at_smc_return
END_FUNC vector_std_smc_entry

LOCAL_FUNC vector_fast_smc_entry , : , .identity_map
	readjust_pc
	addi	sp, sp, -64
	//store_xregs sp, THREAD_SMC_ARGS_X0, 0, 7
	sd  a0, THREAD_ECALL_ARGS_A0(sp)
	sd  a1, THREAD_ECALL_ARGS_A1(sp)
	sd  a2, THREAD_ECALL_ARGS_A2(sp)
	sd  a3, THREAD_ECALL_ARGS_A3(sp)
	sd  a4, THREAD_ECALL_ARGS_A4(sp)
	sd  a5, THREAD_ECALL_ARGS_A5(sp)
	sd  a6, THREAD_ECALL_ARGS_A6(sp)
	sd  a7, THREAD_ECALL_ARGS_A7(sp)	
	mv	a0, sp
	call thread_handle_fast_smc
	//load_xregs sp, THREAD_SMC_ARGS_X0, 1, 8
	ld  a1, THREAD_ECALL_ARGS_A0(sp)
	ld  a2, THREAD_ECALL_ARGS_A1(sp)
	ld  a3, THREAD_ECALL_ARGS_A2(sp)
	ld  a4, THREAD_ECALL_ARGS_A3(sp)
	ld  a5, THREAD_ECALL_ARGS_A4(sp)
	ld  a6, THREAD_ECALL_ARGS_A5(sp)
	ld  a7, THREAD_ECALL_ARGS_A6(sp)
	addi	sp, sp, 64
	li	a0, TEESMC_OPTEED_RETURN_CALL_DONE
	//smc	#0
	ecall
	/* SMC should not return */
	//panic_at_smc_return
END_FUNC vector_fast_smc_entry

LOCAL_FUNC vector_fiq_entry , : , .identity_map
	readjust_pc
	/* Secure Monitor received a FIQ and passed control to us. */
	call	thread_check_canaries
	call	itr_core_handler
	li	x0, TEESMC_OPTEED_RETURN_FIQ_DONE
	//smc	#0
	ecall
	/* SMC should not return */
	//panic_at_smc_return
END_FUNC vector_fiq_entry

LOCAL_FUNC vector_cpu_on_entry , : , .identity_map
	call	cpu_on_handler
	mv	a1, a0
	li	a0, TEESMC_OPTEED_RETURN_ON_DONE
//	smc	#0
	ecall
	/* SMC should not return */
//	panic_at_smc_return
END_FUNC vector_cpu_on_entry

LOCAL_FUNC vector_cpu_off_entry , : , .identity_map
	readjust_pc
	call	thread_cpu_off_handler
	mv	a1, a0
	li	a0, TEESMC_OPTEED_RETURN_OFF_DONE
//	smc	#0
	ecall
	/* SMC should not return */
//	panic_at_smc_return
END_FUNC vector_cpu_off_entry

LOCAL_FUNC vector_cpu_suspend_entry , : , .identity_map
	readjust_pc
	call	thread_cpu_suspend_handler
	mv	a1, a0
	li	a0, TEESMC_OPTEED_RETURN_SUSPEND_DONE
//	smc	#0
	ecall
	/* SMC should not return */
//	panic_at_smc_return
END_FUNC vector_cpu_suspend_entry

LOCAL_FUNC vector_cpu_resume_entry , : , .identity_map
	readjust_pc
	call	thread_cpu_resume_handler
	mv	a1, a0
	li	a0, TEESMC_OPTEED_RETURN_RESUME_DONE
//	smc	#0
	ecall
	/* SMC should not return */
//	panic_at_smc_return
END_FUNC vector_cpu_resume_entry

LOCAL_FUNC vector_system_off_entry , : , .identity_map
	readjust_pc
	call	thread_system_off_handler
	mv	a1, a0
	li	a0, TEESMC_OPTEED_RETURN_SYSTEM_OFF_DONE
//	smc	#0
	ecall
	/* SMC should not return */
//	panic_at_smc_return
END_FUNC vector_system_off_entry

LOCAL_FUNC vector_system_reset_entry , : , .identity_map
	readjust_pc
	call	thread_system_reset_handler
	mv	a1, a0
	li	a0, TEESMC_OPTEED_RETURN_SYSTEM_RESET_DONE
//	smc	#0
	ecall
	/* SMC should not return */
//	panic_at_smc_return
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
	/* clean riscv MIE of mstatus reg */
	csrci   mstatus,8
	
	call	thread_get_tmp_sp
	mv	sp, a0

	call	thread_state_free

	li	a0, TEESMC_OPTEED_RETURN_CALL_DONE
	mv	a1, s2
	li	a2, 0
	li	a3, 0
	li	a4, 0
//	smc	#0
	ecall
	/* SMC should not return */
//	panic_at_smc_return
END_FUNC thread_std_smc_entry

/* void thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS]) */
FUNC thread_rpc , :
#if 0
	/* Read daif and create an SPSR */
	mrs	x1, daif
	orr	x1, x1, #(SPSR_64_MODE_EL1 << SPSR_64_MODE_EL_SHIFT)

	/* Mask all maskable exceptions before switching to temporary stack */
	msr	daifset, #DAIFBIT_ALL
	push	x0, xzr
	push	x1, x30
	bl	thread_get_ctx_regs
	ldr	x30, [sp, #8]
	store_xregs x0, THREAD_CTX_REGS_X19, 19, 30
	mov	x19, x0

	bl	thread_get_tmp_sp
	pop	x1, xzr		/* Match "push x1, x30" above */
	mov	x2, sp
	str	x2, [x19, #THREAD_CTX_REGS_SP]
	ldr	x20, [sp]	/* Get pointer to rv[] */
	mov	sp, x0		/* Switch to tmp stack */
	/*
	 * We need to read rv[] early, because thread_state_suspend
	 * can invoke virt_unset_guest() which will unmap pages,
	 * where rv[] resides
	 */
	load_wregs x20, 0, 21, 23	/* Load rv[] into w20-w22 */

	la	x2, .thread_rpc_return
	mv	a0, THREAD_FLAGS_COPY_ARGS_ON_RETURN
	call	thread_state_suspend
	mv	a4, a0		/* Supply thread index */
	li	a0, TEESMC_OPTEED_RETURN_CALL_DONE
	mv	a1, x21
	mv	a2, x22
	mv	a3, x23
//	smc	#0
	ecall
	/* SMC should not return */
//	panic_at_smc_return

.thread_rpc_return:
	/*
	 * At this point has the stack pointer been restored to the value
	 * stored in THREAD_CTX above.
	 *
	 * Jumps here from thread_resume above when RPC has returned. The
	 * IRQ and FIQ bits are restored to what they where when this
	 * function was originally entered.
	 */
//	pop	x16, xzr	/* Get pointer to rv[] */
	ld 
	store_wregs x16, 0, 0, 3	/* Store w0-w3 into rv[] */
	ret
#endif
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
	li	a0, TEESMC_OPTEED_RETURN_CALL_DONE
	li	a1, OPTEE_SMC_RETURN_RPC_FOREIGN_INTR
	li	a2, 0
	li	a3, 0
//	smc	#0
	ecall
	/* SMC should not return */
//	panic_at_smc_return
END_FUNC thread_foreign_intr_exit

//BTI(emit_aarch64_feature_1_and     GNU_PROPERTY_AARCH64_FEATURE_1_BTI)
