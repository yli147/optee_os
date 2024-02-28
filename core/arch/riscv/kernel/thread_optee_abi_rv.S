/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2023 NXP
 * Copyright (c) 2023 Andes Technology Corporation
 */

#include <asm.S>
#include <generated/asm-defines.h>
#include <keep.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <riscv.h>
#include <riscv_macros.S>
#include <sbi.h>
#include <tee/optee_abi.h>
#include <tee/teeabi_opteed.h>
#include <tee/teeabi_opteed_macros.h>

#define TEE_ABI_BASE_ADDR 0xf47f0000
#define TEE_ABI_BASE_PHYS_ADDR 0xf17f0000
#define SBI_EXT_RPXY 0x52505859
/*
 * Implement based on the transport method used to communicate between
 * untrusted domain and trusted domain. It could be an SBI/ECALL-based to
 * a security monitor running in M-Mode and panic or messaging-based across
 * domains where we return to a messaging callback which parses and handles
 * messages.
 *
 * void thread_return_to_udomain(unsigned long arg0, unsigned long arg1,
 *                               unsigned long arg2, unsigned long arg3,
 *                               unsigned long arg4, unsigned long arg5);
 */
FUNC thread_return_to_udomain , :
	/* Caller should put arguments in shared memory */
#if defined(CFG_RISCV_SBI)
	li  	t0, TEEABI_OPTEED_RETURN_ENTRY_DONE
	beq 	a0, t0, abi_entry
	li  	a3, 32
	j 	abi_return
abi_entry:
	mv	t0, a1
	li  	a7, SBI_EXT_RPXY  /* SBI_EXT_RPXY */
	li  	a6, 0x01          /* SBI_EXT_RPXY_SET_SHMEM */
	li  	a0, 0x00001000    /* SHMEM SIZE */
	li  	a1, TEE_ABI_BASE_PHYS_ADDR  /* SHMEM_ADDR */
	li  	a2, 0x0
	li  	a3, 0x0
	li  	a4, 0x0
	li  	a5, 0x0
	ecall
	mv	a1, t0
	li  	t0, TEE_ABI_BASE_ADDR
	sd  	a1, 0(t0)
	li  	a3, 0
abi_return:
	li  	a7, SBI_EXT_RPXY    /* SBI_EXT_RPXY */
	li  	a6, 0x02            /* SBI_EXT_RPXY_SEND_NORMAL_MESSAGE */
	li  	a0, 0x10000         /* RPXY_TRANS_PROT_SEC | SBI_EXT_RPXY_TRANSPORT_ID */
	li  	a1, 0x01            /* SPD_SRVGRP_BASE */
	li  	a2, 0x02            /* SPD_BASE_SRV_COMPLETE */
	ecall
#else
	/* Other protocol */
#endif
	/* ABI to REE should not return */
	panic_at_abi_return
END_FUNC thread_return_to_udomain

FUNC thread_std_abi_entry , :
	jal	__thread_std_abi_entry

	/* Save return value */
	mv	s0, a0

	/* Disable all interrupts */
	csrc	CSR_XSTATUS, CSR_XSTATUS_IE

	/* Switch to temporary stack */
	jal	thread_get_tmp_sp
	mv	sp, a0

	/*
	 * We are returning from thread_alloc_and_run()
	 * set thread state as free
	 */
	jal	thread_state_free

	/* Restore __thread_std_abi_entry() return value */
	li  	t0, TEE_ABI_BASE_ADDR
	sd  	s0, 0(t0)
	li  	a0, 0
	sd  	a0, 8(t0)
	sd  	a0, 16(t0)
	sd  	a0, 24(t0)
	li	a0, TEEABI_OPTEED_RETURN_CALL_DONE

	/* Return to untrusted domain */
	jal	thread_return_to_udomain
END_FUNC thread_std_abi_entry

/* void thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS]) */
FUNC thread_rpc , :
	 /* Use stack for temporary storage */
	addi	sp, sp, -REGOFF(4)

	/* Read xSTATUS */
	csrr	a1, CSR_XSTATUS

	/* Mask all maskable exceptions before switching to temporary stack */
	csrc	CSR_XSTATUS, CSR_XSTATUS_IE

	/* Save return address xSTATUS and pointer to rv */
	STR	a0, REGOFF(0)(sp)
	STR	a1, REGOFF(1)(sp)
	STR	s0, REGOFF(2)(sp)
	STR	ra, REGOFF(3)(sp)
	addi	s0, sp, REGOFF(4)

	/* Save thread state */
	jal	thread_get_ctx_regs
	store_xregs a0, THREAD_CTX_REG_SP, REG_SP
	store_xregs a0, THREAD_CTX_REG_S0, REG_S0, REG_S1
	store_xregs a0, THREAD_CTX_REG_S2, REG_S2, REG_S11

	/* Get to tmp stack */
	jal	thread_get_tmp_sp

	/* Get pointer to rv */
	LDR	s1, REGOFF(0)(sp)

	/* xSTATUS to restore */
	LDR	a1, REGOFF(1)(sp)
	/* Switch to tmp stack */
	mv	sp, a0

	/* Early load rv[] into s2-s4 */
	lw	s2, 0(s1)
	lw	s3, 4(s1)
	lw	s4, 8(s1)

	li	a0, THREAD_FLAGS_COPY_ARGS_ON_RETURN
	la	a2, .thread_rpc_return
	jal	thread_state_suspend

	li  	t0, TEE_ABI_BASE_ADDR
	sd  	a0, 24(t0) /* thread index */
	sd  	s2, 0(t0) /* rv[0] */
	sd  	s3, 8(t0) /* rv[1] */
	sd  	s4, 16(t0) /* rv[2] */
	li	a0, TEEABI_OPTEED_RETURN_CALL_DONE

	/* Return to untrusted domain */
	jal	thread_return_to_udomain
.thread_rpc_return:
	/*
	 * Jumps here from thread_resume() above when RPC has returned.
	 * At this point has the stack pointer been restored to the value
	 * stored in THREAD_CTX above.
	 */

	/* Get pointer to rv[] */
	LDR	a4, REGOFF(0)(sp)

	/* Store a0-a3 into rv[] */
	sw	a0, 0(a4)
	sw	a1, 4(a4)
	sw	a2, 8(a4)
	sw	a3, 12(a4)

	/* Pop saved XSTATUS from stack */
	LDR	s0, REGOFF(1)(sp)
	csrw	CSR_XSTATUS, s0

	/* Pop return address and s0 from stack */
	LDR	ra, REGOFF(3)(sp)
	LDR	s0, REGOFF(2)(sp)

	addi	sp, sp, REGOFF(4)
	ret
END_FUNC thread_rpc

LOCAL_FUNC vector_std_abi_entry, : , .identity_map
	li  	a0, TEE_ABI_BASE_ADDR
	jal	thread_handle_std_abi
	/*
	 * Normally thread_handle_std_abi() should return via
	 * thread_exit(), thread_rpc(), but if thread_handle_std_abi()
	 * hasn't switched stack (error detected) it will do a normal "C"
	 * return.
	 */
	/* Restore thread_handle_std_abi() return value */
	li  	t0, TEE_ABI_BASE_ADDR
	sd  	a0, 0(t0)
	li  	a0, 0
	sd  	a0, 8(t0)
	sd  	a0, 16(t0)
	sd  	a0, 24(t0)
	li	a0, TEEABI_OPTEED_RETURN_CALL_DONE

	/* Return to untrusted domain */
	j	thread_return_to_udomain
END_FUNC vector_std_abi_entry

LOCAL_FUNC vector_fast_abi_entry , : , .identity_map
	li  a0, TEE_ABI_BASE_ADDR
	jal	thread_handle_fast_abi

	li	a0, TEEABI_OPTEED_RETURN_CALL_DONE
	/* Return to untrusted domain */
	j	thread_return_to_udomain
END_FUNC vector_fast_abi_entry

LOCAL_FUNC vector_fiq_entry , : , .identity_map
	/* Secure Monitor received a FIQ and passed control to us. */
	jal	interrupt_main_handler

	li	a0, TEEABI_OPTEED_RETURN_FIQ_DONE
	/* Return to untrusted domain */
	j	thread_return_to_udomain
END_FUNC vector_fiq_entry

/*
 * Vector table supplied to M-mode secure monitor (e.g., openSBI) at
 * initialization.
 *
 * Note that M-mode secure monitor depends on the layout of this vector table,
 * any change in layout has to be synced with M-mode secure monitor.
 */
FUNC thread_vector_table , : , .identity_map, , nobti
	.option push
	.option norvc
	j   vector_std_abi_entry
	j   vector_fast_abi_entry
	j   .
	j   .
	j   .
	j   .
	j   vector_fiq_entry
	j   .
	j   .
	.option pop
END_FUNC thread_vector_table
DECLARE_KEEP_PAGER thread_vector_table
