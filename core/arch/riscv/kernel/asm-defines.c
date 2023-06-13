// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */

#include <gen-asm-defines.h>
#include <kernel/boot.h>
#include <kernel/thread.h>
#include <kernel/thread_private.h>
#include <types_ext.h>

DEFINES
{
	/* struct thread_ctx */
	DEFINE(THREAD_CTX_SIZE, sizeof(struct thread_ctx));
	DEFINE(THREAD_CTX_KERN_SP, offsetof(struct thread_ctx, kern_sp));
	DEFINE(THREAD_CTX_STACK_VA_END, offsetof(struct thread_ctx,
						 stack_va_end));

	/* struct thread_core_local */
	DEFINE(THREAD_CORE_LOCAL_SIZE, sizeof(struct thread_core_local));
	DEFINE(THREAD_CORE_LOCAL_TMP_STACK_VA_END,
	       offsetof(struct thread_core_local, tmp_stack_va_end));
	DEFINE(THREAD_CORE_LOCAL_CURR_THREAD,
	       offsetof(struct thread_core_local, curr_thread));
	DEFINE(THREAD_CORE_LOCAL_FLAGS,
	       offsetof(struct thread_core_local, flags));
	DEFINE(THREAD_CORE_LOCAL_ABT_STACK_VA_END,
	       offsetof(struct thread_core_local, abt_stack_va_end));
	DEFINE(THREAD_CORE_LOCAL_R0, offsetof(struct thread_core_local, r[0]));
	DEFINE(THREAD_CORE_LOCAL_R1, offsetof(struct thread_core_local, r[1]));
	DEFINE(THREAD_CORE_LOCAL_R2, offsetof(struct thread_core_local, r[2]));
	DEFINE(THREAD_CORE_LOCAL_R3, offsetof(struct thread_core_local, r[3]));
	DEFINE(STACK_TMP_GUARD, STACK_CANARY_SIZE / 2 + STACK_TMP_OFFS);

	/* struct thread_ctx_regs */
	DEFINE(THREAD_CTX_REG_EPC, offsetof(struct thread_ctx_regs, pc));
	DEFINE(THREAD_CTX_REG_STATUS, offsetof(struct thread_ctx_regs, status));
	DEFINE(THREAD_CTX_REG_RA, offsetof(struct thread_ctx_regs, ra));
	DEFINE(THREAD_CTX_REG_SP, offsetof(struct thread_ctx_regs, sp));
	DEFINE(THREAD_CTX_REG_GP, offsetof(struct thread_ctx_regs, gp));
	DEFINE(THREAD_CTX_REG_TP, offsetof(struct thread_ctx_regs, tp));
	DEFINE(THREAD_CTX_REG_T0, offsetof(struct thread_ctx_regs, t0));
	DEFINE(THREAD_CTX_REG_T1, offsetof(struct thread_ctx_regs, t1));
	DEFINE(THREAD_CTX_REG_T2, offsetof(struct thread_ctx_regs, t2));
	DEFINE(THREAD_CTX_REG_S0, offsetof(struct thread_ctx_regs, s0));
	DEFINE(THREAD_CTX_REG_S1, offsetof(struct thread_ctx_regs, s1));
	DEFINE(THREAD_CTX_REG_A0, offsetof(struct thread_ctx_regs, a0));
	DEFINE(THREAD_CTX_REG_A1, offsetof(struct thread_ctx_regs, a1));
	DEFINE(THREAD_CTX_REG_A2, offsetof(struct thread_ctx_regs, a2));
	DEFINE(THREAD_CTX_REG_A3, offsetof(struct thread_ctx_regs, a3));
	DEFINE(THREAD_CTX_REG_A4, offsetof(struct thread_ctx_regs, a4));
	DEFINE(THREAD_CTX_REG_A5, offsetof(struct thread_ctx_regs, a5));
	DEFINE(THREAD_CTX_REG_A6, offsetof(struct thread_ctx_regs, a6));
	DEFINE(THREAD_CTX_REG_A7, offsetof(struct thread_ctx_regs, a7));
	DEFINE(THREAD_CTX_REG_S2, offsetof(struct thread_ctx_regs, s2));
	DEFINE(THREAD_CTX_REG_S3, offsetof(struct thread_ctx_regs, s3));
	DEFINE(THREAD_CTX_REG_S4, offsetof(struct thread_ctx_regs, s4));
	DEFINE(THREAD_CTX_REG_S5, offsetof(struct thread_ctx_regs, s5));
	DEFINE(THREAD_CTX_REG_S6, offsetof(struct thread_ctx_regs, s6));
	DEFINE(THREAD_CTX_REG_S7, offsetof(struct thread_ctx_regs, s7));
	DEFINE(THREAD_CTX_REG_S8, offsetof(struct thread_ctx_regs, s8));
	DEFINE(THREAD_CTX_REG_S9, offsetof(struct thread_ctx_regs, s9));
	DEFINE(THREAD_CTX_REG_S10, offsetof(struct thread_ctx_regs, s10));
	DEFINE(THREAD_CTX_REG_S11, offsetof(struct thread_ctx_regs, s11));
	DEFINE(THREAD_CTX_REG_T3, offsetof(struct thread_ctx_regs, t3));
	DEFINE(THREAD_CTX_REG_T4, offsetof(struct thread_ctx_regs, t4));
	DEFINE(THREAD_CTX_REG_T5, offsetof(struct thread_ctx_regs, t5));
	DEFINE(THREAD_CTX_REG_T6, offsetof(struct thread_ctx_regs, t6));
	DEFINE(THREAD_CTX_REGS_SIZE, sizeof(struct thread_ctx_regs));

	/* struct thread_user_mode_rec */
	DEFINE(THREAD_USER_MODE_REC_CTX_REGS_PTR,
	       offsetof(struct thread_user_mode_rec, ctx_regs_ptr));
	DEFINE(THREAD_USER_MODE_REC_RA,
	       offsetof(struct thread_user_mode_rec, r[0]));
	DEFINE(THREAD_USER_MODE_REC_S0,
	       offsetof(struct thread_user_mode_rec, r[4]));
	DEFINE(THREAD_USER_MODE_REC_S2,
	       offsetof(struct thread_user_mode_rec, r[6]));

	DEFINE(THREAD_USER_MODE_REC_SIZE, sizeof(struct thread_user_mode_rec));

	/* struct thread_trap_regs */
	DEFINE(THREAD_TRAP_REG_SP, offsetof(struct thread_trap_regs, sp));
	DEFINE(THREAD_TRAP_REG_RA, offsetof(struct thread_trap_regs, ra));
	DEFINE(THREAD_TRAP_REG_GP, offsetof(struct thread_trap_regs, gp));
	DEFINE(THREAD_TRAP_REG_TP, offsetof(struct thread_trap_regs, tp));
	DEFINE(THREAD_TRAP_REG_T0, offsetof(struct thread_trap_regs, t0));
	DEFINE(THREAD_TRAP_REG_T1, offsetof(struct thread_trap_regs, t1));
	DEFINE(THREAD_TRAP_REG_T2, offsetof(struct thread_trap_regs, t2));
	DEFINE(THREAD_TRAP_REG_S0, offsetof(struct thread_trap_regs, s0));
	DEFINE(THREAD_TRAP_REG_S1, offsetof(struct thread_trap_regs, s1));
	DEFINE(THREAD_TRAP_REG_A0, offsetof(struct thread_trap_regs, a0));
	DEFINE(THREAD_TRAP_REG_A1, offsetof(struct thread_trap_regs, a1));
	DEFINE(THREAD_TRAP_REG_A2, offsetof(struct thread_trap_regs, a2));
	DEFINE(THREAD_TRAP_REG_A3, offsetof(struct thread_trap_regs, a3));
	DEFINE(THREAD_TRAP_REG_A4, offsetof(struct thread_trap_regs, a4));
	DEFINE(THREAD_TRAP_REG_A5, offsetof(struct thread_trap_regs, a5));
	DEFINE(THREAD_TRAP_REG_A6, offsetof(struct thread_trap_regs, a6));
	DEFINE(THREAD_TRAP_REG_A7, offsetof(struct thread_trap_regs, a7));
	DEFINE(THREAD_TRAP_REG_S2, offsetof(struct thread_trap_regs, s2));
	DEFINE(THREAD_TRAP_REG_S3, offsetof(struct thread_trap_regs, s3));
	DEFINE(THREAD_TRAP_REG_S4, offsetof(struct thread_trap_regs, s4));
	DEFINE(THREAD_TRAP_REG_S5, offsetof(struct thread_trap_regs, s5));
	DEFINE(THREAD_TRAP_REG_S6, offsetof(struct thread_trap_regs, s6));
	DEFINE(THREAD_TRAP_REG_S7, offsetof(struct thread_trap_regs, s7));
	DEFINE(THREAD_TRAP_REG_S8, offsetof(struct thread_trap_regs, s8));
	DEFINE(THREAD_TRAP_REG_S9, offsetof(struct thread_trap_regs, s9));
	DEFINE(THREAD_TRAP_REG_S10, offsetof(struct thread_trap_regs, s10));
	DEFINE(THREAD_TRAP_REG_S11, offsetof(struct thread_trap_regs, s11));
	DEFINE(THREAD_TRAP_REG_T3, offsetof(struct thread_trap_regs, t3));
	DEFINE(THREAD_TRAP_REG_T4, offsetof(struct thread_trap_regs, t4));
	DEFINE(THREAD_TRAP_REG_T5, offsetof(struct thread_trap_regs, t5));
	DEFINE(THREAD_TRAP_REG_T6, offsetof(struct thread_trap_regs, t6));
	DEFINE(THREAD_TRAP_REG_EPC, offsetof(struct thread_trap_regs, epc));
	DEFINE(THREAD_TRAP_REG_STATUS, offsetof(struct thread_trap_regs,
					       status));
	DEFINE(THREAD_TRAP_REGS_SIZE, sizeof(struct thread_trap_regs));


	DEFINE(THREAD_SMC_ARGS_A0, offsetof(struct thread_smc_args, a0));
	DEFINE(THREAD_SMC_ARGS_A1, offsetof(struct thread_smc_args, a1));
	DEFINE(THREAD_SMC_ARGS_A2, offsetof(struct thread_smc_args, a2));
	DEFINE(THREAD_SMC_ARGS_A3, offsetof(struct thread_smc_args, a3));
	DEFINE(THREAD_SMC_ARGS_A4, offsetof(struct thread_smc_args, a4));
	DEFINE(THREAD_SMC_ARGS_A5, offsetof(struct thread_smc_args, a5));
	DEFINE(THREAD_SMC_ARGS_A6, offsetof(struct thread_smc_args, a6));
	DEFINE(THREAD_SMC_ARGS_A7, offsetof(struct thread_smc_args, a7));
	DEFINE(THREAD_SMC_ARGS_SIZE, sizeof(struct thread_smc_args));

	/* struct thread_scall_regs */
	DEFINE(THREAD_SCALL_REG_STATUS, offsetof(struct thread_svc_regs,
						status));
	DEFINE(THREAD_SCALL_REG_RA, offsetof(struct thread_svc_regs, ra));
	DEFINE(THREAD_SCALL_REG_SP, offsetof(struct thread_svc_regs, sp));
	DEFINE(THREAD_SCALL_REG_A0, offsetof(struct thread_svc_regs, a0));
	DEFINE(THREAD_SCALL_REG_A1, offsetof(struct thread_svc_regs, a1));
	DEFINE(THREAD_SCALL_REG_A2, offsetof(struct thread_svc_regs, a2));
	DEFINE(THREAD_SCALL_REG_A3, offsetof(struct thread_svc_regs, a3));
	DEFINE(THREAD_SCALL_REG_A4, offsetof(struct thread_svc_regs, a4));
	DEFINE(THREAD_SCALL_REG_A5, offsetof(struct thread_svc_regs, a5));
	DEFINE(THREAD_SCALL_REG_A6, offsetof(struct thread_svc_regs, a6));
	DEFINE(THREAD_SCALL_REG_A7, offsetof(struct thread_svc_regs, a7));
	DEFINE(THREAD_SCALL_REGS_SIZE, sizeof(struct thread_svc_regs));

    /* struct core_mmu_config */
    DEFINE(CORE_MMU_CONFIG_SIZE, sizeof(struct core_mmu_config));
    DEFINE(CORE_MMU_CONFIG_LOAD_OFFSET,
           offsetof(struct core_mmu_config, load_offset));
}
