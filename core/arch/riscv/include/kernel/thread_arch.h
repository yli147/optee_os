/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __KERNEL_THREAD_ARCH_H
#define __KERNEL_THREAD_ARCH_H

#ifndef __ASSEMBLER__
#include <compiler.h>
#include <riscv.h>
#include <types_ext.h>
#include <kernel/vfp.h>

#define THREAD_CORE_LOCAL_ALIGNED __aligned(2 * RISCV_XLEN_BYTES)

struct thread_pauth_keys {
};

struct thread_core_local {
	unsigned long r[4];
	uint32_t hart_id;
	vaddr_t tmp_stack_va_end;
	short int curr_thread;
	uint32_t flags;
	vaddr_t abt_stack_va_end;
#ifdef CFG_TEE_CORE_DEBUG
	unsigned int locked_count; /* Number of spinlocks held */
#endif
#ifdef CFG_CORE_DEBUG_CHECK_STACKS
	bool stackcheck_recursion;
#endif
} THREAD_CORE_LOCAL_ALIGNED;

struct thread_user_vfp_state {
	struct vfp_state vfp;
	bool lazy_saved;
	bool saved;
};

struct thread_smc_args {
	unsigned long a0;/* SBI function ID */
	unsigned long a1;/* Parameter */
	unsigned long a2;/* Parameter */
	unsigned long a3;/* Thread ID when returning from RPC */
	unsigned long a4;/* Not used */
	unsigned long a5;/* Not used */
	unsigned long a6;/* Not used */
	unsigned long a7;/* Hypervisor Client ID */
};

struct thread_abort_regs {
	unsigned long ra;
	unsigned long sp;
	unsigned long gp;
	unsigned long tp;
	unsigned long t0;
	unsigned long t1;
	unsigned long t2;
	unsigned long s0;
	unsigned long s1;
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
	unsigned long s2;
	unsigned long s3;
	unsigned long s4;
	unsigned long s5;
	unsigned long s6;
	unsigned long s7;
	unsigned long s8;
	unsigned long s9;
	unsigned long s10;
	unsigned long s11;
	unsigned long t3;
	unsigned long t4;
	unsigned long t5;
	unsigned long t6;
	unsigned long status;
	unsigned long cause;
	unsigned long epc;
	unsigned long tval;
	unsigned long satp;
};

struct thread_trap_regs {
	unsigned long ra;
	unsigned long sp;
	unsigned long gp;
	unsigned long tp;
	unsigned long t0;
	unsigned long t1;
	unsigned long t2;
	unsigned long s0;
	unsigned long s1;
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
	unsigned long s2;
	unsigned long s3;
	unsigned long s4;
	unsigned long s5;
	unsigned long s6;
	unsigned long s7;
	unsigned long s8;
	unsigned long s9;
	unsigned long s10;
	unsigned long s11;
	unsigned long t3;
	unsigned long t4;
	unsigned long t5;
	unsigned long t6;
	unsigned long epc;
	unsigned long status;
} __aligned(16);

struct thread_svc_regs {
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
	unsigned long t0;
	unsigned long t1;
	unsigned long t2;
	unsigned long t3;
	unsigned long t4;
	unsigned long t5;
	unsigned long t6;
	unsigned long ra;
	unsigned long sp;
	unsigned long usr_sp;
	unsigned long status;
} __aligned(16);

struct thread_ctx_regs {
	unsigned long ra;
	unsigned long sp;
	unsigned long gp;
	unsigned long tp;
	unsigned long t0;
	unsigned long t1;
	unsigned long t2;
	unsigned long s0;
	unsigned long s1;
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
	unsigned long s2;
	unsigned long s3;
	unsigned long s4;
	unsigned long s5;
	unsigned long s6;
	unsigned long s7;
	unsigned long s8;
	unsigned long s9;
	unsigned long s10;
	unsigned long s11;
	unsigned long t3;
	unsigned long t4;
	unsigned long t5;
	unsigned long t6;
	unsigned long pc;
	unsigned long status;
};

struct user_mode_ctx;

/*
 * These flags should vary according to the privilege mode selected
 * to run OP-TEE core on (M/HS/S). For now default to S-Mode.
 */

#define THREAD_EXCP_FOREIGN_INTR	CSR_XIE_EIE
#define THREAD_EXCP_NATIVE_INTR		(CSR_XIE_SIE | CSR_XIE_TIE)
#define THREAD_EXCP_ALL	(THREAD_EXCP_FOREIGN_INTR | THREAD_EXCP_NATIVE_INTR)

uint32_t thread_kernel_enable_vfp(void);
void thread_kernel_disable_vfp(uint32_t state);
void thread_kernel_save_vfp(void);
void thread_kernel_restore_vfp(void);
void thread_user_save_vfp(void);
void thread_user_clear_vfp(struct user_mode_ctx *uctx);
vaddr_t thread_get_saved_thread_sp(void);

static inline void thread_get_user_kcode(struct mobj **mobj, size_t *offset,
					 vaddr_t *va, size_t *sz)
{
	*mobj = NULL;
	*offset = 0;
	*va = 0;
	*sz = 0;
}

static inline void thread_get_user_kdata(struct mobj **mobj, size_t *offset,
					 vaddr_t *va, size_t *sz)
{
	*mobj = NULL;
	*offset = 0;
	*va = 0;
	*sz = 0;
}

/*
 * Disables and empties the prealloc RPC cache one reference at a time. If
 * all threads are idle this function returns true and a cookie of one shm
 * object which was removed from the cache. When the cache is empty *cookie
 * is set to 0 and the cache is disabled else a valid cookie value. If one
 * thread isn't idle this function returns false.
 */
bool thread_disable_prealloc_rpc_cache(uint64_t *cookie);

/*
 * Enabled the prealloc RPC cache. If all threads are idle the cache is
 * enabled and this function returns true. If one thread isn't idle this
 * function return false.
 */
bool thread_enable_prealloc_rpc_cache(void);

#endif /*__ASSEMBLER__*/
#endif /*__KERNEL_THREAD_ARCH_H*/
