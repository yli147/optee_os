/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#ifndef __KERNEL_THREAD_PRIVATE_ARCH_H
#define __KERNEL_THREAD_PRIVATE_ARCH_H

#ifndef __ASSEMBLER__

#include <kernel/thread.h>
#include <kernel/vfp.h>

#define STACK_TMP_OFFS		0
#define STACK_TMP_SIZE		(4096 + STACK_TMP_OFFS)
#define STACK_THREAD_SIZE	8192

#if TRACE_LEVEL > 0
#define STACK_ABT_SIZE		0
#else
#define STACK_ABT_SIZE		0
#endif

#ifdef CFG_CORE_DEBUG_CHECK_STACKS
#define STACK_CHECK_EXTRA	1536
#else
#define STACK_CHECK_EXTRA	0
#endif
#define THREAD_RPC_NUM_ARGS     4

#define	TRAP_MODE_KERNEL	0
#define	TRAP_MODE_USER		1

struct thread_user_mode_rec {
	unsigned long ctx_regs_ptr;
	unsigned long exit_status0_ptr;
	unsigned long exit_status1_ptr;
	unsigned long pad;
	/*
	 * x[] is used to save registers for user/kernel context-switching
	 * 0-3: ra-tp
	 * 4-5: s0-s1
	 * 6-15: s2-s11
	 */
	unsigned long r[16];
};

#ifdef CFG_WITH_VFP
struct thread_vfp_state {
	bool ns_saved;
	bool sec_saved;
	bool sec_lazy_saved;
	struct vfp_state ns;
	struct vfp_state sec;
	struct thread_user_vfp_state *uvfp;
};
#endif /*CFG_WITH_VFP*/

#endif /*__ASSEMBLER__*/

#ifndef __ASSEMBLER__

extern long thread_user_kcode_offset;

void thread_trap_handler(long cause, unsigned long epc,
			 struct thread_trap_regs *regs,
			 bool user);
/*
 * Initializes TVEC for current hart. Called by thread_init_per_cpu()
 */
void thread_init_tvec(void);
void thread_trap_vect(void);
void thread_trap_vect_end(void);

void thread_handle_fast_smc(struct thread_smc_args *args);
uint32_t thread_handle_std_smc(uint32_t a0, uint32_t a1, uint32_t a2,
			       uint32_t a3, uint32_t a4, uint32_t a5,
			       uint32_t a6, uint32_t a7);
void thread_std_smc_entry(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
			  uint32_t a4, uint32_t a5);
uint32_t __thread_std_smc_entry(uint32_t a0, uint32_t a1, uint32_t a2,
				uint32_t a3, uint32_t a4, uint32_t a5);

/*
 * Private functions made available for thread_rv.S
 */
void thread_user_enable_vfp(struct thread_user_vfp_state *uvfp);
int thread_state_suspend(uint32_t flags, uint64_t cpsr, vaddr_t pc);
void thread_resume(struct thread_ctx_regs *regs);
uint32_t __thread_enter_user_mode(struct thread_ctx_regs *regs,
				  uint32_t *exit_status0,
				  uint32_t *exit_status1);
void *thread_get_tmp_sp(void);
void thread_state_free(void);
struct thread_ctx_regs *thread_get_ctx_regs(void);
void thread_alloc_and_run(uint32_t a0, uint32_t a1, uint32_t a2, uint32_t a3,
			  uint32_t a4, uint32_t a5);
void thread_resume_from_rpc(uint32_t thread_id, uint32_t a0, uint32_t a1,
			    uint32_t a2, uint32_t a3);
void thread_rpc(uint32_t rv[THREAD_RPC_NUM_ARGS]);
void thread_scall_handler(struct thread_svc_regs *regs);
void thread_exit_user_mode(unsigned long a0, unsigned long a1,
               unsigned long a2, unsigned long a3,
               unsigned long sp, unsigned long pc,
               unsigned long status);

#endif /*__ASSEMBLER__*/
#endif /*__KERNEL_THREAD_PRIVATE_ARCH_H*/
