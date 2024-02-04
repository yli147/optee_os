// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023 Andes Technology Corporation
 * Copyright 2022-2023 NXP
 */

#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <console.h>
#include <keep.h>
#include <kernel/boot.h>
#include <kernel/dt.h>
#include <kernel/linker.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/thread.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/tee_mm.h>
#include <mm/tee_pager.h>
#include <platform_config.h>
#include <riscv.h>
#include <sbi.h>
#include <stdio.h>
#include <trace.h>
#include <util.h>

#define PADDR_INVALID               ULONG_MAX

paddr_t start_addr;
unsigned long boot_args[4];

uint32_t sem_cpu_sync[CFG_TEE_CORE_NB_CORE];

#if defined(CFG_DT)
static int mark_tddram_as_reserved(struct dt_descriptor *dt)
{
	return add_res_mem_dt_node(dt, "optee_core", CFG_TDDRAM_START,
				   CFG_TDDRAM_SIZE);
}

static void update_external_dt(void)
{
	struct dt_descriptor *dt = get_external_dt_desc();

	if (!dt || !dt->blob)
		return;

	if (mark_tddram_as_reserved(dt))
		panic("Failed to config secure memory");
}
#else /*CFG_DT*/
static void update_external_dt(void)
{
}
#endif /*!CFG_DT*/

void init_sec_mon(unsigned long nsec_entry __maybe_unused)
{
	assert(nsec_entry == PADDR_INVALID);
	/* Do nothing as we don't have a secure monitor */
}

#ifdef CFG_RISCV_S_MODE
static void start_secondary_cores(void)
{
	size_t i = 0;
	size_t pos = get_core_pos();

	for (i = 0; i < CFG_TEE_CORE_NB_CORE; i++)
		if (i != pos && IS_ENABLED(CFG_RISCV_SBI) &&
		    sbi_boot_hart(i, start_addr, i))
			EMSG("Error starting secondary hart %zu", i);
}
#endif

static void init_runtime(void)
{
	malloc_add_pool(__heap1_start, __heap1_end - __heap1_start);

	IMSG_RAW("\n");
}

void init_tee_runtime(void)
{
	core_mmu_init_ta_ram();
	call_preinitcalls();
	call_initcalls();
}

static void init_primary(unsigned long nsec_entry)
{
	thread_init_core_local_stacks();

	/*
	 * Mask asynchronous exceptions before switch to the thread vector
	 * as the thread handler requires those to be masked while
	 * executing with the temporary stack. The thread subsystem also
	 * asserts that the foreign interrupts are blocked when using most of
	 * its functions.
	 */
	thread_set_exceptions(THREAD_EXCP_ALL);

	init_runtime();
	thread_init_boot_thread();
	thread_init_primary();
	thread_init_per_cpu();
	init_sec_mon(nsec_entry);
}

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void plat_primary_init_early(void)
{
}

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void boot_primary_init_intc(void)
{
}

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void boot_secondary_init_intc(void)
{
}

void boot_init_primary_early(void)
{
	unsigned long e = PADDR_INVALID;

	init_primary(e);
}

void boot_init_primary_late(unsigned long fdt,
			    unsigned long tos_fw_config __unused)
{
	init_external_dt(fdt, CFG_DTB_MAX_SIZE);
	update_external_dt();

	IMSG("OP-TEE version: %s", core_v_str);
	if (IS_ENABLED(CFG_INSECURE)) {
		IMSG("WARNING: This OP-TEE configuration might be insecure!");
		IMSG("WARNING: Please check https://optee.readthedocs.io/en/latest/architecture/porting_guidelines.html");
	}
	IMSG("Primary CPU initializing");
	boot_primary_init_intc();
	init_tee_runtime();
	call_finalcalls();
	IMSG("Primary CPU initialized");

#ifdef CFG_RISCV_S_MODE
	start_secondary_cores();
#endif
}

static void init_secondary_helper(unsigned long nsec_entry)
{
	size_t pos = get_core_pos();

	IMSG("Secondary CPU %zu initializing", pos);

	/*
	 * Mask asynchronous exceptions before switch to the thread vector
	 * as the thread handler requires those to be masked while
	 * executing with the temporary stack. The thread subsystem also
	 * asserts that the foreign interrupts are blocked when using most of
	 * its functions.
	 */
	thread_set_exceptions(THREAD_EXCP_ALL);

	thread_init_per_cpu();
	init_sec_mon(nsec_entry);
	boot_secondary_init_intc();

	IMSG("Secondary CPU %zu initialized", pos);
}

void boot_init_secondary(unsigned long nsec_entry __unused)
{
	init_secondary_helper(PADDR_INVALID);
}

#include <sbi.h>
#include <kernel/thread_private_arch.h>
#include "tee/optee_abi.h"
#include "tee/teeabi_opteed_macros.h"
#include "tee/teeabi_opteed.h"

#define SMC_TYPE_FAST                   UL(1)
#define SMC_TYPE_YIELD                  UL(0)

#define FUNCID_TYPE_SHIFT               U(31)
#define FUNCID_TYPE_MASK                U(0x1)

#define GET_SMC_TYPE(id)                (((id) >> FUNCID_TYPE_SHIFT) & \
                                         FUNCID_TYPE_MASK)
struct sbiret {
        long error;
        long value;
};
#define _sbi_ecall(ext, fid, arg0, arg1, arg2, arg3, arg4, arg5, ...) ({  \
        register unsigned long a0 asm("a0") = (unsigned long)arg0; \
        register unsigned long a1 asm("a1") = (unsigned long)arg1; \
        register unsigned long a2 asm("a2") = (unsigned long)arg2; \
        register unsigned long a3 asm("a3") = (unsigned long)arg3; \
        register unsigned long a4 asm("a4") = (unsigned long)arg4; \
        register unsigned long a5 asm("a5") = (unsigned long)arg5; \
        register unsigned long a6 asm("a6") = (unsigned long)fid;  \
        register unsigned long a7 asm("a7") = (unsigned long)ext;  \
        asm volatile ("ecall" \
                : "+r" (a0), "+r" (a1) \
                : "r" (a2), "r" (a3), "r" (a4), "r" (a5), "r"(a6), "r"(a7) \
                : "memory"); \
        (struct sbiret){ .error = a0, .value = a1 }; \
})

#define sbi_ecall(...) _sbi_ecall(__VA_ARGS__, 0, 0, 0, 0, 0, 0, 0)

unsigned long value;
unsigned long expt1;
unsigned long expt2;
unsigned long expt3;
unsigned long event_id;

// NSEC_SHM 0xf4000000..0xf41fffff pa 0xf1600000..0xf17fffff size 0x00200000 (pgdir)
#define TEE_NSCOMM_BUF_BASE 0xF47F0000

void __noreturn sbi_rpxy_event_complete(void *fdt __unused)
{
	int ext; int fid; unsigned long arg0;
	unsigned long arg1; unsigned long arg2;
	struct thread_abi_args *txrx = (struct thread_abi_args *)(TEE_NSCOMM_BUF_BASE);  
	/*
	 * Pass the vector address returned from main_init
	 * Compensate for the load offset since cpu_on_handler() is
	 * called with MMU off.
	 * CORE_MMU_CONFIG_LOAD_OFFSET = 16
	 * SBI CALL
		@param a0 : Pointer to Arg0  <= SBI_RPMI_MM_TRANSPORT_ID 0x0
		@param a1 : Pointer to Arg1  <= SBI_RPMI_MM_SRV_GROUP 0x0A
		@param a2 : Arg2			<= SBI_RPMI_MM_SRV_COMPLETE/TEESMC_OPTEED_RETURN_ENTRY_DONE 0x03
		@param a3 : Arg3			<= message length 0x8
		@param a4 : Arg4			<= boot_mmu_config   -- how to pass this to rpxy ??
		@param a5 : Arg5			<= thread_vector_table  -- do we still need this ??
		@param a6 : FunctionID     <= SBI_RPXY_SEND_NORMAL_MSG 0x2
		@param a7 : ExtensionId    <= SBI_EXT_RPXY 0x52505859
	 */
	ext = 0x52505859;
	fid = 0x02;
	arg0 = 0x0;
    arg1 = 0x0A;
	arg2 = 0x03; //SBI_RPMI_MM_SRV_COMPLETE

	txrx->a0 = value;
	txrx->a1 = expt1;
	txrx->a2 = expt2;
	txrx->a3 = expt3;
	txrx->a4 = event_id;
	sbi_ecall(ext, fid, arg0, arg1, arg2, 0, 0, 0);

	while(1) {
		if (GET_SMC_TYPE(txrx->a0) == SMC_TYPE_FAST) {
			struct thread_abi_args *smc_args = txrx;
			thread_handle_fast_abi(smc_args);
			ext = 0x52505859;
			fid = 0x02;
			arg0 = 0x0;
			arg1 = 0x0A;
			arg2 = 0x03; // SBI_RPMI_MM_SRV_COMPLETE;
			txrx->a4 = 0;
			txrx->a3 = smc_args->a3;
			txrx->a2 = smc_args->a2;
			txrx->a1 = smc_args->a1;
			txrx->a0 = smc_args->a0;
			sbi_ecall(ext, fid, arg0, arg1, arg2, 0, 0, 0);
		} else {
			thread_handle_std_abi(txrx->a0, txrx->a1, txrx->a2, txrx->a3, txrx->a4, txrx->a5, txrx->a6, txrx->a7);
			ext = 0x52505859;
			fid = 0x02;
			arg0 = 0x0;
			arg1 = 0x0A;
			arg2 = 0x03; // SBI_RPMI_MM_SRV_COMPLETE;
			txrx->a0 = value;
			txrx->a1 = expt1;
			txrx->a2 = expt2;
			txrx->a3 = expt3;
			txrx->a4 = event_id;
			sbi_ecall(ext, fid, arg0, arg1, arg2, 0, 0, 0);
		}
	}
}