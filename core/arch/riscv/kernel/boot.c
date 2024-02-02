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
	IMSG("boot_primary_init_intc done");
	init_tee_runtime();
	IMSG("init_tee_runtime done");
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

#include "tee/optee_abi.h"
#include "tee/teeabi_opteed_macros.h"
#include "tee/teeabi_opteed.h"

#define SMC_TYPE_FAST                   UL(1)
#define SMC_TYPE_YIELD                  UL(0)

#define FUNCID_TYPE_SHIFT               U(31)
#define FUNCID_TYPE_MASK                U(0x1)

#define GET_SMC_TYPE(id)                (((id) >> FUNCID_TYPE_SHIFT) & \
                                         FUNCID_TYPE_MASK)

#if 0
#define SMC_TYPE_FAST                   UL(1)
#define SMC_TYPE_YIELD                  UL(0)

#define FUNCID_TYPE_SHIFT               U(31)
#define FUNCID_TYPE_MASK                U(0x1)

#define GET_SMC_TYPE(id)                (((id) >> FUNCID_TYPE_SHIFT) & \
                                         FUNCID_TYPE_MASK)

#define TEESMC_OPTEED_RV(func_num) \
        OPTEE_SMC_CALL_VAL(OPTEE_ABI_32, OPTEE_ABI_FAST_CALL, \
                           OPTEE_ABI_OWNER_TRUSTED_OS_OPTEED, (func_num))

#define TEESMC_OPTEED_FUNCID_RETURN_CALL_DONE           5
#define TEESMC_OPTEED_RETURN_CALL_DONE \
        TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_RETURN_CALL_DONE)

#define TEESMC_OPTEED_FUNCID_RETURN_ENTRY_DONE          0
#define TEESMC_OPTEED_RETURN_ENTRY_DONE \
        TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_RETURN_ENTRY_DONE)
#endif

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


extern const struct core_mmu_config boot_mmu_config;
extern struct thread_vector_table thread_vector_table;
#include <sbi.h>
#include <kernel/thread_private_arch.h>
struct rpmi_tee {
	unsigned long a0;
	unsigned long a1;
	unsigned long a2;
	unsigned long a3;
	unsigned long a4;
	unsigned long a5;
	unsigned long a6;
	unsigned long a7;
};

unsigned long rpmi_a0;
unsigned long rpmi_a1;
unsigned long rpmi_a2;
unsigned long rpmi_a3;
unsigned long rpmi_a4;
unsigned long rpmi_a5;

//struct rpmi_tee_rx aa;
unsigned long opteed_return_entry_done(void *fdt __unused)
{
	int ext; int fid; unsigned long arg0;
	unsigned long arg1; unsigned long arg2;
	unsigned long arg3; unsigned long arg4;
	unsigned long arg5;
	
	// NSEC_SHM 0xf4000000..0xf41fffff pa 0xf1600000..0xf17fffff size 0x00200000 (pgdir)
	struct rpmi_tee *rx = (struct rpmi_tee_rx *)(0xF41F0000);  
	struct rpmi_tee *tx = (struct rpmi_tee_tx *)(0xF41F0000); 

	//csr_write(CSR_UIE, 0);
	//write_csr(uie, 0);
	//read_sstatus();
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
		@param a4 : Arg4			<= boot_mmu_config
		@param a5 : Arg5			<= thread_vector_table
		@param a6 : FunctionID     <= SBI_RPXY_SEND_NORMAL_MSG 0x2
		@param a7 : ExtensionId    <= SBI_EXT_RPXY 0x52505859
	 */
	ext = 0x52505859;
	fid = 0x01;
	arg0 = 0x00001000;
	arg1 = 0xF17F0000;
	arg2 = 0x0;
	arg3 = 0x0;
	arg4 = 0x0;
	arg5 = 0x0;
	sbi_ecall(ext, fid, arg0, arg1, arg2, arg3, arg4, arg5);

	ext = 0x52505859;
	fid = 0x02;
	arg0 = 0x0;
    arg1 = 0x0A;
	arg2 = 0x03;
	tx->a6 = TEEABI_OPTEED_RETURN_ENTRY_DONE;
	tx->a0 = rpmi_a0;
	tx->a1 = rpmi_a1;
	sbi_ecall(ext, fid, arg0, arg1, arg2, sizeof(struct rpmi_tee), 0, 0);

	return 0;
}

unsigned long opteed_return_call_done(void *fdt __unused)
{
	int ext; int fid; unsigned long arg0;
	unsigned long arg1; unsigned long arg2;
	unsigned long arg3; unsigned long arg4;
	unsigned long arg5;
	struct rpmi_tee *rx = (struct rpmi_tee_rx *)(0xF41F0000);  
	struct rpmi_tee *tx = (struct rpmi_tee_tx *)(0xF41F0000); 
	// struct rpmi_tee *tx = (struct rpmi_tee_tx *)(0xF41F0000); 
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
		@param a4 : Arg4			<= boot_mmu_config
		@param a5 : Arg5			<= thread_vector_table
		@param a6 : FunctionID     <= SBI_RPXY_SEND_NORMAL_MSG 0x2
		@param a7 : ExtensionId    <= SBI_EXT_RPXY 0x52505859
	 */
	ext = 0x52505859;
	fid = 0x02;
	arg0 = 0x0;
    arg1 = 0x0A;
	arg2 = 0x03;
	tx->a6 = TEEABI_OPTEED_RETURN_CALL_DONE;
	tx->a1 = rpmi_a1;
	tx->a2 = rpmi_a2;
	tx->a3 = rpmi_a3;
	tx->a4 = rpmi_a4;
	sbi_ecall(ext, fid, arg0, arg1, arg2, sizeof(struct rpmi_tee), 0, 0);
	//write_csr(uie, 0);
	return 0;
}

unsigned long event_loop(void *fdt __unused)
{
	int ext; int fid; unsigned long arg0;
	unsigned long arg1; unsigned long arg2;
	unsigned long arg3; unsigned long arg4;
	unsigned long arg5;

	// NSEC_SHM 0xf4600000..0xf47fffff pa 0xf1600000..0xf17fffff size 0x00200000 (pgdir)
	struct rpmi_tee *rx = (struct rpmi_tee_rx *)(0xF47F0000);  
	struct rpmi_tee *tx = (struct rpmi_tee_tx *)(0xF47F0000); 
	// struct rpmi_tee *tx = (struct rpmi_tee_tx *)(0xF41F0000); 
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
		@param a4 : Arg4			<= boot_mmu_config
		@param a5 : Arg5			<= thread_vector_table
		@param a6 : FunctionID     <= SBI_RPXY_SEND_NORMAL_MSG 0x2
		@param a7 : ExtensionId    <= SBI_EXT_RPXY 0x52505859
	 */
#if 1
while(1) {
	EMSG("test_switch: while loop %x %x ", rx->a0, GET_SMC_TYPE(rx->a0));
if (GET_SMC_TYPE(rx->a0) == SMC_TYPE_FAST) {

		struct thread_abi_args *smc_args = rx;
		EMSG("test_switch: SMC_TYPE_FAST %x %x %x %x %x %x", rx->a1, rx->a2, rx->a3, rx->a4, rx->a5, rx->a6, rx->a0);
		thread_handle_fast_abi(smc_args);
		EMSG("test_switch: SMC_TYPE_FAST %x %x %x %x %x", smc_args->a0, smc_args->a1, smc_args->a2, smc_args->a3, smc_args->a4);

			ext = 0x52505859;
			fid = 0x02;
			arg0 = 0x0;
			arg1 = 0x0A;
			arg2 = 0x03; // TEESMC_OPTEED_RETURN_CALL_DONE;
#if 1
static int fast_call = 0;
if(fast_call == 0) {
		tx->a0 = 0x0;
		tx->a1 = 0x0;
		tx->a2 = 0xf1600000;
		tx->a3 = 0x200000;
		tx->a4 = 0x1;
		fast_call++;	
} else if(fast_call == 1) {
		tx->a0 = 0x0;
		tx->a1 = 0x7;
		tx->a2 = 0x0;
		tx->a3 = 0x0;
		tx->a4 = 0x0;
		fast_call++;
} else if(fast_call == 2) {
		tx->a0 = 0;
		tx->a1 = 0;
		tx->a2 = 0;
		tx->a3 = 0;
		tx->a4 = 0;
		fast_call++;
} 
#else
		tx->a4 = smc_args->a3;
		tx->a3 = smc_args->a2;
		tx->a2 = smc_args->a1;
		tx->a1 = smc_args->a0;
		// tx->a0 = smc_args->a0;
#endif
		tx->a6 = TEEABI_OPTEED_RETURN_CALL_DONE;
			sbi_ecall(ext, fid, arg0, arg1, arg2, sizeof(struct rpmi_tee), 0, 0);
	} else {
		EMSG("test_switch: SMC_STD %x %x %x %x %x %x %x", rx->a1, rx->a2, rx->a3, rx->a4, rx->a5, rx->a6, rx->a0);
		//thread_handle_std_abi(rx->a1, rx->a2, rx->a3, rx->a4, rx->a5, rx->a6, rx->a0, 0x544545);
		// thread_handle_std_abi(rx->a0, rx->a1, rx->a2, rx->a3, rx->a4, rx->a5, rx->a6, 0x544545);
		//thread_handle_std_abi(rx->a2, rx->a3, rx->a4, rx->a5, rx->a6, rx->a0, rx->a1, 0x544545);
		thread_handle_std_abi(rx->a0, rx->a1, rx->a2, rx->a3, rx->a4, rx->a5, rx->a6, 0x544545);
		EMSG("test_switch: SMC_STD %x %x %x %x %x %x %x", rx->a1, rx->a2, rx->a3, rx->a4, rx->a5, rx->a6, rx->a0);
		/*
	 * Normally thread_handle_std_smc() should return via
	 * thread_exit(), thread_rpc(), but if thread_handle_std_smc()
	 * hasn't switched stack (error detected) it will do a normal "C"
	 * return.
	 */
			ext = 0x52505859;
		fid = 0x02;
		arg0 = 0x0;
		arg1 = 0x0A;
		arg2 = 0x03; // TEESMC_OPTEED_RETURN_CALL_DONE;
		arg3 = 0x08;

		tx->a6 = TEEABI_OPTEED_RETURN_CALL_DONE;
		tx->a1 = rpmi_a1;
		tx->a2 = rpmi_a2;
		tx->a3 = rpmi_a3;
		tx->a4 = rpmi_a4;

		sbi_ecall(ext, fid, arg0, arg1, arg2, sizeof(struct rpmi_tee), 0, 0);
	
	}
}
#endif
	return 0;

}