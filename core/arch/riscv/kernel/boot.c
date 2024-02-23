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
#include <libfdt.h>
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

#ifdef CFG_CORE_DYN_SHM
static uint64_t get_dt_val_and_advance(const void *data, size_t *offs,
				       uint32_t cell_size)
{
	uint64_t rv = 0;

	if (cell_size == 1) {
		uint32_t v;

		memcpy(&v, (const uint8_t *)data + *offs, sizeof(v));
		*offs += sizeof(v);
		rv = fdt32_to_cpu(v);
	} else {
		uint64_t v;

		memcpy(&v, (const uint8_t *)data + *offs, sizeof(v));
		*offs += sizeof(v);
		rv = fdt64_to_cpu(v);
	}

	return rv;
}

/*
 * Find all non-secure memory from DT. Memory marked inaccessible by Secure
 * World is ignored since it could not be mapped to be used as dynamic shared
 * memory.
 */
static int get_nsec_memory_helper(void *fdt, struct core_mmu_phys_mem *mem)
{
	const uint8_t *prop = NULL;
	uint64_t a = 0;
	uint64_t l = 0;
	size_t prop_offs = 0;
	size_t prop_len = 0;
	int elems_total = 0;
	int addr_size = 0;
	int len_size = 0;
	int offs = 0;
	size_t n = 0;
	int len = 0;

	addr_size = fdt_address_cells(fdt, 0);
	if (addr_size < 0)
		return 0;

	len_size = fdt_size_cells(fdt, 0);
	if (len_size < 0)
		return 0;

	while (true) {
		offs = fdt_node_offset_by_prop_value(fdt, offs, "device_type",
						     "memory",
						     sizeof("memory"));
		if (offs < 0)
			break;

		if (fdt_get_status(fdt, offs) != (DT_STATUS_OK_NSEC |
						   DT_STATUS_OK_SEC))
			continue;

		prop = fdt_getprop(fdt, offs, "reg", &len);
		if (!prop)
			continue;

		prop_len = len;
		for (n = 0, prop_offs = 0; prop_offs < prop_len; n++) {
			a = get_dt_val_and_advance(prop, &prop_offs, addr_size);
			if (prop_offs >= prop_len) {
				n--;
				break;
			}

			l = get_dt_val_and_advance(prop, &prop_offs, len_size);
			if (mem) {
				mem->type = MEM_AREA_DDR_OVERALL;
				mem->addr = a;
				mem->size = l;
				mem++;
			}
		}

		elems_total += n;
	}

	return elems_total;
}

static struct core_mmu_phys_mem *get_nsec_memory(void *fdt, size_t *nelems)
{
	struct core_mmu_phys_mem *mem = NULL;
	int elems_total = 0;

	elems_total = get_nsec_memory_helper(fdt, NULL);
	if (elems_total <= 0)
		return NULL;

	mem = nex_calloc(elems_total, sizeof(*mem));
	if (!mem)
		panic();

	elems_total = get_nsec_memory_helper(fdt, mem);
	assert(elems_total > 0);

	*nelems = elems_total;

	return mem;
}
#endif /*CFG_CORE_DYN_SHM*/

#ifdef CFG_CORE_DYN_SHM
static void discover_nsec_memory(void)
{
	struct core_mmu_phys_mem *mem;
	const struct core_mmu_phys_mem *mem_begin = NULL;
	const struct core_mmu_phys_mem *mem_end = NULL;
	size_t nelems;
	void *fdt = get_external_dt();

	if (fdt) {
		mem = get_nsec_memory(fdt, &nelems);
		if (mem) {
			core_mmu_set_discovered_nsec_ddr(mem, nelems);
			return;
		}

		DMSG("No non-secure memory found in FDT");
	}

	mem_begin = phys_ddr_overall_begin;
	mem_end = phys_ddr_overall_end;
	nelems = mem_end - mem_begin;
	if (nelems) {
		/*
		 * Platform cannot use both register_ddr() and the now
		 * deprecated register_dynamic_shm().
		 */
		assert(phys_ddr_overall_compat_begin ==
		       phys_ddr_overall_compat_end);
	} else {
		mem_begin = phys_ddr_overall_compat_begin;
		mem_end = phys_ddr_overall_compat_end;
		nelems = mem_end - mem_begin;
		if (!nelems)
			return;
		DMSG("Warning register_dynamic_shm() is deprecated, please use register_ddr() instead");
	}

	mem = nex_calloc(nelems, sizeof(*mem));
	if (!mem)
		panic();

	memcpy(mem, phys_ddr_overall_begin, sizeof(*mem) * nelems);
	core_mmu_set_discovered_nsec_ddr(mem, nelems);
}
#else /*CFG_CORE_DYN_SHM*/
static void discover_nsec_memory(void)
{
}
#endif /*!CFG_CORE_DYN_SHM*/

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
	discover_nsec_memory();
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
