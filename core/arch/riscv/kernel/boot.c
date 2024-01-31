// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2015-2022, Linaro Limited
 */

#include <riscv.h>
#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <console.h>
#include <crypto/crypto.h>
#include <drivers/gic.h>
#include <initcall.h>
#include <inttypes.h>
#include <keep.h>
#include <kernel/asan.h>
#include <kernel/boot.h>
#include <kernel/linker.h>
#include <kernel/misc.h>
#include <kernel/panic.h>
#include <kernel/tee_misc.h>
#include <kernel/thread.h>
#include <kernel/tpm.h>
#include <libfdt.h>
#include <malloc.h>
#include <memtag.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <mm/fobj.h>
#include <mm/tee_mm.h>
#include <mm/tee_pager.h>
//#include <sm/psci.h>
#include <stdio.h>
#include <trace.h>
#include <utee_defines.h>
#include <util.h>
#include <sm/optee_smc.h>
#include <platform_config.h>

#if defined(CFG_WITH_VFP)
#include <kernel/vfp.h>
#endif

unsigned long boot_cpu_hartid;
/*
 * In this file we're using unsigned long to represent physical pointers as
 * they are received in a single register when OP-TEE is initially entered.
 * This limits 32-bit systems to only use make use of the lower 32 bits
 * of a physical address for initial parameters.
 *
 * 64-bit systems on the other hand can use full 64-bit physical pointers.
 */
#define PADDR_INVALID		ULONG_MAX

#ifdef CFG_DT
struct dt_descriptor {
	void *blob;
#ifdef _CFG_USE_DTB_OVERLAY
	int frag_id;
#endif
};

static struct dt_descriptor external_dt __nex_bss;
#endif

#ifdef CFG_SECONDARY_INIT_CNTFRQ
static uint32_t cntfrq;
#endif

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void plat_primary_init_early(void)
{
}
DECLARE_KEEP_PAGER(plat_primary_init_early);

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void main_init_gic(void)
{
}

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak void main_secondary_init_gic(void)
{
}

/* May be overridden in plat-$(PLATFORM)/main.c */
__weak unsigned long plat_get_aslr_seed(void)
{
	DMSG("Warning: no ASLR seed");

	return 0;
}

/*
 * This function is called as a guard after each smc call which is not
 * supposed to return.
 */
void __panic_at_smc_return(void)
{
	panic();
}

void init_sec_mon(unsigned long nsec_entry __maybe_unused)
{
	assert(nsec_entry == PADDR_INVALID);
	/* Do nothing as we don't have a secure monitor */
}

static void init_vfp_nsec(void)
{
}

static void init_vfp_sec(void)
{
	/* Not using VFP */
}


static void primary_save_cntfrq(void)
{
}

static void secondary_init_cntfrq(void)
{
}

#ifdef CFG_CORE_SANITIZE_KADDRESS
static void init_run_constructors(void)
{
	const vaddr_t *ctor;

	for (ctor = &__ctor_list; ctor < &__ctor_end; ctor++)
		((void (*)(void))(*ctor))();
}

static void init_asan(void)
{

	/*
	 * CFG_ASAN_SHADOW_OFFSET is also supplied as
	 * -fasan-shadow-offset=$(CFG_ASAN_SHADOW_OFFSET) to the compiler.
	 * Since all the needed values to calculate the value of
	 * CFG_ASAN_SHADOW_OFFSET isn't available in to make we need to
	 * calculate it in advance and hard code it into the platform
	 * conf.mk. Here where we have all the needed values we double
	 * check that the compiler is supplied the correct value.
	 */

#define __ASAN_SHADOW_START \
	ROUNDUP(TEE_RAM_VA_START + (TEE_RAM_VA_SIZE * 8) / 9 - 8, 8)
	assert(__ASAN_SHADOW_START == (vaddr_t)&__asan_shadow_start);
#define __CFG_ASAN_SHADOW_OFFSET \
	(__ASAN_SHADOW_START - (TEE_RAM_VA_START / 8))
	COMPILE_TIME_ASSERT(CFG_ASAN_SHADOW_OFFSET == __CFG_ASAN_SHADOW_OFFSET);
#undef __ASAN_SHADOW_START
#undef __CFG_ASAN_SHADOW_OFFSET

	/*
	 * Assign area covered by the shadow area, everything from start up
	 * to the beginning of the shadow area.
	 */
	asan_set_shadowed((void *)TEE_TEXT_VA_START, &__asan_shadow_start);

	/*
	 * Add access to areas that aren't opened automatically by a
	 * constructor.
	 */
	asan_tag_access(&__ctor_list, &__ctor_end);
	asan_tag_access(__rodata_start, __rodata_end);
#ifdef CFG_WITH_PAGER
	asan_tag_access(__pageable_start, __pageable_end);
#endif /*CFG_WITH_PAGER*/
	asan_tag_access(__nozi_start, __nozi_end);
	asan_tag_access(__exidx_start, __exidx_end);
	asan_tag_access(__extab_start, __extab_end);

	init_run_constructors();

	/* Everything is tagged correctly, let's start address sanitizing. */
	asan_start();
}
#else /*CFG_CORE_SANITIZE_KADDRESS*/
static void init_asan(void)
{
}
#endif /*CFG_CORE_SANITIZE_KADDRESS*/

static void init_runtime(void)
{
	init_asan();

	/*
	 * By default whole OP-TEE uses malloc, so we need to initialize
	 * it early. But, when virtualization is enabled, malloc is used
	 * only by TEE runtime, so malloc should be initialized later, for
	 * every virtual partition separately. Core code uses nex_malloc
	 * instead.
	 */
	malloc_add_pool(__heap1_start, __heap1_end - __heap1_start);

	IMSG_RAW("\n");
}

void *get_dt(void)
{
	void *fdt = get_embedded_dt();

	if (!fdt)
		fdt = get_external_dt();

	return fdt;
}

#if defined(CFG_EMBED_DTB)
void *get_embedded_dt(void)
{
	static bool checked;

	assert(cpu_mmu_enabled());

	if (!checked) {
		IMSG("Embedded DTB found");

		if (fdt_check_header(embedded_secure_dtb))
			panic("Invalid embedded DTB");

		checked = true;
	}

	return embedded_secure_dtb;
}
#else
void *get_embedded_dt(void)
{
	return NULL;
}
#endif /*CFG_EMBED_DTB*/

#if defined(CFG_DT)
void *get_external_dt(void)
{
	assert(cpu_mmu_enabled());
	return external_dt.blob;
}

static TEE_Result release_external_dt(void)
{
	int ret = 0;

	if (!external_dt.blob)
		return TEE_SUCCESS;

	ret = fdt_pack(external_dt.blob);
	if (ret < 0) {
		EMSG("Failed to pack Device Tree at 0x%" PRIxPA ": error %d",
		     virt_to_phys(external_dt.blob), ret);
		panic();
	}

	if (core_mmu_remove_mapping(MEM_AREA_EXT_DT, external_dt.blob,
				    CFG_DTB_MAX_SIZE))
		panic("Failed to remove temporary Device Tree mapping");

	/* External DTB no more reached, reset pointer to invalid */
	external_dt.blob = NULL;

	return TEE_SUCCESS;
}
boot_final(release_external_dt);

#ifdef _CFG_USE_DTB_OVERLAY
static int add_dt_overlay_fragment(struct dt_descriptor *dt, int ioffs)
{
	char frag[32];
	int offs;
	int ret;

	snprintf(frag, sizeof(frag), "fragment@%d", dt->frag_id);
	offs = fdt_add_subnode(dt->blob, ioffs, frag);
	if (offs < 0)
		return offs;

	dt->frag_id += 1;

	ret = fdt_setprop_string(dt->blob, offs, "target-path", "/");
	if (ret < 0)
		return -1;

	return fdt_add_subnode(dt->blob, offs, "__overlay__");
}

static int init_dt_overlay(struct dt_descriptor *dt, int __maybe_unused dt_size)
{
	int fragment;

	if (IS_ENABLED(CFG_EXTERNAL_DTB_OVERLAY)) {
		if (!fdt_check_header(dt->blob)) {
			fdt_for_each_subnode(fragment, dt->blob, 0)
				dt->frag_id += 1;
			return 0;
		}
	}

	return fdt_create_empty_tree(dt->blob, dt_size);
}
#else
static int add_dt_overlay_fragment(struct dt_descriptor *dt __unused, int offs)
{
	return offs;
}

static int init_dt_overlay(struct dt_descriptor *dt __unused,
			   int dt_size __unused)
{
	return 0;
}
#endif /* _CFG_USE_DTB_OVERLAY */

static int add_dt_path_subnode(struct dt_descriptor *dt, const char *path,
			       const char *subnode)
{
	int offs;

	offs = fdt_path_offset(dt->blob, path);
	if (offs < 0)
		return -1;
	offs = add_dt_overlay_fragment(dt, offs);
	if (offs < 0)
		return -1;
	offs = fdt_add_subnode(dt->blob, offs, subnode);
	if (offs < 0)
		return -1;
	return offs;
}

static int add_optee_dt_node(struct dt_descriptor *dt)
{
	int offs;
	int ret;

	if (fdt_path_offset(dt->blob, "/firmware/optee") >= 0) {
		DMSG("OP-TEE Device Tree node already exists!");
		return 0;
	}

	offs = fdt_path_offset(dt->blob, "/firmware");
	if (offs < 0) {
		offs = add_dt_path_subnode(dt, "/", "firmware");
		if (offs < 0)
			return -1;
	}

	offs = fdt_add_subnode(dt->blob, offs, "optee");
	if (offs < 0)
		return -1;

	ret = fdt_setprop_string(dt->blob, offs, "compatible",
				 "linaro,optee-tz");
	if (ret < 0)
		return -1;
	ret = fdt_setprop_string(dt->blob, offs, "method", "smc");
	if (ret < 0)
		return -1;
	if (CFG_CORE_ASYNC_NOTIF_GIC_INTID) {
		/*
		 * The format of the interrupt property is defined by the
		 * binding of the interrupt domain root. In this case it's
		 * one Arm GIC v1, v2 or v3 so we must be compatible with
		 * these.
		 *
		 * An SPI type of interrupt is indicated with a 0 in the
		 * first cell.
		 *
		 * The interrupt number goes in the second cell where
		 * SPIs ranges from 0 to 987.
		 *
		 * Flags are passed in the third cell where a 1 means edge
		 * triggered.
		 */
		const uint32_t gic_spi = 0;
		const uint32_t irq_type_edge = 1;
		uint32_t val[] = {
			TEE_U32_TO_BIG_ENDIAN(gic_spi),
			TEE_U32_TO_BIG_ENDIAN(CFG_CORE_ASYNC_NOTIF_GIC_INTID -
					      GIC_SPI_BASE),
			TEE_U32_TO_BIG_ENDIAN(irq_type_edge),
		};

		ret = fdt_setprop(dt->blob, offs, "interrupts", val,
				  sizeof(val));
		if (ret < 0)
			return -1;
	}
	return 0;
}

#ifdef CFG_PSCI_ARM32
static int append_psci_compatible(void *fdt, int offs, const char *str)
{
	return fdt_appendprop(fdt, offs, "compatible", str, strlen(str) + 1);
}

static int dt_add_psci_node(struct dt_descriptor *dt)
{
	int offs;

	if (fdt_path_offset(dt->blob, "/psci") >= 0) {
		DMSG("PSCI Device Tree node already exists!");
		return 0;
	}

	offs = add_dt_path_subnode(dt, "/", "psci");
	if (offs < 0)
		return -1;
	if (append_psci_compatible(dt->blob, offs, "arm,psci-1.0"))
		return -1;
	if (append_psci_compatible(dt->blob, offs, "arm,psci-0.2"))
		return -1;
	if (append_psci_compatible(dt->blob, offs, "arm,psci"))
		return -1;
	if (fdt_setprop_string(dt->blob, offs, "method", "smc"))
		return -1;
	if (fdt_setprop_u32(dt->blob, offs, "cpu_suspend", PSCI_CPU_SUSPEND))
		return -1;
	if (fdt_setprop_u32(dt->blob, offs, "cpu_off", PSCI_CPU_OFF))
		return -1;
	if (fdt_setprop_u32(dt->blob, offs, "cpu_on", PSCI_CPU_ON))
		return -1;
	if (fdt_setprop_u32(dt->blob, offs, "sys_poweroff", PSCI_SYSTEM_OFF))
		return -1;
	if (fdt_setprop_u32(dt->blob, offs, "sys_reset", PSCI_SYSTEM_RESET))
		return -1;
	return 0;
}

static int check_node_compat_prefix(struct dt_descriptor *dt, int offs,
				    const char *prefix)
{
	const size_t prefix_len = strlen(prefix);
	size_t l;
	int plen;
	const char *prop;

	prop = fdt_getprop(dt->blob, offs, "compatible", &plen);
	if (!prop)
		return -1;

	while (plen > 0) {
		if (memcmp(prop, prefix, prefix_len) == 0)
			return 0; /* match */

		l = strlen(prop) + 1;
		prop += l;
		plen -= l;
	}

	return -1;
}

static int dt_add_psci_cpu_enable_methods(struct dt_descriptor *dt)
{
	int offs = 0;

	while (1) {
		offs = fdt_next_node(dt->blob, offs, NULL);
		if (offs < 0)
			break;
		if (fdt_getprop(dt->blob, offs, "enable-method", NULL))
			continue; /* already set */
		if (check_node_compat_prefix(dt, offs, "arm,cortex-a"))
			continue; /* no compatible */
		if (fdt_setprop_string(dt->blob, offs, "enable-method", "psci"))
			return -1;
		/* Need to restart scanning as offsets may have changed */
		offs = 0;
	}
	return 0;
}

static int config_psci(struct dt_descriptor *dt)
{
	if (dt_add_psci_node(dt))
		return -1;
	return dt_add_psci_cpu_enable_methods(dt);
}
#else
static int config_psci(struct dt_descriptor *dt __unused)
{
	return 0;
}
#endif /*CFG_PSCI_ARM32*/

static void set_dt_val(void *data, uint32_t cell_size, uint64_t val)
{
	if (cell_size == 1) {
		fdt32_t v = cpu_to_fdt32((uint32_t)val);

		memcpy(data, &v, sizeof(v));
	} else {
		fdt64_t v = cpu_to_fdt64(val);

		memcpy(data, &v, sizeof(v));
	}
}

static int add_res_mem_dt_node(struct dt_descriptor *dt, const char *name,
			       paddr_t pa, size_t size)
{
	int offs = 0;
	int ret = 0;
	int addr_size = -1;
	int len_size = -1;
	bool found = true;
	char subnode_name[80] = { 0 };

	offs = fdt_path_offset(dt->blob, "/reserved-memory");

	if (offs < 0) {
		found = false;
		offs = 0;
	}

	if (IS_ENABLED(_CFG_USE_DTB_OVERLAY)) {
		len_size = sizeof(paddr_t) / sizeof(uint32_t);
		addr_size = sizeof(paddr_t) / sizeof(uint32_t);
	} else {
		len_size = fdt_size_cells(dt->blob, offs);
		if (len_size < 0)
			return -1;
		addr_size = fdt_address_cells(dt->blob, offs);
		if (addr_size < 0)
			return -1;
	}

	if (!found) {
		offs = add_dt_path_subnode(dt, "/", "reserved-memory");
		if (offs < 0)
			return -1;
		ret = fdt_setprop_cell(dt->blob, offs, "#address-cells",
				       addr_size);
		if (ret < 0)
			return -1;
		ret = fdt_setprop_cell(dt->blob, offs, "#size-cells", len_size);
		if (ret < 0)
			return -1;
		ret = fdt_setprop(dt->blob, offs, "ranges", NULL, 0);
		if (ret < 0)
			return -1;
	}

	ret = snprintf(subnode_name, sizeof(subnode_name),
		       "%s@%" PRIxPA, name, pa);
	if (ret < 0 || ret >= (int)sizeof(subnode_name))
		DMSG("truncated node \"%s@%" PRIxPA"\"", name, pa);
	offs = fdt_add_subnode(dt->blob, offs, subnode_name);
	if (offs >= 0) {
		uint32_t data[FDT_MAX_NCELLS * 2];

		set_dt_val(data, addr_size, pa);
		set_dt_val(data + addr_size, len_size, size);
		ret = fdt_setprop(dt->blob, offs, "reg", data,
				  sizeof(uint32_t) * (addr_size + len_size));
		if (ret < 0)
			return -1;
		ret = fdt_setprop(dt->blob, offs, "no-map", NULL, 0);
		if (ret < 0)
			return -1;
	} else {
		return -1;
	}
	return 0;
}

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

		if (_fdt_get_status(fdt, offs) != (DT_STATUS_OK_NSEC |
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

#ifdef CFG_CORE_RESERVED_SHM
static int mark_static_shm_as_reserved(struct dt_descriptor *dt)
{
	vaddr_t shm_start;
	vaddr_t shm_end;

	core_mmu_get_mem_by_type(MEM_AREA_NSEC_SHM, &shm_start, &shm_end);
	if (shm_start != shm_end)
		return add_res_mem_dt_node(dt, "optee_shm",
					   virt_to_phys((void *)shm_start),
					   shm_end - shm_start);

	DMSG("No SHM configured");
	return -1;
}
#endif /*CFG_CORE_RESERVED_SHM*/

static void init_external_dt(unsigned long phys_dt)
{
	struct dt_descriptor *dt = &external_dt;
	void *fdt;
	int ret;

	if (!phys_dt) {
		/*
		 * No need to panic as we're not using the DT in OP-TEE
		 * yet, we're only adding some nodes for normal world use.
		 * This makes the switch to using DT easier as we can boot
		 * a newer OP-TEE with older boot loaders. Once we start to
		 * initialize devices based on DT we'll likely panic
		 * instead of returning here.
		 */
		IMSG("No non-secure external DT");
		return;
	}

	fdt = core_mmu_add_mapping(MEM_AREA_EXT_DT, phys_dt, CFG_DTB_MAX_SIZE);
	if (!fdt)
		panic("Failed to map external DTB");

	dt->blob = fdt;

	ret = init_dt_overlay(dt, CFG_DTB_MAX_SIZE);
	if (ret < 0) {
		EMSG("Device Tree Overlay init fail @ %#lx: error %d", phys_dt,
		     ret);
		panic();
	}

	ret = fdt_open_into(fdt, fdt, CFG_DTB_MAX_SIZE);
	if (ret < 0) {
		EMSG("Invalid Device Tree at %#lx: error %d", phys_dt, ret);
		panic();
	}

	IMSG("Non-secure external DT found");
}

static int mark_tzdram_as_reserved(struct dt_descriptor *dt)
{
	return add_res_mem_dt_node(dt, "optee_core", CFG_TZDRAM_START,
				   CFG_TZDRAM_SIZE);
}

static void update_external_dt(void)
{
	struct dt_descriptor *dt = &external_dt;

	if (!dt->blob)
		return;

	if (!IS_ENABLED(CFG_CORE_FFA) && add_optee_dt_node(dt))
		panic("Failed to add OP-TEE Device Tree node");

	if (config_psci(dt))
		panic("Failed to config PSCI");

#ifdef CFG_CORE_RESERVED_SHM
	if (mark_static_shm_as_reserved(dt))
		panic("Failed to config non-secure memory");
#endif

	if (mark_tzdram_as_reserved(dt))
		panic("Failed to config secure memory");
}
#else /*CFG_DT*/
void *get_external_dt(void)
{
	return NULL;
}

static void init_external_dt(unsigned long phys_dt __unused)
{
}

static void update_external_dt(void)
{
}

#ifdef CFG_CORE_DYN_SHM
static struct core_mmu_phys_mem *get_nsec_memory(void *fdt __unused,
						 size_t *nelems __unused)
{
	return NULL;
}
#endif /*CFG_CORE_DYN_SHM*/
#endif /*!CFG_DT*/

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

void init_tee_runtime(void)
{
#ifndef CFG_WITH_PAGER
	/* Pager initializes TA RAM early */
	core_mmu_init_ta_ram();
#endif
	/*
	 * With virtualization we call this function when creating the
	 * OP-TEE partition instead.
	 */
	if (!IS_ENABLED(CFG_VIRTUALIZATION))
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
	primary_save_cntfrq();
	init_vfp_sec();
	/*
	 * Pager: init_runtime() calls thread_kernel_enable_vfp() so we must
	 * set a current thread right now to avoid a chicken-and-egg problem
	 * (thread_init_boot_thread() sets the current thread but needs
	 * things set by init_runtime()).
	 */
	thread_get_core_local()->curr_thread = 0;
	init_runtime();

	if (IS_ENABLED(CFG_VIRTUALIZATION)) {
		/*
		 * Virtualization: We can't initialize threads right now because
		 * threads belong to "tee" part and will be initialized
		 * separately per each new virtual guest. So, we'll clear
		 * "curr_thread" and call it done.
		 */
		thread_get_core_local()->curr_thread = -1;
	} else {
		thread_init_boot_thread();
	}
	thread_init_primary();
	thread_init_per_cpu();
	init_sec_mon(nsec_entry);
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area.
 */
void __weak boot_init_primary_late(unsigned long fdt)
{
	init_external_dt(fdt);
	tpm_map_log_area(get_external_dt());
	discover_nsec_memory();
	update_external_dt();
	configure_console_from_dt();

	IMSG("OP-TEE version: %s", core_v_str);
	if (IS_ENABLED(CFG_WARN_INSECURE)) {
		IMSG("WARNING: This OP-TEE configuration might be insecure!");
		IMSG("WARNING: Please check https://optee.readthedocs.io/en/latest/architecture/porting_guidelines.html");
	}
	IMSG("Primary CPU initializing");
#ifdef CFG_CORE_ASLR
	DMSG("Executing at offset %#lx with virtual load address %#"PRIxVA,
	     (unsigned long)boot_mmu_config.load_offset, VCORE_START_VA);
#endif
	if (IS_ENABLED(CFG_MEMTAG))
		DMSG("Memory tagging %s",
		     memtag_is_enabled() ?  "enabled" : "disabled");

	main_init_gic();
	init_vfp_nsec();
	if (IS_ENABLED(CFG_VIRTUALIZATION)) {
		IMSG("Initializing virtualization support");
		core_mmu_init_virtualization();
	} else {
		init_tee_runtime();
	}
	call_finalcalls();
	IMSG("Primary CPU switching to normal world boot");
}

static void init_secondary_helper(unsigned long nsec_entry)
{
	IMSG("Secondary CPU %zu initializing", get_core_pos());

	/*
	 * Mask asynchronous exceptions before switch to the thread vector
	 * as the thread handler requires those to be masked while
	 * executing with the temporary stack. The thread subsystem also
	 * asserts that the foreign interrupts are blocked when using most of
	 * its functions.
	 */
	thread_set_exceptions(THREAD_EXCP_ALL);

	secondary_init_cntfrq();
	thread_init_per_cpu();
	init_sec_mon(nsec_entry);
	main_secondary_init_gic();
	init_vfp_sec();
	init_vfp_nsec();

	IMSG("Secondary CPU %zu switching to normal world boot", get_core_pos());
}

/*
 * Note: this function is weak just to make it possible to exclude it from
 * the unpaged area so that it lies in the init area.
 */
void __weak boot_init_primary_early(unsigned long pageable_part __maybe_unused,
				    unsigned long nsec_entry __maybe_unused)
{
	unsigned long e = PADDR_INVALID;

	init_primary(e);
}

#if defined(CFG_WITH_ARM_TRUSTED_FW)
unsigned long boot_cpu_on_handler(unsigned long a0 __maybe_unused,
				  unsigned long a1 __unused)
{
	init_secondary_helper(PADDR_INVALID);
	return 0;
}
#else
void boot_init_secondary(unsigned long nsec_entry)
{
	init_secondary_helper(nsec_entry);
}
#endif

#if defined(CFG_CORE_ASLR)
#if defined(CFG_DT)
unsigned long __weak get_aslr_seed(void *fdt)
{
	int rc = fdt_check_header(fdt);
	const uint64_t *seed = NULL;
	int offs = 0;
	int len = 0;

	if (rc) {
		DMSG("Bad fdt: %d", rc);
		goto err;
	}

	offs =  fdt_path_offset(fdt, "/secure-chosen");
	if (offs < 0) {
		DMSG("Cannot find /secure-chosen");
		goto err;
	}
	seed = fdt_getprop(fdt, offs, "kaslr-seed", &len);
	if (!seed || len != sizeof(*seed)) {
		DMSG("Cannot find valid kaslr-seed");
		goto err;
	}

	return fdt64_to_cpu(*seed);

err:
	/* Try platform implementation */
	return plat_get_aslr_seed();
}
#else /*!CFG_DT*/
unsigned long __weak get_aslr_seed(void *fdt __unused)
{
	/* Try platform implementation */
	return plat_get_aslr_seed();
}
#endif /*!CFG_DT*/
#endif /*CFG_CORE_ASLR*/

#define SMC_TYPE_FAST                   UL(1)
#define SMC_TYPE_YIELD                  UL(0)

#define FUNCID_TYPE_SHIFT               U(31)
#define FUNCID_TYPE_MASK                U(0x1)

#define GET_SMC_TYPE(id)                (((id) >> FUNCID_TYPE_SHIFT) & \
                                         FUNCID_TYPE_MASK)

#define TEESMC_OPTEED_RV(func_num) \
        OPTEE_SMC_CALL_VAL(OPTEE_SMC_32, OPTEE_SMC_FAST_CALL, \
                           OPTEE_SMC_OWNER_TRUSTED_OS_OPTEED, (func_num))

#define TEESMC_OPTEED_FUNCID_RETURN_CALL_DONE           5
#define TEESMC_OPTEED_RETURN_CALL_DONE \
        TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_RETURN_CALL_DONE)

#define TEESMC_OPTEED_FUNCID_RETURN_ENTRY_DONE          0
#define TEESMC_OPTEED_RETURN_ENTRY_DONE \
        TEESMC_OPTEED_RV(TEESMC_OPTEED_FUNCID_RETURN_ENTRY_DONE)

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
unsigned long DelegatedMainEntry(void *fdt __unused)
{
	int ext; int fid; unsigned long arg0;
	unsigned long arg1; unsigned long arg2;
	unsigned long arg3; unsigned long arg4;
	unsigned long arg5;
	
	//struct rpmi_tee_rx *rx = (struct rpmi_tee_rx *)(&aa);
	// NSEC_SHM 0xf4000000..0xf41fffff pa 0xf1600000..0xf17fffff size 0x00200000 (pgdir)
	struct rpmi_tee *rx = (struct rpmi_tee_rx *)(0xF41F0000);  
	struct rpmi_tee *tx = (struct rpmi_tee_tx *)(0xF41F0000); 

	//read_sstatus();
	EMSG("#### DelegatedMainEntry where the initial sstatus is set ??? %x", read_sstatus());
	ext = 0x52505859;
	fid = 0x01;
	arg0 = 0x00001000;
	arg1 = 0xF17F0000;
	arg2 = 0x0;
	arg3 = 0x0;
	arg4 = 0x0;
	arg5 = 0x0;
	sbi_ecall(ext, fid, arg0, arg1, arg2, arg3, arg4, arg5);

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
	tx->a6 = TEESMC_OPTEED_RETURN_ENTRY_DONE;
	tx->a0 = rpmi_a0;
	tx->a1 = rpmi_a1;
	EMSG("test_switch: TEESMC_OPTEED_RETURN_ENTRY_DONE END %x %x %x %x", arg4, arg5, rpmi_a0, rpmi_a1);
	sbi_ecall(ext, fid, arg0, arg1, arg2, sizeof(struct rpmi_tee), 0, 0);

static int fast_call = 0;
while(1) {
	if (GET_SMC_TYPE(rx->a0) == SMC_TYPE_FAST) {
		EMSG("test_switch: SMC_TYPE_FAST");
			struct thread_smc_args *smc_args = rx;
			thread_handle_fast_smc(smc_args);
		EMSG("test_switch: SMC_TYPE_FAST end");

			ext = 0x52505859;
			fid = 0x02;
			arg0 = 0x0;
			arg1 = 0x0A;
			arg2 = 0x03; // TEESMC_OPTEED_RETURN_CALL_DONE;


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
			tx->a6 = TEESMC_OPTEED_RETURN_CALL_DONE;
			sbi_ecall(ext, fid, arg0, arg1, arg2, sizeof(struct rpmi_tee), 0, 0);
	} else {
		EMSG("test_switch: SMC_STD");
		thread_handle_std_smc(rx->a1, rx->a2, rx->a3, rx->a4, rx->a5, rx->a6, rx->a0, 0x4f505445);
		EMSG("test_switch: SMC_STD EXIT");
		ext = 0x52505859;
		fid = 0x02;
		arg0 = 0x0;
		arg1 = 0x0A;
		arg2 = 0x03; // TEESMC_OPTEED_RETURN_CALL_DONE;
		arg3 = 0x08;

		tx->a1 = rpmi_a1;
		tx->a2 = rpmi_a2;
		tx->a3 = rpmi_a3;
		tx->a4 = rpmi_a4;
		tx->a6 = TEESMC_OPTEED_RETURN_CALL_DONE;


		sbi_ecall(ext, fid, arg0, arg1, arg2, sizeof(struct rpmi_tee), 0, 0);
	}

	}
	return 0;
}

unsigned long DelegatedStdSmcEntry(void *fdt __unused)
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
	EMSG("test_call_done: enter");
	ext = 0x52505859;
	fid = 0x02;
	arg0 = 0x0;
    arg1 = 0x0A;
	arg2 = 0x03;
	tx->a6 = TEESMC_OPTEED_RETURN_CALL_DONE;
	tx->a1 = rpmi_a1;
	tx->a2 = rpmi_a2;
	tx->a3 = rpmi_a3;
	tx->a4 = rpmi_a4;
	sbi_ecall(ext, fid, arg0, arg1, arg2, sizeof(struct rpmi_tee), 0, 0);
	EMSG("test_call_done: debug 1");

	while(1) {
		//struct thread_smc_args *smc_args = rx;
		//EMSG("SMC_TYPE_YIELD before thread_handle_std_smc 0x%x 0x%x 0x%x", rx->a0, rx->a1, rx->a2);
		//EMSG("SMC_TYPE_YIELD before thread_handle_std_smc 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x 0x%x\n", rx->a1, rx->a2, rx->a3, rx->a4, rx->a5, rx->a6, rx->a7, rx->a0);
		EMSG("test_call_done: SMC_STD");
		// thread_handle_std_smc(rx->a0, rx->a1, rx->a2, rx->a3, rx->a4, rx->a5, rx->a6, rx->a7);
		// r0 is ext id
		// r1 is func id 
		thread_handle_std_smc(rx->a1, rx->a2, rx->a3, rx->a4, rx->a5, rx->a6, rx->a0, 0x4f505445);
		EMSG("test_call_done: SMC_STD exit");
		ext = 0x52505859;
		fid = 0x02;
		arg0 = 0x0;
		arg1 = 0x0A;
		arg2 = 0x03; // TEESMC_OPTEED_RETURN_CALL_DONE;
		arg3 = 0x08;

		tx->a6 = TEESMC_OPTEED_RETURN_CALL_DONE;
		tx->a1 = rpmi_a1;
		tx->a2 = rpmi_a2;
		tx->a3 = rpmi_a3;
		tx->a4 = rpmi_a4;

		sbi_ecall(ext, fid, arg0, arg1, arg2, sizeof(struct rpmi_tee), 0, 0);

			//optee_vector_table->yield_smc_entry);
	}
	return 0;
}

unsigned long mm;
unsigned long nn;
unsigned long oo;
unsigned long pp;

unsigned long DelegatedThreadRpcEntry(void *fdt __unused)
{
	int ext; int fid; unsigned long arg0;
	unsigned long arg1; unsigned long arg2;
	unsigned long arg3; unsigned long arg4;
	unsigned long arg5;
	//struct rpmi_tee_rx *rx = (struct rpmi_tee_rx *)(&aa);
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
	// EMSG("TEESMC_OPTEED_RETURN_CALL_DONE");
	ext = 0x52505859;
	fid = 0x02;
	arg0 = 0x0;
    arg1 = 0x0A;
	arg2 = 0x03;
	tx->a1 = mm;
	tx->a2 = nn;
	tx->a3 = oo;
	tx->a4 = pp;
	tx->a6 = TEESMC_OPTEED_RETURN_CALL_DONE;
	EMSG("optee_return_done: enter");
	//EMSG("TEESMC_OPTEED_RETURN_CALL_DONE END %x %x %x %x", tx->a1, tx->a2, tx->a3, tx->a4);
	sbi_ecall(ext, fid, arg0, arg1, arg2, sizeof(struct rpmi_tee), 0, 0);
	EMSG("optee_return_done: exit");

	while(1) {
		EMSG("optee_return_done: SMC_TYPE_STD enter");
		thread_handle_std_smc(rx->a1, rx->a2, rx->a3, rx->a4, rx->a5, rx->a6, rx->a0, 0x4f505445);
		EMSG("optee_return_done: SMC_TYPE_STD enter");
		ext = 0x52505859;
		fid = 0x02;
		arg0 = 0x0;
		arg1 = 0x0A;
		arg2 = 0x03; // TEESMC_OPTEED_RETURN_CALL_DONE;
		arg3 = 0x08;

		tx->a6 = TEESMC_OPTEED_RETURN_CALL_DONE;
		tx->a1 = rpmi_a1;
		tx->a2 = rpmi_a2;
		tx->a3 = rpmi_a3;
		tx->a4 = rpmi_a4;

		sbi_ecall(ext, fid, arg0, arg1, arg2, sizeof(struct rpmi_tee), 0, 0);

			//optee_vector_table->yield_smc_entry);
	}
	return 0;
}
