/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016, Linaro Limited
 * Copyright (c) 2014, STMicroelectronics International N.V.
 */
#ifndef __CORE_MMU_ARCH_H
#define __CORE_MMU_ARCH_H

#ifndef __ASSEMBLER__
#include <riscv.h>
#include <assert.h>
#include <compiler.h>
#include <config.h>
#include <kernel/user_ta.h>
#include <mm/tee_mmu_types.h>
#include <types_ext.h>
#include <util.h>
#endif

#include <platform_config.h>

/*
 * Platforms can define TRUSTED_{S,D}RAM_* or TZ{S,D}RAM_*. We're helping
 * here with the transition to TRUSTED_{S,D}RAM_* by defining these if
 * missing based on the legacy defines.
 */
#ifdef TZSRAM_BASE
#ifdef TRUSTED_SRAM_BASE
#error TRUSTED_SRAM_BASE is already defined
#endif
#define TRUSTED_SRAM_BASE	TZSRAM_BASE
#define TRUSTED_SRAM_SIZE	TZSRAM_SIZE
#endif

#ifdef TZDRAM_BASE
#ifdef TRUSTED_DRAM_BASE
#error TRUSTED_DRAM_BASE is already defined
#endif
#define TRUSTED_DRAM_BASE	TZDRAM_BASE
#define TRUSTED_DRAM_SIZE	TZDRAM_SIZE
#endif

#define SMALL_PAGE_SHIFT	U(12)


#define CORE_MMU_PGDIR_SHIFT	U(21)
#define CORE_MMU_PGDIR_LEVEL	U(3)

#define CORE_MMU_USER_CODE_SHIFT	SMALL_PAGE_SHIFT

#define CORE_MMU_USER_PARAM_SHIFT	SMALL_PAGE_SHIFT

/*
 * Level of base table (i.e. first level of page table),
 * depending on address space
 */
#if !defined(CFG_WITH_LPAE) || (CFG_LPAE_ADDR_SPACE_BITS < 40)
#define CORE_MMU_BASE_TABLE_SHIFT	U(30)
#define CORE_MMU_BASE_TABLE_LEVEL	U(1)
#else /* (CFG_LPAE_ADDR_SPACE_BITS > 39) */
#error "CFG_WITH_LPAE with CFG_LPAE_ADDR_SPACE_BITS > 39 isn't supported!"
#endif

/*
 * CORE_MMU_BASE_TABLE_OFFSET is used when switching to/from reduced kernel
 * mapping. The actual value depends on internals in core_mmu_lpae.c which
 * we rather not expose here. There's a compile time assertion to check
 * that these magic numbers are correct.
 */
#define CORE_MMU_BASE_TABLE_OFFSET \
	(CFG_TEE_CORE_NB_CORE * \
	 BIT(CFG_LPAE_ADDR_SPACE_BITS - CORE_MMU_BASE_TABLE_SHIFT) * \
	 U(8))
/*
 * TEE_RAM_VA_START:            The start virtual address of the TEE RAM
 * TEE_TEXT_VA_START:           The start virtual address of the OP-TEE text
 */

/*
 * Identify mapping constraint: virtual base address is the physical start addr.
 * If platform did not set some macros, some get default value.
 */
#ifndef TEE_RAM_VA_SIZE
#define TEE_RAM_VA_SIZE			CORE_MMU_PGDIR_SIZE
#endif

#ifndef TEE_LOAD_ADDR
#define TEE_LOAD_ADDR			TEE_RAM_START
#endif

#define TEE_RAM_VA_START		TEE_RAM_START
#define TEE_TEXT_VA_START		(TEE_RAM_VA_START + \
					 (TEE_LOAD_ADDR - TEE_RAM_START))

#ifndef STACK_ALIGNMENT
#define STACK_ALIGNMENT			(sizeof(long) * U(2))
#endif

#ifndef __ASSEMBLER__

/*
 * Assembly code in enable_mmu() depends on the layout of this struct.
 */
struct core_mmu_config {
	uint64_t ttbr_base;
	uint64_t ttbr_core_offset;
	uint64_t load_offset;	
};

/*
 * struct core_mmu_user_map - current user mapping register state
 * @user_map:	physical address of user map translation table
 * @asid:	ASID for the user map
 *
 * Note that this struct should be treated as an opaque struct since
 * the content depends on descriptor table format.
 */
struct core_mmu_user_map {
	uint64_t user_map;
	uint32_t asid;
};

bool core_mmu_user_va_range_is_defined(void);

/* Cache maintenance operation type */
enum cache_op {
	DCACHE_CLEAN,
	DCACHE_AREA_CLEAN,
	DCACHE_INVALIDATE,
	DCACHE_AREA_INVALIDATE,
	ICACHE_INVALIDATE,
	ICACHE_AREA_INVALIDATE,
	DCACHE_CLEAN_INV,
	DCACHE_AREA_CLEAN_INV,
};

/* L1/L2 cache maintenance */
TEE_Result cache_op_inner(enum cache_op op, void *va, size_t len);

static inline TEE_Result cache_op_outer(enum cache_op op __unused,
					paddr_t pa __unused,
					size_t len __unused)
{
	/* Nothing to do about L2 Cache Maintenance when no PL310 */
	return TEE_SUCCESS;
}

/* Do section mapping, not support on LPAE */
void map_memarea_sections(const struct tee_mmap_region *mm, uint32_t *ttb);

static inline bool core_mmu_check_max_pa(paddr_t pa __maybe_unused)
{
	return pa <= (BIT64(39) - 1);
}

/*
 * Special barrier to make sure all the changes to translation tables are
 * visible before returning.
 */
static inline void core_mmu_table_write_barrier(void)
{
	asm volatile("sfence.vma");
}

static inline bool core_mmu_entry_have_security_bit(uint32_t attr)
{
	return !(attr & TEE_MATTR_TABLE);
}

static inline unsigned int core_mmu_get_va_width(void)
{
	return 39;
}
#endif /*__ASSEMBLER__*/

#endif /* CORE_MMU_H */
