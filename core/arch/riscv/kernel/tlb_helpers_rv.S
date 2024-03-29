/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022 NXP
 */

#include <riscv.h>
#include <asm.S>
#include <util.h>

/* void tlbi_all(void); */
FUNC tlbi_all , :
	sfence.vma	zero, zero
	ret
END_FUNC tlbi_all

/* void tlbi_mva_allasid(vaddr_t mva); */
FUNC tlbi_mva_allasid , :
	sfence.vma	a0, zero
	ret
END_FUNC tlbi_mva_allasid

/* void tlbi_asid(unsigned int asid); */
FUNC tlbi_asid , :
	sfence.vma	zero, a0
	ret
END_FUNC tlbi_asid

/* void tlbi_asid(vaddr_t mva, unsigned int asid); */
FUNC tlbi_mva_asid , :
	sfence.vma	a0, a1
	ret
END_FUNC tlbi_mva_asid
