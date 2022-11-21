/*
 * Copyright (c) 2017, Linaro Limited. All rights reserved.
 * Copyright (c) 2013-2014, ARM Limited and Contributors. All rights reserved.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <riscv.h>
#include <asm.S>

	/* ------------------------------------------
	 * Clean+Invalidate from base address till
	 * size. 'x0' = addr, 'x1' = size
	 * ------------------------------------------
	 */
FUNC dcache_cleaninv_range , :
	ret	
	//do_dcache_maintenance_by_mva civac
END_FUNC dcache_cleaninv_range

	/* ------------------------------------------
	 * Clean from base address till size.
	 * 'x0' = addr, 'x1' = size
	 * ------------------------------------------
	 */
FUNC dcache_clean_range , :
	//do_dcache_maintenance_by_mva cvac
END_FUNC dcache_clean_range

	/* ------------------------------------------
	 * Invalidate from base address till
	 * size. 'x0' = addr, 'x1' = size
	 * ------------------------------------------
	 */
FUNC dcache_inv_range , :
	//do_dcache_maintenance_by_mva ivac
END_FUNC dcache_inv_range

	/* ------------------------------------------
	 * Clean from base address till size to point of unification
	 * 'x0' = addr, 'x1' = size
	 * ------------------------------------------
	 */
FUNC dcache_clean_range_pou , :
	//do_dcache_maintenance_by_mva cvau
END_FUNC dcache_clean_range_pou

FUNC dcache_op_louis , :
//	dcsw_op #CLIDR_LOUIS_SHIFT, #CLIDR_FIELD_WIDTH, #CSSELR_LEVEL_SHIFT
END_FUNC dcache_op_louis

FUNC dcache_op_all , :
//	dcsw_op #CLIDR_LOC_SHIFT, #CLIDR_FIELD_WIDTH, #CSSELR_LEVEL_SHIFT
END_FUNC dcache_op_all


FUNC icache_inv_all , :
END_FUNC icache_inv_all

FUNC icache_inv_range , :
END_FUNC icache_inv_range

