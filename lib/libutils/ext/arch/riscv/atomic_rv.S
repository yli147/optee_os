/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015-2016, Linaro Limited
 */

#include <asm.S>


/* uint32_t atomic_inc32(uint32_t *v); */
FUNC atomic_inc32 , :
retry_inc:
	lr.w a1, (a0)
	add	a1, a1, 1
	sc.w a2, a1, (a0)
	bnez a2, retry_inc
	mv	a0, a1
	ret
END_FUNC atomic_inc32

/* uint32_t atomic_dec32(uint32_t *v); */
FUNC atomic_dec32 , :
retry_dec:
	lr.w a1, (a0)
	add	a1, a1, -1
	sc.w a2, a1, (a0)
	bnez a2, retry_dec
	mv	a0, a1
	ret
END_FUNC atomic_dec32
