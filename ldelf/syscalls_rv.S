/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2015, Linaro Limited
 * Copyright (c) 2020, Arm Limited
 */

#include <asm.S>

	.section .text

	.macro LDELF_SYSCALL name, scn, num_args
	FUNC \name , :

	.if \num_args > 8
	.error "Too many arguments for syscall"
	.endif

	li	t0, \scn
	ecall
	ret
	END_FUNC \name
	.endm

	FUNC _ldelf_panic, :
		j	__ldelf_panic
	/* Not reached */
	END_FUNC _ldelf_panic

#include "syscalls_asm.S"

