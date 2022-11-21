// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2021, Huawei Technology Co., Ltd
 */

#include <riscv.h>
#include <kernel/panic.h>

void cpu_idle(void)
{
	//dsb();
	mb();
	wfi();
}
