/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright 2022-2023 NXP
 * Copyright 2024 Andes Technology
 *
 * Brief   Andes AE350 platform configuration.
 */

#ifndef PLATFORM_CONFIG_H
#define PLATFORM_CONFIG_H

#include <mm/generic_ram_layout.h>

/* The stack pointer is always kept 16-byte aligned */
#define STACK_ALIGNMENT		16

/* DRAM */
#ifndef DRAM_BASE
#define DRAM_BASE		0x00000000
#define DRAM_SIZE		0x80000000
#endif

/* PLIC */
#ifndef PLIC_BASE
#define PLIC_BASE		0xe4000000
#define PLIC_REG_SIZE		0x600000
#define PLIC_NUM_SOURCES	0x47
#endif

/* UART */
#ifndef UART2_BASE
#define UART2_BASE		0xF0300000
#define UART2_REG_SHIFT		0x2
#define UART2_REG_OFFSET	0x20
#endif
#define UART2_IRQ		0x09

/* Foreign interrupt */
#define FOREIGN_IRQ             0x0f

/* RTC */
#ifndef RTC_BASE
#define RTC_BASE		0xF0600000
#endif
#define RTC_IRQ			0x02

#ifdef CFG_RISCV_MTIME_RATE
#define RISCV_MTIME_RATE CFG_RISCV_MTIME_RATE
#else
#define RISCV_MTIME_RATE 1000000
#endif

#endif /*PLATFORM_CONFIG_H*/
