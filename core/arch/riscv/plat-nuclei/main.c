// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright 2022 NXP
 */
#include <io.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>
#include "stdio.h"

/*debug only hart0 S mode*/
#define PLIC_CLAIM_BASE 0x1c201000
#define PLIC_CLAIM_SIZE 0x1000
extern void sbi_console_putchar(int ch);
register_phys_mem_pgdir(MEM_AREA_IO_SEC, PLIC_CLAIM_BASE, PLIC_CLAIM_SIZE);
static volatile vaddr_t plic_claim_base = 0;
void itr_core_handler(void)
{
    int id;

    sbi_console_putchar('@');
    if (plic_claim_base == 0)
        plic_claim_base = core_mmu_get_va(PLIC_CLAIM_BASE, MEM_AREA_IO_SEC,
                    PLIC_CLAIM_SIZE);
    /*claim*/
    id = io_read32(plic_claim_base + 4);
    if (id == 38 || id == 39) {
        static volatile vaddr_t timer_base = 0;

        if (timer_base ==0)
            timer_base = core_mmu_get_va(0x10012000, MEM_AREA_IO_SEC,
                    0x1000);
        *(volatile unsigned int*)timer_base = 300000000;
        *(volatile unsigned int*)(timer_base +4) = (unsigned int)(-1);
/*         if (id == 38) {
            *(volatile unsigned int*)timer_base = (unsigned int)(-1);
            *(volatile unsigned int*)(timer_base +4) = 500000000;
        } else if (id == 39) {
            *(volatile unsigned int*)timer_base = 500000000;
            *(volatile unsigned int*)(timer_base +4) = (unsigned int)(-1);
        } */
    }
    /*complete*/
    io_write32(plic_claim_base + 4, id);
}
