// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2024 Andes Technology Corporation
 */

#include <kernel/misc.h>
#include <mm/core_memprot.h>
#include <mm/core_mmu.h>
#include <riscv.h>
#include <sbi.h>
#include <string.h>
#include <types_ext.h>
#include <util.h>

struct optee_msg_payload {
	unsigned long data[5];	/* a0~a4 */
};

struct sbi_rpxy {
	struct io_pa_va shmem_base;
	bool active;
};

static struct sbi_rpxy sbi_rpxy_hart_data[CFG_TEE_CORE_NB_CORE];

vaddr_t sbi_rpxy_get_shmem(void)
{
	uint32_t exceptions = thread_mask_exceptions(THREAD_EXCP_ALL);
	struct sbi_rpxy *rpxy = &sbi_rpxy_hart_data[get_core_pos()];
	thread_unmask_exceptions(exceptions);

	assert(rpxy->active);

	return rpxy->shmem_base.va;
}

int sbi_rpxy_setup_shmem(unsigned int hartid)
{
	struct sbiret ret = { };
	struct sbi_rpxy *rpxy = &sbi_rpxy_hart_data[hartid];
	void *shmem = NULL;

	if (rpxy->active) {
		return SBI_ERR_FAILURE;
	}

	/* Allocate 4 KiB memory aligend with 4 KiB (required by SBI RPXY). */
	shmem = memalign(SMALL_PAGE_SIZE, SMALL_PAGE_SIZE);
	if (!shmem) {
		EMSG("Allocate RPXY shared memory fail");
		return SBI_ERR_FAILURE;
	}
	rpxy->shmem_base.va = (vaddr_t)shmem;
	rpxy->shmem_base.pa = virt_to_phys(shmem);

	ret = sbi_ecall(SBI_EXT_RPXY, SBI_EXT_RPXY_SETUP_SHMEM,
			SMALL_PAGE_SIZE, rpxy->shmem_base.pa, 0, 0);
	if (ret.error) {
		EMSG("Setup RPXY shared memory for hart %d error %ld",
		     hartid, ret.error);
		return SBI_ERR_FAILURE;
	}

	rpxy->active = true;

	EMSG("Setup RPXY shared memory for hart %d OK, PA: 0x%lX, VA: 0x%lX\n",
	     hartid, rpxy->shmem_base.pa, rpxy->shmem_base.va);

	return SBI_SUCCESS;
}

int sbi_rpxy_send_normal_message(uint32_t transportid,
				 uint32_t srvgrpid, uint8_t srvid,
				 void *tx, unsigned long tx_msglen,
				 void *rx, unsigned long *rx_msglen)
{
	struct sbiret ret = { };
	struct sbi_rpxy *rpxy = NULL;

	thread_mask_exceptions(THREAD_EXCP_ALL);
	rpxy = &sbi_rpxy_hart_data[get_core_pos()];

	if (tx_msglen) {
		memcpy((void *)rpxy->shmem_base.va, tx, tx_msglen);
	}

	ret = sbi_ecall(SBI_EXT_RPXY, SBI_EXT_RPXY_SEND_NORMAL_MSG, transportid,
			srvgrpid, srvid, tx_msglen, 0, 0);

	if (!ret.error && rx) {
		memcpy(rx, (void *)rpxy->shmem_base.va, ret.value);
		if (rx_msglen) {
			*rx_msglen = ret.value;
		}
	}

	return ret.error;
}

void thread_return_to_udomain_by_rpxy(unsigned long arg0, unsigned long arg1,
				      unsigned long arg2, unsigned long arg3,
				      unsigned long arg4,
				      unsigned long arg5 __unused)
{
	struct optee_msg_payload optee_msg = {
		.data = {arg0, arg1, arg2, arg3, arg4},
	};

	sbi_rpxy_send_normal_message(0x10000, 0x01, 0x02,
				     &optee_msg, sizeof(optee_msg), NULL, NULL);
}
