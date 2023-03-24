// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2023. Nuclei Tech.
 */

#include <drivers/gic.h>
#include <io.h>
#include <kernel/interrupt.h>
#include <kernel/misc.h>
#include <kernel/pseudo_ta.h>
#include <trace.h>
#include <mm/core_mmu.h>
#include <mm/core_memprot.h>

#define SEC_TIMER_SERVICE_UUID \
		{ 0x6272636D, 0x2019, 0x0801,  \
		{ 0x42, 0x43, 0x4D, 0x5F, 0x57, 0x44, 0x54, 0x30 } }

#define PTA_NUCLEI_SEC_TIMER_CMD_SET_TIMEOUT	1
#define PTA_NUCLEI_SEC_TIMER_CMD_STOP			2

#define SEC_TIMER_TA_NAME		"pta_nuclei_sec_timer.ta"

#define SEC_TIMER_BASE 0x10012000
#define SEC_TIMER_SIZE 0x1000

register_phys_mem_pgdir(MEM_AREA_IO_SEC, SEC_TIMER_BASE, SEC_TIMER_SIZE);
static	volatile    vaddr_t timer_base = 0;
static TEE_Result pta_timer_set_timeout(uint32_t param_types,
				     TEE_Param params[TEE_NUM_PARAMS])
{

	uint32_t timeout1 = 0;
	uint32_t timeout2 = 0;

	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_VALUE_INPUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	timeout1 = params[0].value.a;
	timeout2 = params[1].value.a;
	if (timer_base == 0)
		timer_base = core_mmu_get_va(SEC_TIMER_BASE, MEM_AREA_IO_SEC,
	                   SEC_TIMER_SIZE);
	
	*(volatile unsigned int*)timer_base = timeout1;
	*(volatile unsigned int*)(timer_base + 1) = timeout2;

	return TEE_SUCCESS;
}

static TEE_Result pta_timer_stop(uint32_t param_types,
				     TEE_Param params[TEE_NUM_PARAMS])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	if (exp_param_types != param_types) {
		EMSG("Invalid Param types");
		return TEE_ERROR_BAD_PARAMETERS;
	}

	if (timer_base == 0)
		timer_base = core_mmu_get_va(SEC_TIMER_BASE, MEM_AREA_IO_SEC,
	                   SEC_TIMER_SIZE);
	
	*(volatile unsigned int*)timer_base = (unsigned int)-1;
	*(volatile unsigned int*)(timer_base + 1) = (unsigned int)-1;

	return TEE_SUCCESS;
}

static TEE_Result invoke_command(void *session_context __unused,
				 uint32_t cmd_id,
				 uint32_t param_types,
				 TEE_Param params[TEE_NUM_PARAMS])
{
	TEE_Result res = TEE_SUCCESS;

	DMSG("command entry point[%d] for \"%s\"", cmd_id, SEC_TIMER_TA_NAME);

	switch (cmd_id) {
	case PTA_NUCLEI_SEC_TIMER_CMD_SET_TIMEOUT:
		res = pta_timer_set_timeout(param_types, params);
		break;
	case PTA_NUCLEI_SEC_TIMER_CMD_STOP:
		res = pta_timer_stop(param_types, params);
		break;
	default:
		EMSG("cmd: %d Not supported %s", cmd_id, SEC_TIMER_TA_NAME);
		res = TEE_ERROR_NOT_SUPPORTED;
		break;
	}

	return res;
}

pseudo_ta_register(.uuid = SEC_TIMER_SERVICE_UUID,
		   .name = SEC_TIMER_TA_NAME,
		   .flags = PTA_DEFAULT_FLAGS,
		   .invoke_command_entry_point = invoke_command);
