ifeq ($(CFG_WITH_USER_TA),y)
srcs-y += arch_svc_a64.S
srcs-$(CFG_CACHE_API) += svc_cache.c
srcs-y += arch_svc.c
endif
ifneq ($(CFG_CORE_FFA),y)
srcs-y += entry_fast.c
cppflags-entry_fast.c-y += -DTEE_IMPL_GIT_SHA1=$(TEE_IMPL_GIT_SHA1)
endif
srcs-y += cache.c
