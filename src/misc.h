#ifndef __RKIT_MISC_H__
#define __RKIT_MISC_H__
#include <linux/version.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 13, 0)
#define HOOK_ARG_TYPE const struct nf_hook_ops *
#else
#define HOOK_ARG_TYPE unsigned int
#endif

#endif /* __RKIT_MISC_H__ */
