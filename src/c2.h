#ifndef __C2_H__
#include <linux/version.h>
#include <linux/kernel.h>

void c2_init(void);
void c2_exit(void);

struct c2hdr {
    __u8 nonce[20];
    struct nlattr *attr;
};

#endif /* __C2_H__ */
