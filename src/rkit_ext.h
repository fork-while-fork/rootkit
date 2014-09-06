#ifndef __RKIT_EXT_H__
#define __RKIT_EXT_H__

#include <linux/list.h>
#include <net/netlink.h>

struct rkit_ext_ops {
    void (*eval)(const struct nlattr * const tb[]);
};

struct rkit_ext_type {
    unsigned int id;
    const struct rkit_ext_ops *ops;
    struct hlist_node node;
    struct module *owner;
    const struct nla_policy *policy;
    unsigned int maxattr;
};

void rkit_register_ext(struct rkit_ext_type *);
void rkit_unregister_ext(struct rkit_ext_type *);

#endif /* __RKIT_EXT_H__ */
