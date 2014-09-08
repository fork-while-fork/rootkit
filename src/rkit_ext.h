#ifndef __RKIT_EXT_H__
#define __RKIT_EXT_H__

#include <linux/list.h>
#include <net/netlink.h>

struct rkit_ext_ops {
    void (*eval)(struct nlattr **tb);
};

struct rkit_ext_type {
    unsigned int id;
    const struct rkit_ext_ops *ops;
    struct hlist_node node;
    struct module *owner;
    const struct nla_policy *policy;
    unsigned int maxattr;
};

bool rkit_check_id(u16 id);
void rkit_register_ext(struct rkit_ext_type *);
void rkit_unregister_ext(struct rkit_ext_type *);
struct rkit_ext_type *rkit_ext_by_id(unsigned int);
int rkit_ext_parse(struct nlattr **, struct rkit_ext_type *, struct nlattr *);
int rkit_ext_run(struct rkit_ext_type *ext, struct nlattr *attr);

#endif /* __RKIT_EXT_H__ */
