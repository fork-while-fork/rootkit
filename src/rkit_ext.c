#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/netlink.h>

#include "rkit_ext.h"

static DEFINE_SPINLOCK(rkit_ext_mutex);
static DEFINE_HASHTABLE(rkit_extensions, 8);

static void rkit_ext_lock(void)
{
    spin_lock_bh(&rkit_ext_mutex);
}

static void rkit_ext_unlock(void)
{
    spin_unlock_bh(&rkit_ext_mutex);
}

static unsigned int rkit_gen_id = 0;

static void rkit_hash_add(struct rkit_ext_type *ext)
{
    ext->id = ++rkit_gen_id;
    rkit_ext_lock();
    hlist_add_head(&ext->node, &rkit_extensions[ext->id % HASH_SIZE(rkit_extensions)]);
    rkit_ext_unlock();
}

static void rkit_hash_del(struct rkit_ext_type *ext)
{
    rkit_ext_lock();
    hlist_del_init(&ext->node);
    rkit_ext_unlock();
}

void rkit_register_ext(struct rkit_ext_type *ext)
{
    rkit_hash_add(ext);
}

void rkit_unregister_ext(struct rkit_ext_type *ext)
{
    rkit_hash_del(ext);
}

struct rkit_ext_type *rkit_ext_by_id(unsigned int id)
{
    unsigned int hash = id % HASH_SIZE(rkit_extensions);
    struct rkit_ext_type *ext = NULL;

    rkit_ext_lock();
    hlist_for_each_entry(ext, &rkit_extensions[hash], node) {
        if (ext->id == id) {
            rkit_ext_unlock();
            return ext;
        }
    }
    rkit_ext_unlock();

    return NULL;
}

int rkit_ext_parse(struct nlattr **tb, struct rkit_ext_type *ext, struct nlattr *attr)
{
    err = nla_parse_nested(tb, ext->maxattr, attr, ext->policy);
}

