#include <linux/spinlock.h>
#include <linux/hashtable.h>
#include <linux/netlink.h>

#include "rkit_ext.h"

#define RKIT_GEN_BASE 0x0000
#define RKIT_GEN_MAX  0x000F

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

static unsigned int rkit_gen_id = RKIT_GEN_BASE;

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
    return nla_parse_nested(tb, ext->maxattr, attr, ext->policy);
}

int rkit_ext_run(struct rkit_ext_type *ext, struct nlattr *attr)
{
    struct nlattr **tb = kmalloc(sizeof(struct nlattr *) * ext->maxattr, GFP_KERNEL);
    int err;

    err = rkit_ext_parse(tb, ext, attr);

    return err;
}

bool rkit_check_id(u16 id) 
{
    return (id > RKIT_GEN_BASE);
}

