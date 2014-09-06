#include <linux/spinlock.h>
#include "rkit_ext.h"

static DEFINE_SPINLOCK(rkit_ext_mutex);
static LIST_HEAD(rkit_extensions);

static void rkit_ext_lock(void)
{
    spin_lock_bh(&rkit_ext_mutex);
}

static void rkit_ext_unlock(void)
{
    spin_unlock_bh(&rkit_ext_mutex);
}

void rkit_register_ext(struct rkit_ext_type *ext)
{
    rkit_ext_lock();
    list_add(&ext->list, &rkit_extensions);
    rkit_ext_unlock();
}

void rkit_unregister_ext(struct rkit_ext_type *ext)
{
    rkit_ext_lock();
    list_del(&ext->list);
    rkit_ext_unlock();
}

