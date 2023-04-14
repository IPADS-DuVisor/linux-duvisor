#include <linux/kernel.h>
#include <linux/module.h>

static int cmd = 0;
static int arg = 0;

module_param(cmd, int, S_IRUGO);
module_param(arg, int, S_IRUGO);

extern void *vinterrupts_mmio;
#define MIN(a, b) ((a) < (b) ? (a) : (b))

static void test_write_irq(void)
{
        pr_info("[debug] %s:%d ", __func__, __LINE__);
}

static int __init breakdown_init(void)
{

        pr_info("%s", __func__);
        switch (cmd)
        {
        case 0:
                test_write_irq();
                break;
        default:
                pr_err("unexpected cmd:%d", cmd);
        }
        return 0;
}

static void __exit breakdown_exit(void)
{
        pr_info("%s", __func__);
}

module_init(breakdown_init)
module_exit(breakdown_exit)
MODULE_LICENSE("GPL");

