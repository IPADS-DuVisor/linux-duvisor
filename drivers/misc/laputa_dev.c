#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <uapi/misc/laputa_dev.h>

#include <asm/ulh.h>
#include <asm/csr.h>

static long laputa_dev_ioctl(struct file* file,
        unsigned int cmd, unsigned long arg)
{
    int rc;
    void __user *uarg = (void __user *) arg;

    switch (cmd) {
        case IOCTL_LAPUTA_GET_API_VERSION: {
            unsigned long version;
            pr_info("IOCTL_LAPUTA_GET_API_VERSION\n");
            
            rc = -EFAULT;
            version = 0x12345678;
            if (copy_to_user((unsigned long *)uarg, &version, sizeof(version)))
                break;
            
            rc = 0;
            break;
        }

        case IOCTL_LAPUTA_REGISTER_SHARED_MEM: {
            /* [0] base_uaddr [1] mem_size */
            unsigned long sm_info[2];
            pid_t tgid = current->tgid;
            struct ulh_data *ud = current->group_leader->ulh_data;

            rc = -EPERM;
            if (!ud) break;
            
            rc = -EFAULT;
            if (copy_from_user(&sm_info, uarg, sizeof(sm_info)))
                break;
            pr_info("IOCTL_LAPUTA_REGISTER_SHARED_MEM "
                    "tgid: %d, base_uaddr: %lx, mem_size: %lx\n", 
                    tgid, sm_info[0], sm_info[1]);
            /* TODO: xlat uaddr to kaddr */
            ud->sm_base_addr = sm_info[0];
            ud->sm_size = sm_info[1];

            rc = 0;
            break;
        }

        case IOCTL_LAPUTA_REQUEST_DELEG: {
            /* [0] e-deleg [1] i-deleg */
            unsigned long deleg_info[2];
            pid_t tgid = current->tgid;
            struct ulh_data *ud = current->group_leader->ulh_data;
            unsigned long e_mask, i_mask;

            rc = -EPERM;
            if (!ud) break;
            
            rc = -EFAULT;
            if (copy_from_user(&deleg_info, uarg, sizeof(deleg_info)))
                break;
            pr_info("IOCTL_LAPUTA_REQUEST_DELEG "
                    "tgid: %d, edeleg: %lx, ideleg: %lx\n", 
                    tgid, deleg_info[0], deleg_info[1]);

            e_mask = (1UL << EXC_INST_MISALIGNED)
                | (1UL << EXC_INST_ACCESS)
                | (1UL << EXC_ILLEGAL_INST)
                | (1UL << EXC_BREAKPOINT)
                | (1UL << EXC_LOAD_ADDR_MISALIGNED)
                | (1UL << EXC_LOAD_ACCESS)
                | (1UL << EXC_STORE_ADDR_MISALIGNED)
                | (1UL << EXC_STORE_ACCESS)
                | (1UL << EXC_SYSCALL)
                | (1UL << EXC_INST_PAGE_FAULT)
                | (1UL << EXC_LOAD_PAGE_FAULT)
                | (1UL << EXC_STORE_PAGE_FAULT)
                | (1UL << EXC_INST_GUEST_PAGE_FAULT)
                | (1UL << EXC_LOAD_GUEST_PAGE_FAULT)
                | (1UL << EXC_VIRT_INST)
                | (1UL << EXC_STORE_GUEST_PAGE_FAULT);

            i_mask = (1UL << IRQ_VS_SOFT)
                | (1UL << IRQ_VS_TIMER)
                | (1UL << IRQ_VS_EXT);

            if (deleg_info[0] & ~e_mask) {
                pr_err("%s:%d invalid exception delegation: %lx\n", 
                        __func__, __LINE__, deleg_info[0] & ~e_mask);
                rc = -EPERM;
                break;
            }
            if (deleg_info[1] & ~i_mask) {
                pr_err("%s:%d invalid interrupt delegation: %lx\n", 
                        __func__, __LINE__, deleg_info[1] & ~i_mask);
                rc = -EPERM;
                break;
            }

            ud->sedeleg = deleg_info[0];
            ud->sideleg = deleg_info[1];
            csr_write(CSR_SEDELEG, ud->sedeleg);
            csr_write(CSR_SIDELEG, ud->sideleg);
            
            rc = 0;
            break;
        }

        default:
            rc = -ENOSYS;
            break;
    }

    return rc;
}

static int laputa_dev_open(struct inode *inode, struct file *filep)
{
    /* TODO: set up data structures for current process */
    pid_t tgid = current->tgid;
    if (current->group_leader->ulh_data) {
        pr_err("%s:%d tgid = %d ulh_data NOT NULL!\n", __func__, __LINE__, tgid);
        return -EPERM;
    }
    current->group_leader->ulh_data = kzalloc(sizeof(struct ulh_data), GFP_KERNEL);
    pr_info("%s:%d tgid = %d\n", __func__, __LINE__, tgid);
    return 0;
}

static int laputa_dev_release(struct inode *inode, struct file *filep)
{
    /* TODO: clean up data structures for current process */
    pid_t tgid = current->tgid;
    if (!current->group_leader->ulh_data) {
        pr_err("%s:%d tgid = %d ulh_data is NULL!\n", __func__, __LINE__, tgid);
        return -EPERM;
    }
    kfree(current->group_leader->ulh_data);
    current->group_leader->ulh_data = NULL;
    pr_info("%s:%d tgid = %d\n", __func__, __LINE__, tgid);
    return 0;
}

static const struct file_operations laputa_fops = {
    .owner          = THIS_MODULE,
    .read           = NULL,
    .write          = NULL,
    .unlocked_ioctl = laputa_dev_ioctl,
    .open           = laputa_dev_open,
    .release        = laputa_dev_release,
};

static struct miscdevice laputa_miscdev = {
    .minor          = MISC_DYNAMIC_MINOR,
    .name           = "ulh/laputa_dev",
    .fops           = &laputa_fops,
};

static int __init laputa_dev_init(void)
{
    int err;
    err = misc_register(&laputa_miscdev);
    if (err != 0) {
        pr_err("Could not register /dev/ulh/laputa_dev\n");
        return err;
    }

    pr_info("ULH: laputa device installed\n");

    return 0;
}

static void __exit laputa_dev_cleanup(void)
{
    misc_deregister(&laputa_miscdev);
}

module_init(laputa_dev_init);
module_exit(laputa_dev_cleanup);

MODULE_LICENSE("GPL");
