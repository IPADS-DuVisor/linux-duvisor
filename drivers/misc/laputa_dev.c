#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/miscdevice.h>
#include <uapi/misc/laputa_dev.h>

static long laputa_dev_ioctl(struct file* file,
        unsigned int cmd, unsigned long arg)
{
    int rc;
    void __user *uarg = (void __user *) arg;

    switch (cmd) {
        case IOCTL_LAPUTA_GET_API_VERSION: {
            unsigned long version;
            pr_info("%s:%d IOCTL_LAPUTA_GET_API_VERSION\n", __func__, __LINE__);
            
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
            
            rc = -EFAULT;
            if (copy_from_user(&sm_info, uarg, sizeof(sm_info)))
                break;
            pr_info("%s:%d IOCTL_LAPUTA_REGISTER_SHARED_MEM base_uaddr = %lx "
                    "mem_size = %lx\n", __func__, __LINE__, sm_info[0], sm_info[1]);
            /* TODO: record the shared memory in task_struct */
            
            rc = 0;
            break;
        }

        case IOCTL_LAPUTA_REQUEST_DELEG: {
            /* [0] e-deleg [1] i-deleg */
            unsigned long deleg_info[2];
            
            rc = -EFAULT;
            if (copy_from_user(&deleg_info, uarg, sizeof(deleg_info)))
                break;
            pr_info("%s:%d IOCTL_LAPUTA_REGISTER_SHARED_MEM edeleg = %lx "
                    "ideleg = %lx\n", __func__, __LINE__, deleg_info[0], deleg_info[1]);
            /* TODO: set deleg field in task_struct */
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
    pr_info("%s:%d tgid = %d\n", __func__, __LINE__, task_tgid_vnr(current));
    return 0;
}

static int laputa_dev_release(struct inode *inode, struct file *filep)
{
    /* TODO: clean up data structures for current process */
    pr_info("%s:%d tgid = %d\n", __func__, __LINE__, task_tgid_vnr(current));
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
