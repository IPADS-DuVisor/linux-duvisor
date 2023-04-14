#include <linux/module.h>
#include <linux/mm.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/sched/task_stack.h>
#include <linux/miscdevice.h>
#include <linux/dma-map-ops.h>
#include <uapi/misc/dv_driver.h>

#include <asm/ulh.h>
#include <asm/csr.h>
#include <asm/hwcap.h>
#include <asm/processor.h>
#include <asm/sbi.h>

static struct miscdevice duvisor_miscdev;
extern unsigned long *vinterrupts_mmio;

static int dv_driver_mmap(struct file *file, struct vm_area_struct *vma)
{
    size_t size = vma->vm_end - vma->vm_start;
    struct page *cma_pages = NULL;
    void *mem = NULL;
    struct ulh_vm_data *vm_dat = current->group_leader->ulh_vm_data;
    struct ulh_vm_mem *mem_info = NULL;

    static int pmp_cnt = 0;

    unsigned long pmp_addr = 0;
    
    if (vma->vm_pgoff != 0)
        return -EINVAL;

    /* TODO: check the size of mmap */

    if (!(cma_pages = dma_alloc_contiguous(duvisor_miscdev.this_device, 
                    size, GFP_KERNEL))) {
        return -ENOMEM;
    }

    pr_info("**********\n");
    pr_info("***DuVisor want PMP: 0x%lx, pmp_cnt: %d\n", size, ++pmp_cnt);
    pr_info("**********\n");

    mem = page_to_virt(cma_pages);

    pmp_addr = page_to_phys(cma_pages);
    pr_info("******Call M mode for vPMP********");
    sbi_ecall(0x9, 0x0, pmp_addr, size, 0x0, 0x0, 0x0, 0x0);
    pr_info("******Finish M mode for vPMP********");
    
    if (remap_pfn_range(vma, vma->vm_start,
                virt_to_pfn(mem),
                size, vma->vm_page_prot)) {
        dma_free_contiguous(duvisor_miscdev.this_device, cma_pages, size);
        return -EAGAIN;
    }

    mem_info = kmalloc(sizeof(struct ulh_vm_mem), GFP_KERNEL);
    mem_info->size = size;
    mem_info->uaddr = vma->vm_start;
    mem_info->kaddr = mem;
    mem_info->pfn = virt_to_pfn(mem);

#if 0

    // map vinterrupt if size is 0x1000
    if (size == 0x10000) {
        mem_info->kaddr = vinterrupts_mmio;
        mem_info->pfn = virt_to_pfn(vinterrupts_mmio);
        //pr_info("Get vinterrupt in user space! kaddr: %lx, pfn: %lx, uaddr: %lx, vinterrupts_mmio 0x%lx\n", mem_info->kaddr, mem_info->pfn, mem_info->uaddr, *vinterrupts_mmio);
        pr_info("Get vinterrupt in user space! kaddr: %lx, pfn: %lx, uaddr: %lx\n", mem_info->kaddr, mem_info->pfn, mem_info->uaddr);
    }

#endif

    mutex_lock(&vm_dat->mem_lock);
    list_add(&mem_info->mem_node, &vm_dat->mem_list);
    mutex_unlock(&vm_dat->mem_lock);
    
    pr_info("%s: size: %lx, uaddr: %lx, pfn: %lx, kaddr: %px\n",
            __func__, size, vma->vm_start, virt_to_pfn(mem), mem);

    //writel(0x0, vinterrupts_mmio);

    return 0;
}

static long dv_driver_ioctl(struct file *file,
        unsigned int cmd, unsigned long arg)
{
    int rc;
    void __user *uarg = (void __user *) arg;

    switch (cmd) {
        case IOCTL_DUVISOR_GET_API_VERSION: {
            unsigned long version;
            pr_info("IOCTL_DUVISOR_GET_API_VERSION\n");
            
            rc = -EFAULT;
            version = 0x12345678;
            if (copy_to_user((unsigned long *)uarg, &version, sizeof(version)))
                break;
            
            rc = 0;
            break;
        }

        case IOCTL_DUVISOR_GET_VINTERRUPT_ADDR: {
            unsigned long vinterrupt_addr;
            pr_info("IOCTL_DUVISOR_GET_VINTERRUPT_ADDR\n");
            
            rc = -EFAULT;
            vinterrupt_addr = (unsigned long)vinterrupts_mmio;
            if (copy_to_user((unsigned long *)uarg, &vinterrupt_addr, sizeof(vinterrupt_addr)))
                break;
            
            rc = 0;
            break;
        }

        case IOCTL_DUVISOR_GET_CPUID: {
            unsigned long cpuid;
            unsigned long hartid;
            pr_info("IOCTL_DUVISOR_GET_CPUID\n");

            //unsigned long mhartid = csr_read(mhartid);
            // pr_info("IOCTL_DUVISOR_GET_CPUID: smp_processor_id 0x%lx\n", smp_processor_id());

            if (copy_from_user(&hartid, uarg, sizeof(hartid)))
                break;
            
            //rc = -EFAULT;
            //cpuid = smp_processor_id();
            //if (copy_to_user((unsigned long *)uarg, &cpuid, sizeof(cpuid)))
            //    break;

            for_each_cpu(cpuid, cpu_online_mask) {
                if (cpuid_to_hartid_map(cpuid) == hartid) {
                    if (copy_to_user((unsigned long *)uarg, &cpuid, sizeof(cpuid))) {
                        rc = -EFAULT;
                        return rc;
                    }
                }
            }

            rc = 0;
            break;
        }

        case IOCTL_DUVISOR_SET_VINTERRUPT: {
            int vinterrupt_value;
            //pr_info("**********IOCTL_DUVISOR_SET_VINTERRUPT********\n");

            if (copy_from_user(&vinterrupt_value, uarg, sizeof(vinterrupt_value)))
                break;

            //pr_info("IOCTL_DUVISOR_SET_VINTERRUPT value %d", vinterrupt_value);
            
            //rc = -EFAULT;
            //vinterrupt_addr = vinterrupts_mmio;
            //if (copy_to_user((unsigned long *)uarg, &vinterrupt_addr, sizeof(vinterrupt_addr)))
            //    break;
            writel(vinterrupt_value, (volatile void __iomem *)vinterrupts_mmio);
            
            rc = 0;
            break;
        }

        case IOCTL_DUVISOR_VPLIC_CLAIM: {
            //pr_info("**********IOCTL_DUVISOR_VPLIC_CLAIM********\n");

            //int vinterrupt_value;
            //if (copy_from_user(&vinterrupt_value, uarg, sizeof(vinterrupt_value)))
            //    break;
            
            //rc = -EFAULT;
            //vinterrupt_addr = vinterrupts_mmio;
            //if (copy_to_user((unsigned long *)uarg, &vinterrupt_addr, sizeof(vinterrupt_addr)))
            //    break;
            unsigned long claimed_addr = 0xffffffd000202004;
            //unsigned long claimed_addr = vinterrupts_mmio - (unsigned long)0x1f00000 + 0x200004 + 0x2000;
            //pr_info("IOCTL_DUVISOR_VPLIC_CLAIM readl: 0x%lx - 0x%lx", claimed_addr, vinterrupts_mmio);
            //writel(0x82, claimed_addr);
            //pr_info("IOCTL_DUVISOR_VPLIC_CLAIM readl: 0x%lx - 0x%x", claimed_addr, readl(claimed_addr));
            //readl(claimed_addr);
            writel(0x82, (volatile void __iomem *)claimed_addr);
            
            rc = 0;
            break;
        }

        case IOCTL_DUVISOR_REGISTER_SHARED_MEM: {
            /* [0] base_uaddr [1] mem_size */
            unsigned long sm_info[2];
            pid_t tgid = current->tgid;
            struct ulh_vm_data *vm_dat = current->group_leader->ulh_vm_data;

            rc = -EPERM;
            if (!vm_dat) break;
            
            rc = -EFAULT;
            if (copy_from_user(&sm_info, uarg, sizeof(sm_info)))
                break;
            pr_info("IOCTL_DUVISOR_REGISTER_SHARED_MEM "
                    "tgid: %d, base_uaddr: %lx, mem_size: %lx\n", 
                    tgid, sm_info[0], sm_info[1]);
            /* TODO: xlat uaddr to kaddr */
            vm_dat->sm_base_addr = sm_info[0];
            vm_dat->sm_size = sm_info[1];

            rc = 0;
            break;
        }

        case IOCTL_REMOTE_FENCE: {
            struct sbiret ret = sbi_ecall(5, 0, 0, 0, 0, 0, 0, 0);

            unsigned long ecall_ret[2];
            ecall_ret[0] = ret.error;
            ecall_ret[1] = ret.value;

            if (copy_to_user((unsigned long *)uarg, &ecall_ret, sizeof(ecall_ret)))
                break;

            break;
        }

        case IOCTL_DUVISOR_REQUEST_DELEG: {
            /* [0] e-deleg [1] i-deleg */
            unsigned long deleg_info[2];
            pid_t tgid = current->tgid;
            struct ulh_vm_data *vm_dat = current->group_leader->ulh_vm_data;
            unsigned long e_mask, i_mask;

            rc = -EPERM;
            if (!vm_dat) break;
            
            rc = -EFAULT;
            if (copy_from_user(&deleg_info, uarg, sizeof(deleg_info)))
                break;
            pr_info("IOCTL_DUVISOR_REQUEST_DELEG "
                    "tgid: %d, edeleg: %lx, ideleg: %lx\n", 
                    tgid, deleg_info[0], deleg_info[1]);

            e_mask = (1UL << EXC_SUPERVISOR_ECALL)
                | (1UL << EXC_INST_GUEST_PAGE_FAULT)
                | (1UL << EXC_LOAD_GUEST_PAGE_FAULT)
                | (1UL << EXC_VIRT_INST)
                | (1UL << EXC_STORE_GUEST_PAGE_FAULT);

            i_mask = (1UL << IRQ_U_SOFT)
                | (1UL << IRQ_U_TIMER)
                | (1UL << IRQ_U_EXT)
                | (1UL << IRQ_U_TIMER);

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

            vm_dat->sedeleg = deleg_info[0];
            vm_dat->sideleg = deleg_info[1];
            csr_write(CSR_SEDELEG, vm_dat->sedeleg);
            csr_write(CSR_SIDELEG, vm_dat->sideleg);

            vm_dat->hedeleg = (1UL << EXC_INST_MISALIGNED)
                | (1UL << EXC_BREAKPOINT)
                | (1UL << EXC_SYSCALL)
                | (1UL << EXC_INST_PAGE_FAULT)
                | (1UL << EXC_LOAD_PAGE_FAULT)
                | (1UL << EXC_STORE_PAGE_FAULT);
            csr_write(CSR_HEDELEG, vm_dat->hedeleg);

            vm_dat->hideleg = (1UL << IRQ_VS_SOFT)
                | (1UL << IRQ_VS_TIMER)
                | (1UL << IRQ_VS_EXT);
            csr_write(CSR_HIDELEG, vm_dat->hideleg);

            rc = 0;

            /* set up scounteren */
            vm_dat->scounteren = 0xffffffff;
            csr_write(CSR_SCOUNTEREN, vm_dat->scounteren);
            
            break;
        }

        case IOCTL_DUVISOR_REGISTER_VCPU: {
            pid_t tid = current->pid;
            if (current->ulh_vcpu_data) {
                pr_err("%s:%d tid = %d ulh_vcpu_data NOT NULL!\n", 
                        __func__, __LINE__, tid);
                return -EPERM;
            }
            current->ulh_vcpu_data = kzalloc(sizeof(struct ulh_vcpu_data), GFP_KERNEL);
            task_pt_regs(current)->hstatus |= HSTATUS_HU;
            pr_info("IOCTL_DUVISOR_REGISTER_VCPU: tid = %d\n", tid);

            rc = 0;
            break;
        }

        /* TODO: free ulh_vcpu_data memory by kernel */
        case IOCTL_DUVISOR_UNREGISTER_VCPU: {
            pid_t tid = current->pid;
            if (!current->ulh_vcpu_data) {
                pr_err("%s:%d tid = %d ulh_vcpu_data is NULL!\n", 
                        __func__, __LINE__, tid);
                return -EPERM;
            }
            kfree(current->ulh_vcpu_data);
            current->ulh_vcpu_data = NULL;
            task_pt_regs(current)->hstatus &= ~HSTATUS_HU;
            pr_info("IOCTL_DUVISOR_UNREGISTER_VCPU: tid = %d\n", tid);

            rc = 0;
            break;
        }

        case IOCTL_DUVISOR_QUERY_PFN: {
            unsigned long uaddr, pfn = 0UL;
            pid_t tgid = current->tgid;
            struct ulh_vm_data *vm_dat = current->group_leader->ulh_vm_data;
            struct ulh_vm_mem *mem_info;

            rc = -EPERM;
            if (!vm_dat) break;
            
            rc = -EFAULT;
            if (copy_from_user(&uaddr, uarg, sizeof(uaddr)))
                break;

            if (uaddr & 0xfff)
                break;

            list_for_each_entry(mem_info, &vm_dat->mem_list, mem_node) {
                if (mem_info->uaddr == uaddr)
                    pfn = mem_info->pfn;
            }
            if (pfn == 0)
                break;
            
            if (copy_to_user((unsigned long *)uarg, &pfn, sizeof(pfn)))
                break;
            pr_info("IOCTL_DUVISOR_QUERY_PFN tgid: %d, uaddr: %lx, pfn: %lx\n", 
                    tgid, uaddr, pfn);

            rc = 0;
            break;
        }

        case IOCTL_DUVISOR_RELEASE_PFN: {
            unsigned long pfn;
            pid_t tgid = current->tgid;
            struct ulh_vm_data *vm_dat = current->group_leader->ulh_vm_data;
            struct ulh_vm_mem *mem_info, *tmp;

            rc = -EPERM;
            if (!vm_dat) break;
            
            rc = -EFAULT;
            if (copy_from_user(&pfn, uarg, sizeof(pfn)))
                break;

            if (pfn == 0)
                break;

            list_for_each_entry_safe(mem_info, tmp, &vm_dat->mem_list, mem_node) {
                if (mem_info->pfn == pfn) {
                    mutex_lock(&vm_dat->mem_lock);
                    list_del(&mem_info->mem_node);
                    mutex_unlock(&vm_dat->mem_lock);

                    dma_free_contiguous(duvisor_miscdev.this_device, 
                            virt_to_page(mem_info->kaddr), mem_info->size);
                    kfree(mem_info);
                    break;
                }
            }
            if (pfn == 0)
                break;
            
            pr_info("IOCTL_DUVISOR_RELEASE_PFN tgid: %d, pfn: %lx\n", 
                    tgid, pfn);

            rc = 0;
            break;
        }

        case IOCTL_DUVISOR_GET_VMID: {
            static unsigned long vmid = 0;
            unsigned long fetch_vmid;

            fetch_vmid = __sync_fetch_and_add(&vmid, 1);

            pr_info("IOCTL_DUVISOR_GET_VMID: 0x%lx\n", fetch_vmid);
            
            rc = -EFAULT;
            if (copy_to_user((unsigned long *)uarg, &fetch_vmid, 
                sizeof(fetch_vmid)))
                break;
            
            rc = 0;
            break;
        }

        default:
            rc = -ENOSYS;
            break;
    }

    return rc;
}

static int dv_driver_open(struct inode *inode, struct file *filep)
{
    /* TODO: set up data structures for current process */
    pid_t tgid = current->tgid;
    struct ulh_vm_data *vm_dat = current->group_leader->ulh_vm_data;
    if (vm_dat) {
        pr_err("%s:%d tgid = %d ulh_vm_data NOT NULL!\n", __func__, __LINE__, tgid);
        return -EPERM;
    }

    vm_dat = kzalloc(sizeof(struct ulh_vm_data), GFP_KERNEL);
    mutex_init(&vm_dat->mem_lock);
    INIT_LIST_HEAD(&vm_dat->mem_list);
    current->group_leader->ulh_vm_data = vm_dat;

    pr_info("%s:%d tgid = %d\n", __func__, __LINE__, tgid);
    return 0;
}

static int dv_driver_release(struct inode *inode, struct file *filep)
{
    /* TODO: clean up data structures for current process */
    pid_t tgid = current->tgid;
    struct ulh_vm_data *vm_dat = current->group_leader->ulh_vm_data;
    struct ulh_vm_mem *mem_info, *tmp;
    if (!vm_dat) {
        pr_err("%s:%d tgid = %d ulh_vm_data is NULL!\n", __func__, __LINE__, tgid);
        return -EPERM;
    }

    list_for_each_entry_safe(mem_info, tmp, &vm_dat->mem_list, mem_node) {
        list_del(&mem_info->mem_node);
        dma_free_contiguous(duvisor_miscdev.this_device, 
                virt_to_page(mem_info->kaddr), mem_info->size);
        kfree(mem_info);
    }
    kfree(vm_dat);
    current->group_leader->ulh_vm_data = NULL;

    pr_info("%s:%d tgid = %d\n", __func__, __LINE__, tgid);
    
    return 0;
}

static const struct file_operations duvisor_fops = {
    .owner          = THIS_MODULE,
    .read           = NULL,
    .write          = NULL,
    .mmap           = dv_driver_mmap,
    .unlocked_ioctl = dv_driver_ioctl,
    .open           = dv_driver_open,
    .release        = dv_driver_release,
};

static struct miscdevice duvisor_miscdev = {
    .minor          = MISC_DYNAMIC_MINOR,
    .name           = "dv_driver",
    .fops           = &duvisor_fops,
};

static int __init dv_driver_init(void)
{
    int err;

#ifdef CONFIG_ULH_QEMU
    if (!riscv_isa_extension_available(NULL, z)) {
        pr_info("ULH: HU-extension not supported, skip installing dv_driver\n");
        return -ENODEV;
    }
#endif

    err = misc_register(&duvisor_miscdev);
    if (err != 0) {
        pr_err("Could not register /dev/dv_driver\n");
        return err;
    }

    pr_info("ULH: duvisor device installed\n");

    return 0;
}

static void __exit dv_driver_cleanup(void)
{
    misc_deregister(&duvisor_miscdev);
}

module_init(dv_driver_init);
module_exit(dv_driver_cleanup);

MODULE_LICENSE("GPL");
