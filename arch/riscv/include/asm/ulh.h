#ifndef _ULH_H_
#define _ULH_H_

#include <linux/mutex.h>
#include <linux/list.h>

struct ulh_vm_mem {
    struct list_head mem_node;
    unsigned long size;
    unsigned long uaddr;
    void *kaddr;
    unsigned long pfn;
};

struct ulh_vm_data {
    unsigned long sm_base_addr;
    unsigned long sm_size;
    unsigned long sedeleg;
    unsigned long sideleg;
    unsigned long hedeleg;
    unsigned long hideleg;
    unsigned long scounteren;
    struct mutex mem_lock;
    struct list_head mem_list;
};

/* TODO: move HU, HUVS, U CSRs, vtime CSRs from pt_regs to ulh_vcpu_data */
struct ulh_vcpu_data {
};

#endif /* _ULH_H_ */
