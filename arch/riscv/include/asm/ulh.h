#ifndef _ULH_H_
#define _ULH_H_

struct ulh_vm_data {
    unsigned long sm_base_addr;
    unsigned long sm_size;
    unsigned long sedeleg;
    unsigned long sideleg;
    unsigned long hedeleg;
    unsigned long hideleg;
};

/* TODO: move HU, HUVS, U CSRs from pt_regs to ulh_vcpu_data */
struct ulh_vcpu_data {};

#endif /* _ULH_H_ */
