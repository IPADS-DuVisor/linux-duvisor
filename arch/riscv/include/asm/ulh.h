#ifndef _ULH_H_
#define _ULH_H_

struct ulh_data {
    unsigned long sm_base_addr;
    unsigned long sm_size;
    unsigned long sedeleg;
    unsigned long sideleg;
    bool uaccess_ok;
};

#endif /* _ULH_H_ */
