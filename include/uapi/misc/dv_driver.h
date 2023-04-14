#ifndef __DV_DRIVER_H__
#define __DV_DRIVER_H__

#include <linux/types.h>
#include <linux/ioctl.h>

/* TODO: ensure no conflict */
#define DUVISOR_MAGIC 'k'
#define IOCTL_DUVISOR_GET_API_VERSION \
    _IOR(DUVISOR_MAGIC, 1, unsigned long)
/* TODO: base addr & size */
#define IOCTL_DUVISOR_REGISTER_SHARED_MEM \
    _IOW(DUVISOR_MAGIC, 2, unsigned long [2])
#define IOCTL_DUVISOR_REQUEST_DELEG \
    _IOW(DUVISOR_MAGIC, 3, unsigned long [2])
#define IOCTL_DUVISOR_REGISTER_VCPU \
    _IO(DUVISOR_MAGIC, 4)
#define IOCTL_DUVISOR_UNREGISTER_VCPU \
    _IO(DUVISOR_MAGIC, 5)
#define IOCTL_DUVISOR_QUERY_PFN \
    _IOWR(DUVISOR_MAGIC, 6, unsigned long)
#define IOCTL_DUVISOR_RELEASE_PFN \
    _IOW(DUVISOR_MAGIC, 7, unsigned long)
#define IOCTL_REMOTE_FENCE \
    _IOR(DUVISOR_MAGIC, 8, unsigned long [2])
#define IOCTL_DUVISOR_GET_VMID \
    _IOR(DUVISOR_MAGIC, 9, unsigned long)
#define IOCTL_DUVISOR_GET_VINTERRUPT_ADDR \
    _IOR(DUVISOR_MAGIC, 10, unsigned long)
#define IOCTL_DUVISOR_GET_CPUID \
    _IOR(DUVISOR_MAGIC, 11, unsigned long)
#define IOCTL_DUVISOR_SET_VINTERRUPT \
    _IOR(DUVISOR_MAGIC, 12, unsigned long)
#define IOCTL_DUVISOR_VPLIC_CLAIM \
    _IOR(DUVISOR_MAGIC, 13, unsigned long)
#endif
