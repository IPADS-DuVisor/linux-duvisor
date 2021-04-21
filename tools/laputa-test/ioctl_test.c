#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/ioctl.h>

#include "../../include/uapi/misc/laputa_dev.h"
#include "csr.h"

#define IOCTL_DRIVER_NAME "/dev/laputa_dev"
            
static const unsigned long e_mask = (1UL << EXC_SUPERVISOR_ECALL) | 
    (1UL << EXC_INST_GUEST_PAGE_FAULT) | 
    (1UL << EXC_LOAD_GUEST_PAGE_FAULT) | 
    (1UL << EXC_VIRT_INST) | 
    (1UL << EXC_STORE_GUEST_PAGE_FAULT);

static const unsigned long i_mask = (1UL << IRQ_U_SOFT) | 
    (1UL << IRQ_U_TIMER) | 
    (1UL << IRQ_U_EXT);

int open_driver(const char* driver_name) {
    printf("* Open Driver\n");

    int fd_driver = open(driver_name, O_RDWR);
    if (fd_driver == -1) {
        printf("ERROR: could not open \"%s\".\n", driver_name);
        printf("    errno = %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    return fd_driver;
}

void close_driver(const char* driver_name, int fd_driver) {
    printf("* Close Driver\n");

    int result = close(fd_driver);
    if (result == -1) {
        printf("ERROR: could not close \"%s\".\n", driver_name);
        printf("    errno = %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}

int pass_huret(void) {
    unsigned long deleg_info[2];
    unsigned long tmp_buf_pfn, hugatp;
    int fd_ioctl = open_driver(IOCTL_DRIVER_NAME);

    if (ioctl(fd_ioctl, IOCTL_LAPUTA_GET_API_VERSION, &tmp_buf_pfn) < 0) {
        perror("Error ioctl IOCTL_LAPUTA_GET_API_VERSION");
        return -1;
    }
    hugatp = tmp_buf_pfn | (8UL << 60);
    printf("tmp_buf_pfn = %lx : %lx\n", tmp_buf_pfn, hugatp);

    deleg_info[0] = (1 << 20) | (1 << 21) | (1 << 23);
    deleg_info[1] = 1 << 0;
    if (ioctl(fd_ioctl, IOCTL_LAPUTA_REQUEST_DELEG, deleg_info) < 0) {
        perror("Error ioctl IOCTL_LAPUTA_REQUEST_DELEG");
        return -1;
    }

    if (ioctl(fd_ioctl, IOCTL_LAPUTA_REGISTER_VCPU) < 0) {
        perror("Error ioctl IOCTL_LAPUTA_REGISTER_VCPU");
        return -1;
    }

    printf("uret test for ULH\n");

    asm volatile(
            "li t0, 0x200000180\n\t" 
            "csrw 0x800, t0\n\t" // hustatus

            "la t0, 1f\n\t" 
            "csrw 0x5, t0\n\t" // utvec

            "csrw 0x41, %0\n\t" // uepc

            "csrw 0x880, %1\n\t" // hugatp
            
            "li t0, 0x0\n\t"
            "csrw 0x480, t0\n\t" // huvsatp
            
            ".word 0xE2000073\n\t" // hufence
            
#if 0
            "csrr t0, 0x41\n\t" // uepc
            "la t1, 1f\n\t"
            "csrr t2, 0x800\n\t" // hustatus
            "_loop:\n\t"
            "j _loop\n\t"
#endif
            "uret\n\t"
            "1:\n\t"
#if 0
            "csrr t0, 0x42\n\t" // ucause
            "_tmp:\n\t"
            "j _tmp\n\t"
#endif
            :: "r"(tmp_buf_pfn << 12), "r"(hugatp) : "t0");

    if (ioctl(fd_ioctl, IOCTL_LAPUTA_UNREGISTER_VCPU) < 0) {
        perror("Error ioctl IOCTL_LAPUTA_UNREGISTER_VCPU");
        return -1;
    }

    close_driver(IOCTL_DRIVER_NAME, fd_ioctl);
    return 0;
}

int pass_ioctls(void) {
    unsigned long value;
    int fd_ioctl = open_driver(IOCTL_DRIVER_NAME);
    
    if (ioctl(fd_ioctl, IOCTL_LAPUTA_GET_API_VERSION, &value) < 0) {
        perror("Error ioctl IOCTL_LAPUTA_GET_API_VERSION");
        return -1;
    }
    printf("Value is %lx\n", value);

    unsigned long sm_info[2];
    sm_info[0] = 0xdead000;
    sm_info[1] = 0x1000;
    if (ioctl(fd_ioctl, IOCTL_LAPUTA_REGISTER_SHARED_MEM, sm_info) < 0) {
        perror("Error ioctl IOCTL_LAPUTA_REGISTER_SHARED_MEM");
        return -1;
    }

    unsigned long deleg_info[2];
    deleg_info[0] = 1 << EXC_INST_GUEST_PAGE_FAULT;
    deleg_info[1] = 1 << IRQ_U_SOFT;
    if (ioctl(fd_ioctl, IOCTL_LAPUTA_REQUEST_DELEG, deleg_info) < 0) {
        perror("Error ioctl IOCTL_LAPUTA_REQUEST_DELEG");
        return -1;
    }

    close_driver(IOCTL_DRIVER_NAME, fd_ioctl);
    return 0;
}

int pass_csrs(void) {
    int fd_ioctl = open_driver(IOCTL_DRIVER_NAME);

    unsigned long deleg_info[2];
    deleg_info[0] = e_mask;
    deleg_info[1] = i_mask;
    if (ioctl(fd_ioctl, IOCTL_LAPUTA_REQUEST_DELEG, deleg_info) < 0) {
        perror("Error ioctl IOCTL_LAPUTA_REQUEST_DELEG");
        return -1;
    }

    if (ioctl(fd_ioctl, IOCTL_LAPUTA_REGISTER_VCPU) < 0) {
        perror("Error ioctl IOCTL_LAPUTA_REGISTER_VCPU");
        return -1;
    }

    unsigned long val;
    unsigned long before, after;

    after = (HSTATUS_VSXL & (2UL << HSTATUS_VSXL_SHIFT)) | HSTATUS_GVA;
    before = csr_swap(CSR_HUSTATUS, after);
    assert(before == (HSTATUS_VSXL & (2UL << HSTATUS_VSXL_SHIFT)));
    val = csr_swap(CSR_HUSTATUS, 0);
    assert(val == after);

    /* EXC_VS_* should be set by HEDELEG */

    /* IRQ_VS_* should be set by HIDELEG */

    after = (1 << IRQ_VS_SOFT);
    before = csr_swap(CSR_HUVIP, after);
    assert(before == 0);
    val = csr_swap(CSR_HUVIP, 0);
    assert(val == after);

    /* HUIP should reflect the value of HUVIP */
    after = (1 << IRQ_U_TIMER);
    before = csr_swap(CSR_HUIP, after);
    assert(before == 0);
    val = csr_swap(CSR_HUIP, 0);
    assert(val == after);

    after = (1 << IRQ_U_TIMER);
    before = csr_swap(CSR_HUIE, after);
    assert(before == 0);
    val = csr_swap(CSR_HUIE, 0);
    assert(val == after);

    after = 0x1234;
    before = csr_swap(CSR_HUTIMEDELTA, after);
    assert(before == 0);
    val = csr_swap(CSR_HUTIMEDELTA, 0);
    assert(val == after);

    after = 0x1234;
    before = csr_swap(CSR_HUTVAL, after);
    assert(before == 0);
    val = csr_swap(CSR_HUTVAL, 0);
    assert(val == after);

    after = 0x1234;
    before = csr_swap(CSR_HUTINST, after);
    assert(before == 0);
    val = csr_swap(CSR_HUTINST, 0);
    assert(val == 0);

    after = 0x1234;
    before = csr_swap(CSR_HUGATP, after);
    assert(before == 0);
    val = csr_swap(CSR_HUGATP, 0);
    assert(val == after);

    after = 0x1234;
    before = csr_swap(CSR_USCRATCH, after);
    assert(before == 0);
    val = csr_swap(CSR_USCRATCH, 0);
    assert(val == after);

    after = 0x1234;
    before = csr_swap(CSR_UTVAL, after);
    assert(before == 0);
    val = csr_swap(CSR_UTVAL, 0);
    assert(val == after);

    after = 0x1234;
    before = csr_swap(CSR_UEPC, after);
    assert(before == 0);
    val = csr_swap(CSR_UEPC, 0);
    assert(val == after);

    after = 0x1234;
    before = csr_swap(CSR_UTVEC, after);
    assert(before == 0);
    val = csr_swap(CSR_UTVEC, 0);
    assert(val == after);

    after = 0x1234;
    before = csr_swap(CSR_UCAUSE, after);
    assert(before == 0);
    val = csr_swap(CSR_UCAUSE, 0);
    assert(val == after);

    if (ioctl(fd_ioctl, IOCTL_LAPUTA_UNREGISTER_VCPU) < 0) {
        perror("Error ioctl IOCTL_LAPUTA_UNREGISTER_VCPU");
        return -1;
    }

    close_driver(IOCTL_DRIVER_NAME, fd_ioctl);
    return 0;
}

int fail_ideleg(void) {
    int fd_ioctl = open_driver(IOCTL_DRIVER_NAME);
    
    unsigned long deleg_info[2];
    deleg_info[0] = 1 << EXC_SUPERVISOR_ECALL;
    deleg_info[1] = 1 << IRQ_S_SOFT;
    if (ioctl(fd_ioctl, IOCTL_LAPUTA_REQUEST_DELEG, deleg_info) < 0) {
        perror("Error ioctl IOCTL_LAPUTA_REQUEST_DELEG");
        close_driver(IOCTL_DRIVER_NAME, fd_ioctl);
        return 0;
    }

    close_driver(IOCTL_DRIVER_NAME, fd_ioctl);
    return -1;
}

int fail_edeleg(void) {
    int fd_ioctl = open_driver(IOCTL_DRIVER_NAME);
    
    unsigned long deleg_info[2];
    deleg_info[0] = 1 << EXC_INST_PAGE_FAULT;
    deleg_info[1] = 1 << EXC_VIRT_INST;
    if (ioctl(fd_ioctl, IOCTL_LAPUTA_REQUEST_DELEG, deleg_info) < 0) {
        perror("Error ioctl IOCTL_LAPUTA_REQUEST_DELEG");
        close_driver(IOCTL_DRIVER_NAME, fd_ioctl);
        return 0;
    }

    close_driver(IOCTL_DRIVER_NAME, fd_ioctl);
    return -1;
}

int main(void) {
    int ret, nr_pass = 0, nr_fail = 0;
    int times = 100;
    printf("SMP tests for %d times on 4 cores\n", times);
    
    for (int i = 0; i < times; i++) {
        cpu_set_t my_set;
        CPU_ZERO(&my_set);
        CPU_SET((size_t)(i % 4), &my_set);
        sched_setaffinity(0, sizeof(cpu_set_t), &my_set);
    
        if ((ret = pass_ioctls()))
            break;
    }
    if (ret) nr_fail++;
    else nr_pass++;
    
    for (int i = 0; i < times; i++) {
        cpu_set_t my_set;
        CPU_ZERO(&my_set);
        CPU_SET((size_t)(i % 4), &my_set);
        sched_setaffinity(0, sizeof(cpu_set_t), &my_set);
    
        if ((ret = pass_csrs()))
            break;
    }
    if (ret) nr_fail++;
    else nr_pass++;
    
    for (int i = 0; i < times; i++) {
        cpu_set_t my_set;
        CPU_ZERO(&my_set);
        CPU_SET((size_t)(i % 4), &my_set);
        sched_setaffinity(0, sizeof(cpu_set_t), &my_set);
    
        if ((ret = fail_ideleg()))
            break;
    }
    if (ret) nr_fail++;
    else nr_pass++;
    
    for (int i = 0; i < times; i++) {
        cpu_set_t my_set;
        CPU_ZERO(&my_set);
        CPU_SET((size_t)(i % 4), &my_set);
        sched_setaffinity(0, sizeof(cpu_set_t), &my_set);
    
        if ((ret = fail_edeleg()))
            break;
    }
    if (ret) nr_fail++;
    else nr_pass++;

    for (int i = 0; i < times; i++) {
        cpu_set_t my_set;
        CPU_ZERO(&my_set);
        CPU_SET((size_t)(i % 4), &my_set);
        sched_setaffinity(0, sizeof(cpu_set_t), &my_set);
    
        if ((ret = pass_huret()))
            break;
    }
    if (ret) nr_fail++;
    else nr_pass++;
    
    printf("\n ------------ \n");
    if (nr_fail)
        printf("\nFAILED: [%d / %d] tests failed\n", nr_fail, nr_pass + nr_fail);
    else
        printf("\nPASSED: [%d / %d] tests passed\n", nr_pass, nr_pass + nr_fail);
    printf("\n ------------ \n");

    return EXIT_SUCCESS;
}
