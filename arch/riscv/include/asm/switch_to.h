/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2012 Regents of the University of California
 */

#ifndef _ASM_RISCV_SWITCH_TO_H
#define _ASM_RISCV_SWITCH_TO_H

#include <linux/sched/task_stack.h>
#include <asm/processor.h>
#include <asm/ptrace.h>
#include <asm/csr.h>

#ifdef CONFIG_FPU
extern void __fstate_save(struct task_struct *save_to);
extern void __fstate_restore(struct task_struct *restore_from);

static inline void __fstate_clean(struct pt_regs *regs)
{
	regs->status = (regs->status & ~SR_FS) | SR_FS_CLEAN;
}

static inline void fstate_off(struct task_struct *task,
			      struct pt_regs *regs)
{
	regs->status = (regs->status & ~SR_FS) | SR_FS_OFF;
}

static inline void fstate_save(struct task_struct *task,
			       struct pt_regs *regs)
{
	if ((regs->status & SR_FS) == SR_FS_DIRTY) {
		__fstate_save(task);
		__fstate_clean(regs);
	}
}

static inline void fstate_restore(struct task_struct *task,
				  struct pt_regs *regs)
{
	if ((regs->status & SR_FS) != SR_FS_OFF) {
		__fstate_restore(task);
		__fstate_clean(regs);
	}
}

static inline void __switch_to_aux(struct task_struct *prev,
				   struct task_struct *next)
{
	struct pt_regs *regs;

	regs = task_pt_regs(prev);
	if (unlikely(regs->status & SR_SD))
		fstate_save(prev, regs);
	fstate_restore(next, task_pt_regs(next));
}

extern bool has_fpu;
#else
#define has_fpu false
#define fstate_save(task, regs) do { } while (0)
#define fstate_restore(task, regs) do { } while (0)
#define __switch_to_aux(__prev, __next) do { } while (0)
#endif

extern struct task_struct *__switch_to(struct task_struct *,
				       struct task_struct *);

#ifdef CONFIG_ULH_FPGA
static inline unsigned long rdvtimecmp(void) {
	register unsigned long vtimecmp asm("a0");
	asm volatile(".word 0xe0102577\r\n");
	return vtimecmp;
}

static inline void wrvtimecmp(unsigned long vtimecmp){
	asm volatile(".word 0xe0a01077\r\n");
}

static inline unsigned long rdvtimectl(void) {
	register unsigned long vtimectl asm("a0");
	asm volatile(".word 0xf0202577\r\n");
	return vtimectl;
}

static inline void wrvtimectl(unsigned long vtimectl){
	asm volatile(".word 0xf0a01077\r\n");
}

static inline uint64_t rdvcpuid(void){
	register unsigned long vcpuid asm("a0");
	asm volatile(".word 0xf8102577\r\n");
	return vcpuid;
}

static inline void wrvcpuid(uint64_t vcpuid){
	asm volatile(".word 0xf8a01077\r\n");
}
#endif

/* NOTE: an exception from kthread will jump to finish_task_switch
 * directly after __switch_to, rather than return to context_switch.
 * Therefore, we must put switch_ulh_data before __switch_to.
 */
static inline void switch_ulh_data(struct task_struct *next)
{
	struct ulh_vm_data *vm_dat = (next->group_leader->ulh_vm_data);
	if (vm_dat) {
		csr_write(CSR_SEDELEG, vm_dat->sedeleg);
		csr_write(CSR_SIDELEG, vm_dat->sideleg | (1 << IRQ_U_SOFT));
		csr_write(CSR_HEDELEG, vm_dat->hedeleg);
		csr_write(CSR_HIDELEG, vm_dat->hideleg);
		csr_write(CSR_SCOUNTEREN, vm_dat->scounteren);

    	/*
    	 * rs1 = zero
    	 * rs2 = zero
    	 * HFENCE.GVMA
    	 * 0110001 00000 00000 000 00000 1110011
    	 */
        asm volatile(".word 0x62000073 \n");
	} else {
		/* cancel timer and then clear huip for non-vcpu thread*/
#ifdef CONFIG_ULH_QEMU
		csr_write(CSR_VTIMECTL, 0);
		csr_write(CSR_VCPUID, 0);
#endif
#ifdef CONFIG_ULH_FPGA
		wrvtimectl(0);
		wrvcpuid(0);
#endif
		csr_write(CSR_HUIE, 0);
		csr_write(CSR_SEDELEG, 0);
		csr_write(CSR_SIDELEG, (1 << IRQ_U_SOFT));
		csr_write(CSR_HEDELEG, 0);
		csr_write(CSR_HIDELEG, 0);
	}
}

#define switch_to(prev, next, last)			\
do {							\
	struct task_struct *__prev = (prev);		\
	struct task_struct *__next = (next);		\
	if (has_fpu)					\
		__switch_to_aux(__prev, __next);	\
	switch_ulh_data(__next); \
	((last) = __switch_to(__prev, __next));		\
} while (0)

#endif /* _ASM_RISCV_SWITCH_TO_H */
