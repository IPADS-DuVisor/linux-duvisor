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

static inline void switch_ulh_data(void)
{
	struct ulh_vm_data *cur_vm_dat = (current->group_leader->ulh_vm_data);
    if (cur_vm_dat) {
        csr_write(CSR_SEDELEG, cur_vm_dat->sedeleg);
        csr_write(CSR_SIDELEG, cur_vm_dat->sideleg);
        csr_write(CSR_HEDELEG, cur_vm_dat->hedeleg);
        csr_write(CSR_HIDELEG, cur_vm_dat->hideleg);
    } else {
        csr_write(CSR_SEDELEG, 0);
        csr_write(CSR_SIDELEG, 0);
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
	((last) = __switch_to(__prev, __next));		\
    switch_ulh_data(); \
} while (0)

#endif /* _ASM_RISCV_SWITCH_TO_H */
