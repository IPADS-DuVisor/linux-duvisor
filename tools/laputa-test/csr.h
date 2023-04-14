#ifndef _ASM_RISCV_CSR_H
#define _ASM_RISCV_CSR_H

#define __AC(X,Y)   (X##Y)
#define _AC(X,Y)    __AC(X,Y)

/* Interrupt causes (minus the high bit) */
#define IRQ_U_SOFT		0
#define IRQ_S_SOFT		1
#define IRQ_VS_SOFT		2
#define IRQ_M_SOFT		3
#define IRQ_U_TIMER		4
#define IRQ_S_TIMER		5
#define IRQ_VS_TIMER	6
#define IRQ_M_TIMER		7
#define IRQ_U_EXT		8
#define IRQ_S_EXT		9
#define IRQ_VS_EXT		10
#define IRQ_M_EXT		11
#define IRQ_U_VTIMER	16

/* Exception causes */
#define EXC_INST_MISALIGNED	0
#define EXC_INST_ACCESS		1
#define EXC_ILLEGAL_INST	2
#define EXC_BREAKPOINT		3
#define EXC_LOAD_ADDR_MISALIGNED	4
#define EXC_LOAD_ACCESS		5
#define EXC_STORE_ADDR_MISALIGNED	6
#define EXC_STORE_ACCESS	7
#define EXC_SYSCALL		8
#define EXC_HS_ECALL	9
#define EXC_VS_ECALL	10
#define EXC_INST_PAGE_FAULT	12
#define EXC_LOAD_PAGE_FAULT	13
#define EXC_STORE_PAGE_FAULT	15
#define EXC_INST_GUEST_PAGE_FAULT	20
#define EXC_LOAD_GUEST_PAGE_FAULT	21
#define EXC_VIRT_INST	            22
#define EXC_STORE_GUEST_PAGE_FAULT	23

/* HSTATUS flags */
#define HSTATUS_VSXL		_AC(0x300000000, UL)
#define HSTATUS_VSXL_SHIFT	32
#define HSTATUS_VTSR		_AC(0x00400000, UL)
#define HSTATUS_VTW		_AC(0x00200000, UL)
#define HSTATUS_VTVM		_AC(0x00100000, UL)
#define HSTATUS_VGEIN		_AC(0x0003f000, UL)
#define HSTATUS_VGEIN_SHIFT	12
#define HSTATUS_HU		_AC(0x00000200, UL)
#define HSTATUS_SPVP		_AC(0x00000100, UL)
#define HSTATUS_SPV		_AC(0x00000080, UL)
#define HSTATUS_GVA		_AC(0x00000040, UL)
#define HSTATUS_VSBE		_AC(0x00000020, UL)

/* Hpervisor CSRs */
#define CSR_HSTATUS         0x600
#define CSR_HEDELEG         0x602
#define CSR_HIDELEG         0x603
#define CSR_HIE             0x604
#define CSR_HCOUNTEREN      0x606
#define CSR_HGEIE           0x607
#define CSR_HTVAL           0x643
#define CSR_HVIP            0x645
#define CSR_HIP             0x644
#define CSR_HTINST          0x64A
#define CSR_HGEIP           0xE12
#define CSR_HGATP           0x680
#define CSR_HTIMEDELTA      0x605
#define CSR_HTIMEDELTAH     0x615

/* User Trap Handling */
#define CSR_UTVEC           0x005
#define CSR_USCRATCH        0x040
#define CSR_UEPC            0x041
#define CSR_UCAUSE          0x042
#define CSR_UTVAL           0x043

/* HU CSRs BEGIN */
#define HU_RW_CSR_OFFSET    (0x800)
#define HU_RW_CSR_MASK      (0xff)
#define MAP_RW_H_TO_HU(h_csr) (HU_RW_CSR_OFFSET | (HU_RW_CSR_MASK & h_csr))

#define CSR_HUSTATUS         MAP_RW_H_TO_HU(CSR_HSTATUS)
#define CSR_HUEDELEG         MAP_RW_H_TO_HU(CSR_HEDELEG)
#define CSR_HUIDELEG         MAP_RW_H_TO_HU(CSR_HIDELEG)
#define CSR_HUIE             MAP_RW_H_TO_HU(CSR_HIE)
#define CSR_HUCOUNTEREN      MAP_RW_H_TO_HU(CSR_HCOUNTEREN)
#define CSR_HUTVAL           MAP_RW_H_TO_HU(CSR_HTVAL)
#define CSR_HUVIP            MAP_RW_H_TO_HU(CSR_HVIP)
#define CSR_HUIP             MAP_RW_H_TO_HU(CSR_HIP)
#define CSR_HUTINST          MAP_RW_H_TO_HU(CSR_HTINST)
#define CSR_HUGATP           MAP_RW_H_TO_HU(CSR_HGATP)
#define CSR_HUTIMEDELTA      MAP_RW_H_TO_HU(CSR_HTIMEDELTA)
#define CSR_HUTIMEDELTAH     MAP_RW_H_TO_HU(CSR_HTIMEDELTAH)

#define HUVS_RW_CSR_OFFSET    (0x400)
#define HUVS_RW_CSR_MASK      (0xff)
#define MAP_RW_H_TO_HUVS(vs_csr) (HUVS_RW_CSR_OFFSET | (HUVS_RW_CSR_MASK & vs_csr))
/* User level virtual CSRs */
#define CSR_HUVSSTATUS        MAP_RW_H_TO_HUVS(CSR_VSSTATUS)
#define CSR_HUVSIE            MAP_RW_H_TO_HUVS(CSR_VSIE)
#define CSR_HUVSTVEC          MAP_RW_H_TO_HUVS(CSR_VSTVEC)
#define CSR_HUVSSCRATCH       MAP_RW_H_TO_HUVS(CSR_VSSCRATCH)
#define CSR_HUVSEPC           MAP_RW_H_TO_HUVS(CSR_VSEPC)
#define CSR_HUVSCAUSE         MAP_RW_H_TO_HUVS(CSR_VSCAUSE)
#define CSR_HUVSTVAL          MAP_RW_H_TO_HUVS(CSR_VSTVAL)
#define CSR_HUVSIP            MAP_RW_H_TO_HUVS(CSR_VSIP)
#define CSR_HUVSATP           MAP_RW_H_TO_HUVS(CSR_VSATP)

#define CSR_VTIMECMP           0x401
#define CSR_VTIMECTL           0x402
#define CSR_VTIMECMPH          0x481
/* HU CSRs END */

#ifndef __ASSEMBLY__

#define __ASM_STR(x)    #x

#define csr_swap(csr, val)					\
({								\
	unsigned long __v = (unsigned long)(val);		\
	__asm__ __volatile__ ("csrrw %0, " __ASM_STR(csr) ", %1"\
			      : "=r" (__v) : "rK" (__v)		\
			      : "memory");			\
	__v;							\
})

#define csr_read(csr)						\
({								\
	register unsigned long __v;				\
	__asm__ __volatile__ ("csrr %0, " __ASM_STR(csr)	\
			      : "=r" (__v) :			\
			      : "memory");			\
	__v;							\
})

#define csr_write(csr, val)					\
({								\
	unsigned long __v = (unsigned long)(val);		\
	__asm__ __volatile__ ("csrw " __ASM_STR(csr) ", %0"	\
			      : : "rK" (__v)			\
			      : "memory");			\
})

#define csr_read_set(csr, val)					\
({								\
	unsigned long __v = (unsigned long)(val);		\
	__asm__ __volatile__ ("csrrs %0, " __ASM_STR(csr) ", %1"\
			      : "=r" (__v) : "rK" (__v)		\
			      : "memory");			\
	__v;							\
})

#define csr_set(csr, val)					\
({								\
	unsigned long __v = (unsigned long)(val);		\
	__asm__ __volatile__ ("csrs " __ASM_STR(csr) ", %0"	\
			      : : "rK" (__v)			\
			      : "memory");			\
})

#define csr_read_clear(csr, val)				\
({								\
	unsigned long __v = (unsigned long)(val);		\
	__asm__ __volatile__ ("csrrc %0, " __ASM_STR(csr) ", %1"\
			      : "=r" (__v) : "rK" (__v)		\
			      : "memory");			\
	__v;							\
})

#define csr_clear(csr, val)					\
({								\
	unsigned long __v = (unsigned long)(val);		\
	__asm__ __volatile__ ("csrc " __ASM_STR(csr) ", %0"	\
			      : : "rK" (__v)			\
			      : "memory");			\
})

#endif /* __ASSEMBLY__ */

#endif /* _ASM_RISCV_CSR_H */
