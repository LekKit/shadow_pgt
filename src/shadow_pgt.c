/*
shadow_pgt.c - Shadow pagetable kernel module
Copyright (C) 2024  LekKit <github.com/LekKit>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

#include "shadow_pgt.h"

#if !defined(__riscv) || __riscv_xlen != 64
#error shadow_pgt is a riscv64-only kernel module for now!
#endif

#ifdef __riscv

#define CSR_SSTATUS  0x100
#define CSR_STVEC    0x105
#define CSR_SSCRATCH 0x140
#define CSR_SEPC     0x141
#define CSR_SATP     0x180

#define CSR_SSTATUS_SIE  0x2ULL
#define CSR_SSTATUS_SPIE 0x20ULL
#define CSR_SSTATUS_SPP  0x100ULL

#define CSR_ASM(x) #x

#define CSR_READ(csr, v)                       \
__asm__ __volatile__ ("csrr %0, " CSR_ASM(csr) \
              : "=r" (v) :                     \
              : "memory");

#define CSR_WRITE(csr, v)                          \
__asm__ __volatile__ ("csrw " CSR_ASM(csr) ", %0" \
              : : "rK" (v)                         \
              : "memory");

#define CSR_SWAP(csr, v)                               \
__asm__ __volatile__ ("csrrw %0, " CSR_ASM(csr) ", %1" \
              : "=r" (v) : "rK" (v)                    \
              : "memory");

#define CSR_SETBITS(csr, v)                            \
__asm__ __volatile__ ("csrrs %0, " CSR_ASM(csr) ", %1" \
              : "=r" (v) : "rK" (v)                    \
              : "memory");

#define CSR_CLEARBITS(csr, v)                          \
__asm__ __volatile__ ("csrrc %0, " CSR_ASM(csr) ", %1" \
              : "=r" (v) : "rK" (v)                    \
              : "memory");

#endif

struct shadow_pgt* shadow_pgt_init(void)
{
    struct shadow_pgt* pgt = pgt_kvzalloc(sizeof(struct shadow_pgt));
    return pgt;
}

void shadow_pgt_free(struct shadow_pgt* pgt)
{
    pgt_kvfree(pgt);
}

int shadow_pgt_map(struct shadow_pgt* pgt, const struct shadow_map* map)
{
    return -22;
}

int shadow_pgt_unmap(struct shadow_pgt* pgt, const struct shadow_map* map)
{
    return -22;
}

int shadow_pgt_enter(struct shadow_pgt* pgt)
{
    pgt_debug_print("+shadow_pgt_enter()");
#ifdef __riscv
    // Disable interrupts in current context
    size_t sstatus = CSR_SSTATUS_SIE;
    CSR_CLEARBITS(CSR_SSTATUS, sstatus);

    // Save previous sstatus
    pgt->sstatus = sstatus;

    // Enable interrupts for return context
    sstatus |= CSR_SSTATUS_SPIE;

    // Set return to U-mode
    sstatus &= ~CSR_SSTATUS_SPP;
    CSR_WRITE(CSR_SSTATUS, sstatus);

    // Save host kernel satp
    CSR_READ(CSR_SATP, pgt->satp);

    // Set up shadow land state
    pgt->stvec = (size_t)shadow_pgt_trap_handler;
    pgt->sscratch = (size_t)pgt;
    pgt->sepc = pgt->uctx.pc;

    // Swap host kernel S-mode state with shadow land state
    CSR_SWAP(CSR_SEPC, pgt->sepc);
    CSR_SWAP(CSR_STVEC, pgt->stvec);
    CSR_SWAP(CSR_SSCRATCH, pgt->sscratch);

    // TODO: Actual shadow pagetable allocation
    pgt->shadow_satp = pgt->satp;

    pgt_debug_print("Entering shadow land...");

    // Enter asm routine to switch satp & ucontext into shadow land...
    shadow_pgt_enter_trampoline(pgt);

    pgt_debug_print("Returning to host kernel...");

    // Restore host kernel S-mode state
    CSR_WRITE(CSR_STVEC, pgt->stvec);

    size_t sscratch = pgt->sscratch;
    CSR_SWAP(CSR_SSCRATCH, sscratch);

    // sscratch held guest a0
    pgt->uctx.xreg[10] = sscratch;

    // sepc held guest pc
    CSR_SWAP(CSR_SEPC, pgt->sepc);
    pgt->uctx.pc = pgt->sepc;

    // Restore actual initial host kernel sstatus
    CSR_WRITE(CSR_SSTATUS, pgt->sstatus);
#endif
    pgt_debug_print("-shadow_pgt_enter()");
    return 0;
}
