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

#define compiler_barrier() __asm__ __volatile__ ("" : : : "memory")

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
              : "memory")

#define CSR_WRITE(csr, v)                          \
__asm__ __volatile__ ("csrw " CSR_ASM(csr) ", %0" \
              : : "rK" (v)                         \
              : "memory")

#define CSR_SWAP(csr, v)                               \
__asm__ __volatile__ ("csrrw %0, " CSR_ASM(csr) ", %1" \
              : "=r" (v) : "rK" (v)                    \
              : "memory")

#define CSR_SETBITS(csr, v)                            \
__asm__ __volatile__ ("csrrs %0, " CSR_ASM(csr) ", %1" \
              : "=r" (v) : "rK" (v)                    \
              : "memory")

#define CSR_CLEARBITS(csr, v)                          \
__asm__ __volatile__ ("csrrc %0, " CSR_ASM(csr) ", %1" \
              : "=r" (v) : "rK" (v)                    \
              : "memory")

#endif

/*
 * Each pagetable page is doubled:
 * - First goes actual RISC-V pagetable page
 * - AFter it, the page which holds virtual kernel addresses to it's child pages
 */

#define MMU_VALID_PTE     0x1
#define MMU_READ          0x2
#define MMU_WRITE         0x4
#define MMU_EXEC          0x8
#define MMU_LEAF_PTE      0xA
#define MMU_USER_USABLE   0x10
#define MMU_GLOBAL_MAP    0x20
#define MMU_PAGE_ACCESSED 0x40
#define MMU_PAGE_DIRTY    0x80

#define MMU_PAGE_SHIFT    12
#define MMU_PAGE_MASK     0xFFF
#define MMU_PAGE_SIZE     0x1000
#define MMU_PAGE_PNMASK   (~0xFFFULL)

#define SV64_VPN_BITS     9
#define SV64_VPN_MASK     0x1FF
#define SV64_PHYS_BITS    56
#define SV64_PHYS_MASK    bit_mask(SV64_PHYS_BITS)

#define SV39_LEVELS       3
#define SV48_LEVELS       4
#define SV57_LEVELS       5

#define SV_LEVELS SV39_LEVELS

#define PAGETABLE_PTES 512

static inline uint64_t sign_extend(uint64_t val, uint8_t bits)
{
    return ((int64_t)(val << (64 - bits))) >> (64 - bits);
}
/*
static pgt_pte_t* pgt_get_page_pte(struct shadow_pgt* pgt, size_t vaddr)
{
    uint8_t bit_off = (SV_LEVELS * SV64_VPN_BITS) + MMU_PAGE_SHIFT - SV64_VPN_BITS;
    pgt_pte_t* pagetable = pgt->pagetable;

    for (size_t i = 0; i < SV_LEVELS; ++i) {
        size_t pgt_entry = (vaddr >> bit_off) & SV64_VPN_MASK;
        pgt_pte_t pte = pagetable[pgt_entry];
        if (pte & MMU_VALID_PTE) {

        }


        bit_off -= SV64_VPN_BITS;
    }
}
*/
static void pgt_free_pagetable(pgt_pte_t* pagetable)
{
    for (size_t i = 0; i < PAGETABLE_PTES; ++i) {
        pgt_pte_t pte = pagetable[i];
        if (pte & MMU_VALID_PTE) {
            if (pte & MMU_LEAF_PTE) {
                // Release a pinned user page
                struct pgt_pin_page* pin_page = (void*)pagetable[PAGETABLE_PTES + i];
                pgt_release_user_page(pin_page);
            } else {
                // Free pagetable level
                pgt_pte_t* next_pagetable = (void*)pagetable[PAGETABLE_PTES + i];
                pgt_free_pagetable(next_pagetable);
            }
        }
    }
    pgt_free_pages(pagetable, 2);
}

struct shadow_pgt* shadow_pgt_init(void)
{
    pgt_debug_print("+shadow_pgt_init()");
    struct shadow_pgt* pgt = pgt_kvzalloc(sizeof(struct shadow_pgt));

    pgt->pagetable = pgt_alloc_pages(2);

    pgt_debug_print("-shadow_pgt_init()");
    return pgt;
}

void shadow_pgt_free(struct shadow_pgt* pgt)
{
    pgt_debug_print("+shadow_pgt_free()");
    pgt_free_pagetable(pgt->pagetable);
    pgt_kvfree(pgt);
    pgt_debug_print("-shadow_pgt_free()");
}

int shadow_pgt_map(struct shadow_pgt* pgt, const struct shadow_map* map)
{
    if ((map->size & 0xFFF) || (map->vaddr & 0xFFF) || (((size_t)map->uaddr) & 0xFFF)) {
        // Misaligned mapping
        return -1;
    }
    if (sign_extend(map->vaddr, 39) != map->vaddr) {
        // Non-canonical address for sv39
        return -1;
    }

    pgt_spin_lock(&pgt->lock);

    // TODO: Pagetable map
    pgt_spin_unlock(&pgt->lock);
    return -1;
}

int shadow_pgt_unmap(struct shadow_pgt* pgt, const struct shadow_map* map)
{
    if ((map->size & 0xFFF) || (map->vaddr & 0xFFF) || (((size_t)map->uaddr) & 0xFFF)) {
        // Misaligned mapping
        return -1;
    }
    if (sign_extend(map->vaddr, 39) != map->vaddr) {
        // Non-canonical address for sv39
        return -1;
    }

    pgt_spin_lock(&pgt->lock);
    // TODO: Pagetable unmap
    pgt_spin_unlock(&pgt->lock);
    return -1;
}

static void shadow_pgt_enter_internal(struct shadow_pgt* pgt)
{
#ifdef __riscv
    // Disable interrupts in current context, set return mode to U-mode
    size_t sstatus = CSR_SSTATUS_SIE | CSR_SSTATUS_SPIE | CSR_SSTATUS_SPP;
    CSR_CLEARBITS(CSR_SSTATUS, sstatus);

    // Save previous sstatus
    pgt->sstatus = sstatus;

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

    // Enter asm routine to switch satp & ucontext into shadow land...
    compiler_barrier();
    shadow_pgt_enter_trampoline(pgt);
    compiler_barrier();

    // Restore host kernel S-mode state
    CSR_WRITE(CSR_STVEC, pgt->stvec);

    size_t sscratch = pgt->sscratch;
    CSR_SWAP(CSR_SSCRATCH, sscratch);

    // sscratch held guest a0
    pgt->uctx.xreg[9] = sscratch;

    // sepc held guest pc
    CSR_SWAP(CSR_SEPC, pgt->sepc);
    pgt->uctx.pc = pgt->sepc;

    // Restore actual initial host kernel sstatus
    CSR_WRITE(CSR_SSTATUS, pgt->sstatus);
#endif
}

int shadow_pgt_enter(struct shadow_pgt* pgt)
{
    pgt_spin_lock(&pgt->lock);
    pgt_debug_print("+shadow_pgt_enter()");
    shadow_pgt_enter_internal(pgt);
    pgt_debug_print("-shadow_pgt_enter()");
    pgt_spin_unlock(&pgt->lock);
    return 0;
}
