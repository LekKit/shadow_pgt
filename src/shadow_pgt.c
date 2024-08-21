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

#define compiler_barrier() __asm__ __volatile__ ("" : : : "memory")

#ifdef __riscv

#define CSR_SSTATUS    0x100
#define CSR_STVEC      0x105
#define CSR_SCOUNTEREN 0x106
#define CSR_SSCRATCH   0x140
#define CSR_SEPC       0x141
#define CSR_SATP       0x180

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

// Allocate PTEs for given virtual address in a pagetable
static pgt_pte_t* pgt_alloc_page_pte(pgt_pte_t* pagetable, size_t vaddr)
{
    uint8_t bit_off = (SV_LEVELS * SV64_VPN_BITS) + MMU_PAGE_SHIFT - SV64_VPN_BITS;

    for (size_t i = SV_LEVELS; i--;) {
        size_t pgt_entry = (vaddr >> bit_off) & SV64_VPN_MASK;
        if (i == 0) {
            if (pagetable[pgt_entry]) {
                pgt_debug_print("Page vaddr is already claimed!");
                return NULL;
            } else {
                return &pagetable[pgt_entry];
            }
        } else {
            void* next_pagetable = (void*)pagetable[PAGETABLE_PTES + pgt_entry];
            if (next_pagetable) {
                pagetable = next_pagetable;
            } else {
                // Allocate pagetable level
                next_pagetable = pgt_alloc_pages(2);
                if (next_pagetable) {
                    // Map magetable level
                    size_t table_phys = pgt_virt_to_phys(next_pagetable);
                    pagetable[PAGETABLE_PTES + pgt_entry] = (pgt_pte_t)next_pagetable;
                    pagetable[pgt_entry] = ((table_phys & MMU_PAGE_PNMASK) >> 2) | MMU_VALID_PTE;
                    pagetable = next_pagetable;
                } else {
                    // Allocation failure
                    return NULL;
                }
            }
        }
        bit_off -= SV64_VPN_BITS;
    }
    return NULL;
}

// Map userspace page into pagetable
// TODO: Test this!
static bool pgt_map_user_page(pgt_pte_t* pagetable, const struct shadow_map* map)
{
    struct pgt_pin_page* pin_page = pgt_pin_user_page((size_t)map->uaddr,  (map->flags & SHADOW_PGT_WRITE));
    if (pin_page == NULL) {
        // Failed to pin user page
        return false;
    }

    pgt_pte_t* pte = pgt_alloc_page_pte(pagetable, map->vaddr);
    if (pte == NULL) {
        // Failed to allocate PTE
        pgt_release_user_page(pin_page);
        return false;
    }

    pgt_pte_t flags = MMU_VALID_PTE | MMU_USER_USABLE | MMU_PAGE_ACCESSED | MMU_PAGE_DIRTY | (map->flags & SHADOW_PGT_RWX);
    *pte = ((pin_page->phys & MMU_PAGE_PNMASK) >> 2) | flags;
    pte[PAGETABLE_PTES] = (pgt_pte_t)pin_page;
    return true;
}

// Map kernel page into pagetable, uaddr is used as kernel virtual address
// DO NOT EVER PASS KERNEL SYMBOL ADDRESSES HERE BECAUSE LINUX WILL FUCK EVERYTHING UP
// Thanks Linux! (1)
static bool pgt_map_kernel_page(pgt_pte_t* pagetable, const struct shadow_map* map)
{
    pgt_pte_t* pte = pgt_alloc_page_pte(pagetable, map->vaddr);
    if (pte == NULL) {
        // Failed to allocate PTE
        return false;
    }

    size_t page_phys = pgt_virt_to_phys(map->uaddr);
    pgt_pte_t flags = MMU_VALID_PTE | MMU_PAGE_ACCESSED | MMU_PAGE_DIRTY | (map->flags & SHADOW_PGT_RWX);
    *pte = ((page_phys & MMU_PAGE_PNMASK) >> 2) | flags;
    return true;
}

static inline size_t pgt_vpn2_shifted(size_t virt)
{
    const uint8_t bit_off = (SV_LEVELS * SV64_VPN_BITS) + MMU_PAGE_SHIFT - SV64_VPN_BITS;
    return (virt >> bit_off) & SV64_VPN_MASK;
}

// Free pagetable entries and unmap pages from virt_start to virt_end
static bool pgt_free_pagetable(pgt_pte_t* pagetable, size_t virt_start, size_t virt_end, bool free)
{
    if (pagetable == NULL) {
        return false;
    }

    bool free_pgt_level = free && pgt_vpn2_shifted(virt_start) == 0 && pgt_vpn2_shifted(virt_end) == SV64_VPN_MASK;
    for (size_t i = pgt_vpn2_shifted(virt_start); i <= pgt_vpn2_shifted(virt_end); ++i) {
        pgt_pte_t pte = pagetable[i];

        if (pte & MMU_VALID_PTE) {
            if (pte & MMU_LEAF_PTE) {
                if (pte & MMU_USER_USABLE) {
                    // Release a pinned user page
                    struct pgt_pin_page* pin_page = (void*)pagetable[PAGETABLE_PTES + i];
                    pagetable[PAGETABLE_PTES + i] = 0;
                    pgt_release_user_page(pin_page);
                    // Unmap user page PTE
                    pagetable[i] = 0;
                }
            } else {
                // Free pagetable level
                pgt_pte_t* next_pagetable = (void*)pagetable[PAGETABLE_PTES + i];
                if (pgt_free_pagetable(next_pagetable, virt_start << SV64_VPN_BITS, virt_end << SV64_VPN_BITS, true)) {
                    // Unmap pagetable PTE
                    pagetable[i] = 0;
                    pagetable[PAGETABLE_PTES + i] = 0;
                } else {
                    // Keep parent pageteble level
                    free_pgt_level = false;
                }
            }
        }
    }

    if (free_pgt_level) {
        // Free whole pagetable level
        pgt_free_pages(pagetable, 2);
        return true;
    }

    return false;
}

struct shadow_pgt* shadow_pgt_init(void)
{
    pgt_debug_print("+shadow_pgt_init()");

    size_t trampoline_size = (size_t)(&shadow_pgt_trampoline_end - &shadow_pgt_trampoline_start);
    if (trampoline_size > MMU_PAGE_SIZE) {
        pgt_debug_print("Trampoline code doesn't fit into page!!!");
        return NULL;
    }
    if (sizeof(struct shadow_pgt) > MMU_PAGE_SIZE) {
        pgt_debug_print("struct shadow_pgt doesn't fit into page!!!");
        return NULL;
    }

    struct shadow_pgt* pgt = pgt_alloc_pages(1);
    if (pgt == NULL) {
        // Allocation failure
        return NULL;
    }

    pgt->pagetable = pgt_alloc_pages(2);
    if (pgt->pagetable == NULL) {
        // Allocation failure
        shadow_pgt_free(pgt);
        return NULL;
    }

    // Linux doesn't let us allocate executable pages so we can't randomize trampoline page...
    // Thanks Linux! (2)
    pgt->shadow_trampoline_page = pgt_alloc_pages(1);
    if (pgt->shadow_trampoline_page == NULL) {
        // Allocation failure
        shadow_pgt_free(pgt);
        return NULL;
    }

    // Ugly hack because Linux doesn't let us use memcpy on kernel code
    // Thanks Linux! (3)
    volatile char* trampoline_page = pgt->shadow_trampoline_page;
    for (size_t i = 0; i < trampoline_size; ++i) {
        trampoline_page[i] = ((volatile char*)(&shadow_pgt_trampoline_start))[i];
    }

    // Map trampoline code into shadow pagetable
    struct shadow_map trampoline_code = {
        .uaddr = pgt->shadow_trampoline_page,
        .vaddr = (size_t)&shadow_pgt_trampoline_start,
        .size = MMU_PAGE_SIZE,
        .flags = SHADOW_PGT_READ | SHADOW_PGT_EXEC,
    };
    if (!pgt_map_kernel_page(pgt->pagetable, &trampoline_code)) {
        // Failed to map trampoline code page
        pgt_debug_print("Failed to map trampoline code!");
        shadow_pgt_free(pgt);
        return NULL;
    }

    // Map pgt context into shadow pagetable
    struct shadow_map pgt_map = {
        .uaddr = pgt,
        .vaddr = (size_t)pgt,
        .size = MMU_PAGE_SIZE,
        .flags = SHADOW_PGT_READ | SHADOW_PGT_WRITE,
    };
    if (!pgt_map_kernel_page(pgt->pagetable, &pgt_map)) {
        // Failed to map trampoline state page
        pgt_debug_print("Failed to map trampoline state!");
        shadow_pgt_free(pgt);
        return NULL;
    }

#ifdef __riscv
    // Shadow pagetable uses SV39 MMU mode
    pgt->shadow_satp = (pgt_virt_to_phys(pgt->pagetable) >> 12) | (8ULL << 60);
#endif

    pgt_debug_print("-shadow_pgt_init()");
    return pgt;
}

void shadow_pgt_free(struct shadow_pgt* pgt)
{
    pgt_debug_print("+shadow_pgt_free()");
    if (pgt->pagetable) {
        pgt_free_pagetable(pgt->pagetable, 0, -1, true);
    }
    if (pgt->shadow_trampoline_page) {
        pgt_free_pages(pgt->shadow_trampoline_page, 1);
    }
    pgt_free_pages(pgt, 1);
    pgt_debug_print("-shadow_pgt_free()");
}

int shadow_pgt_map(struct shadow_pgt* pgt, const struct shadow_map* map)
{
    int ret = 0;
    struct shadow_map tmp = *map;
    if ((map->size & 0xFFF) || (map->vaddr & 0xFFF) || (((size_t)map->uaddr) & 0xFFF)) {
        // Misaligned mapping
        pgt_debug_print("Misaligned mapping!");
        return -22; // EINVAL
    }
    if (sign_extend(map->vaddr, 39) != map->vaddr) {
        // Non-canonical address for sv39
        pgt_debug_print("Non-canonical address!");
        return -22; // EINVAL
    }
    if (!(map->flags & MMU_LEAF_PTE)) {
        // Tried to map non-leaf page!
        pgt_debug_print("Non-leaf page!");
        return -22; // EINVAL
    }

    pgt_spin_lock(&pgt->lock);

    size_t virt_pgt = (size_t)pgt;
    size_t virt_code = (size_t)&shadow_pgt_trampoline_start;
    for (size_t i = 0; i < map->size; i += MMU_PAGE_SIZE) {
        size_t vaddr = map->vaddr + i;
        if (vaddr != virt_pgt && vaddr != virt_code) {
            // Not overlapping kernel trampoline pages, good to go
            tmp.vaddr = vaddr;
            pgt_free_pagetable(pgt->pagetable, vaddr, vaddr, false);
            if (!pgt_map_user_page(pgt->pagetable, &tmp)) {
                ret = -12; // ENOMEM
            }
        } else {
            // TODO: Trampoline page should try to run away from collisions
            pgt_debug_print("Don't touch my trampoline dammit!");
            ret = -1; // EPERM
        }
    }

    pgt_spin_unlock(&pgt->lock);
    return ret;
}

static void shadow_pgt_unmap_split(struct shadow_pgt* pgt, size_t virt_start, size_t virt_end)
{
    size_t virt_pgt = (size_t)pgt;
    size_t virt_code = (size_t)&shadow_pgt_trampoline_start;
    if (virt_start <= virt_pgt && virt_end >= virt_pgt) {
        // Split unmapping around trampoline state page
        if (virt_start < virt_pgt) {
            shadow_pgt_unmap_split(pgt, virt_start, virt_pgt - MMU_PAGE_SIZE);
        }
        if (virt_end > virt_pgt) {
            shadow_pgt_unmap_split(pgt, virt_pgt + MMU_PAGE_SIZE, virt_end);
        }
    } else if (virt_start <= virt_code && virt_end >= virt_code) {
        // Split unmapping around trampoline code page
        if (virt_start < virt_code) {
            shadow_pgt_unmap_split(pgt, virt_start, virt_code - MMU_PAGE_SIZE);
        }
        if (virt_end > virt_code) {
            shadow_pgt_unmap_split(pgt, virt_code + MMU_PAGE_SIZE, virt_end);
        }
    } else {
        pgt_free_pagetable(pgt->pagetable, virt_start, virt_end, false);
    }
}

int shadow_pgt_unmap(struct shadow_pgt* pgt, const struct shadow_map* map)
{
    if ((map->size & 0xFFF) || (map->vaddr & 0xFFF) || (((size_t)map->uaddr) & 0xFFF)) {
        // Misaligned mapping
        pgt_debug_print("Misaligned mapping!");
        return -22; // EINVAL
    }

    pgt_spin_lock(&pgt->lock);

    // TODO make proper unmapper work
    shadow_pgt_unmap_split(pgt, map->vaddr, map->vaddr + map->size - MMU_PAGE_SIZE);

    pgt_spin_unlock(&pgt->lock);
    return 0;
}

static void shadow_pgt_enter_internal(struct shadow_pgt* pgt)
{
#ifdef __riscv
    // Disable interrupts in current context, set return mode to U-mode
    size_t sstatus = CSR_SSTATUS_SIE | CSR_SSTATUS_SPIE | CSR_SSTATUS_SPP;
    CSR_CLEARBITS(CSR_SSTATUS, sstatus);

    // Save previous sstatus
    pgt->sstatus = sstatus;

    // Disable access to time CSR
    pgt->scounteren = 0;
    CSR_SWAP(CSR_SCOUNTEREN, pgt->scounteren);

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

    // Restore scounteren
    CSR_WRITE(CSR_SCOUNTEREN, pgt->scounteren);

    // Restore actual initial host kernel sstatus
    CSR_WRITE(CSR_SSTATUS, pgt->sstatus);
#else
    (void)pgt;
#endif
}

int shadow_pgt_enter(struct shadow_pgt* pgt)
{
    pgt_spin_lock(&pgt->lock);
    //pgt_debug_print("+shadow_pgt_enter()");
    shadow_pgt_enter_internal(pgt);
    //pgt_debug_print("-shadow_pgt_enter()");
    pgt_spin_unlock(&pgt->lock);
    return 0;
}
