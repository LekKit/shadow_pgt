/*
shadow_pgt.h - Shadow pagetable kernel module
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

#ifndef SHADOW_PGT_H
#define SHADOW_PGT_H

#include "shadow_pgt_uapi.h"

struct shadow_pgt_pin_page {
    struct page* kdata;
    void* kernel_va;
    size_t phys;
};

/*
 * Reschedule while in-kernel
 */

int pgt_resched(void);

/*
 * Debug printk
 */

void pgt_debug_print(const char* str);

/*
 * Kernel virtual page allocation
 */

void* pgt_alloc_pages(size_t npages);

void pgt_free_pages(void* ptr, size_t npages);

/*
 * Kernel virtual address to physical address
 */

size_t pgt_virt_to_phys(void* virt);

/*
 * Kernel heap allocations
 */

void* pgt_kvzalloc(size_t size);

void pgt_kvfree(void* ptr);

/*
 * Pinning user pages
 */

struct shadow_pgt_pin_page* pgt_pin_user_page(size_t uaddr, bool write);

void pgt_release_user_page(struct shadow_pgt_pin_page* pin_page);

/*
 * Shadow pagetable internal APIs
 */

struct shadow_pgt {
    struct shadow_ucontext uctx;
    struct shadow_ucontext sctx;
#ifdef __riscv
    // Pagetable swap host kernel <-> shadow land
    size_t shadow_satp;
    size_t satp;

    // Host kernel state save while switched
    size_t sstatus;
    size_t sscratch;
    size_t stvec;
    size_t sepc;
#endif
};

struct shadow_pgt* shadow_pgt_init(void);

void shadow_pgt_free(struct shadow_pgt* pgt);

int shadow_pgt_map(struct shadow_pgt* pgt, const struct shadow_map* map);

int shadow_pgt_unmap(struct shadow_pgt* pgt, const struct shadow_map* map);

/*
 * Context switch internal APIs
 */

int shadow_pgt_enter(struct shadow_pgt* pgt);

// ASM stuff
extern const char shadow_pgt_trampoline_start;

void shadow_pgt_enter_trampoline(struct shadow_pgt* pgt);

void shadow_pgt_trap_handler(void);

extern const char shadow_pgt_trampoline_end;


#endif