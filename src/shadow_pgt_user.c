/*
shadow_pgt_user.c - Shadow pagetable userspace testing
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

/*
 * This is for easier debug without fucking up your kernel
 * and rebooting it each time.
 */

#include <stdlib.h>
#include <stdio.h>
#include <sched.h>
#include <sys/mman.h>

#include "shadow_pgt.h"

struct pgt_pin_page_user {
    struct pgt_pin_page map;
    void* page;
};

int pgt_resched(void)
{
    sched_yield();
    return 1;
}

void pgt_debug_print(const char* str)
{
    printf("shadow_pgt: %s\n", str);
}

void* pgt_alloc_pages(size_t npages)
{
#ifdef USE_MMAP
    void* ret = mmap(NULL, (npages << 12), PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (ret == MAP_FAILED) ret = NULL;
    return ret;
#else
    return pgt_kvzalloc(npages << 12);
#endif
}

void pgt_free_pages(void* ptr, size_t npages)
{
#ifdef USE_MMAP
    if (ptr) {
        munmap(ptr, (npages << 12));
    }
#else
    pgt_kvfree(ptr);
    (void)npages;
#endif
}

size_t pgt_virt_to_phys(void* virt)
{
    // silly_cat.png
    return (size_t)virt;
}

void* pgt_kvzalloc(size_t size)
{
    return calloc(size, 1);
}

void pgt_kvfree(void* ptr)
{
    free(ptr);
}

struct pgt_pin_page* pgt_pin_user_page(size_t uaddr, bool write)
{
    void* page = (void*)uaddr;
    struct pgt_pin_page_user* pin_page = pgt_kvzalloc(sizeof(struct pgt_pin_page_user));
    if (!pin_page) {
        // Allocation failure
        return NULL;
    }
    (void)write;
    pin_page->page = page;
    pin_page->map.virt = page;
    pin_page->map.phys = pgt_virt_to_phys(pin_page->map.virt);
    return (struct pgt_pin_page*)pin_page;
}

void pgt_release_user_page(struct pgt_pin_page* u_page)
{
    // No releasing is to be done, WE ARE the userspace
    pgt_kvfree(u_page);
}

__asm__ (
".balign 4096\n"

".global shadow_pgt_trampoline_start\n"
"shadow_pgt_trampoline_start:\n"

".global shadow_pgt_enter_trampoline\n"
"shadow_pgt_enter_trampoline:\n"
"ret\n"

".global shadow_pgt_trap_handler\n"
"shadow_pgt_trap_handler:\n"
"ret\n"

".balign 4096\n"

".global shadow_pgt_trampoline_end\n"
"shadow_pgt_trampoline_end:\n"
);

int main()
{
    struct shadow_pgt* pgt = shadow_pgt_init();
    if (pgt == NULL) {
        pgt_debug_print("shadow_pgt_init() failed!");
        return -1;
    }

    struct shadow_map map = {
        .vaddr = 0,
        .size = ~0xFFFULL,
    };
    shadow_pgt_unmap(pgt, &map);

    shadow_pgt_free(pgt);
    return 0;
}
