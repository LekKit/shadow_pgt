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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
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
    if (ptr) {
        // Debug page presence
        memset(ptr, 0, 12 << npages);
        pgt_kvfree(ptr);
    }
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

static uint64_t rvtimer_clocksource(uint64_t freq)
{
    struct timespec now = {0};
    clock_gettime(CLOCK_REALTIME, &now);
    return (now.tv_sec * freq) + (now.tv_nsec * freq / 1000000000ULL);
}

static void rvvm_randombytes(void* buffer, size_t size)
{
    // Xorshift RNG seeded by precise timer
    static bool init = false;
    static uint64_t seed = 0;
    uint8_t* bytes = buffer;
    size_t size_rem = size & 0x7;

    if (!init) {
        seed = rvtimer_clocksource(1000000000ULL);
    }

    size -= size_rem;
    for (size_t i=0; i<size; i += 8) {
        seed ^= (seed >> 17);
        seed ^= (seed << 21);
        seed ^= (seed << 28);
        seed ^= (seed >> 49);
        memcpy(bytes + i, &seed, 8);
    }
    seed ^= (seed >> 17);
    seed ^= (seed << 21);
    seed ^= (seed << 28);
    seed ^= (seed >> 49);
    memcpy(bytes + size, &seed, size_rem);
}

static inline uint64_t sign_extend(uint64_t val, uint8_t bits)
{
    return ((int64_t)(val << (64 - bits))) >> (64 - bits);
}

static size_t random_page(void)
{
    size_t random = 0;
    rvvm_randombytes(&random, sizeof(random));
    return sign_extend(random & ~0xFFFULL, 39);
}

int main()
{
    struct shadow_pgt* pgt = shadow_pgt_init();
    if (pgt == NULL) {
        pgt_debug_print("shadow_pgt_init() failed!");
        return -1;
    }

    for (size_t t = 0; t < 10; ++t) {
        for (size_t i = 0; i < 10000; ++i) {
            struct shadow_map map = {
                .vaddr = random_page(),
                .size = 0x1000,
                .flags = SHADOW_PGT_RWX,
            };
            if (shadow_pgt_map(pgt, &map)) {
                pgt_debug_print("shadow_pgt_map() failed!");
            }
        }

        for (size_t i = 0; i < 100000; ++i) {
            struct shadow_map map = {
                .vaddr = random_page(),
                .size = 0x1000,
                .flags = SHADOW_PGT_RWX,
            };
            if (shadow_pgt_unmap(pgt, &map)) {
                pgt_debug_print("shadow_pgt_unmap() failed!");
            }
        }
    }

    {
        struct shadow_map map = {
            .vaddr = (size_t)&shadow_pgt_trampoline_start,
            .size = 0x1000,
            .flags = SHADOW_PGT_RWX,
        };
        if (shadow_pgt_map(pgt, &map)) {
            pgt_debug_print("shadow_pgt_unmap() failed!");
        }
    }

    {
        struct shadow_map map = {
            .vaddr = (size_t)pgt,
            .size = 0x1000,
            .flags = SHADOW_PGT_RWX,
        };
        if (shadow_pgt_map(pgt, &map)) {
            pgt_debug_print("shadow_pgt_unmap() failed!");
        }
    }

    {
        struct shadow_map map = {
            .vaddr = 0,
            .size = ~0xFFFULL,
        };
        if (shadow_pgt_unmap(pgt, &map)) {
            pgt_debug_print("shadow_pgt_unmap() failed!");
        }
    }

    shadow_pgt_free(pgt);
    return 0;
}
