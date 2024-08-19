/*
shadow_pgt_uapi.h - Shadow pagetable UAPI
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

#ifndef SHADOW_PGT_UAPI
#define SHADOW_PGT_UAPI

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

struct shadow_map {
    size_t vaddr;   // Pointer in shadow VM space
    void* uaddr;    // Userspace address
    size_t size;    // Must be page-aligned!
    uint32_t flags; // Mapping R/W/X flags
};

struct shadow_ucontext {
#ifdef __riscv
    size_t pc;
    size_t xreg[31];
    double freg[32];
#endif
};

/*
 * Mapping R/W/X flags
 */

#define SHADOW_PGT_READ  0x2
#define SHADOW_PGT_WRITE 0x4
#define SHADOW_PGT_EXEC  0x8

/*
 * Shadow pagetable ioctls
 */

// Map the range, arg: struct shadow_map*
#define SHADOW_PGT_MAP   0xFFAA

// Unmap the range, arg: struct shadow_map*
#define SHADOW_PGT_UNMAP 0xFFAB

// Run the CPU with passed context, arg: struct shadow_ucontext*
#define SHADOW_PGT_ENTER 0xFFAC

#ifdef __cplusplus
}
#endif

#endif
