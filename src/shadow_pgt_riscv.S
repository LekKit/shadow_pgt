/*
shadow_pgt_riscv.S - Shadow pagetable RISC-V context switching
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

#if __riscv_xlen == 64
#define REG_L ld
#define REG_S sd
#define REG_SIZE 8
#define UCONTEXT_SIZE 512
#else
#define REG_L lw
#define REG_S sw
#define REG_SIZE 4
#define UCONTEXT_SIZE 256
#endif

# YEAH we are fucking going to copy this code into trampoline page
.global shadow_pgt_trampoline_start
shadow_pgt_trampoline_start:

.global shadow_pgt_trap_handler
shadow_pgt_trap_handler:
    # Pointer to shadow_pgt is held in sscratch
    csrrw a0, sscratch, a0

    # Save guest registers except a0
    REG_S x1, REG_SIZE * 1(a0)
    REG_S x2, REG_SIZE * 2(a0)
    REG_S x3, REG_SIZE * 3(a0)
    REG_S x4, REG_SIZE * 4(a0)
    REG_S x5, REG_SIZE * 5(a0)
    REG_S x6, REG_SIZE * 6(a0)
    REG_S x7, REG_SIZE * 7(a0)
    REG_S x8, REG_SIZE * 8(a0)
    REG_S x9, REG_SIZE * 9(a0)
    REG_S x11, REG_SIZE * 11(a0)
    REG_S x12, REG_SIZE * 12(a0)
    REG_S x13, REG_SIZE * 13(a0)
    REG_S x14, REG_SIZE * 14(a0)
    REG_S x15, REG_SIZE * 15(a0)
    REG_S x16, REG_SIZE * 16(a0)
    REG_S x17, REG_SIZE * 17(a0)
    REG_S x18, REG_SIZE * 18(a0)
    REG_S x19, REG_SIZE * 19(a0)
    REG_S x20, REG_SIZE * 20(a0)
    REG_S x21, REG_SIZE * 21(a0)
    REG_S x22, REG_SIZE * 22(a0)
    REG_S x23, REG_SIZE * 23(a0)
    REG_S x24, REG_SIZE * 24(a0)
    REG_S x25, REG_SIZE * 25(a0)
    REG_S x26, REG_SIZE * 26(a0)
    REG_S x27, REG_SIZE * 27(a0)
    REG_S x28, REG_SIZE * 28(a0)
    REG_S x29, REG_SIZE * 29(a0)
    REG_S x30, REG_SIZE * 30(a0)
    REG_S x31, REG_SIZE * 31(a0)

    # Restore host kernel satp
    REG_L a1, (UCONTEXT_SIZE * 2) + (REG_SIZE * 1) (a0)
    csrw satp, a1

    # Damned TLB flush - maybe we'll be able to optimize it one day
    sfence.vma

    # Restore callee-saved host registers
    REG_L x2, UCONTEXT_SIZE + (REG_SIZE * 2) (a0)
    REG_L x3, UCONTEXT_SIZE + (REG_SIZE * 3) (a0)
    REG_L x4, UCONTEXT_SIZE + (REG_SIZE * 4) (a0)
    REG_L x8, UCONTEXT_SIZE + (REG_SIZE * 8) (a0)
    REG_L x9, UCONTEXT_SIZE + (REG_SIZE * 9) (a0)
    REG_L x18, UCONTEXT_SIZE + (REG_SIZE * 18) (a0)
    REG_L x19, UCONTEXT_SIZE + (REG_SIZE * 19) (a0)
    REG_L x20, UCONTEXT_SIZE + (REG_SIZE * 20) (a0)
    REG_L x21, UCONTEXT_SIZE + (REG_SIZE * 21) (a0)
    REG_L x22, UCONTEXT_SIZE + (REG_SIZE * 22) (a0)
    REG_L x23, UCONTEXT_SIZE + (REG_SIZE * 23) (a0)
    REG_L x24, UCONTEXT_SIZE + (REG_SIZE * 24) (a0)
    REG_L x25, UCONTEXT_SIZE + (REG_SIZE * 25) (a0)
    REG_L x26, UCONTEXT_SIZE + (REG_SIZE * 26) (a0)
    REG_L x27, UCONTEXT_SIZE + (REG_SIZE * 27) (a0)

    # We can now just return back into the kernel C code after the shadow_pgt_enter_trampoline call
    REG_L ra, UCONTEXT_SIZE(a0)
    ret

.global shadow_pgt_enter_trampoline
shadow_pgt_enter_trampoline:
    # Save host return address as return context PC
    REG_S ra, UCONTEXT_SIZE (a0)

    # Save callee-saved host registers
    REG_S x2, UCONTEXT_SIZE + (REG_SIZE * 2) (a0)
    REG_S x3, UCONTEXT_SIZE + (REG_SIZE * 3) (a0)
    REG_S x4, UCONTEXT_SIZE + (REG_SIZE * 4) (a0)
    REG_S x8, UCONTEXT_SIZE + (REG_SIZE * 8) (a0)
    REG_S x9, UCONTEXT_SIZE + (REG_SIZE * 9) (a0)
    REG_S x18, UCONTEXT_SIZE + (REG_SIZE * 18) (a0)
    REG_S x19, UCONTEXT_SIZE + (REG_SIZE * 19) (a0)
    REG_S x20, UCONTEXT_SIZE + (REG_SIZE * 20) (a0)
    REG_S x21, UCONTEXT_SIZE + (REG_SIZE * 21) (a0)
    REG_S x22, UCONTEXT_SIZE + (REG_SIZE * 22) (a0)
    REG_S x23, UCONTEXT_SIZE + (REG_SIZE * 23) (a0)
    REG_S x24, UCONTEXT_SIZE + (REG_SIZE * 24) (a0)
    REG_S x25, UCONTEXT_SIZE + (REG_SIZE * 25) (a0)
    REG_S x26, UCONTEXT_SIZE + (REG_SIZE * 26) (a0)
    REG_S x27, UCONTEXT_SIZE + (REG_SIZE * 27) (a0)

    # Restore shadow satp
    REG_L a1, (UCONTEXT_SIZE * 2) (a0)
    csrw satp, a1

    # Damned TLB flush - maybe we'll be able to optimize it one day
    sfence.vma

    # Restore guest registers except a0
    REG_L x1, REG_SIZE * 1(a0)
    REG_L x2, REG_SIZE * 2(a0)
    REG_L x3, REG_SIZE * 3(a0)
    REG_L x4, REG_SIZE * 4(a0)
    REG_L x5, REG_SIZE * 5(a0)
    REG_L x6, REG_SIZE * 6(a0)
    REG_L x7, REG_SIZE * 7(a0)
    REG_L x8, REG_SIZE * 8(a0)
    REG_L x9, REG_SIZE * 9(a0)
    REG_L x11, REG_SIZE * 11(a0)
    REG_L x12, REG_SIZE * 12(a0)
    REG_L x13, REG_SIZE * 13(a0)
    REG_L x14, REG_SIZE * 14(a0)
    REG_L x15, REG_SIZE * 15(a0)
    REG_L x16, REG_SIZE * 16(a0)
    REG_L x17, REG_SIZE * 17(a0)
    REG_L x18, REG_SIZE * 18(a0)
    REG_L x19, REG_SIZE * 19(a0)
    REG_L x20, REG_SIZE * 20(a0)
    REG_L x21, REG_SIZE * 21(a0)
    REG_L x22, REG_SIZE * 22(a0)
    REG_L x23, REG_SIZE * 23(a0)
    REG_L x24, REG_SIZE * 24(a0)
    REG_L x25, REG_SIZE * 25(a0)
    REG_L x26, REG_SIZE * 26(a0)
    REG_L x27, REG_SIZE * 27(a0)
    REG_L x28, REG_SIZE * 28(a0)
    REG_L x29, REG_SIZE * 29(a0)
    REG_L x30, REG_SIZE * 30(a0)
    REG_L x31, REG_SIZE * 31(a0)

    # Restore guest a0
    REG_L x10, REG_SIZE * 10(a0)

    # Return to shadow land context which is running in U-mode
    # This enables interrupts, we will eventually trap into shadow_pgt_trap_handler
    sret

.global shadow_pgt_trampoline_end
shadow_pgt_trampoline_end:
