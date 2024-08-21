/*
shadow_pgt_linux.c - Shadow pagetable Linux kernel module
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

/*
 * Module stuff headers
 */

#include <linux/module.h>   // MODULE_*, module_*

#include <linux/fs.h>       // file_operations, alloc_chrdev_region, unregister_chrdev_region
#include <linux/miscdevice.h>

#include <asm/uaccess.h>    // copy_from_user(), copy_to_user()

MODULE_AUTHOR("LekKit");
MODULE_LICENSE("GPL");

/*
 * Kernel-specific wrappers
 */

#include <linux/slab.h>     // kmalloc(), kfree()
#include <linux/mm.h>       // get_user_pages_fast()
#include <linux/highmem.h>  // kmap(), kunmap()

#include <asm/io.h>         // virt_to_phys()

struct pgt_pin_page_linux {
    struct pgt_pin_page map;
    struct page* page;
};

int pgt_resched(void)
{
    if (need_resched()) {
        schedule();
    }

    return signal_pending(current);
}

void pgt_debug_print(const char* str)
{
    printk(KERN_ERR "shadow_pgt: %s\n", str);
}

void* pgt_alloc_pages(size_t npages)
{
    void* ret = (void*)__get_free_pages (GFP_KERNEL, get_order(npages << 12));
    if (!ret) {
        // Allocation failure
        return NULL;
    }

    // Zero pages
    for (size_t i = 0; i < npages; ++i) {
        clear_page(ret + (i << 12));
    }

    return ret;
}

void pgt_free_pages(void* ptr, size_t npages)
{
    if (ptr) {
        free_pages((unsigned long)ptr, get_order(npages << 12));
    }
}

size_t pgt_virt_to_phys(void* virt)
{
    return virt_to_phys(virt);
}

void* pgt_kvzalloc(size_t size)
{
    return kvzalloc(size, GFP_KERNEL);
}

void pgt_kvfree(void* ptr)
{
    if (ptr) {
        kvfree(ptr);
    }
}

struct pgt_pin_page* pgt_pin_user_page(size_t uaddr, bool write)
{
    struct page* page = NULL;
    struct pgt_pin_page_linux* pin_page = pgt_kvzalloc(sizeof(struct pgt_pin_page_linux));
    if (!pin_page) {
        // Allocation failure
        return NULL;
    }
    if (get_user_pages_fast(uaddr, 1, write, &page) != 1) {
        // Failed to pin userspace page
        pgt_kvfree(pin_page);
        return NULL;
    }
    pin_page->page = page;
    pin_page->map.virt = kmap(page);
    pin_page->map.phys = pgt_virt_to_phys(pin_page->map.virt);
    return (struct pgt_pin_page*)pin_page;
}

void pgt_release_user_page(struct pgt_pin_page* u_page)
{
    struct pgt_pin_page_linux* pin_page = (struct pgt_pin_page_linux*)u_page;
    kunmap(pin_page->page);
    put_page(pin_page->page);
    pgt_kvfree(pin_page);
}

/*
 * Module entry points
 */

static int shadow_pgt_open(struct inode* inode, struct file* filp)
{
    struct shadow_pgt* pgt = shadow_pgt_init();
    if (pgt == NULL) return -ENOMEM;

    filp->private_data = pgt;

    return 0;
}

static int shadow_pgt_release(struct inode* inode, struct file* filp)
{
    struct shadow_pgt* pgt = filp->private_data;

    shadow_pgt_free(pgt);

    return 0;
}

static long shadow_pgt_ioctl(struct file* filp, unsigned int cmd, unsigned long data)
{
    struct shadow_pgt* pgt = filp->private_data;

    switch (cmd) {
        case SHADOW_PGT_MAP: {
            struct shadow_map map = {0};
            if (copy_from_user(&map, (void*)data, sizeof(struct shadow_map))) {
                // Failed to copy struct shadow_map from userland
                return -EFAULT;
            }
            if (!access_ok(map.uaddr, map.size)) {
                // map.uaddr points outside of user address space
                return -EFAULT;
            }
            return shadow_pgt_map(pgt, &map);
        }
        case SHADOW_PGT_UNMAP: {
            struct shadow_map map = {0};
            if (copy_from_user(&map, (void*)data, sizeof(struct shadow_map))) {
                // Failed to copy struct shadow_map from userland
                return -EFAULT;
            }
            return shadow_pgt_unmap(pgt, &map);
        }
        case SHADOW_PGT_ENTER: {
            if (copy_from_user(&pgt->uctx, (void*)data, sizeof(struct shadow_ucontext))) {
                // Failed to copy struct shadow_ucontext from userland
                return -EFAULT;
            }
            int ret = shadow_pgt_enter(pgt);
            if (ret != 0) {
                // shadow_pgt_enter() failed
                return ret;
            }
            if (copy_to_user((void*)data, &pgt->uctx, sizeof(struct shadow_ucontext))) {
                return -EFAULT;
            }
            return 0;
        }
    }

    return -EINVAL;
}

static struct file_operations shadow_pgt_fops = {
    .owner = THIS_MODULE,
    .open = shadow_pgt_open,
    .unlocked_ioctl = shadow_pgt_ioctl,
    .release = shadow_pgt_release,
};

static struct miscdevice shadow_pgt_cdevsw = {
    .minor = MISC_DYNAMIC_MINOR,
    .name = "shadow_pgt",
    .fops = &shadow_pgt_fops,
    .mode = 0666,
};

static int __init shadow_pgt_init_module(void)
{
    int ret = misc_register(&shadow_pgt_cdevsw);
    if (ret) {
        printk(KERN_ERR "shadow_pgt: misc_register() failed\n");
        return ret;
    }

    printk(KERN_INFO "shadow_pgt: Shadow pagetable for userspace (C) LekKit 2024\n");

    size_t trampoline_size = (size_t)(&shadow_pgt_trampoline_end - &shadow_pgt_trampoline_start);
    printk(KERN_ERR "shadow_pgt: Trampoline size: %ld bytes\n", trampoline_size);
    printk(KERN_ERR "shadow_pgt: shadow_ucontext size: %ld bytes\n", sizeof(struct shadow_ucontext));

    return 0;
}

static void __exit shadow_pgt_exit_module(void)
{
    misc_deregister(&shadow_pgt_cdevsw);

    printk(KERN_ERR "shadow_pgt: K thx bye\n");
}

module_init(shadow_pgt_init_module);
module_exit(shadow_pgt_exit_module);
