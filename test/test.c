#include "shadow_pgt_uapi.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

int main()
{
    int pgt_fd = open("/dev/shadow_pgt", O_RDONLY);

    if (pgt_fd < 0) {
        printf("Failed to open /dev/shadow_pgt: %s\n", strerror(errno));
        return -1;
    }

    printf("Opened /dev/shadow_pgt!\n");

    struct shadow_ucontext ctx = {0};

    int ret = ioctl(pgt_fd, SHADOW_PGT_ENTER, &ctx);
    if (ret != 0) {
        printf("ioctl(SHADOW_PGT_ENTER) failed: %s\n", strerror(errno));
    }

    printf("Returned from SHADOW_PGT_ENTER!\n");
    close(pgt_fd);
    return 0;
}
