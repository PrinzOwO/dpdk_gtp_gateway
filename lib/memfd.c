#include "memfd.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mman.h>

#include "logger.h"

void *memfd_malloc(int *ret_fd, char *ret_filename, int filename_len)
{
    *ret_fd = memfd_create("memfd_memory", O_RDWR);
    if (*ret_fd < 0) {
        logger(LOG_LIB, L_CRITICAL, "memfd_create failed: %s \n", strerror(errno));
        return NULL;
    }

    if (ftruncate(*ret_fd, MAX_MEMFD_SIZE) < 0) {
        logger(LOG_LIB, L_CRITICAL, "ftruncate failed: %s \n", strerror(errno));
        close(*ret_fd);
        return NULL;
    }

    void *ptr = mmap(NULL, MAX_MEMFD_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, *ret_fd, 0);
    memset(ptr, 0, MAX_MEMFD_SIZE);

    snprintf(ret_filename, filename_len, "/proc/%d/fd/%d", getpid(), *ret_fd);

    return ptr;
}

void memfd_free(void *ptr)
{
    munmap(ptr, MAX_MEMFD_SIZE);
}
