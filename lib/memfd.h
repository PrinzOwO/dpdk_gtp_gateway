#ifndef __MEMFD_H__
#define __MEMFD_H__

#define MAX_MEMFD_SIZE 1024

void *memfd_malloc(int *ret_fd, char *ret_filename, int filename_len);

void memfd_free(void *ptr);

#endif /* __MEMFD_H__ */