#ifndef __UNIX_SOCK_H__
#define __UNIX_SOCK_H__

int unix_sock_create(const char *name);

int unix_sock_read(int fd, void *buf, int buf_size);

#endif /* __UNIX_SOCK_H__ */