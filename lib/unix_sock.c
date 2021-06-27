
#include "unix_sock.h"

#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/socket.h>
#include <fcntl.h>

#include "logger.h"

int unix_sock_create(const char *name)
{
    int fd;
    if ((fd = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
        logger(LOG_LIB, L_CRITICAL, "Unix socket create failed\n");
        return -1;
    }

    struct sockaddr_un un;
    memset(&un, 0, sizeof(un));
    un.sun_family = AF_UNIX;
    strncpy(un.sun_path, name, sizeof(un.sun_path));
    int un_size = offsetof(struct sockaddr_un, sun_path) + strlen(un.sun_path);
    unlink(name);
    if (bind(fd, (struct sockaddr *) &un, un_size) < 0) {
        logger(LOG_LIB, L_CRITICAL, "Unix socket bind failed");
        close(fd);
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    return fd;
}

int unix_sock_destroy(int fd, const char *name)
{
    unlink(name);
    close(fd);
    return 0;
}

int unix_sock_read(int fd, void *buf, int buf_size)
{
    return read(fd, buf, buf_size);
}
