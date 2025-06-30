#include <errno.h>
#include <limits.h>
#include <up.h>

#include <sys/epoll.h>

static upoll_t* ups[OPEN_MAX];
static int index = 1;

int
epoll_create(int size)
{
        if (index >= OPEN_MAX) {
                errno = ENFILE;
                return -1;
        }
        ups[index++] = upoll_create(size);
        return index - 1;
}

int
epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
        upoll_t* upq = ups[epfd];
        upoll_event_t* uevent = (upoll_event_t*) event;
        return upoll_ctl(upq, op, fd, uevent);
}

int
epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
        upoll_t* upq = ups[epfd];
        upoll_event_t* uevents = (upoll_event_t*) events;
        return upoll_wait(upq, uevents, maxevents, timeout);
}
