/* epoll.h
 Copyright (c) fd0, All rights reserved.

 This library is free software; you can redistribute it and/or
 modify it under the terms of the GNU Lesser General Public
 License as published by the Free Software Foundation; either
 version 3.0 of the License, or (at your option) any later version.

 This library is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 Lesser General Public License for more details.

 You should have received a copy of the GNU Lesser General Public
 License along with this library.*/

#ifndef	_SYS_EPOLL_H
#define	_SYS_EPOLL_H 1

#include <stdint.h>
#include <sys/types.h>

#ifndef OPEN_MAX
#define OPEN_MAX 256
#endif

#ifndef __EPOLL_PACKED
# define __EPOLL_PACKED __attribute__ ((__packed__))
#endif

#define EPOLLIN  0x01
#define EPOLLOUT 0x02
#define EPOLLERR 0x04
#define EPOLLET  0x08
#define EPOLLHUP 0x010

/* Valid opcodes ( "op" parameter ) to issue to epoll_ctl().  */
#define EPOLL_CTL_ADD 1	/* Add a file descriptor to the interface.  */
#define EPOLL_CTL_DEL 2	/* Remove a file descriptor from the interface.  */
#define EPOLL_CTL_MOD 3	/* Change file descriptor epoll_event structure.  */

typedef union epoll_data
{
  void *ptr;
  int fd;
  uint32_t u32;
  uint64_t u64;
} epoll_data_t;

struct epoll_event
{
  uint32_t events; /* Epoll events */
  epoll_data_t data; /* User data variable */
};

#ifdef __cplusplus
extern "C" {
#endif

int
epoll_create (int size);

int
epoll_ctl (int epfd, int op, int fd, struct epoll_event *event);

int
epoll_wait (int epfd, struct epoll_event *events, int maxevents, int timeout);

#ifdef __cplusplus
}
#endif

#endif /* sys/epoll.h */
