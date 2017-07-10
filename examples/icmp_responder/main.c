/*
 *------------------------------------------------------------------
 * Copyright (c) 2017 Cisco and/or its affiliates.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *------------------------------------------------------------------
 */

#include <stdlib.h>
#include <stdint.h>          
#include <net/if.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <netdb.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <asm/byteorder.h>
#include <byteswap.h>
#include <string.h>
#include <sys/epoll.h>
#include <errno.h>
#include <unistd.h>

#include <libmemif.h>

#define APP_NAME "ICMP_Responder"
#define IF_NAME  "memif_connection"

#define DBG(...) do {                                               \
                    printf (APP_NAME":%s:%d: ", __func__, __LINE__);         \
                    printf (__VA_ARGS__);                           \
                    printf ("\n");                                  \
                } while (0)

int epfd;
memif_conn_handle_t conn;

/* TODO: memif connection status report (memif_details...) */

int
add_epoll_fd (int fd, uint32_t events)
{
    if (fd < 0)
    {
        DBG ("invalid fd %d", fd);
        return -1;
    }
    struct epoll_event evt;
    memset (&evt, 0, sizeof (evt));
    evt.events = events;
    evt.data.fd = fd;
    if (epoll_ctl (epfd, EPOLL_CTL_ADD, fd, &evt) < 0)
    {
        DBG ("epoll_ctl: %s fd %d", strerror (errno), fd);
        return -1;
    }
    DBG ("fd %d added to epoll", fd);
    return 0;
}

int
del_epoll_fd (int fd)
{
    if (fd < 0)
    {
        DBG ("invalid fd %d", fd);
        return -1;
    }
    struct epoll_event evt;
    memset (&evt, 0, sizeof (evt));
    if (epoll_ctl (epfd, EPOLL_CTL_DEL, fd, &evt) < 0)
    {
        DBG ("epoll_ctl: %s fd %d", strerror (errno), fd);
        return -1;
    }
    DBG ("fd %d removed from epoll", fd);
    return 0;
}

/* informs user about connected status. private_ctx is used by user to identify connection
    (multiple connections WIP) */
int
on_connect (memif_conn_handle_t conn, void *private_ctx)
{
    DBG ("connected!");
    return 0;
}

/* informs user about disconnected status. private_ctx is used by user to identify connection
    (multiple connections WIP) */
int
on_disconnect (memif_conn_handle_t conn, void *private_ctx)
{
    DBG ("disconnected!");
    return 0;
}

/* user needs to watch new fd or stop watching fd that is about to be closed */
int
control_fd_update (int fd, uint8_t events)
{
    if (events & MEMIF_FD_EVENT_DEL)
        return del_epoll_fd (fd);

    uint32_t evt = 0;
    if (events & MEMIF_FD_EVENT_READ)
        evt |= EPOLLIN;
    if (events & MEMIF_FD_EVENT_WRITE)
        evt |= EPOLLOUT;

    return add_epoll_fd (fd, evt);
}

int
icmpr_memif_create (int is_master)
{
    /* setting memif connection arguments */
    memif_conn_args_t args;
    int fd = -1;
    memset (&args, 0, sizeof (args));
    args.is_master = is_master;
    args.log2_ring_size = 10;
    args.buffer_size = 2048;
    args.num_s2m_rings = 1;
    args.num_m2s_rings = 1;
    strncpy ((char *) args.interface_name, IF_NAME, strlen (IF_NAME));
    strncpy ((char *) args.instance_name, APP_NAME, strlen (APP_NAME));
    args.mode = 0;
    /* socket filename is not specified, because this app is supposed to
         connect to VPP over memif. so default socket filename will be used */

    args.interface_id = 0;
    /* last argument for memif_create (void * private_ctx) is used by user
       to identify connection. this context is returned with callbacks */
    int rv = memif_create (&conn, &args, on_connect, on_disconnect, NULL);
    if (rv < 0)
    {
        DBG ("memif create error!");
    }
    else
    {
        DBG ("memif created!");
    }
    return rv;
}

int
icmpr_memif_delete ()
{
    int rv = 0;
    /* disconenct then delete memif connection */
    rv = memif_delete (&conn);
    if (rv < 0)
    {
        DBG ("memif delete error!");
    }
    else
    {
        DBG ("memif deleted!");
    }
    return 0;
}

void
print_help ()
{
    printf ("LIBMEMIF EXAMPLE APP: %s\n", APP_NAME);
    printf ("==============================\n");
    printf ("libmemif version: %s\n", LIBMEMIF_VERSION);
    printf ("memif version: %d\n", MEMIF_VERSION);
    printf ("commands:\n");
    printf ("\thelp - prints this help\n");
    printf ("\texit - exit app\n");
    printf ("\tconn - create memif (slave-mode)\n");
    printf ("\tdel  - delete memif\n");
}

int
user_input_handler ()
{
    char *ui = (char *) malloc (256);
    char *r = fgets (ui, 256, stdin);
    if (ui[0] == '\n')
        return 0;
    ui = strtok (ui, " ");
    if (strncmp (ui, "exit", 4) == 0)
    {
        free (ui);
        icmpr_memif_delete ();
        exit (EXIT_SUCCESS);
    }
    else if (strncmp (ui, "help", 4) == 0)
    {
        print_help ();
        return 0;
    }
    else if (strncmp (ui, "conn", 4) == 0)
    {
        icmpr_memif_create (0);
        return 0;
    }
    else if (strncmp (ui, "del", 3) == 0)
    {
        icmpr_memif_delete ();
        return 0;
    }
    else
        DBG ("unknown command: %s", ui);
    return 0;
}

int
poll_event (int timeout)
{
    struct epoll_event evt, *e;
    int app_err = 0, memif_err = 0, en = 0;
    int tmp, nfd;
    memset (&evt, 0, sizeof (evt));
    evt.events = EPOLLIN | EPOLLOUT;
    en = epoll_pwait (epfd, &evt, 1, timeout, 0);
    if (en < 0)
    {
        DBG ("epoll_pwait: %s", strerror (errno));
        return -1;
    }
    if (en > 0)
    {
    /* this app does not use any other file descriptors than stds and memif control fds */
        if ( evt.data.fd > 2)
        {
            uint32_t events = 0;
            if (evt.events & EPOLLIN)
                events |= MEMIF_FD_EVENT_READ;
            if (evt.events & EPOLLOUT)
                events |= MEMIF_FD_EVENT_WRITE;
            if (evt.events & EPOLLERR)
                events |= MEMIF_FD_EVENT_ERROR;
            memif_err = memif_control_fd_handler (evt.data.fd, events);
        }
        else if (evt.data.fd == 0)
        {
            app_err = user_input_handler ();
        }
        else
        {
            DBG ("unexpected event at memif_epfd. fd %d", evt.data.fd);
        }
    }

    if ((app_err < 0) || (memif_err < 0))
    {
        if (app_err < 0)
            DBG ("user input handler error");
        if (memif_err < 0)
            DBG ("memif control fd handler error");
        return -1;
    }

    return 0;
}

int main ()
{
    epfd = epoll_create (1);
    add_epoll_fd (0, EPOLLIN);

    /* initialize global memif connection handle */
    conn = NULL;

    /* initialize memory interface */
    memif_init (control_fd_update);

    /* main loop */
    while (1)
    {
        if (poll_event (0) < 0)
        {
            DBG ("poll_event error!");
        }
    }
}
