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
#include <signal.h>

#include <libmemif.h>
#include <icmp_proto.h>

#define APP_NAME "ICMP_Responder"
#define IF_NAME  "memif_connection"


#ifdef ICMP_DBG
#define DBG(...) do {                                               \
                    printf (APP_NAME":%s:%d: ", __func__, __LINE__);         \
                    printf (__VA_ARGS__);                           \
                    printf ("\n");                                  \
                } while (0)
#else
#define DBG(...)
#endif

#define INFO(...) do {                                              \
                    printf ("INFO: "__VA_ARGS__);                   \
                    printf ("\n");                                  \
                } while (0)

int epfd;

/*
 * WIP
 */
/* interrupt fd specific for queue */
typedef struct
{
    uint16_t qid;
    int fd;
} int_fd_t;

typedef struct
{
    uint16_t index;
    /* memif conenction handle */
    memif_conn_handle_t conn;
    /* interrupt file descriptor (specific for each queue) */
    int_fd_t *int_fd;
    /* tx buffers */
    memif_buffer_t **tx_bufs;
    /* number of allocated tx buffers */
    uint16_t tx_buf_num;
    /* rx buffers */
    memif_buffer_t **rx_bufs;
    /* number of allocated rx buffers */
    uint16_t rx_buf_num;
} memif_connection_t;

memif_connection_t memif_connection;

static void
print_memif_details ()
{
    memif_connection_t *c = &memif_connection;
    printf ("MEMIF DETAILS\n");
    printf ("==============================\n");

    /* TODO: loop for all connections */
    if (c->conn == NULL)
    {
        printf ("no connection!\n");
        return;
    }
    memif_details_t md = memif_get_details (c->conn);
    printf ("\tinterface name: %s\n",(char *) md.if_name);
    printf ("\tapp name: %s\n",(char *) md.inst_name);
    printf ("\tremote interface name: %s\n",(char *) md.remote_if_name);
    printf ("\tremote app name: %s\n",(char *) md.remote_inst_name);
    printf ("\tid: %u\n", md.id);
    printf ("\tsecret: %s\n",(char *) md.secret);
    printf ("\trole: ");
    if (md.role)
        printf ("slave\n");
    else
        printf ("master\n");
    printf ("\tmode: ");
    switch (md.mode)
    {
        case 0:
            printf ("ethernet\n");
            break;
        case 1:
            printf ("ip\n");
            break;
        case 2:
            printf ("punt/inject\n");
            break;
        default:
            printf ("unknown\n");
            break;
    }
    printf ("\tsocket filename: %s\n",(char *) md.socket_filename);
    printf ("\tring_size: %u\n", md.ring_size);
    printf ("\tbuffer_size: %u\n", md.buffer_size);
    printf ("\trx queues: %u\n", md.rx_queues);
    printf ("\ttx queues: %u\n", md.tx_queues);
    printf ("\tlink: ");
    if (md.link_up_down)
        printf ("up\n");
    else
        printf ("down\n");
}

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
mod_epoll_fd (int fd, uint32_t events)
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
    if (epoll_ctl (epfd, EPOLL_CTL_MOD, fd, &evt) < 0)
    {
        DBG ("epoll_ctl: %s fd %d", strerror (errno), fd);
        return -1;
    }
    DBG ("fd %d moddified on epoll", fd);
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
    INFO ("memif connected!");
    int_fd_t *ifd = (int_fd_t *) malloc (sizeof (int_fd_t));
    ifd->fd = memif_get_queue_efd ((&memif_connection)->conn, 0);
    ifd->qid = 0;
    (&memif_connection)->int_fd = ifd;
    return add_epoll_fd (ifd->fd, EPOLLIN);
}

/* informs user about disconnected status. private_ctx is used by user to identify connection
    (multiple connections WIP) */
int
on_disconnect (memif_conn_handle_t conn, void *private_ctx)
{
    INFO ("memif disconnected!");
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

    if (events & MEMIF_FD_EVENT_MOD)
        return mod_epoll_fd (fd, evt);

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
    int rv = memif_create (&(&memif_connection)->conn, &args, on_connect, on_disconnect, NULL);
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
    rv = memif_delete (&(&memif_connection)->conn);
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
    printf ("LIBMEMIF EXAMPLE APP: %s", APP_NAME);
#ifdef ICMP_DBG
    printf (" (debug)");
#endif
    printf ("\n");
    printf ("==============================\n");
    printf ("libmemif version: %s", LIBMEMIF_VERSION);
#ifdef MEMIF_DBG
    printf (" (debug)");
#endif
    printf ("\n");
    printf ("memif version: %d\n", MEMIF_VERSION);
    printf ("commands:\n");
    printf ("\thelp - prints this help\n");
    printf ("\texit - exit app\n");
    printf ("\tconn - create memif (slave-mode)\n");
    printf ("\tdel  - delete memif\n");
    printf ("\tshow - print memif details\n");
}

int
icmpr_buffer_alloc (long n)
{
    memif_connection_t *c = &memif_connection;
    c->tx_bufs = (memif_buffer_t **) malloc (sizeof (memif_buffer_t *) * n);
    DBG ("call memif_buffer_alloc");
    int r = memif_buffer_alloc (c->conn, 0, c->tx_bufs, n);
    DBG ("allocated %d/%ld buffers", r, n);
    c->tx_buf_num += r;
    return 0;
}

int
icmpr_tx_burst ()
{
    memif_connection_t *c = &memif_connection;
    int r = memif_tx_burst (c->conn, 0, c->tx_bufs, c->tx_buf_num);
    DBG ("tx: %d/%u", r, c->tx_buf_num);
    c->tx_buf_num -= r;
    return 0;
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
    else if (strncmp (ui, "show", 4) == 0)
    {
        print_memif_details ();
    }
    else
        DBG ("unknown command: %s", ui);
    return 0;
}

int
icmpr_interrupt (int fd)
{
    memif_connection_t *c = &memif_connection;
    DBG ("interrupted!");
    uint64_t b;
    ssize_t r = read (fd, &b, sizeof (b));

    int rx = memif_rx_burst (c->conn, 0, c->rx_bufs, c->rx_buf_num);
    c->rx_buf_num -= rx;

    DBG ("received %d buffers. %u free buffers", rx, c->rx_buf_num);

    icmpr_buffer_alloc (rx);
    int i;
    for (i = 0; i < rx; i++)
    {
        resolve_packet ((void *) (*(c->rx_bufs + i))->data,
                            (*(c->rx_bufs + i))->data_len, (void *) (*(c->tx_bufs + i))->data,
                            &(*(c->tx_bufs + i))->data_len);
    }

    int fb = memif_buffer_free (c->conn, 0, c->rx_bufs, rx);
    c->rx_buf_num += fb;

    DBG ("freed %d buffers. %u free buffers", fb, c->rx_buf_num);

    icmpr_tx_burst ();

    return 0;
}

int
poll_event (int timeout)
{
    memif_connection_t *c = &memif_connection;
    struct epoll_event evt, *e;
    int app_err = 0, memif_err = 0, en = 0;
    int tmp, nfd;
    uint32_t events = 0;
    memset (&evt, 0, sizeof (evt));
    evt.events = EPOLLIN | EPOLLOUT;
    sigset_t sigset;
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
            if (evt.data.fd == c->int_fd->fd)
            {
                icmpr_interrupt (evt.data.fd);
            }
            else
            {
                if (evt.events & EPOLLIN)
                    events |= MEMIF_FD_EVENT_READ;
                if (evt.events & EPOLLOUT)
                    events |= MEMIF_FD_EVENT_WRITE;
                if (evt.events & EPOLLERR)
                    events |= MEMIF_FD_EVENT_ERROR;
                memif_err = memif_control_fd_handler (evt.data.fd, events);
            }
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

    memif_connection_t *c = &memif_connection;

    /* initialize global memif connection handle */
    c->conn = NULL;
    c->int_fd = malloc (sizeof (int_fd_t));
    c->int_fd->fd = -1;
    c->rx_buf_num = 256;
    c->rx_bufs = malloc (sizeof (memif_buffer_t *) * c->rx_buf_num);

    /* initialize memory interface */
    memif_init (control_fd_update);

    /* main loop */
    while (1)
    {
        if (poll_event (-1) < 0)
        {
            DBG ("poll_event error!");
        }
    }
}
