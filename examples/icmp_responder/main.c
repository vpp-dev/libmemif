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

#define MAX_MEMIF_BUFS 256

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
    memif_buffer_t *tx_bufs;
    /* number of tx buffers pointing to shared memory */
    uint16_t tx_buf_num;
    /* rx buffers */
    memif_buffer_t *rx_bufs;
    /* number of rx buffers pointing to shared memory */
    uint16_t rx_buf_num;
} memif_connection_t;

memif_connection_t memif_connection;

static void
print_memif_details ()
{
    memif_connection_t *c = &memif_connection;
    printf ("MEMIF DETAILS\n");
    printf ("==============================\n");


    memif_details_t md;
    memset (&md, 0, sizeof (md));
    ssize_t buflen = 2048;
    char *buf = malloc (buflen);
    memset (buf, 0, buflen);
    int err;

    err = memif_get_details (c->conn, &md, buf, buflen);
    if (err != MEMIF_ERR_SUCCESS)
    {
        INFO ("%s", memif_strerror (err));
        if (err == MEMIF_ERR_NOCONN)
        {
            free (buf);
            return;
        }
    }

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

    free (buf);
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
    memif_connection_t *c = &memif_connection;
    INFO ("memif connected!");
    int err;
    err = memif_get_queue_efd (c->conn, 0, &c->int_fd->fd);
    INFO ("memif_get_queue_efd: %s", memif_strerror (err));
    c->int_fd->qid = 0;
    return add_epoll_fd (c->int_fd->fd, EPOLLIN);
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
    int err = memif_create (&(&memif_connection)->conn, &args, on_connect, on_disconnect, NULL);
    INFO ("memif_create: %s", memif_strerror (err));
    return 0;
}

int
icmpr_memif_delete ()
{
    int err;
    /* disconenct then delete memif connection */
    err = memif_delete (&(&memif_connection)->conn);
    INFO ("memif_delete: %s", memif_strerror (err));
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
    printf ("\tshow - show connection details\n");
}

int
icmpr_buffer_alloc (long n)
{
    memif_connection_t *c = &memif_connection;
    int err;
    uint16_t r, qid = 0;
    err = memif_buffer_alloc (c->conn, qid, c->tx_bufs, n, &r);
    INFO ("memif_buffer_alloc: %s", memif_strerror (err));
    c->tx_buf_num += r;
    DBG ("allocated %d/%ld buffers, %u free buffers", r, n, MAX_MEMIF_BUFS - c->tx_buf_num);
    return 0;
}

int
icmpr_tx_burst ()
{
    memif_connection_t *c = &memif_connection;
    int err;
    uint16_t r, qid = 0;
    err = memif_tx_burst (c->conn, qid, c->tx_bufs, c->tx_buf_num, &r);
    INFO ("memif_tx_burst: %s", memif_strerror (err));
    DBG ("tx: %d/%u", r, c->tx_buf_num);
    c->tx_buf_num -= r;
    return 0;
}

int
icmpr_free ()
{
    memif_connection_t *c = &memif_connection;
    free (c->int_fd);
    c->int_fd = NULL;
    free (c->tx_bufs);
    c->tx_bufs = NULL;
    free (c->rx_bufs);
    c->rx_bufs = NULL;

    return 0;
}

int
user_input_handler ()
{
    char *in = (char *) malloc (256);
    char *ui = fgets (in, 256, stdin);
    if (in[0] == '\n')
        goto done;
    ui = strtok (in, " ");
    if (strncmp (ui, "exit", 4) == 0)
    {
        free (in);
        icmpr_memif_delete ();
        icmpr_free ();
        exit (EXIT_SUCCESS);
    }
    else if (strncmp (ui, "help", 4) == 0)
    {
        print_help ();
        goto done;
    }
    else if (strncmp (ui, "conn", 4) == 0)
    {
        icmpr_memif_create (0);
        goto done;
    }
    else if (strncmp (ui, "del", 3) == 0)
    {
        icmpr_memif_delete ();
        goto done;
    }
    else if (strncmp (ui, "show", 4) == 0)
    {
        print_memif_details ();
        goto done;
    }
    else
    {
        DBG ("unknown command: %s", ui);
        goto done;
    }

    return 0;
done:
    free (in);
    return 0;
}

int
icmpr_interrupt (int fd)
{
    memif_connection_t *c = &memif_connection;
/*    DBG ("interrupted!");
    uint64_t b;
    ssize_t r = read (fd, &b, sizeof (b));
*/

    int err;
    uint16_t rx;
    err = memif_rx_burst (c->conn, 0, c->rx_bufs, MAX_MEMIF_BUFS, &rx);
    INFO ("memif_rx_burst: %s", memif_strerror (err));
    c->rx_buf_num += rx;

    DBG ("received %d buffers. %u/%u alloc/free buffers",
                rx, c->rx_buf_num, MAX_MEMIF_BUFS - c->rx_buf_num);

    icmpr_buffer_alloc (rx);
    int i;
    for (i = 0; i < rx; i++)
    {
        resolve_packet ((void *) (c->rx_bufs + i)->data,
                            (c->rx_bufs + i)->data_len, (void *) (c->tx_bufs + i)->data,
                            &(c->tx_bufs + i)->data_len);
    }

    uint16_t fb;
    err = memif_buffer_free (c->conn, 0, c->rx_bufs, rx, &fb);
    INFO ("memif_buffer_free: %s", memif_strerror (err));
    c->rx_buf_num -= fb;

    DBG ("freed %d buffers. %u/%u alloc/free buffers",
                fb, c->rx_buf_num, MAX_MEMIF_BUFS - c->rx_buf_num);

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
    sigemptyset (&sigset);
    en = epoll_pwait (epfd, &evt, 1, timeout, &sigset);
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
                INFO ("memif_control_fd_handler: %s", memif_strerror (memif_err));
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
    /* alloc memif buffers */
    c->rx_buf_num = 0;
    c->rx_bufs = (memif_buffer_t *) malloc (sizeof (memif_buffer_t) * MAX_MEMIF_BUFS);
    c->tx_buf_num = 0;
    c->tx_bufs = (memif_buffer_t *) malloc (sizeof (memif_buffer_t) * MAX_MEMIF_BUFS);

    /* initialize memory interface */
    int err;
    err = memif_init (control_fd_update);
    INFO ("memif_init: %s", memif_strerror (err));

    /* main loop */
    while (1)
    {
        if (poll_event (-1) < 0)
        {
            DBG ("poll_event error!");
        }
    }
}
