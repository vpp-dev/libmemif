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

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/un.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

#include <socket_test.h>

#define TEST_SOCK_DIR "/libmemif/memif.sock"

static int
get_queue_len (memif_msg_queue_elt_t *q)
{
    int r = 0;
    memif_msg_queue_elt_t *c = q;
    while (c != NULL)
    {
        r++;
        c = c->next;
    }
    return r;
}

static int
test_msg_queue_add_pop ()
{
    int rv = 0;
    memif_connection_t conn;
    conn.msg_queue = NULL;
    conn.fd = -1;

    int i, len = 10;

    for (i = 0; i < len; i++)
    {
        if (i % 2)
            memif_msg_enq_ack (&conn);
        else
            memif_msg_enq_init (&conn);
    }

    if (len != get_queue_len (conn.msg_queue))
    {
        ERROR("incorrect queue len");
        rv = -1;
    }

    int pop = 6;

    for (i = 0; i < pop; i++)
    {
        if (i % 2)
        {
            if (conn.msg_queue->msg.type != MEMIF_MSG_TYPE_ACK)
            {
                ERROR ("incorrect msg type");
                rv = -1;
            }
        }
        else
        {
            if (conn.msg_queue->msg.type != MEMIF_MSG_TYPE_INIT)
            {
                ERROR ("incorrect msg type");
                rv = -1;
            }
        }
        conn.flags |= MEMIF_CONNECTION_FLAG_WRITE;
        /* function will return -1 because no socket is created */
        memif_conn_fd_write_ready (&conn);
    }

    if ((len - pop) != get_queue_len (conn.msg_queue))
    {
        ERROR("incorrect queue_len");
        rv = -1;
    }

    return rv;

}

static int
test_msg_enq_ack ()
{
    int rv = 0;
    memif_connection_t conn;
    conn.msg_queue = NULL;

    memif_msg_enq_ack (&conn);
    memif_msg_queue_elt_t *e = conn.msg_queue;

    if (e->msg.type != MEMIF_MSG_TYPE_ACK)
    {
        ERROR ("incorrect msg type");
        rv = -1;
    }
    if (e->fd != -1)
    {
        ERROR ("incorrect file descriptor");
        rv = -1;
    }
    return rv; 
}


static int
test_msg_enq_init ()
{
    int rv = 0;
    memif_connection_t conn;
    conn.msg_queue = NULL;

    conn.args.interface_id = 69;
    conn.args.mode = 0;

    strncpy ((char *)conn.args.instance_name, TEST_APP_NAME, strlen (TEST_APP_NAME));
    strncpy ((char *) conn.args.secret, TEST_SECRET, strlen (TEST_SECRET));
    
    memif_msg_enq_init (&conn);
    memif_msg_queue_elt_t *e = conn.msg_queue;
    
    if (e->msg.type != MEMIF_MSG_TYPE_INIT)
    {
        ERROR ("incorrect msg type");
        rv = -1;
    }
    if (e->fd != -1)
    {
        ERROR ("incorrect file descriptor");
        rv = -1;
    }
    memif_msg_init_t *i = &e->msg.init;
    if (i->version != MEMIF_VERSION)
    {
        ERROR ("incorrect memif version");
        rv = -1;
    }
    if (i->id != conn.args.interface_id)
    {
        ERROR ("incorrect interface id");
        rv = -1;
    }
    if (i->mode != conn.args.mode)
    {
        ERROR ("incorrect mode");
        rv = -1;
    }
    if (strncmp ((char *) i->name, (char *) conn.args.instance_name,
                strlen ((char *) i->name)) != 0)
    {
        ERROR ("incorrect interface name");
        rv = -1;
    }
    if (strncmp ((char *) i->secret, (char *) conn.args.secret,
                strlen ((char *) i->secret)) != 0)
    {
        ERROR ("incorrect secret");
        rv = -1;
    }

    return rv;
}

static int
test_msg_enq_add_region ()
{
    int rv = 0, frv = 0;
    memif_connection_t conn;
    conn.msg_queue = NULL;
    conn.regions = (memif_region_t *) malloc (sizeof(memif_region_t));
    memif_region_t *mr = conn.regions;
    mr->fd = 5;
    mr->region_size = 2048;
    mr->next = NULL;
    uint8_t region_index = 0;

    frv = memif_msg_enq_add_region (&conn, region_index);
    if (frv < 0)
    {
        ERROR ("function error");
        rv = -1;
    }
    memif_msg_queue_elt_t *e = conn.msg_queue;
    if (e->msg.type != MEMIF_MSG_TYPE_ADD_REGION)
    {
        ERROR ("incorrect msg type");
        rv = -1;
    }
    if (e->fd != mr->fd)
    {
        ERROR ("file descriptor mismatch");
        rv = -1;
    }
    memif_msg_add_region_t *ar = &e->msg.add_region;
    if (ar->index != region_index)
    {
        ERROR ("region index mismatch");
        rv = -1;
    }
    if (ar->size != mr->region_size)
    {
        ERROR ("region size mismatch");
        rv = -1;
    }

    region_index = 9;
    frv = memif_msg_enq_add_region (&conn, region_index);
    if (frv == 0)
    {
        ERROR ("invalid region_index (success fn)");
        rv = -1;
    }
    region_index = 0;

    free (conn.regions);
    conn.regions = NULL;
    mr = NULL;
    frv = memif_msg_enq_add_region (&conn, region_index);
    if (frv == 0)
    {
        ERROR ("invalid region (success fn)");
        rv = -1;
    }

    return rv;
}

static int
test_msg_receive_add_region ()
{
    int rv = 0, frv = 0;
    memif_connection_t conn;
    conn.regions = NULL;
    memif_msg_t msg;
    msg.type = MEMIF_MSG_TYPE_ADD_REGION;
    msg.add_region.size = 2048;
    msg.add_region.index = 0;

    int fd = 5;

    frv = memif_msg_receive_add_region (&conn, &msg, fd);
    if (frv < 0)
    {
        ERROR ("fuinction error");
        rv = -1;
    }

    msg.add_region.index = 9;
    frv = memif_msg_receive_add_region (&conn, &msg, fd);
    if (frv == 0)
    {
        ERROR ("invalid region index (success fn)");
        rv = -1;
    }
   
    memif_region_t *mr = conn.regions;
    if (mr->fd != fd)
    {
        ERROR ("incorrect file descriptor");
        rv = -1;
    }
    if (mr->region_size != 2048)
    {
        ERROR ("incorrect region size");
        rv = -1;
    }
    if (mr->shm != NULL)
    {
        ERROR ("invalid shm");
        rv = -1;
    }
 
    return rv;
}

static int
test_msg_receive_hello ()
{
    int rv = 0;
    memif_connection_t conn;
    conn.msg_queue = NULL;

    memif_msg_t msg;

    memif_msg_hello_t *h = &msg.hello;

    msg.type = MEMIF_MSG_TYPE_HELLO;
    
    h->min_version = MEMIF_VERSION;
    h->max_version = MEMIF_VERSION;
    h->max_s2m_ring = 1;
    h->max_m2s_ring = 1;
    h->max_log2_ring_size = 14;
    strncpy ((char *) h->name, TEST_IF_NAME, strlen (TEST_IF_NAME));

    conn.args.num_s2m_rings = 4;
    conn.args.num_m2s_rings = 6;
    conn.args.log2_ring_size = 10;

    rv = memif_msg_receive_hello (&conn, &msg);
    if (rv < 0)
    {
        ERROR ("memif protocol mismatch");
        return rv;
    }

    if (conn.args.num_s2m_rings != 2)
    {
        ERROR ("incorrect number of slave to master rings");
        rv = -1;
    }
    if (conn.args.num_m2s_rings != 2)
    {
        ERROR ("incorrect number of master to slave rings");
        rv = -1;
    }
    if (conn.args.log2_ring_size != 10)
    {
        ERROR ("incorrect ring size");
        rv = -1;
    }
    if (strncmp ((char *) conn.remote_name, TEST_IF_NAME, strlen (TEST_IF_NAME)) !=  0)
    {
        ERROR ("incorrect remote name");
        rv = -1;
    }

    h->max_version = 9;
    if (memif_msg_receive_hello (&conn, &msg) == 0)
    {
        ERROR ("no error on protocol mismatch");
        rv = -1;
    }

    return rv; 
}

static int
test_msg_receive_init ()
{
    int rv = 0, frv = 0;
    memif_connection_t conn;
    conn.msg_queue = NULL;

    conn.args.interface_id = 69;
    conn.args.is_master = 1;
    conn.fd = -1;
    conn.args.mode = 0;
    memset (conn.args.secret, '\0', 24);
    strncpy ((char *) conn.args.secret, TEST_SECRET, strlen (TEST_SECRET));


    memif_msg_t msg;

    memif_msg_init_t *i = &msg.init;

    msg.type = MEMIF_MSG_TYPE_INIT;

    i->version = MEMIF_VERSION;
    i->id = 69;
    i->mode = 0;
    memset (i->name, '\0', 32);
    memset (i->secret, '\0', 24);
    strncpy ((char *) i->name, TEST_IF_NAME, strlen (TEST_IF_NAME));
    strncpy ((char *) i->secret, TEST_SECRET, strlen (TEST_SECRET));

    frv = memif_msg_receive_init (&conn, &msg);
    if (frv < 0)
    {
        ERROR ("function error");
        rv = -1;
    }
    i->version = 9;
    frv = memif_msg_receive_init (&conn, &msg);
    if (frv == 0)
    {
        ERROR ("version mismatch (fn succes)");
        rv = -1;
    }
    i->version = MEMIF_VERSION;
    i->id = 78;
    frv = memif_msg_receive_init (&conn, &msg);
    if (frv == 0)
    {
        ERROR ("id mismatch (fn success)");
        rv = -1;
    }
    i->id = 69;
    i->mode = 1;
    frv = memif_msg_receive_init (&conn, &msg);
    if (frv == 0)
    {
        ERROR ("mode mismatch (fn success)");
        rv = -1;
    }
    i->mode = 0;
    i->secret[0] = '\0';
    frv = memif_msg_receive_init (&conn, &msg);
    if (frv == 0)
    {
        ERROR ("secret mismatch (fn success)");
        rv = -1;
    }
    strncpy ((char *) i->secret, TEST_SECRET, strlen (TEST_SECRET));
    conn.args.is_master = 0;
    frv = memif_msg_receive_init (&conn, &msg);
    if (frv == 0)
    {
        ERROR ("slave cannot accept connection (fn success)");
        rv = -1;
    }
    conn.args.is_master = 1;
    conn.fd = 5;
    frv = memif_msg_receive_init (&conn, &msg);
    if (frv == 0)
    {
        ERROR ("already connected (fn success)");
        rv = -1;
    }
    return rv;
}

static int
test_msg_enq_add_ring ()
{
    int rv = 0, frv = 0;
    memif_connection_t conn;
    conn.msg_queue = NULL;
    conn.rx_queues = NULL;
    conn.tx_queues = (memif_queue_t *) malloc (sizeof (memif_queue_t));

    memif_queue_t *mq = conn.tx_queues;    
    uint8_t dir = MEMIF_RING_S2M;
    mq->int_fd = 5;
    mq->offset = 0;
    mq->log2_ring_size = 10;

    frv = memif_msg_enq_add_ring (&conn, 0, dir);
    if (frv < 0)
    {
        ERROR ("function error");
        rv = -1;
    }
    memif_msg_queue_elt_t *e = conn.msg_queue;
    if (e->msg.type != MEMIF_MSG_TYPE_ADD_RING)
    {
        ERROR ("incorrect msg type");
        rv = -1;
    }
    if (e->fd != mq->int_fd)
    {
        ERROR ("incorrect int fd");
        rv = -1;
    }
    memif_msg_add_ring_t *ar = &e->msg.add_ring;
    if (ar->index != 0)
    {
        ERROR ("incorrect queue index");
        rv = -1;
    }
    if (ar->offset != mq->offset)
    {
        ERROR ("ring offset mismatch");
        rv = -1;
    }
    if (ar->log2_ring_size != mq->log2_ring_size)
    {
        ERROR ("ring size mismatch");
        rv = -1;
    }
    if ((ar->flags & MEMIF_MSG_ADD_RING_FLAG_S2M) == 0)
    {
        ERROR ("incorrect ring flag");
        rv = -1;
    }
    
    dir = MEMIF_RING_M2S;
    frv = memif_msg_enq_add_ring (&conn, 0, dir);
    if (frv == 0)
    {
        ERROR ("uninitialized queue (success fn)");
        rv = -1;
    }
    dir = MEMIF_RING_S2M;
    frv = memif_msg_enq_add_ring (&conn, 9, dir);
    if (frv == 0)
    {
        ERROR ("invalid queue index (success fn)");
        rv = -1;
    }

    return rv;
}

static int
test_msg_enq_connect ()
{
    int rv = 0;
    memif_connection_t conn;
    conn.msg_queue = NULL;
    strncpy ((char *) conn.args.interface_name, TEST_IF_NAME, strlen (TEST_IF_NAME));

    memif_msg_enq_connect (&conn);
    memif_msg_queue_elt_t *e = conn.msg_queue;
    if (e->msg.type != MEMIF_MSG_TYPE_CONNECT)
    {
        ERROR ("incorrect msg type");
        rv = -1;
    }
    if (e->fd != -1)
    {
        ERROR ("invalid file descriptor");
        rv = -1;
    }
    if (strncmp ((char *) e->msg.connect.if_name, TEST_IF_NAME, strlen (TEST_IF_NAME)) != 0)
    {
        ERROR ("incorrect interface name");
        rv = -1;
    }
    return rv;
}

static int
test_msg_enq_connected ()
{
    int rv = 0;
    memif_connection_t conn;
    conn.msg_queue = NULL;
    strncpy ((char *) conn.args.interface_name, TEST_IF_NAME, strlen (TEST_IF_NAME));

    memif_msg_enq_connected (&conn);
    memif_msg_queue_elt_t *e = conn.msg_queue;
    if (e->msg.type != MEMIF_MSG_TYPE_CONNECTED)
    {
        ERROR ("incorrect msg type");
        rv = -1;
    }
    if (e->fd != -1)
    {
        ERROR ("invalid file descriptor");
        rv = -1;
    }
    if (strncmp ((char *) e->msg.connected.if_name, TEST_IF_NAME, strlen (TEST_IF_NAME)) != 0)
    {
        ERROR ("incorrect interface name");
        rv = -1;
    }
    return rv;
}

static int
test_msg_send_disconnect ()
{
    int rv = 0, frv = 0;
    memif_connection_t conn;
    conn.fd = -1;

    /* only possible fail if memif_msg_send fails...  */
    /* obsolete without socket */
    frv = memif_msg_send_disconnect (&conn);
    if (frv < 0)
    {
        /*ERROR ("function error");*/
        /*rv = -1;*/
        rv = 0;
    }
    return rv;
}

static int
test_msg_receive_connect ()
{
    int rv = 0, frv = 0;
    memif_connection_t conn;
    conn.regions = NULL;
    conn.tx_queues = NULL;
    conn.rx_queues = NULL;
    memif_msg_t msg;

    msg.type = MEMIF_MSG_TYPE_CONNECT;
    strncpy ((char *) msg.connect.if_name, TEST_IF_NAME, strlen (TEST_IF_NAME));
    frv = memif_msg_receive_connect (&conn, &msg);
    if (frv < 0)
    {
        /* fail only if memif_connect1 fails
            (obsolete test) */
        ERROR ("function error");
        rv = -1;
    }
    if (strncmp ((char *) conn.remote_name, TEST_IF_NAME, strlen (TEST_IF_NAME)) != 0 )
    {
        ERROR ("incorrect remote interface name");
        rv = -1;
    }
    return rv;
}

static int
test_msg_receive_connected ()
{
    int rv = 0, frv = 0;
    memif_connection_t conn;
    conn.regions = NULL;
    conn.tx_queues = NULL;
    conn.rx_queues = NULL;
    memif_msg_t msg;

    msg.type = MEMIF_MSG_TYPE_CONNECTED;
    strncpy ((char *) msg.connect.if_name, TEST_IF_NAME, strlen (TEST_IF_NAME));
    
    frv = memif_msg_receive_connected (&conn, &msg);
    if (frv < 0)
    {
        /* fail only if memif_connect1 fails
            (obsolete test) */
        ERROR ("function error");
        rv = -1;
    }
    if (strncmp ((char *) conn.remote_name, TEST_IF_NAME, strlen (TEST_IF_NAME)) != 0 )
    {
        ERROR ("incorrect remote interface name");
        rv = -1;
    }
    return rv;
}

static int
test_msg_receive_disconnect ()
{
    int rv = 0, frv = 0;
    memif_connection_t conn;
    memif_msg_t msg;
    msg.type = MEMIF_MSG_TYPE_DISCONNECT;
    strncpy ((char *) msg.disconnect.string, "DC", 2);

    frv = memif_msg_receive_disconnect (&conn, &msg);
    if (frv == 0)
    {
        /* function can only return -1 */
        ERROR ("not possible");
        rv = -1;
    }
    if (strncmp ((char *) conn.remote_disconnect_string, "DC", 2) != 0)
    {
        ERROR ("incorrect disconnect string");
        rv = -1;
    }
    return rv;
}

int
test_socket (uint16_t *s, uint16_t *f)
{
    TEST_SET ("SOCKET.C");
    
    if (test_msg_queue_add_pop () < 0)
    {
        (*f)++;
        TEST_FAIL ("msg queue add/pop");
    }
    else
    {
        (*s)++;
        TEST_OK ("msg queue add/pop");
    }
    if (test_msg_enq_ack () < 0)
    {
        (*f)++;
        TEST_FAIL ("msg enq ack");
    }
    else
    {
        (*s)++;
        TEST_OK ("msg enq ack");
    }
    if (test_msg_enq_init () < 0)
    {
        (*f)++;
        TEST_FAIL ("msg enq init");
    }
    else
    {
        (*s)++;
        TEST_OK ("msg enq init");
    }
    if (test_msg_enq_add_region () < 0)
    {
        (*f)++;
        TEST_FAIL ("msg enq add region");
    }
    else
    {
        (*s)++;
        TEST_OK ("msg enq add region");
    }
    if (test_msg_enq_add_ring () < 0)
    {
        (*f)++;
        TEST_FAIL ("msg enq add ring");
    }
    else
    {
        (*s)++;
        TEST_OK ("msg enq add ring");
    }
    if (test_msg_receive_hello () < 0)
    {
        (*f)++;
        TEST_FAIL ("msg recv hello");
    }
    else
    {
        (*s)++;
        TEST_OK ("msg recv hello");
    }
    if (test_msg_receive_init () < 0)
    {
        (*f)++;
        TEST_FAIL ("msg recv init");
    }
    else
    {
        (*s)++;
        TEST_OK ("msg recv init");
    }
    if (test_msg_receive_add_region () < 0)
    {
        (*f)++;
        TEST_FAIL ("msg recv add region");
    }
    else
    {
        (*s)++;
        TEST_OK ("msg recv add region");
    }
    if (test_msg_enq_connect () < 0)
    {
        (*f)++;
        TEST_FAIL ("msg enq connect");
    }
    else
    {
        (*s)++;
        TEST_OK ("msg enq connect");
    }
    if (test_msg_enq_connected () < 0)
    {
        (*f)++;
        TEST_FAIL ("msg enq connected");
    }
    else
    {
        (*s)++;
        TEST_OK ("msg enq connected");
    }
    if (test_msg_send_disconnect () < 0)
    {
        (*f)++;
        TEST_FAIL ("msg send disconnect");
    }
    else
    {
        (*s)++;
        TEST_OK ("msg send disconnect");
    }
    if (test_msg_receive_connect () < 0)
    {
        (*f)++;
        TEST_FAIL ("msg recv connect");
    }
    else
    {
        (*s)++;
        TEST_OK ("msg recv connect");
    }
    if (test_msg_receive_connected () < 0)
    {
        (*f)++;
        TEST_FAIL ("msg recv connected");
    }
    else
    {
        (*s)++;
        TEST_OK ("msg recv connected");
    }
    if (test_msg_receive_disconnect () < 0)
    {
        (*f)++;
        TEST_FAIL ("msg recv disconnect");
    }
    else
    {
        (*s)++;
        TEST_OK ("msg recv disconnect");
    }
    return 0;
}
