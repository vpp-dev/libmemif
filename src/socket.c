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
#include <sys/socket.h>
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

#include <socket.h>
#include <memif.h>

#define memif_min(a,b) ((a < b) ? (a) : (b))

/* sends msg to socket */
static_fn int
memif_msg_send (int fd, memif_msg_t *msg, int afd)
{
    return 0;
}

/* response from memif master - master is ready to handle next message */
static_fn void
memif_msg_enq_ack (memif_connection_t *c)
{
    memif_msg_queue_elt_t *e =
        (memif_msg_queue_elt_t *) malloc (sizeof (memif_msg_queue_elt_t));

    e->msg.type = MEMIF_MSG_TYPE_ACK;
    e->fd = -1;

    e->next = NULL;
    if (c->msg_queue == NULL)
    {
        c->msg_queue = e;
        return;
    }

    memif_msg_queue_elt_t *cur = c->msg_queue;
    while (cur->next != NULL)
    {
        cur = cur->next;
    }
    cur->next = e;
}

static_fn int
memif_msg_send_hello (memif_connection_t *c)
{
    memif_msg_t msg = { 0 };
    memif_msg_hello_t *h = &msg.hello;
    msg.type = MEMIF_MSG_TYPE_HELLO;
    h->min_version = MEMIF_VERSION;
    h->max_version = MEMIF_VERSION;
    h->max_s2m_ring = MEMIF_MAX_M2S_RING;
    h->max_m2s_ring = MEMIF_MAX_M2S_RING;
    h->max_region = MEMIF_MAX_REGION;
    h->max_log2_ring_size = MEMIF_MAX_LOG2_RING_SIZE;

    strncpy ((char *) h->name, (char *) c->args.instance_name,
            strlen ((char *) c->args.instance_name));

    /* msg hello is not enqueued but sent directly,
         because it is the first msg to be sent */
    return memif_msg_send (c->fd, &msg, -1);
}

/* send id and secret (optional) for interface identification */
static_fn void
memif_msg_enq_init (memif_connection_t *c)
{
    memif_msg_queue_elt_t *e =
        (memif_msg_queue_elt_t *) malloc (sizeof (memif_msg_queue_elt_t));
    
    memif_msg_init_t *i = &e->msg.init;

    e->msg.type = MEMIF_MSG_TYPE_INIT;
    e->fd = -1;
    i->version = MEMIF_VERSION;
    i->id = c->args.interface_id;
    i->mode = c->args.mode;
    
    strncpy ((char *) i->name, (char *) c->args.instance_name,
                strlen ((char *) c->args.instance_name));
    if (c->args.secret)
        strncpy ((char *) i->secret, (char *) c->args.secret, sizeof (i->secret));

    e->next = NULL;
    if (c->msg_queue == NULL)
    {
        c->msg_queue = e;
        return;
    }

    memif_msg_queue_elt_t *cur = c->msg_queue;
    while (cur->next != NULL)
    {
        cur = cur->next;
    }
    cur->next = e;
}

static_fn int
memif_msg_receive_hello (memif_connection_t *c, memif_msg_t *msg)
{
    memif_msg_hello_t *h = &msg->hello;

    if (msg->hello.min_version > MEMIF_VERSION ||
        msg->hello.max_version < MEMIF_VERSION)
    {
        DBG ("incompatible protocol version");
        return -1;
    }
    /* use nested struct c->run containing following variables?
        (this would be used to adjust shared memory information while keeping
        configured values intact) */
    c->args.num_s2m_rings = memif_min (h->max_s2m_ring + 1,
                                    c->args.num_s2m_rings);
    c->args.num_m2s_rings = memif_min (h->max_m2s_ring + 1,
                                    c->args.num_m2s_rings);
    c->args.log2_ring_size = memif_min (h->max_log2_ring_size,
                                        c->args.log2_ring_size);
    strncpy ((char *) c->remote_name, (char *) h->name, strlen ((char *) h->name));

    return 0;
}

/* handle interface identification (id, secret (optional)) */
static_fn int
memif_msg_receive_init (memif_connection_t *c, memif_msg_t *msg)
{
    memif_msg_init_t *i = &msg->init;
    uint8_t err_string[96];
    if (i->version != MEMIF_VERSION)
    {
        DBG ("MEMIF_VER_ERR");
        strncpy ((char *) err_string, MEMIF_VER_ERR, strlen (MEMIF_VER_ERR));
        goto error;
    }
    if (c->args.interface_id != i->id)
    {
        DBG ("MEMIF_ID_ERR");
        strncpy ((char *) err_string, MEMIF_ID_ERR, strlen (MEMIF_ID_ERR));
        goto error;
    }


    if (!(c->args.is_master))
    {
        DBG ("MEMIF_SLAVE_ERR");
        strncpy ((char *) err_string, MEMIF_SLAVE_ERR, strlen (MEMIF_SLAVE_ERR));
        goto error;
    }
    if (c->fd != -1)
    {
        DBG ("MEMIF_CONN_ERR");
        strncpy ((char *) err_string, MEMIF_CONN_ERR, strlen (MEMIF_CONN_ERR));
        goto error;
    }
    if (i->mode != c->args.mode)
    {
        DBG ("MEMIF_MODE_ERR");
        strncpy ((char *) err_string, MEMIF_MODE_ERR, strlen (MEMIF_MODE_ERR));
        goto error;
    }
    
    strncpy ((char *) c->remote_name, (char *) i->name, strlen ((char *) i->name));

    if (c->args.secret)
    {
        int r;
        if (i->secret)
        {
            if (strlen ((char *) c->args.secret) != strlen ((char *) i->secret))
                {
                    DBG ("MEMIF_SECRET_ERR");
                    strncpy ((char *) err_string,
                        MEMIF_SECRET_ERR, strlen (MEMIF_SECRET_ERR));
                    return -1;
                }
            r = strncmp ((char *) i->secret, (char *) c->args.secret,
                     strlen ((char *) c->args.secret));
            if (r != 0)
            {
                    DBG ("MEMIF_SECRET_ERR");
                    strncpy ((char *) err_string,
                        MEMIF_SECRET_ERR, strlen (MEMIF_SECRET_ERR));
                return -1;
            }
        }
        else
        {
            DBG ("MEMIF_NOSECRET_ERR");
            strncpy ((char *) err_string,
                MEMIF_NOSECRET_ERR, strlen (MEMIF_NOSECRET_ERR));
            return -1;
        }     
    }
    return 0;

error:
    memif_msg_send_disconnect (c, err_string, 1);
    return -1;
}

static_fn int
memif_msg_receive (memif_connection_t *c)
{
    return 0;
}

int
memif_conn_fd_error (memif_connection_t *c)
{
    DBG ("connection fd error");
    strncpy ((char *) c->remote_disconnect_string, "connection fd error",
        19);
    memif_disconnect_internal (c);
    return 0;
}

/* calls memif_msg_receive to handle pending messages on socket */
int
memif_conn_fd_read_ready (memif_connection_t *c)
{
    int rv = 0;
    rv = memif_msg_receive (c);
    if (rv < 0)
    {
        memif_disconnect_internal (c);
    }
    return 0;
}

/* get msg from msg queue buffer and send it to socket */
int
memif_conn_fd_write_ready (memif_connection_t *c)
{
    int rv = 0; 
    if ((c->flags & MEMIF_CONNECTION_FLAG_WRITE) == 0)
        return rv;

    memif_msg_queue_elt_t *e = c->msg_queue;
    if (e == NULL)
        return rv;

    c->msg_queue = c->msg_queue->next;
  
    c->flags &= ~MEMIF_CONNECTION_FLAG_WRITE;
 
    rv = memif_msg_send (c->fd, &e->msg, e->fd);
    free(e);
    return rv;
}

int
memif_conn_fd_accept_ready (memif_connection_t *c)
{
    int addr_len;
    struct sockaddr_un client;
    int conn_fd;

    DBG ("accept called");

    addr_len = sizeof (client);
    conn_fd = accept (c->fd, (struct sockaddr *) &client, (socklen_t *) &addr_len);

    if (conn_fd < 0)
    {
        DBG ("accept fd %d", c->fd);
        return -1;
    }
    DBG ("accept fd %d", c->fd);
    DBG ("conn fd %d", conn_fd);

    c->read_fn = memif_conn_fd_read_ready;
    c->write_fn = memif_conn_fd_write_ready;
    c->error_fn = memif_conn_fd_error;
    c->fd = conn_fd;

    int e = memif_msg_send_hello (c);
    if (e < 0)
    {
        DBG ("memif msg send hello error!");
        return -1;
    }

    return 0;
}
