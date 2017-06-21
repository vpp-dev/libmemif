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

#include <socket_test.h>

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
        memif_slave_conn_fd_write_ready (&conn);
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

    return 0;
}
