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

#ifndef _LIBMEMIF_H_
#define _LIBMEMIF_H_

#define LIBMEMIF_VERSION "1.0"

#include <inttypes.h>

#include <memif.h>

/* types of events that need to be watched for specific fd */
/* user needs to set events that occured on fd and pass them to memif_control_fd_handler */
#define MEMIF_FD_EVENT_READ  (1 << 0)
#define MEMIF_FD_EVENT_WRITE (1 << 1)
/* inform libmemif that error occured on fd */
#define MEMIF_FD_EVENT_ERROR (1 << 2)
/* if set, informs that fd is going to be closed (user may want to stop watching for events on this fd) */
#define MEMIF_FD_EVENT_DEL   (1 << 3)
/* update events */
#define MEMIF_FD_EVENT_MOD   (1 << 4)

typedef void* memif_conn_handle_t;

/** \brief Memif control file descriptor update (callback function)
    @param fd - new file descriptor to watch
    @param events - event type(s) to watch for

    this callback is called when there is new fd to watch for events on
    or if fd is about to be closed (user mey want to stop watching for events on this fd)
*/
typedef int (memif_control_fd_update_t) (int fd, uint8_t events);



/** \brief Memif connection status update (callback function)
    @param conn - memif connection handle
    @param private_ctx - private context

    informs user about connection status connected/disconnected
    on connected -> start watching for events on interrupt fd
*/
typedef int (memif_connection_update_t) (memif_conn_handle_t conn, void *private_ctx);

typedef struct
{
    uint8_t *socket_filename;
    uint8_t secret[24];

    uint8_t num_s2m_rings;
    uint8_t num_m2s_rings;
    uint16_t buffer_size;
    memif_log2_ring_size_t log2_ring_size;
    uint8_t is_master;

    memif_interface_id_t interface_id;
    uint8_t interface_name[32];
    uint8_t instance_name[32];
    memif_interface_mode_t  mode:8;
} memif_conn_args_t;

typedef struct
{
    uint16_t desc_index;
    uint32_t buffer_len;
    uint32_t data_len;
    void *data;
} memif_buffer_t;

typedef struct
{
    uint8_t if_name[32];
    uint8_t inst_name[32];
    uint8_t remote_if_name[32];
    uint8_t remote_inst_name[32];

    uint32_t id;
    uint8_t secret[24]; /* optional */
    uint8_t role; /* 0 = master, 1 = slave */
    uint8_t mode; /* 0 = ethernet, 1 = ip, 2 = punt/inject */
    uint8_t socket_filename[128];
    uint32_t ring_size;
    uint16_t buffer_size;
    uint8_t rx_queues;
    uint8_t tx_queues;

    uint8_t link_up_down; /* 1 = up, 0 = down */
} memif_details_t;


memif_details_t memif_get_details (memif_conn_handle_t conn);

/** \brief Memif initialization
    @param on_control_fd_update - if control fd updates inform user to watch new fd

    initialize internal libmemif structures. create timerfd (used to periodically request connection by
    disconnected memifs in slave mode, with no additional API call). this fd is passed to user with memif_control_fd_update_t
    timer is inactive at this state. it activates with if there is at least one memif in slave mode
*/
int memif_init (memif_control_fd_update_t *on_control_fd_update);

/** \brief Memory interface create function
    @param conn - connection handle for user app
    @param args - memory interface connection arguments
    @param on_connect - inform user about connected status
    @param on_disconnect - inform user about disconnected status
    @param private_ctx - private contex passed back to user with callback

    creates memory interface.

    slave-mode
        start timer that will send events to timerfd. if this fd is passed to memif_control_fd_handler
        every disconnected memif in slave mode will send connection request.
        on success new fd is passed to user with memif_control_fd_update_t.

    master-mode
        create listener socket and pass fd to user with memif_cntrol_fd_update_t
        if this fd is passed to memif_control_fd_handler accept will be called and
        new fd will be passed to user with memif_control_fd_update_t
*/
int memif_create (memif_conn_handle_t * conn, memif_conn_args_t * args, memif_connection_update_t * on_connect, memif_connection_update_t * on_disconnect, void * private_ctx);

/** \brief Memif control file descriptor handler
    @param fd - file descriptor on which the event occured
    @param events - event type(s) that occured

    if event occures on any control fd, call memif_control_fd_handler
    internal - lib will "identify" fd (timerfd, lsitener, control) and handle event accordingly

    fd type
        timerfd
            every disconnected memif in slave mode will request connection
        listener
            call accept on this fd and pass new fd to user
        control
            handle socket messaging (internal connection establishment)
*/
int memif_control_fd_handler (int fd, uint8_t events);

/** \brief Memif get queue event file descriptor
    @param conn - memif connection handle
    @param qid - number identifying queue

    return interrupt fd for memif queue specified by qid
*/
int memif_get_queue_efd (memif_conn_handle_t conn, uint16_t qid);

/** \brief Memif delete
    @param conn - memif connection handle

    disconnect session (free queues and regions, close file descriptors, unmap shared memory)
    set connection handle to NULL, to avoid possible double free
*/
int memif_delete (memif_conn_handle_t *conn);

int memif_buffer_alloc (memif_conn_handle_t conn, uint16_t qid,
                        memif_buffer_t **bufs, uint16_t count);

int memif_buffer_free (memif_conn_handle_t conn, uint16_t qid,
                       memif_buffer_t **bufs, uint16_t count);

int memif_tx_burst (memif_conn_handle_t conn, uint16_t qid,
                    memif_buffer_t **bufs, uint16_t count);

int memif_rx_burst (memif_conn_handle_t conn, uint16_t qid,
                    memif_buffer_t **bufs, uint16_t count);

#endif /* _LIBMEMIF_H_ */
