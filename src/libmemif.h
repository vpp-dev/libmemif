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

#include <inttypes.h>

#include <memif.h>

typedef void* memif_conn_handle_t;

typedef struct
{
    uint8_t *socket_filename;
    uint8_t secret[24];

    uint8_t num_s2m_rings;
    uint8_t num_m2s_rings;
    uint16_t buffer_size;
    uint16_t log2_ring_size;
    uint8_t is_master;

    uint32_t interface_id;
    uint8_t interface_name[32];
    uint8_t instance_name[32];
    memif_interface_mode_t  mode:8;
} memif_conn_args_t;

/* initialize memif connection. connect socket */
int memif_connect (memif_conn_handle_t *conn, memif_conn_args_t * args);

/* returns file descriptor for control channel. user can register fd for polling */
/* on event user calls memif_control_handler () */
int memif_get_control_fd (memif_conn_handle_t conn);

/* handles control channel events (connect/disconnect) */
int memif_control_fd_handler (memif_conn_handle_t conn, int fd);

/* disconnect session (free memory, close file descriptors, unmap shared memory) */
int memif_disconnect (memif_conn_handle_t conn);

#endif /* _LIBMEMIF_H_ */
