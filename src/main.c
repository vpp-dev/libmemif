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

#include <stdint.h>

/* memif protocol msg, ring and descriptor definitions */
#include <memif.h>
/* memif api */
#include <libmemif.h>
/* socket messaging functions */
#include <socket.h>
/* private structs and functions */
#include <memif_private.h>

int
memif_connect (memif_conn_handle_t *conn, memif_conn_args_t *args)
{
    return 0;
}

int
memif_get_control_fd (memif_conn_handle_t conn)
{
    return 0;
}

int
memif_control_fd_handler (memif_conn_handle_t conn, int fd)
{
    return 0;
}

int
memif_disconnect (memif_conn_handle_t conn)
{
    return 0;
}
