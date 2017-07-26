Shared Memory Packet Interface (memif) Library
==============================================
## Introduction

Shared memory packet interface (memif) provides high performance packet transmit and receive between user application and Vector Packet Processing (VPP). 

## Work in progress

- [x] Slave mode
  - [x] Connect to VPP over memif
  - [x] ICMP responder example app
- [x] Transmit/receive packets
- [x] Interrupt mode support
- [x] File descriptor event polling in libmemif (optional)
  - [x] Simplify file descriptor event polling (one handler for control and interrupt channel)
- [ ] Multiple connections
- [x] Multipe queues
  - [ ] Multithread support
- [ ] Master mode
	- [ ] Multiple regions
- [ ] Performance testing
- [ ] Documentation


## Getting started

#### Instalation

Clone repository to your local machine. From root directory execute:

For debug build:
```
# ./bootstrap
# ./configure
# make
# make install
```
    
For release build:
```
# ./bootstrap
# ./configure
# make release
# make install
```
Verify installation:
```
# ./.libs/icmp_responder
```
> Make sure to run the binary file from ./.libs. File ./icmp\_responder in libmemif root directory is script that links the library, so it only verifies succesfull build. Default install path is /usr/lib.
Use _help_ command to display build information and commands:
```
LIBMEMIF EXAMPLE APP: ICMP_Responder (debug)
==============================
libmemif version: 1.0 (debug)
memif version: 256
commands:
    help - prints this help
    exit - exit app
    conn - create memif (slave-mode)
    del  - delete memif
    show - show connection details
```

#### Unit tests

Unit tests use [Check](https://libcheck.github.io/check/index.html) framework. This framework must be instaled in order to build *unit\_test* binary.
Ubuntu/Debian:
```
sudo apt-get install check
```
[More platforms](https://libcheck.github.io/check/web/install.html)

#### Connecting to VPP

For detailed information on api calls and structures please refer to [libmemif.h](src/libmemif.h)

1. Initialize memif
   - Declare callback function handling file descriptor event polling. memif\_control\_fd\_update\_t
   - Call memif initialization function. memif\_init
   
> If event occures on any file descriptor returned by this callback, call memif\_control\_fd\_handler function. 
> If callback function parameter for memif\_init function is set to NULL, libmemif will handle file descriptor event polling.
  Api call memif\_poll\_event will call epoll\_pwait wit user defined timeout to poll event on file descriptors opend by libmemif.
    
> Mmeif initialization function will initialize internal structures and create timer file descriptor, which will be used for sending periodic connection requests. Timer is disarmed if no memif interface is created.
 
2. Creating interface
   - Declare memif conenction handle. memif\_conn\_handle\_t
   - Specify connection arguments. memif\_conn\_args\_t
   - Declare callback functions called on connected/disconencted status changed. memif\_connection\_update\_t
   - Call memif interface create function. memif\_create
> Arms timer file descriptor.

3. Connection establishment
    - User application will poll events on all file descriptors returned in memif\_control\_fd\_update\_t callback..
    - On event call memif\_control\_fd\_handler.
    - Everything else regarding connection establishment will be done internally.
    - Once connection has been established, a callback will inform the user about connection status change.

4. Interrupt packet receive
    - If event is polled on interrupt file descriptor, libmemif will call memif\_interrupt\_t callback specified for every connection instance.

6. Memif buffers
    - Packet data are stored in memif\_buffer\_t. Pointer _data_ points to shared memory buffer, and unsigned integer *data\_len* contains packet data length.

5. Packet receive
    - Api call memif\_rx\_burst will set all required fields in memif buffers provided by user application.
    - User application can then process packets.
    - Api call memif\_buffer\_free will make supplied memif buffers ready for next receive and mark shared memory buffers as free.

6. Packet transmit
    - Api call memif\_buffer\_alloc will set all required fields in memif buffers provided by user application. 
    - User application can populate shared memory buffers with packets.
    - Api call memif\_tx\_burst will inform peer interface (master memif on VPP) that there are packets ready to receive and mark memif buffers as free.

7. Helper functions
    - Memif details
      - Api call memif\_get\_details will return details about connection.
    - Memif error messages
      - Every api call returns error code (integer value) maped to error string.
      - Call memif\_strerror will return error message assigned to specific error code.
        - Not all syscall errors are translated to memif error codes. If error code 1 (MEMIF\_ERR\_SYSCALL) is returned then libmemif needs to be compiled with -DMEMIF_DBG flag to print error message. Use _make -B_ to rebuild libmemif in debug mode.
    

#### Example app:

- [ICMP Responder](examples/icmp_responder/main.c)

#### Example app (libmemif fd event polling):
- [ICMP Responder](examples/icmp_responder2/main.c)
> Optional argument: transmit queue id.
```
icmpr_lep 1
```
> Set transmit queue id to 1. Default is 0.
> Application will create memif interface in slave mode and try to connect to VPP. Exit using Ctrl+C. Application will handle SIGINT signal, free allocated memory and exit with EXIT_SUCCESS.

VPP config:
```
# create memif id 0 master
# set int state memif0 up
# set int ip address memif0 192.168.1.1/24
# ping 192.168.1.2
```
For multipe rings (queues) support run VPP with worker threads:
example startup.conf:
```
unix {
  interactive
  nodaemon
  full-coredump
}

cpu {
  workers 2
}
```
VPP config:
```
# create memif id 0 master rx-queues 2 tx-queues 2
# set int state memif0 up
# set int ip address memif0 192.168.1.1/24
# ping 192.168.1.2
```
> Example applications use VPP default socket file for memif: /run/vpp/memif.sock
