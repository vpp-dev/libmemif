## Getting started

#### Build

Install dependencies
```
# sudo apt-get install -y git autoconf pkg_config libtool check
```

Clone repository to your local machine. 
```
# git clone https://github.com/JakubGrajciar/libmemif.git
```

From root directory execute:
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
> Make sure to run the binary file from ./.libs. File ./icmp\_responder in libmemif root directory is script that links the library, so it only verifies successful build. Default install path is /usr/lib.
Use _help_ command to display build information and commands:
```
ICMP_Responder:add_epoll_fd:204: fd 0 added to epoll
MEMIF_DEBUG:src/main.c:memif_init:383: app name: ICMP_Responder
ICMP_Responder:add_epoll_fd:204: fd 4 added to epoll
LIBMEMIF EXAMPLE APP: ICMP_Responder (debug)
==============================
libmemif version: 1.0 (debug)
memif version: 256
commands:
	help - prints this help
	exit - exit app
	conn <index> - create memif (slave-mode)
	del  <index> - delete memif
	show - show connection details
	ip-set <index> <ip-addr> - set interface ip address
	rx-mode <index> <qid> <polling|interrupt> - set queue rx mode
```

#### Unit tests

Unit tests use [Check](https://libcheck.github.io/check/index.html) framework. This framework must be installed in order to build *unit\_test* binary.
Ubuntu/Debian:
```
sudo apt-get install check
```
[More platforms](https://libcheck.github.io/check/web/install.html)

#### Concept (Connecting to VPP)

For detailed information on api calls and structures please refer to [libmemif.h](src/libmemif.h)

1. Initialize memif
   - Declare callback function handling file descriptor event polling. memif\_control\_fd\_update\_t
   - Call memif initialization function. memif\_init
   
> If event occurres on any file descriptor returned by this callback, call memif\_control\_fd\_handler function. 
> If callback function parameter for memif\_init function is set to NULL, libmemif will handle file descriptor event polling.
  Api call memif\_poll\_event will call epoll\_pwait wit user defined timeout to poll event on file descriptors opened by libmemif.
    
> Memif initialization function will initialize internal structures and create timer file descriptor, which will be used for sending periodic connection requests. Timer is disarmed if no memif interface is created.
 
2. Creating interface
   - Declare memif connction handle. memif\_conn\_handle\_t
   - Specify connection arguments. memif\_conn\_args\_t
   - Declare callback functions called on connected/disconnected/interrupted status changed. memif\_connection\_update\_t
   - Call memif interface create function. memif\_create
> If connection is in slave mode, arms timer file descriptor.
> If on interrupt callback is set to NULL, user will not be notified about interrupt. Use memif\_get\_queue\_efd call to get interrupt file descrip[tor for specific queue.

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
      - Every api call returns error code (integer value) mapped to error string.
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

#### Example app (multi-thread queue polling)

- [ICMP Responder](examples/icmp_responder3/main.c)

> Simple example of libmemif multi-thread usage. Connection establishment is handled by main thread. There are two rx queues in this example. One in polling mode and second in interrupt mode.

VPP config:
```
# create memif id 0 master
# set int state memif0 up
# set int ip address memif0 192.168.1.1/24
# ping 192.168.1.2
```
For multiple rings (queues) support run VPP with worker threads:
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
# create memif id 0 master
# set int state memif0 up
# set int ip address memif0 192.168.1.1/24
# ping 192.168.1.2
```
> Master mode queue number is limited by worker threads. Slave mode interface needs to specify number of queues.
```
# create memif id 0 slave rx-queues 2 tx-queues 2
```
> Example applications use VPP default socket file for memif: /run/vpp/memif.sock
> For master mode, socket directory must exist prior to memif\_create call.

