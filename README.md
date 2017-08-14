Shared Memory Packet Interface (memif) Library
==============================================
## Introduction

Shared memory packet interface (memif) provides high performance packet transmit and receive between user application and Vector Packet Processing (VPP). 

## Features

- [x] Slave mode
  - [x] Connect to VPP over memif
  - [x] ICMP responder example app
- [x] Transmit/receive packets
- [x] Interrupt mode support
- [x] File descriptor event polling in libmemif (optional)
  - [x] Simplify file descriptor event polling (one handler for control and interrupt channel)
- [x] Multiple connections
- [x] Multiple queues
  - [x] Multi-thread support
- [x] Master mode
	- [ ] Multiple regions (TODO)
- [ ] Performance testing (TODO)
- [ ] Documentation (TODO)

## Quickstart

For information on how to use libmemif API, please refer to [User manual](UserManual.md).

#### Run in container

Install [docker](https://docs.docker.com/engine/installation) engine.
Useful link: [Docker documentation](https://docs.docker.com/get-started).


Use [example dockerfile](dockerfile). This dockerfile builds and installs libmemif in debug mode and runs ICMP responder example app. Run following command in directory with example dockerfile:
```
# docker build .
```
When build is completed:
```
# docker images
REPOSITORY                     TAG                 IMAGE ID            CREATED             SIZE
<none>                         <none>              c83438f19940        3 seconds ago       468MB
ubuntu                         xenial              0ef2e08ed3fa        5 months ago        130MB
```
Tag your new image:
```
# docker tag c83438f19940 icmp-responder:latest
# docker images
REPOSITORY                     TAG                 IMAGE ID            CREATED             SIZE
icmp-responder                 latest              c83438f19940        3 seconds ago       468MB
ubuntu                         xenial              0ef2e08ed3fa        5 months ago        130MB
```
Run container:
```
docker run -it --rm --name icmp-responder --hostname icmp-responder --privileged -v "/run/vpp/:/run/vpp/" icmp-responder
```
Example application will start in debug mode. Output should look like this:
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

#### Run without container

Build process is explained in [User Manual](UserManual.md).

### Connection to VPP-memif

> Libmemif example app(s) use memif default socket file: /run/vpp/memif.sock.

#### Example setup (VPP-memif master icmp_responder slave)

Run VPP and icmp_responder example.
VPP-side config:
```
# create memif id 0 master
# set int state memif0/0 up
# set int ip address memif0/0 192.168.1.1/24
```
icmp_responder:
```
# conn 0 0
```
Memif in slave mode will try to connect every 2 seconds. If connection establishment is successfull, a message will show.
```
INFO: memif connected!
```
> Error messages like "unmatched interface id" are printed only in debug mode.

Check connected status.
Use show command in icmp_responder
```
show
MEMIF DETAILS
==============================
interface index: 0
	interface ip: 192.168.1.2
	interface name: memif_connection
	app name: ICMP_Responder
	remote interface name: memif0/0
	remote app name: VPP 17.10-rc0~132-g62f9cdd
	id: 0
	secret: 
	role: slave
	mode: ethernet
	socket filename: /run/vpp/memif.sock
	rx queues:
		queue id: 0
		ring size: 1024
		buffer size: 2048
	tx queues:
		queue id: 0
		ring size: 1024
		buffer size: 2048
	link: up
interface index: 1
	no connection

```
Use sh memif command in VPP:
```
DBGvpp# sh memif
interface memif0/0
  remote-name "ICMP_Responder"
  remote-interface "memif_connection"
  id 0 mode ethernet file /run/vpp/memif.sock
  flags admin-up connected
  listener-fd 12 conn-fd 13
  num-s2m-rings 1 num-m2s-rings 1 buffer-size 0
    master-to-slave ring 0:
      region 0 offset 32896 ring-size 1024 int-fd 16
      head 0 tail 0 flags 0x0000 interrupts 0
    master-to-slave ring 0:
      region 0 offset 0 ring-size 1024 int-fd 15
      head 0 tail 0 flags 0x0001 interrupts 0
```

Send ping from VPP to icmp_responder:
```
DBGvpp# ping 192.168.1.2
64 bytes from 192.168.1.2: icmp_seq=2 ttl=64 time=.1888 ms
64 bytes from 192.168.1.2: icmp_seq=3 ttl=64 time=.1985 ms
64 bytes from 192.168.1.2: icmp_seq=4 ttl=64 time=.1813 ms
64 bytes from 192.168.1.2: icmp_seq=5 ttl=64 time=.1929 ms

Statistics: 5 sent, 4 received, 20% packet loss
```
#### Example setup multiple queues (VPP-memif slave icmp_responder master)

Run icmp_responder as in previous example setup.
Run VPP with startup conf, enabling 2 worker threads.
Example startup.conf:
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
VPP-side config:
```
# create memif id 0 slave rx-queues 2 tx-queues 2
# set int state memif0/0 up
# set int ip address memif0/0 192.168.1.1/24
```
icmp_responder:
```
# conn 0 1
```
When connection is established a message will print:
```
INFO: memif connected!
```
> Error messages like "unmatched interface id" are printed only in debug mode.

Check connected status.
Use show command in icmp_responder
```
show
MEMIF DETAILS
==============================
interface index: 0
	interface ip: 192.168.1.2
	interface name: memif_connection
	app name: ICMP_Responder
	remote interface name: memif0/0
	remote app name: VPP 17.10-rc0~132-g62f9cdd
	id: 0
	secret: 
	role: master
	mode: ethernet
	socket filename: /run/vpp/memif.sock
	rx queues:
		queue id: 0
		ring size: 1024
		buffer size: 2048
		queue id: 1
		ring size: 1024
		buffer size: 2048
	tx queues:
		queue id: 0
		ring size: 1024
		buffer size: 2048
		queue id: 1
		ring size: 1024
		buffer size: 2048
	link: up
interface index: 1
	no connection

```
Use sh memif command in VPP:
```
DBGvpp# sh memif
interface memif0/0
  remote-name "ICMP_Responder"
  remote-interface "memif_connection"
  id 0 mode ethernet file /run/vpp/memif.sock
  flags admin-up slave connected
  listener-fd -1 conn-fd 12
  num-s2m-rings 2 num-m2s-rings 2 buffer-size 2048
    slave-to-master ring 0:
      region 0 offset 0 ring-size 1024 int-fd 14
      head 0 tail 0 flags 0x0000 interrupts 0
    slave-to-master ring 1:
      region 0 offset 32896 ring-size 1024 int-fd 15
      head 0 tail 0 flags 0x0000 interrupts 0
    slave-to-master ring 0:
      region 0 offset 65792 ring-size 1024 int-fd 16
      head 0 tail 0 flags 0x0001 interrupts 0
    slave-to-master ring 1:
      region 0 offset 98688 ring-size 1024 int-fd 17
      head 0 tail 0 flags 0x0001 interrupts 0

```
Send ping from VPP to icmp_responder:
```
DBGvpp# ping 192.168.1.2
64 bytes from 192.168.1.2: icmp_seq=2 ttl=64 time=.1439 ms
64 bytes from 192.168.1.2: icmp_seq=3 ttl=64 time=.2184 ms
64 bytes from 192.168.1.2: icmp_seq=4 ttl=64 time=.1458 ms
64 bytes from 192.168.1.2: icmp_seq=5 ttl=64 time=.1687 ms

Statistics: 5 sent, 4 received, 20% packet loss
```
