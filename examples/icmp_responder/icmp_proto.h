#ifndef _ICMP_PROTO_H_
#define _ICMP_PROTO_H_

int resolve_packet (void *in_pck, ssize_t in_size, void *out_pck, uint32_t *out_size);

int print_packet (void *pck);

#endif /* _ICMP_PROTO_H_ */
