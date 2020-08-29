from bcc import BPF

# Network interface to be monoitored
INTERFACE = "br-netrome"

bpf_text = """

#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
#include <linux/bpf.h>

#define IP_TCP 6
#define IP_UDP 17
#define IP_ICMP 1
#define ETH_HLEN 14

BPF_PERF_OUTPUT(skb_events);    // has to be delcared outside any function

int packet_monitor(struct __sk_buff *skb) {
    u8 *cursor = 0;
    u64 saddr;
    u64 daddr;
    u64 ttl;
    u64 hchecksum;
    
    // trial - begin

    u32 magic = 0xfaceb00c;

    // trial - end
    
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if (!(ethernet -> type == 0x0800)) {
        return 0; // drop
    }

    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    /*
    if (ip->nextp != IP_TCP) 
    {
        if (ip -> nextp != IP_UDP) 
        {
            if (ip -> nextp != IP_ICMP) 
                return 0; 
        }
    }
    */

    skb_events.perf_submit_skb(skb, skb -> len, &magic, sizeof(magic));

    saddr = ip -> src;
    daddr = ip -> dst;
    ttl = ip -> ttl;
    hchecksum = ip -> hchecksum;

    skb_events.perf_submit(skb, &saddr, sizeof(saddr));

//    bpf_trace_printk("saddr = %llu, daddr = %llu, ttl = %llu", saddr, daddr, ttl); // only three arguments can be passed using printk

//    bpf_trace_printk("Incoming packet!!\\n");
    return -1;
}

"""

from ctypes import *
import sys
import socket
import os
import struct

bpf = BPF(text=bpf_text)

function_skb_matching = bpf.load_func("packet_monitor", BPF.SOCKET_FILTER)

BPF.attach_raw_socket(function_skb_matching, INTERFACE)

# Just need to add open_perf_buffer() here.
# If perf output is put into the user space program, packet monitor will be completed

print("=========================packet monitor=============================\n")

try:
    while True :
        bpf.perf_buffer_poll()
except KeyboardInterrupt:
    pass

