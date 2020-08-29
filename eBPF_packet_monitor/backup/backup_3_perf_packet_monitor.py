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

struct ip_hdr {
    u64 ip_src;
    u64 ip_dst;
};

int packet_monitor(struct __sk_buff *skb) {
    u8 *cursor = 0;
    u32 saddr;
    u32 daddr;
    u32 ttl;
    u32 hchecksum;
    
    // trial - begin

    u64 magic = 1911;
    u64 magic2 = 1912;
    u64 magic3 = 1913;
    u64 magic4 = 1914;

    // trial - end
    struct ip_hdr parsed;
    
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

    parsed.ip_src = saddr;
    parsed.ip_dst = daddr;

    skb_events.perf_submit_skb(skb, skb->len, &magic, sizeof(magic)); // this one parses number as a hex to the user space
    skb_events.perf_submit_skb(skb, skb->len, &magic2, sizeof(magic2)); // can send multiple values like this
    skb_events.perf_submit_skb(skb, skb->len, &magic3, sizeof(magic3)); // can send multiple values like this
    skb_events.perf_submit_skb(skb, skb->len, &magic4, sizeof(magic4));
    
    // The last four attributes the user space receives are the values retrieved from the kernel space
    

//    bpf_trace_printk("saddr = %llu, daddr = %llu, ttl = %llu", saddr, daddr, ttl); // only three arguments can be passed using printk

//    bpf_trace_printk("Incoming packet!!\\n");
    return -1;
}

"""

from ctypes import *
import ctypes as ct
import sys
import socket
import os
import struct

# define a function to output perf output

def print_skb_event(cpu, data, size):
    class SkbEvent(ct.Structure):
        _fields_ = [ ("magic", ct.c_uint32),
                     ]
        
    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
    print("- bytes : ")
    print("%d" % (skb_event.magic))
    
bpf = BPF(text=bpf_text)

function_skb_matching = bpf.load_func("packet_monitor", BPF.SOCKET_FILTER)

BPF.attach_raw_socket(function_skb_matching, INTERFACE)

bpf["skb_events"].open_perf_buffer(print_skb_event)

# Just need to add open_perf_buffer() here.
# If perf output is put into the user space program, packet monitor will be completed

print("=========================packet monitor=============================\n")

try:
    while True :
#        bpf.perf_buffer_poll()
        value = bpf.perf_buffer_poll()
        print("====value : " + str(value))
except KeyboardInterrupt:
    pass

