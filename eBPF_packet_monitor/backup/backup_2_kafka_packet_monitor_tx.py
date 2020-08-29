from bcc import BPF
from kafka import KafkaProducer
from kafka.errors import KafkaError

# Connect kafka producer here

producer = KafkaProducer(bootstrap_servers=['localhost:9092'])
topicName = 'packetmonitor'

# Network interface to be monoitored
INTERFACE = "br-mellanox"

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
BPF_ARRAY(black_list, u64, 5);

int packet_monitor(struct __sk_buff *skb) {
    u8 *cursor = 0;
    u32 saddr;
    u32 daddr;
    u32 ttl;
    u32 hchecksum;
    
    // trial - begin

    u64 magic = 9999999;
    u64 magic2 = 1912;
    
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

    magic = ip -> src;
    magic2 = ip -> dst;
    
    skb_events.perf_submit_skb(skb, skb->len, &magic, sizeof(magic)); // this one parses number as a hex to the user space
    skb_events.perf_submit_skb(skb, skb->len, &magic2, sizeof(magic2)); // can send multiple values like this
    
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

tester_send = ''

def print_skb_event(cpu, data, size):
    global tester_send
    class SkbEvent(ct.Structure):
#        _fields_ = [ ("magic", ct.c_uint32),("magic2", ct.c_uint32)]
        _fields_ = [("magic", ct.c_uint32)]
        
    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
    
    # add functionalities here that will send data to another program
    
#    print("- : ")
#    print("%d" % (skb_event.magic))

    # trying to implement kafka producer - begin
    tester_kafka = str(skb_event.magic)
#    print(tester_kafka[:4])
    #producer.send(topicName, str('1')) # this one sends str 1 thru kafka
#    print(tester_kafka)
    tester_send = tester_send + ' ' + tester_kafka
#    producer.send(topicName, tester_kafka)
    # trying to implement kafka producer - end
    
bpf = BPF(text=bpf_text)

function_skb_matching = bpf.load_func("packet_monitor", BPF.SOCKET_FILTER)

BPF.attach_raw_socket(function_skb_matching, INTERFACE)

bpf["skb_events"].open_perf_buffer(print_skb_event)

black_list = bpf.get_table("black_list")    # retrieve blacklist list

# Just need to add open_perf_buffer() here.
# If perf output is put into the user space program, packet monitor will be completed

#sys.stdout = open('myoutput.txt','w')

print("=========================packet monitor=============================\n")

try:
    while True :
        bpf.perf_buffer_poll()  # value = bpf.perf_buffer_poll() function does not return any function and therefore, doesn't work
        print("this is tester send")
        print(tester_send)
        producer.send(topicName, tester_send)
        tester_send = ''
        
except KeyboardInterrupt:
    sys.stdout.close()
    pass

