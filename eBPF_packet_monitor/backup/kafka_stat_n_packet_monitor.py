from bcc import BPF
from kafka import KafkaProducer
from kafka.errors import KafkaError
import time

# Connect kafka producer here

#producer = KafkaProducer(bootstrap_servers=['localhost:9092'])
#topicName = 'packetmonitor'

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
BPF_HASH(packet_cnt, u32, long, 256); // let's try to save the number of IPs in here
// name / key / leaf / size

int packet_monitor(struct __sk_buff *skb) {
    u64 SOURCE_IP = 3232235521;
    u8 *cursor = 0;
    u32 saddr;
    u32 daddr;
    u32 ttl;
    u32 hchecksum;
    u32 test_key = 3232235522;
    u32 test_key2 = 3232235521;
    long* count = 0;
    long one = 1;
    
    // trial - begin

    u64 magic = 9999999;
    u64 magic2 = 9;
    
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
    
//    skb_events.perf_submit_skb(skb, skb -> len, &magic, sizeof(magic));

    saddr = ip -> src;
    daddr = ip -> dst;
    ttl = ip -> ttl;

    magic = ip -> src;
    magic2 = ip -> dst;
//    packet_cnt.update(&test_key, &magic2);

    count = packet_cnt.lookup(&test_key); // this prevents transmitted packets from being counted
    if (magic != SOURCE_IP)                 
    {
        if (count)  // check if this map exists
            *count += 1;
        else        // if the map for the key doesn't exist, create one
            {
                packet_cnt.update(&magic, &one);
            }
    }

    // THIS PART IS ONLY FOR TESTING - BEGIN ; DELETE when the test is over

    packet_cnt.update(&test_key2, &one);

    // THIS PART IS ONLY FOR TESTING - END


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

OUTPUT_INTERVAL = 1

def print_skb_event(cpu, data, size):
    global tester_send
    class SkbEvent(ct.Structure):
#        _fields_ = [ ("magic", ct.c_uint32),("magic2", ct.c_uint32)]
        _fields_ = [("magic", ct.c_uint32)]
        
    skb_event = ct.cast(data, ct.POINTER(SkbEvent)).contents
    
    # add functionalities here that will send data to another program
    


# ENABLE THIS PART TO ENABLE SINGEL PACKET MONITOR - BEGIN (2/1)


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
    
# ENABLE THIS PART TO ENABLE SINGLE PACKET MONITOR - END (2/1)

bpf = BPF(text=bpf_text)

function_skb_matching = bpf.load_func("packet_monitor", BPF.SOCKET_FILTER)

BPF.attach_raw_socket(function_skb_matching, INTERFACE)

bpf["skb_events"].open_perf_buffer(print_skb_event)

black_list = bpf.get_table("black_list")    # retrieve blacklist list
    # retrieeve packet_cnt map
packet_cnt = bpf.get_table('packet_cnt')    # retrieeve packet_cnt map

#sys.stdout = open('myoutput.txt','w')

print("=========================packet monitor=============================\n")

try:
    while True :
        # ENABLE THIS PART TO ENABLE SINGLE PACKET MONITOR - BEGIN (2/2)
        '''
        bpf.perf_buffer_poll()  # value = bpf.perf_buffer_poll() function does not return any function and therefore, doesn't work
        print (tester_send)
        tester_send = ''
        '''
        # ENABLE THIS PART TO ENABLE SINGLE PACKET MONITOR - END (2/2)

#        print("this is tester send")
        time.sleep(OUTPUT_INTERVAL)
        packet_cnt_output = packet_cnt.items()
        print(packet_cnt_output)
        output_len = len(packet_cnt_output)
        print(output_len)
        print('\n')
        for i in range(0,output_len):
            print('address : ' + str(packet_cnt_output[i][0])[7:-2] + ' packet number : ' + str(packet_cnt_output[i][1])[7:-1]) + ' ' + str(time.time())
            # time.time() otuputs how much time has passed since 00:00 hrs, 1st of Jan, 1970
        print('done')
        packet_cnt.clear() # delete map entires after printing output. confiremd it deletes values and keys too 
#        producer.send(topicName, tester_send)
        
except KeyboardInterrupt:
    sys.stdout.close()
    pass

