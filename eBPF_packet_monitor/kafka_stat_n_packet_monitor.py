from bcc import BPF
from kafka import KafkaProducer
from kafka.errors import KafkaError
import time
import sys

def help():
    print("execute: {0} <network_interface> <broker_server> <topic_name>".format(sys.argv[0]))
    print("e.g.: {0} eno1 192.168.0.1:9092 topic_name\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) != 3:
    help()
elif len(sys.argv) == 3:
    INTERFACE = sys.argv[1]
    BOOTSTRAP_SERVERS = sys.argv[2]
    TOPICNAME = sys.argv[3]

bootstrap_servers = BOOTSTRAP_SERVERS
topicName = TOPICNAME

# Connect kafka producer here
producer = KafkaProducer(bootstrap_servers)
# Network interface to be monoitored


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
BPF_HASH(packet_cnt, u64, long, 256); // let's try to save the number of IPs in here

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
    u64 add_test = 0;
    
    
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
    if (!(ethernet -> type == 0x0800)) {    
        return 0; // drop
    }

    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
    if (ip->nextp != IP_TCP) 
    {
        if (ip -> nextp != IP_UDP) 
        {
            if (ip -> nextp != IP_ICMP) 
                return 0; 
        }
    }
    
    saddr = ip -> src;
    daddr = ip -> dst;
    ttl = ip -> ttl;

    add_test = saddr;
    add_test = add_test << 32;
    add_test = add_test + daddr;

    count = packet_cnt.lookup(&add_test); // this prevents transmitted packets from being counted
    if (count)  // check if this map exists
        *count += 1;
    else        // if the map for the key doesn't exist, create one
        {
            packet_cnt.update(&add_test, &one);
        }

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
#    producer.send(topicName, str('1')) # this one sends str 1 thru kafka
#    print(tester_kafka)
    tester_send = tester_send + ' ' + tester_kafka
#    producer.send(topicName, tester_kafka)
    # trying to implement kafka producer - end
    
# ENABLE THIS PART TO ENABLE SINGLE PACKET MONITOR - END (2/1)

bpf = BPF(text=bpf_text)

function_skb_matching = bpf.load_func("packet_monitor", BPF.SOCKET_FILTER)

BPF.attach_raw_socket(function_skb_matching, INTERFACE)

    # retrieeve packet_cnt map
packet_cnt = bpf.get_table('packet_cnt')    # retrieeve packet_cnt map

#sys.stdout = open('myoutput.txt','w')

print("=========================packet monitor=============================\n")

try:
    while True :

#        print("this is tester send")
        time.sleep(OUTPUT_INTERVAL)
        packet_cnt_output = packet_cnt.items()
#        print(packet_cnt_output)
        output_len = len(packet_cnt_output)
#        print(output_len)
        print('\n')
        for i in range(0,output_len):
            if (len(str(packet_cnt_output[i][0]))) != 30:
                continue
            tester = int(str(packet_cnt_output[i][0])[8:-2])
            print('raw : ' + str(packet_cnt_output[i][0])[8:-2])
            tester = int(str(bin(tester))[2:]) # raw file
            print('test : ' + str(tester)) # raw file
            print('length : ' + str(len(str(tester))))
            src = int(str(tester)[:32],2) # part1 
            dst = int(str(tester)[32:],2)
            pkt_num = str(packet_cnt_output[i][1])[7:-1]

            kafka_content = str(src) + ' ' + str(dst) + ' ' + pkt_num + ' ' + str(time.localtime()[0])+';'+str(time.localtime()[1]).zfill(2)+';'+str(time.localtime()[2]).zfill(2)+';'+str(time.localtime()[3]).zfill(2)+';'+str(time.localtime()[4]).zfill(2)+';'+str(time.localtime()[5]).zfill(2)
            print(kafka_content)

            producer.send(topicName, kafka_content) 
            # time.time() outputs time elapsed since 00:00 hours, 1st, Jan., 1970.
        packet_cnt.clear() # delete map entires after printing output. confiremd it deletes values and keys too 
        
except KeyboardInterrupt:
    sys.stdout.close()
    pass

