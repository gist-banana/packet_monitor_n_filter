# Licensed under the Apache License, Version 2.0 (the "License")
from kafka import KafkaProducer
from bcc import BPF
import pyroute2
import time
import sys
from ctypes import *

bootstrap_servers = ['lcaolhost:9092','localhost:9091','localhost:9090']
topicName = 'xdp_packet'

producer = KafkaProducer(bootstrap_servers = bootstrap_servers)
producer = KafkaProducer()

def convert_ip_to_bin(data):    # converts machine friendly IP -> human friendly IP
        #input is a machine friendly IP
        data =  "{0:b}".format(data.value).zfill(28)
        #    data = ''.join(str((int((data[0:4]),2))))
        # 0:4 - 1
        # 4:12 - 1
        # 12:20 - 168
        # 20:28

        one = ''.join(str((int((data[20:28]),2))))
        two = ''.join(str((int((data[12:20]),2))))
        three = ''.join(str((int((data[4:12]),2))))
        four = ''.join(str((int((data[0:4]),2))))
        back = one +'.' + two + '.'+ three +'.' + four
        return back

def convert_ip_to_machine(hum_address) :   # converts human friendly IP -> machine friendly IP
    # input is a human friendly IP
    length = len(hum_address)
    dot = []    # save dot positions fo the human readable IP address
    frag = []   # save fragmented numbers of humanm readable IP addresses, each separated by a dot
    i=0
    while (i< length):
        if (hum_address[i] == '.'):
            dot.append(i)   # save dot positions
    i = i +1

    i=0

    while (i < len(dot)):   # fragment human readable IP address in between dots & switch them into binaries
        if (i==0):
            frag.append(bin(int(hum_address[:int(dot[0])])))
        else:
            frag.append(bin(int(hum_address[int(dot[i-1]+1):int(dot[i])])))
        i = i+1

    frag.append(bin(int(hum_address[int(dot[i-1])+1:])))
    i=0
    while (i< len(dot)+1):
            frag[i] = frag[i][2:]
            frag[i] = frag[i].zfill(8)
            i = i+1

    frag.reverse()  # reverse the order of the frag list
    i=0
    binary_ver = ''
    while (i< len(dot)+1):
        binary_ver = binary_ver + frag[i]
        i = i+1

    output = int(binary_ver,2)
    return output

flags = 0
def usage():
    print("Usage: {0} [-S] <ifdev>".format(sys.argv[0]))
    print("       -S: use skb mode\n")
    print("       -H: use hardware offload mode\n")
    print("e.g.: {0} eth0\n".format(sys.argv[0]))
    exit(1)

if len(sys.argv) < 2 or len(sys.argv) > 3:
    usage()

offload_device = None
if len(sys.argv) == 2:
    device = sys.argv[1]
elif len(sys.argv) == 3:
    device = sys.argv[2]

_xdp_file = "xdp.c"

maptype = "percpu_array"
if len(sys.argv) == 3:
    if "-S" in sys.argv:
        # XDP_FLAGS_SKB_MODE
        flags |= (1 << 1)
    if "-H" in sys.argv:
        # XDP_FLAGS_HW_MODE
        maptype = "array"
        offload_device = device
        flags |= (1 << 3)

mode = BPF.XDP
#mode = BPF.SCHED_CLS

if mode == BPF.XDP:
    ret = "XDP_PASS"
    ctxtype = "xdp_md"
else:
    ret = "TC_ACT_SHOT"
    ctxtype = "__sk_buff"

# load BPF program
b = BPF(src_file = _xdp_file, cflags=["-w", "-DRETURNCODE=%s" % ret, "-DCTXTYPE=%s" % ctxtype, "-DMAPTYPE=\"%s\"" % maptype], )

fn = b.load_func("xdp_prog1", mode)

if mode == BPF.XDP:
    b.attach_xdp(device, fn, flags)
else:
    ip = pyroute2.IPRoute()
    ipdb = pyroute2.IPDB(nl=ip)
    idx = ipdb.interfaces[device].index
    ip.tc("add", "clsact", idx)
    ip.tc("add-filter", "bpf", idx, ":1", fd=fn.fd, name=fn.name,
          parent="ffff:fff2", classid=1, direct_action=True)

hash_addr = b.get_table("hash_addr")
dropcnt = b.get_table("dropcnt")

prev = [0] * 256
print(">> hit CTRL+C to stop")
#ip_addr = str(convert_ip_to_bin((hash_addr.items()[0][1])))
while 1:
    #under while
#    try:
        # here
    for k in dropcnt.keys():
        val = dropcnt[k].value if maptype == "array" else dropcnt.sum(k).value
        i = k.value
        ip_addr = str(convert_ip_to_bin((hash_addr.items()[0][1])))
#        ip_addr = str(hash_addr.items()[0][1])  # DELETE THIS LINE AFTER THE TEST
        ip_daddr = str(convert_ip_to_bin(hash_addr.items()[1][1]))
        ip_tos = str(hash_addr.items()[2][1])[8:-2] # [8:-2] deletes those u_clong8242L's unnecessary parts 
        ip_id = str(hash_addr.items()[3][1])[8:-2]
        ip_frag_off = str(hash_addr.items()[4][1])[8:-2]
        ip_ttl = str(hash_addr.items()[5][1])[8:-2]
        ip_protocol = str(hash_addr.items()[6][1])[8:-2]
        ip_check = str(hash_addr.items()[7][1])[8:-2]
        ip_tot_len = str(hash_addr.items()[8][1])[8:-2]
        
        if val:
            delta = val - prev[i]
            prev[i] = val

# delta : number of packets sent within a certain number of period

            contents = str('sdr addr : ' + ip_addr + ' | ' + 'dst addr : ' + ip_daddr + ' | ' + 'tos : ' + ip_tos) \
                    + ' | ' + 'id : ' + ip_id + ' | ' + 'frag off : ' + ip_frag_off + ' | ' + 'ttl : '  + ip_ttl \
                    + ' | ' + 'protocol : ' + ip_protocol + ' | ' + 'check : ' + ip_check + ' | ' + 'total length : ' + ip_tot_len
            print(contents)
            print('\n')
            ack = producer.send(topicName, contents)
            time.sleep(1)
    
    for k,v in hash_addr.items():
        print(str('k :' + ' ' + str(k.value) + ' ' + 'v : ' + str(v.value) + '\n'))
#        time.sleep(1)
#    except KeyboardInterrupt:
#        print("Removing filter from device")
#        break;

if mode == BPF.XDP:
    b.remove_xdp(device, flags)
else:
    ip.tc("del", "clsact", idx)
    ipdb.release()
