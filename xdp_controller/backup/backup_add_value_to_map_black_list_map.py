import os
import subprocess
from pymongo import MongoClient
import time
from kafka import KafkaProducer

# connecting to pymongo db

client = MongoClient('localhost',27017)
db = client['packetmonitor']
collection = db['bpf2']

# to write a system command, refer to the line below:
#subprocess.call(["apt-get","update"])
#subprocess.checkoutput(

entire_bpf_map_info = str(subprocess.check_output(["bpftool","map","show",]))

# save black_list map id - begin
num = entire_bpf_map_info.find("black_list")
test = num - 30
test2 = entire_bpf_map_info[test:num]
num2 = test2.find('\n')
test3 = test2[num2:]
num3 = test3.find(':')
test4 = test3[:num3]
black_list_map_id = int(test4)
print('- targetted bpf map id : ' + str(test4))
#save black_list map id - end

# update bpf map value - begin
#subprocess.call(["bpftool","map","update","id",str(black_list_map_id),"key","00","00","00","00","value","01","00","00","00","00","00","00","00"])
# update bpf map value - end

def update_bpf_map(val1, val2, val3, val4):
    print("-add input value: " + str(val1) + ' ' + str(val2) + ' ' + str(val3) + ' ' + str(val4))
    subprocess.call(["bpftool","map","update","id",str(black_list_map_id),"key",str(val1),str(val2),str(val3),str(val4),"value","01"])
#    print("bpf map with id " + str(black_list_map_id) + "updated...")
#    subprocess.call(["bpftool","map","lookup","id",str(black_list_map_id),"key",])

def delete_bpf_map(val1, val2, val3, val4):
    print('-del input value: ' + str(val1) + ' ' + str(val2) + ' ' + str(val3) + ' ' + str(val4))
    subprocess.call(['bpftool','map','delete','id',str(black_list_map_id),'key',str(val1),str(val2),str(val3),str(val4)])

while(1) :
    input_val = raw_input('enter mode and ip? -a : add / -d : del\n form : xxx xxx xxx xxx a >>>>')
#input : 192 168 000 001 a
#a is in the 16th value

    val1 = input_val[:3]
    val2 = input_val[4:7]
    val3 = input_val[8:11]
    val4 = input_val[12:15]

    if input_val[16] == 'a':
        update_bpf_map(val1,val2,val3,val4)
    elif input_val[16] == 'd':
        delete_bpf_map(val1,val2,val3,val4)


