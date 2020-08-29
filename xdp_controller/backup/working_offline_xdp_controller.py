import os
import subprocess
from kafka import KafkaConsumer

consumer = KafkaConsumer('test', group_id = 'my-group', bootstrap_servers = ['localhost:9092'])

# message received : message.value
for message in consumer:
    print("%s:%d:%d: key=%s value=%s" % (message.topic, message.partition, message.offset, message.key, message.value))

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
subprocess.call(["bpftool","map","update","id",str(black_list_map_id),"key","00","00","00","00","value","01","00","00","00","00","00","00","00"])
# update bpf map value - end

def update_bpf_map(update_value):
    print("input value " + str(update_value))
      
    subprocess.call(["bpftool","map","update","id",str(black_list_map_id),"key","00","00","00","00","value","11","11","11","00","00","00","00","00"])
#    print("bpf map with id " + str(black_list_map_id) + "updated...")
#    subprocess.call(["bpftool","map","lookup","id",str(black_list_map_id),"key",])
        
update_bpf_map(13)

