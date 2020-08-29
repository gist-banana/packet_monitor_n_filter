from pymongo import MongoClient
import time
import subprocess
import array

client = MongoClient()
client = MongoClient('localhost',27017)
db = client['packetmonitor']
collection = db['bfp2']

time_test = time.localtime()

THRESHOLD = 110
shit = str('141414')

#find specfic value :
# db.bpf2.find({"time":"2020;2;16;7;28;2"})

# can query for data that have time less than '2020;2;16;7;28;1' by using :
# db.bpf2.find({'time':{ $lt: '2020;2;16;7;28;1'}})
# can query for data that have time less than '2020;2;16;7;28;1', greater than '2020;2;16;7;27;57' by using:
# db.bpf2.find({'time':{ $lt:'2020;2;16;7;28;1', $gt:'2020;2;16;7;27;57'}})

# below works

#for value in db.bpf2.find({'time':{ '$lt':'2020;2;16;7;28;1', '$gt':'2020;2;16;7;27;57'}}):
#    print(value)

current_time = str(time.localtime()[0])+';'+str(time.localtime()[1])+';'+str(time.localtime()[2])+';'+str(time.localtime()[3])+';'+str(time.localtime()[4])+';'+str(time.localtime()[5])

print('current time : ' + str(current_time))

xdp_status = 0  # mark xdp status

tot_pkt = 0
counter = 0
#for value in db.bpf2.find({'pkt_num':1,'_id':0}): # lt boundary is not includeda
for value in db.bpf2.find({},{'src_ip':1,'dst_ip':1,'_id':0,'pkt_num':1}):
    address_array = ''
    pkt_array = ''
    '''
    temp = str(value)[14:]
    ip_scissors = temp.find("\'")
    ip_address = temp[:ip_scissors]
    pkt_scissors = temp.find("u'",ip_scissors+14)
    pkt_num = temp[pkt_scissors+2:-2]
    print(temp + ' ' + 'ip : ' + ip_address + ' ' + 'pkt_num : ' + pkt_num)
    for i in address_array:
        if i == ip_address: # if the ip address exists within the array
            print(temp[pkt_scissors+2:-2])
            pkt_array[counter] = pkt_array[counter] + pkt_num
        elif i != ip_address:
            counter = counter + 1
    '''
<<<<<<< HEAD:xdp_controller/backup/dbtest.py
    print(value)
=======
    src_ip = str(value)[14:25]
    dst_ip = str(value)[41:52]
    pkt_num = str(value)[69:-3]
    print('src_ip : ' + src_ip + '| dst_ip : ' + dst_ip + '| pkt_num : ' + pkt_num)

    
>>>>>>> 64c6b79134f8c05a82c9e03966b9014ae72d60b2:xdp_controller/dbtest.py

    
    
'''
    if (tot_pkt > THRESHOLD and xdp_status == 0):   # if total packet exceeds the threshold and xdp_status is turned off, turn it on
        while(counter < 100):
    #        producer.send(topicName,'192 168 000 002 a')
            producer.send(topicName,'192 168 000 002 a')
            counter = counter + 1
    elif (tot_pkt < THRESHOLD and xdp_status ==1):
        while(counter < 100):
            producer.send(topicName,'192 168 000 002 d')
            counter = counter + 1
    print('total pkt : ' +  str(tot_pkt))
'''

# after connecting producer.send(), all I have to to do is make XDP controller receive the msg and turn on xdp 


