import os
import subprocess
from pymongo import MongoClient
import time

PKT_THRESHOLD = 100

#current_time = str(time.localtime()[0]) + ';' + str(time.localtime()[1]).zfill(2) + ';' + str(time.localtime()[2]).zfill(2) + ';' + str(time.localtime()[3]).zfill(2) + ';' + str(time.localtime()[4]).zfill(2) + ';' + str(time.localtime()[5]).zfill(2)

#current_time_minus_5 = str(time.localtime()[0]) + ';' + str(time.localtime()[1]).zfill(2) + ';' + str(time.localtime()[2]).zfill(2) + ';' + str(time.localtime()[3]).zfill(2) + ';' + str(time.localtime()[4]).zfill(2) + ';' + str(time.localtime()[5]-5).zfill(2)

# connecting to pymongo db

client = MongoClient('localhost',27017)
db = client['packetmonitor']
collection = db['bpf2']

''' works perfectly. Reference for using queries from now
def print_value():
    print('\n\n\n printing values')
    for post in collection.find({'time':{'$gt':'2020;02;28;06;53;24'}},{'pkt_num':1,'_id':0}):
        print(str(post)[15:-2])
'''

#current_time_minus_5 = '2020;02;28;06;53;30'
#current_time = '2020;02;28;06;53;35'

result = 0
def print_value():
    current_time = str(time.localtime()[0]) + ';' + str(time.localtime()[1]).zfill(2) + ';' + str(time.localtime()[2]).zfill(2) + ';' + str(time.localtime()[3]).zfill(2) + ';' + str(time.localtime()[4]).zfill(2) + ';' + str(time.localtime()[5]).zfill(2)

    current_time_minus_5 = str(time.localtime()[0]) + ';' + str(time.localtime()[1]).zfill(2) + ';' + str(time.localtime()[2]).zfill(2) + ';' + str(time.localtime()[3]).zfill(2) + ';' + str(time.localtime()[4]).zfill(2) + ';' + str(time.localtime()[5]-5).zfill(2)
    global result
    for post in collection.find({'time':{'$gt':current_time_minus_5,'$lt':current_time}},{'pkt_num':1,'_id':0}):
#        print(str(post)[15:-2])
#        print(post)
        result = result + int(str(post)[15:-2])
#        print(result)

# connecting to pymongo db
#    for post in collection.find():
#        print(post)

try:
    while True:
        result = 0
        print_value()
        print(result)
        if (result > PKT_THRESHOLD):
            print('****warning!!!*****')
            
        time.sleep(1)
except KeyboardInterrupt:
    pass
