# url : 127.0.0.1
import pymongo
import time
from kafka import KafkaConsumer
import sys

bootstrap_servers = ['localhost:9091','localhost:9092','localhost:9090']
topicName = 'xdp_packet'

consumer = KafkaConsumer (topicName, group_id = 'group1', bootstrap_servers = bootstrap_servers, auto_offset_reset = 'latest')

from pymongo import MongoClient
client = MongoClient()
db = client['db_packet_header']

ip_src_addr = 0
ip_dst_addr = 0
ip_tos = 0
ip_id = 0
ip_frag_off = 0
ip_ttl = 0
ip_protocol = 0
ip_check = 0
ip_total_length = 1
packet_info = []

    # cut transmitted data in the right order
    # order in which the datas are saved[ip] : src_addr / dst_addr / tos / id / frag_off / ttl / protocol / check / total length
    # each value disected by '|'
global packet_info
test_input = '192.168.1.2|192.168.1.1|0|5072|64|64|1|16871|21504'
front_flag = 0
rear_flag = 0
counter = 0

for i in test_input:
    if i == '|' : 
        packet_info.append(str(test_input[front_flag:counter]))
        front_flag = counter+1
    counter = counter + 1
        
packet_info.append(test_input[front_flag:])  # save the very last section of the header info
    
print('parsing info : ' + str(packet_info))    

'''
def kafka_consumer():
    print('>>> kafka receiving...')
    for message in consumer:
        incoming = str(message.value)
        print(incoming)

kafka_consumer()
'''

ip_src_addr = packet_info[0]
ip_dst_addr = packet_info[1]
ip_tos = packet_info[2]
ip_id = packet_info[3]
ip_frag_off = packet_info[4]
ip_ttl = packet_info[5]
ip_protocol = packet_info[6]
ip_check = packet_info[7]
ip_total_length = packet_info[8]

# CONFIRMED THAT THE DATA HAS BEEN SAVED COMPLETELY 
# Now save the data in the database

article = {"ip_src_addr" : ip_src_addr,
        "ip_dst_addr" : ip_dst_addr,
        "ip_tos" : ip_tos,
        "ip_id" : ip_id,
        "ip_frag_off" : ip_frag_off,
        "ip_ttl" : ip_ttl,
        "ip_protocol" : ip_protocol,
        "ip_check" : ip_check,
        "ip_total_length" : ip_total_length
        }

articles = db.packets_test
result = articles.insert_one(article)

print('> insertion into the db complete\n')

db.list_collection_names()
