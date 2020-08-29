from kafka import KafkaConsumer
import sys
from ast import literal_eval
from pymongo import MongoClient
import pytz
#define information about kafka

bootstrap_servers = ['210.117.251.25:9092']
topicName = 'packetmonitor'

consumer = KafkaConsumer(topicName, bootstrap_servers = bootstrap_servers)

# database test - BEGIN

def insert_into_db(src_ip, dst_ip, pkt_num, time):
    client = MongoClient()
    db = client.packetmonitor    # database name
    collection = db.bpf2    # document name
    collection.insert_one({'src_ip':src_ip,'dst_ip':dst_ip,'pkt_num':pkt_num,'time':time})
    
# database test - END

def kafka_consumer():
    print("kafka consumer test...")
    try :
        for message in consumer:
            value = message.value
            print(value)
            length = len(value)
            counter = 0
            for i in value[::-1]: # to find time in the string, reverse the string for iterated lookup
                if i == ' ':
                    break
                else:
                    counter = counter + 1
            #test_offset = 11
            #source_ip = decimal_to_human(str(value[:test_offset+10]))
            pkt_num = str(value[22:-counter])
            source_ip = decimal_to_human(value[:10])
            destination_ip = decimal_to_human(value[11:21])
            time = str(value[-counter:])
            print('src_ip : ' + source_ip + ' dst_ip : ' + destination_ip + ' packet : ' + pkt_num + 'time : ' + str(value[-counter:]))
            insert_into_db(source_ip, destination_ip, pkt_num, time)
    except KeyboardInterrupt:
        sys.exit()

def decimal_to_human(input_value):
    input_value = int(input_value)
    hex_value = hex(input_value)[2:]
    pt3 = literal_eval((str('0x'+str(hex_value[-2:]))))
    pt2 = literal_eval((str('0x'+str(hex_value[-4:-2]))))
    pt1 = literal_eval((str('0x'+str(hex_value[-6:-4]))))
    pt0 = literal_eval((str('0x'+str(hex_value[-8:-6]))))
    result = str(pt0)+'.'+str(pt1)+'.'+str(pt2)+'.'+str(pt3)
    return result

kafka_consumer()

