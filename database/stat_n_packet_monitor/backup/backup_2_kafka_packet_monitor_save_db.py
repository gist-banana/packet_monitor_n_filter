from kafka import KafkaConsumer
import sys
from ast import literal_eval
from pymongo import MongoClient
import pytz
#define information about kafka

bootstrap_servers_bpf2 = ['210.125.84.133:9092']
topicName_bpf2 = 'packetmonitor'

consumer_bpf2 = KafkaConsumer(topicName, bootstrap_servers = bootstrap_servers_bpf2)

# database test - BEGIN

def insert_into_db(src_ip, pkt_num, time):
    client = MongoClient()
    db = client.packetmonitor    # database name
    collection = db.bpf2    # document name
    collection.insert_one({'src_ip':src_ip,'pkt_num':pkt_num,'time':time})
    
# database test - END

def kafka_consumer():
    print("kafka consumer test...")
    try :
        for message in consumer_bpf2:
            value = message.value
            length = len(value)
            counter = 0
            for i in value[::-1]: # to find time in the string, reverse the string for iterated lookup
                if i == ' ':
                    break
                else:
                    counter = counter + 1

            source_ip = decimal_to_human(str(value[:10]))
            pkt_num = str(value[11:-counter])
            time = str(value[-counter:])
            print('source ip : ' + source_ip + 'packet : ' + pkt_num) + 'time : ' + str(value[-counter:])
            insert_into_db(source_ip, pkt_num, time)
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

