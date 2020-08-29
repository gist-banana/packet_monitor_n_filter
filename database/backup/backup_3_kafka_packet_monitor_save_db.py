from kafka import KafkaConsumer
import sys
from ast import literal_eval
from pymongo import MongoClient

#define information about kafka

bootstrap_servers = ['210.125.84.133:9092']
topicName = 'packetmonitor'

consumer = KafkaConsumer(topicName, bootstrap_servers = bootstrap_servers)

# database test - BEGIN

def insert_into_db(src_ip, dst_ip, time):
    client = MongoClient()
    db = client.packetmonitor    # database name
    collection = db.bpf2    # document name
    collection.insert_one({'src_ip':src_ip,'dst_ip':dst_ip,'time':time})

# database test - END

def kafka_consumer():
    print("kafka consumer test...")
    try :
        for message in consumer:
            value = message.value
            # value being saved appropriately has been confirmed
            # data is either parsed in 3 columns or 6 columns -> len : 30 && len : 60
            if (len(value) == 30):
#                print(value)
                src_ip_0 = str(decimal_to_human(str(value[9:19])))
                dst_ip_0 = str(decimal_to_human(str(value[20:30])))
                print(' src1 : ' + str(src_ip_0) + 'dst1 : ' + str(dst_ip_0))
                time_temp = '111'
                insert_into_db(src_ip_0,dst_ip_0,time_temp)
                
            elif (len(value) == 60):
#                print(value)
                time_temp = '111'
                src_ip_0 = str(decimal_to_human(str(value[9:19])))
                dst_ip_0 = str(decimal_to_human(str(value[20:30])))
                src_ip_1 = str(decimal_to_human(str(value[39:49])))
                dst_ip_1 = str(decimal_to_human(str(value[50:60])))
                print(' src1 : ' + str(src_ip_0) + ' dst1 : ' + str(dst_ip_0) + ' src2 : '+ str(src_ip_1) + ' dst2 : ' + str(dst_ip_1))
                insert_into_db(src_ip_0,dst_ip_0,time_temp)
                insert_into_db(src_ip_1,dst_ip_1,time_temp)
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

