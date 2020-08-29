from kafka import KafkaConsumer
import sys
from ast import literal_eval

#define information about kafka

bootstrap_servers = ['localhost:9092']
topicName = 'packetmonitor'

consumer = KafkaConsumer(topicName, bootstrap_servers = bootstrap_servers)

def kafka_consumer():
    print("kafka consumer test...")
    try :
        for message in consumer:
            value = message.value
            '''
            if (value[0] != '0'):
                if (value != '9999999'):
                    value = str(value)
                    print(decimal_to_human(value))
            '''
            # value being saved appropriately has been confirmed
            # data is either parsed in 3 columns or 6 columns -> len : 30 && len : 60
            if (len(value) == 30):
#                print(value)
                src_ip_0 = decimal_to_human(str(value[9:19]))
                dst_ip_0 = decimal_to_human(str(value[20:30]))
                print(' src1 : ' + str(src_ip_0) + 'dst1 : ' + str(dst_ip_0))
                
            elif (len(value) == 60):
#                print(value)
                src_ip_0 = decimal_to_human(str(value[9:19]))
                dst_ip_0 = decimal_to_human(str(value[20:30]))
                src_ip_1 = decimal_to_human(str(value[39:49]))
                dst_ip_1 = decimal_to_human(str(value[50:60]))
                print(' src1 : ' + str(src_ip_0) + ' dst1 : ' + str(dst_ip_0) + ' src2 : '+ str(src_ip_1) + ' dst2 : ' + str(dst_ip_1))
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
