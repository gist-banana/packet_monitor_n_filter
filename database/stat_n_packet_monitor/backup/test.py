from kafka import KafkaConsumer
import sys
from ast import literal_eval
import pytz
#define information about kafka

bootstrap_servers = ['210.125.84.133:9092','210.125.84.132:9092']
#topics = ['packetmonitor','bpf1']
bootstrap_servers_bpf2 = ['210.125.84.133:9092']
topicName_bpf2 = 'packetmonitor'
bootstrap_servers_bpf1 = ['210.125.84.132:9092']
topicName_bpf1 = 'bpf1'

consumer_bpf2 = KafkaConsumer(topicName_bpf2, bootstrap_servers = bootstrap_servers_bpf2)
consumer_bpf1 = KafkaConsumer(topicName_bpf1, bootstrap_servers = bootstrap_servers_bpf1)
consumer_test = KafkaConsumer('packetmonitor','bpf1',bootstrap_servers=bootstrap_servers)

# database test - BEGIN

def insert_into_db(src_ip, pkt_num, time):
    client = MongoClient()
    db = client.packetmonitor    # database name
    collection = db.bpf2    # document name
    collection.insert_one({'src_ip':src_ip,'pkt_num':pkt_num,'time':time})
    
# database test - END

def kafka_consumer():
    print("kafka consumer test...")
    for message in consumer_test:
        print('hit')
        #value = message.value
        #print(value)

kafka_consumer()

