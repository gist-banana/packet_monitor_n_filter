from pymongo import MongoClient
client = MongoClient()

client = MongoClient('localhost',27017)
db = client.packetmonitor
collection = db.bpf2

for post in collection.find({'time':{'&lt':'2020;2;23;1;29;52'}}):
    print(post)
