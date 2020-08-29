ipint = 3232235521
ip=""
for i in range(4):
        ip1 = ""
        for j in range(8):
#                print ipint % 2
                ip1=str(ipint % 2)+ip1
                ipint = ipint >> 1
#                print ip1
#        print ip1
        ip = str(int(ip1,2)) + "." + ip
print ip.strip(".")
