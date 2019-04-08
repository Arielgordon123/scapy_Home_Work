from scapy.all import *
import re
# load the packet file
packets = rdpcap('CaptureFile.cap')

# Q1
print(packets[0])
print("packet len: ",len(packets[0]))

# OUTPUT 
# b'\x00\x1f\x1f\xbf\x9f\x10\x00&^gf^\x08\x00E\x00\x00F?\xa4\x00\x00\x80\x11uG\xc0\xa8\x02j\xc0\xa8\x02\x01\xc8\xb4\x005\x002x\xc0\x86\x9c\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x03www\x10google-analytics\x03com\x00\x00\x01\x00\x01'
# packet len:  84


# Q2
def serach_in_cap(packet,obj):
    _cnt = 0
    for i in range(len(packet)):
        try:
            l = packet[i].getlayer(Raw)
            for st in range(len(obj)):
                if obj[st][0] in str(l):
                    obj[st][1] +=1

        except Exception:
            print(traceback.print_exc())
    return obj
            
obj = [["google",0],["ynet",0],["SuperPharmLogo.gif",0],["HelloWorld",0]]

obj = serach_in_cap(packets,obj)
for l in obj:
    print(str.format("The string: \"{}\" has {} appearance",l[0],l[1]))

# OUTPUT:
# The string: "google" has 264 appearance
# The string: "ynet" has 307 appearance
# The string: "SuperPharmLogo.gif" has 1 appearance
# The string: "HelloWorld" has 0 appearance


# Q3
def get_num_of_packets(packet):
    _cnt = 0
    sessions = packet.sessions()
    for session in sessions:
        for pck in sessions[session]:
            _cnt += 1
        # print(i)
    return _cnt

print("Packets length is:",get_num_of_packets(packets))

# OUTPUT:
# Packets length is: 1115

# Q4
def get_max_len_packet(packets):
    max_len = 0
    place = 1
    # sessions = packet.sessions()
    for session in range(len(packets)):
        for pck in packets[session]:
            try:
                # print(len(pck.payload), len(pck))
                if max_len < len(pck):
                    max_len = len(pck)
                    place = session
            except:
                pass
    print("max Length is:", max_len, "Sesion Id",place)
    return max_len
# OUTPUT:
# max Length is: 1514 Sesion Id 20

# Q5
def get_min_len_packet(packets):
    min_len = get_max_len_packet(packets)
    place = 1
    # sessions = packet.sessions()
    for session in range(len(packets)):
        for pck in packets[session]:
            try:
                # print(len(pck.payload), len(pck))
                if min_len > len(pck):
                    min_len = len(pck)
                    place = session
            except:
                pass
    print("min Length is:", min_len, "Sesion Id",place)
get_min_len_packet(packets)

# OUTPUT:
# min Length is: 42 Sesion Id 470

# Q6
def get_host_name(packets):
    for session in range(len(packets)):
        for pck in packets[session]:
            try:
                # print(session[IP])
                s = str(pck)
                # print(s)
                print(re.search(r'\\r\\nHost: (.*?)\\r\\n', s).group(1))
                
            except:
                pass
                # print(traceback.format_exc())
get_host_name(packets)

# OUTPUT:

# Q7
def get_user_name(packets):
    for session in range(len(packets)):
        for pck in packets[session]:
            try:
                # print(session[IP])
                s = str(pck)
                # print(s)
                # print(re.search(r'\\r\\npass:(.*?)\\r\\n', s))
                if re.search(r'user', s):
                    password = re.search(r'\\r\\npass:(.*?)\\r\\n',s).group(1)
                    userName = re.search(r'\\r\\nusername:(.*?)\\r\\n',s).group(1)
                    print("userName:",userName,"password:" , password)
                
            except:
                pass
                # print(traceback.format_exc())
get_user_name(packets)
# OUTPUT:
# userName: administrator password: TOP_SECRET

# Q8
def get_dns(packets):
    lst = []
    for i,p in enumerate(packets):
        if p.haslayer(DNS):   
            if p.qdcount > 0 and isinstance(p.qd, DNSQR):
                print(p.dst)
                # Q10
                name = p.qd.qname
                # Q9
                lst.append({"id":i,name:name})
            else:
                continue

            
    print(lst)
        
get_dns(packets)



