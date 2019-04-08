from scapy.all import *

import re

packets = rdpcap('CaptureFile.cap')


print(packets[0])
print("packet len: ",len(packets[0]))


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

print(obj)

def get_num_of_packets(packet):
    _cnt = 0
    sessions = packet.sessions()
    for session in sessions:
        for pck in sessions[session]:
            _cnt += 1
        # print(i)
    return _cnt

print("Packets length is:",get_num_of_packets(packets))

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

# \\r\\nHost: (.*?)\\r\\n
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
# get_host_name(packets)

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

def get_dns(packets):
    s = 0
    pp = 0
    for p in packets:
        if p.haslayer(DNS):   
            if p.qdcount > 0 and isinstance(p.qd, DNSQR):
                p.show()
                name = p.qd.qname
                pp+=1
            elif p.ancount > 0 and isinstance(p.an, DNSRR):
                name = p.an.rdata
                s+=1
            else:
                continue

            print(name)
    print(s,pp)
        # try:
        #     # if packets[session].haslayer(DNSQR):
        #     #     s +=1
        #     #     # packets[session].show()
        #     #     # print(pck.dst, pck.src)
        #     print(ls(packets[session][DNS]))
            
        #     # print(packets[session])
        #     p+=1
        # except:
        #     pass
    
get_dns(packets)