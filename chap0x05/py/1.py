from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

dst_ip = "172.16.111.137" # 靶机IP地址
src_port = RandShort()
dst_port = 80

tcp_connect_scan_resp = sr1(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=10)
print(type(tcp_connect_scan_resp))

if str(type(tcp_connect_scan_resp)) == "<class 'NoneType'>":
        print("no response, filtered.")

# 获取 tcp 应答
elif tcp_connect_scan_resp.haslayer(TCP):
    # Flags:0x012 SYN,ACK
    if tcp_connect_scan_resp.getlayer(TCP).flags == 0x12:
        # Flags: 0x014 ACK,RST
        send_ack = sr(IP(dst=dst_ip)/TCP(sport=src_port,dport=dst_port,flags="AR"),timeout=10)
        print("is open")
    elif tcp_connect_scan_resp.getlayer(TCP).flags == 0x14:
        print("is closed, connection will be reset.")
    print('finished tcp connect scan.\n')
elif(tcp_connect_scan_resp.haslayer(ICMP)):
    if(int(tcp_connect_scan_resp.getlayer(ICMP).type)==3 and int(tcp_connect_scan_resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
            print("filtered")
print('finished tcp syn scan.\n')