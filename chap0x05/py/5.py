from scapy.all import *

def tcp_null_scan(dst_ip, dst_port, dst_timeout=10):

    null_scan_resp = sr1(IP(dst=dst_ip) / TCP(dport=dst_port, flags=""), timeout=10)
    print(type(null_scan_resp))

    if (str(type(null_scan_resp)) == "<class 'NoneType'>"):
        print("Open|Filtered")

    elif (null_scan_resp.haslayer(TCP)):
        if (null_scan_resp.getlayer(TCP).flags == 0x14):
            print("Closed")
    elif (null_scan_resp.haslayer(ICMP)):
        if (int(null_scan_resp.getlayer(ICMP).type) == 3 and int(null_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10,13]):
            print("Filtered")

    print('finished tcp null scan.\n')

tcp_null_scan('172.16.111.137', 80)