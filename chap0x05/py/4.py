from scapy.all import *

def tcp_fin_scan(dst_ip, dst_port, dst_timeout=10):

    fin_scan_resp = sr1(IP(dst=dst_ip) / TCP(dport=dst_port, flags="F"), timeout=10)
    print(type(fin_scan_resp))

    if (str(type(fin_scan_resp)) == "<class 'NoneType'>"):
        print("Open|Filtered")
    elif (fin_scan_resp.haslayer(TCP)):
        if (fin_scan_resp.getlayer(TCP).flags == 0x14):
            print("Closed")

    elif (fin_scan_resp.haslayer(ICMP)):
        if (int(fin_scan_resp.getlayer(ICMP).type) == 3 and int(fin_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10,13]):
            print("Filtered")
    print('finished tcp fin scan.\n')

tcp_fin_scan('172.16.111.137', 80)