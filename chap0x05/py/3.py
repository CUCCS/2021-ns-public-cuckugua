from scapy.all import *

def tcp_xmas_scan(dst_ip, dst_port, timeout=10):

   
    xmas_scan_resp = sr1(IP(dst=dst_ip) / TCP(dport=dst_port, flags="FPU"), timeout=10)
    print(type(xmas_scan_resp))

    if (str(type(xmas_scan_resp)) == "<class 'NoneType'>"):
        print("Open|Filtered")

    elif (xmas_scan_resp.haslayer(TCP)):
        if (xmas_scan_resp.getlayer(TCP).flags == 0x14):
            print("Closed")
    elif (xmas_scan_resp.haslayer(ICMP)):
        if (int(xmas_scan_resp.getlayer(ICMP).type) == 3 and int(xmas_scan_resp.getlayer(ICMP).code) in [1, 2, 3, 9, 10,13]):
            print("Filtered")
    print('finished tcp xmas scan.\n')

tcp_xmas_scan('172.16.111.137', 80)