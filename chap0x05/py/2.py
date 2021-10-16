from scapy.all import *

def tcp_syn_scan(dst_ip, dst_port, timeout=10):

    # send SYN+port(80)
    tcp_sun_scan_p = sr1(IP(dst=dst_ip) / TCP(dport=dst_port,flags="S"),timeout=10)
    print(type(tcp_sun_scan_p))

    if str(type(tcp_sun_scan_p)) == "<class 'NoneType'>":
        print('no response, filtered')
    elif tcp_sun_scan_p.haslayer(TCP):
        # Flags:0x012 SYN,ACK
        if tcp_sun_scan_p.getlayer(TCP).flags == 0x12:
            # Flags: 0x014 ACK+RST
            send_ack = sr(IP(dst=dst_ip) / TCP(dport=dst_port, flags="AR"), timeout=10)
            print("is open")
        elif tcp_sun_scan_p.getlayer(TCP).flags == 0x14:
            print("is closed")
    elif tcp_sun_scan_p.haslayer(ICMP):
        if int(tcp_sun_scan_p.getlayer(ICMP).type)==3 and int(tcp_sun_scan_p.getlayer(ICMP).code) in [1,2,3,9,10,13]:
            print("filtered")
    print('finished tcp syn scan.\n')
    
tcp_syn_scan('172.16.111.137', 80)