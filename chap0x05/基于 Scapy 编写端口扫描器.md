# 基于 Scapy 编写端口扫描器

## 实验目的

- 掌握网络扫描之端口状态探测的基本原理

## 实验环境

- python + [scapy](https://scapy.net/)

## 实验要求

- 禁止探测互联网上的 IP ，严格遵守网络安全相关法律法规

- 完成以下扫描技术的编程实现

- - [x] TCP connect scan / TCP stealth scan
  - [x] TCP Xmas scan / TCP fin scan / TCP null scan
  - [x] UDP scan

- 上述每种扫描技术的实现测试均需要测试端口状态为：`开放`、`关闭` 和 `过滤` 状态时的程序执行结果

- 提供每一次扫描测试的抓包结果并分析与课本中的扫描方法原理是否相符？如果不同，试分析原因；

- 在实验报告中详细说明实验网络环境拓扑、被测试 IP 的端口状态是如何模拟的

- （可选）复刻 `nmap` 的上述扫描技术实现的命令行参数开关


## 网络拓扑

- 攻击者主机:
  - 172.16.111.147
- 受害者主机:
  - 172.16.111.137
- 网关:
  - 172.16.111.1

## 实验步骤

### 环境准备

- 在受害者主机安装ufw模拟端口状态

```sudo apt install ufw
sudo apt install ufw
```

- 在受害者主机安装dnsmasq搭建dns服务

```
sudo apt install dnsmasq
```

- 端口关闭状态

```
sudo ufw disable
systemctl stop apache2
systemctl stop dnsmasq 
```

![端口关闭状态](img/端口关闭状态.jpg)

- 端口开放状态

```
systemctl start apache2 开启服务开放TCP端口
systemctl start dnsmasq 开启服务开放UDP端口
```

![端口开放状态](img/端口开放状态.jpg)

- 端口被过滤状态

```
sudo ufw enable && sudo ufw deny 80/tcp
sudo ufw enable && sudo ufw deny 53/udp
```

![端口被过滤状态](img/端口被过滤状态.jpg)

### TCP connect scan

-  原理

  这种扫描方式可以使用 Connect()调用，使用最基本的 TCP 三次握手链接建立机制，建立一个链接到目标主机的特定端口上。首先发送一个 SYN 数据包到目标主机的特定端口上，接着我们可以通过接收包的情况对端口的状态进行判断：

  - 如果接收到的是一个 SYN/ACK 数据包，则说明端口是开放状态的
  - 如果接收到的是一个 RST/ACK 数据包，通常意味着端口是关闭的并且链接将会被重置
  - 而如果目标主机没有任何响应则意味着目标主机的端口处于过滤状态。

  若接收到 SYN/ACK 数据包（即检测到端口是开启的），便发送一个 ACK 确认包到目标主机，这样便完成了三次握手连接机制。成功后再终止连接。

  优点：稳定可靠，不需要特殊的权限。但扫描方式不隐蔽，服务器日志会纪录下大量密集的连接和错误记录，并容易被防火墙发现和屏蔽。

- 代码

  ```python
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
  ```

   [1.py](py\1.py) 

- 开放

  ```
  systemctl start apache2 （靶机）
  systemctl status apache2 （靶机）
  ```

  ![端口开放1](img/端口开放1.PNG)

  - 靶机抓包

    ```
    sudo tcpdump -i eth0 -enp -w 20211010.1.pcap
    ```

    ![抓包1](img/抓包1.PNG)

  - 扫描端执行代码

    ```
    sudo python3 connect.py
    ```

    ![扫描端1.1](img/扫描端1.1.PNG)

  - 抓包结果

    ![抓包结果1.1](img/抓包结果1.1.PNG)

  - nmap复刻

    ```
    nmap -sT -p 80 172.16.111.137
    ```

    ![namp复刻1.1](img/namp复刻1.1.PNG)

- 关闭

  ```
  systemctl stop apache2（靶机）
  systemctl status apache2
  ufw disable
  ```

  ![端口关闭1](img/端口关闭1.PNG)

  - 靶机抓包

    ```
    sudo tcpdump -i eth0 -enp -w 1.2.pcap
    ```

    ![靶机抓包1.2](img/靶机抓包1.2.PNG)

  - 扫描端执行代码

    ```
    sudo python3 1.py
    ```

    ![扫描端1.2](img/扫描端1.2.PNG)

  - 抓包结果

    ![抓包结果1.2](img/抓包结果1.2.PNG)

  - nmap复刻

    ![namp1.2](C:\Users\lenovo\Desktop\chap0x05\img\namp1.2.PNG)

- 过滤

  ![端口过滤1](img/端口过滤1.PNG)

  - 靶机抓包

    ![靶机1.3](img/靶机1.3.PNG)

  - 扫描端执行代码

    ![扫描端1.3](img/扫描端1.3.PNG)

  - 抓包结果

    ![抓包1.3](img/抓包1.3.PNG)

  - nmap复刻

    ![namp1.3](img/namp1.3.PNG)

### TCP stealth scan

- 原理

  与 TCP Connect 扫描不同，TCP SYN 扫描并不需要打开一个完整的链接。发送一个 SYN 包启动三方握手链接机制，并等待响应。

  - 如果我们接收到一个 SYN/ACK 包表示目标端口是开放的
  - 如果接收到一个 RST/ACK 包表明目标端口是关闭的
  - 如果端口是被过滤的状态则没有响应。

  当得到的是一个 SYN/ACK 包时通过发送一个 RST 包立即拆除连接。

  优点：隐蔽性较全连接扫描好，因为很多系统对这种半扫描很少记录。缺点是构建 SYN 报文需要超级用户权限，且网络防护设备会有记录。

- 代码

  ```python
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
  ```

   [2.py](py\2.py) 

- 开放

  ```
  systemctl start apache2 （靶机）
  systemctl status apache2 （靶机）
  ufw disable (关闭防火墙)
  ```

  ![端口开放2](img/端口开放2.PNG)

  - 靶机抓包

    ```
    sudo tcpdump -i eth0 -enp -w 2.1.pcap
    ```

    ![靶机抓包2.1](img/靶机抓包2.1.PNG)

  - 扫描端执行代码

    ```
    sudo python3 2.py
    ```

    ![扫描端2.1](img/扫描端2.1.PNG)

  - 抓包结果

    ![抓包结果2.1](img/抓包结果2.1.PNG)

  - nmap复刻

    ```
    nmap -sS -p 80 172.16.111.137
    ```

    ![nmap复刻2.1](img/nmap复刻2.1.PNG)

- 关闭

  ```
  systemctl stop apache2
  systemctl status apache2
  ```

  ![端口关闭2](img/端口关闭2.PNG)

  - 靶机抓包

    ![靶机抓包2.2](img/靶机抓包2.2.PNG)

  - 扫描端执行代码

    ![扫描端2.2](img/扫描端2.2.PNG)

  - 抓包结果

    ![抓包结果2.2](img/抓包结果2.2.PNG)

  - nmap复刻

    ![nmap2.2](img/nmap2.2.PNG)

- 过滤

  ```
  ufw enable && ufw deny 80/tcp
  ```

  ![过滤2](img/过滤2.PNG)

  - 靶机抓包

    ![靶机2.3](img/靶机2.3.PNG)

  - 扫描端执行代码

    ![扫描端2.3](img/扫描端2.3.PNG)

  - 抓包结果

    ![抓包2.3](img/抓包2.3.PNG)

  - nmap复刻

    ![nmap2.3](img/nmap2.3.PNG)

### TCP Xmas scan

- 原理

  Xmas 发送一个 TCP 包，并对 TCP 报文头 FIN、URG 和 PUSH 标记进行设置。

  - 若是关闭的端口则响应 RST 报文
  - 开放或过滤状态下的端口则无任何响应。

  优点：隐蔽性好，缺点是需要自己构造数据包，要求拥有超级用户或者授权用户权限。

- 代码

  ```python
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
  ```

   [3.py](py\3.py) 

- 开放

  ![端口开放3](img/端口开放3.PNG)

  - 靶机抓包

    ![靶机3.1](img/靶机3.1.PNG)

  - 扫描端执行代码

    ![抓包3.1](img/抓包3.1.PNG)

  - 抓包结果

    ![抓包2.3](img/抓包2.3.PNG)

  - nmap复刻

    ![nmap3.1](img/nmap3.1.PNG)

- 关闭

  ![端口关闭3](img/端口关闭3.PNG)

  - 靶机抓包

    ![靶机3.2](img/靶机3.2.PNG)

  - 扫描端执行代码

    ![扫描端3.2](img/扫描端3.2.PNG)

  - 抓包结果

    ![抓包结果3.2](img/抓包结果3.2.PNG)

  - nmap复刻

    ![nmap3.2](img/nmap3.2.PNG)

- 过滤

  ![端口过滤3](img/端口过滤3.PNG)

  - 靶机抓包

    ![3.3靶机](img/3.3靶机.PNG)

  - 扫描端执行代码

    ![3.3扫描端](img/3.3扫描端.PNG)

  - 抓包结果

    ![3.3抓包](img/3.3抓包.PNG)

  - nmap复刻

    ![3.3nmap](img/3.3nmap.PNG)

### TCP fin scan

- 原理

  仅发送 FIN 包，它可以直接通过防火墙，如果端口是关闭的就会回复一个 RST 包，如果端口是开放或过滤状态则对 FIN 包没有任何响应。
  优点： FIN 数据包能够通过只监测 SYN 包的包过滤器，且隐蔽性高于 SYN 扫描。缺点和 SYN 扫描类似，需要自己构造数据包，要求由超级用户或者授权用户访问专门的系统调用。

- 代码

  ```python
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
  ```

   [4.py](py\4.py) 

- 开放

  ![端口开放4](img/端口开放4.PNG)

  - 靶机抓包

    ![4.1靶机](img/4.1靶机.PNG)

  - 扫描端执行代码

    ![4.1扫描端](img/4.1扫描端.PNG)

  - 抓包结果

    ![4.1抓包](img/4.1抓包.PNG)

  - nmap复刻

    ![4.1nmap](img/4.1nmap.PNG)

- 关闭

  ![端口关闭4](img/端口关闭4.PNG)

  - 靶机抓包

    ![4.2靶机](img/4.2靶机.PNG)

  - 扫描端执行代码

    ![4.2扫描端](img/4.2扫描端.PNG)

  - 抓包结果

    ![4.2抓包](img/4.2抓包.PNG)

  - nmap复刻

    ![4.2nmap](img/4.2nmap.PNG)

- 过滤

  ![端口过滤4](img/端口过滤4.PNG)

  - 靶机抓包

    ![4.3靶机](img/4.3靶机.PNG)

  - 扫描端执行代码

    ![4.3扫描端](img/4.3扫描端.PNG)

  - 抓包结果

    ![4.3抓包](img/4.3抓包.PNG)

  - nmap复刻

    ![4.3nmap](img/4.3nmap.PNG)

###  TCP null scan

- 原理

  发送一个 TCP 数据包，关闭所有 TCP 报文头标记。只有关闭的端口会发送 RST 响应。

  优点：和 Xmas 一样是隐蔽性好，缺点也是需要自己构造数据包，要求拥有超级用户或者授权用户权限。

- 代码

  ```python
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
  ```

   [5.py](py\5.py) 

- 开放

  ![端口开放5](img/端口开放5.PNG)

  - 靶机抓包

    ![5.1靶机](img/5.1靶机.PNG)

  - 扫描端执行代码

    ![5.1扫描端](img/5.1扫描端.PNG)

  - 抓包结果

    ![5.1抓包](img/5.1抓包.PNG)

  - nmap复刻

    ![5.1nmap](img/5.1nmap.PNG)

- 关闭

  ![端口关闭5](img/端口关闭5.PNG)

  - 靶机抓包

    ![5.2靶机](img/5.2靶机.PNG)

  - 扫描端执行代码

    ![5.2扫描端](img/5.2扫描端.PNG)

  - 抓包结果

    ![5.2抓包](img/5.2抓包.PNG)

  - nmap复刻

    ![5.2nmap](img/5.2nmap.PNG)

- 过滤

  ![端口过滤5](img/端口过滤5.PNG)

  - 靶机抓包

    ![5.3抓包](img/5.3抓包.PNG)

  - 扫描端执行代码

    ![5.3扫描端](img/5.3扫描端.PNG)

  - 抓包结果

    ![5.3抓包](img/5.3抓包.PNG)

  - nmap复刻

    ![5.3扫描端](img/5.3扫描端.PNG)

### UDP scan

- 原理

  UDP 是一个无链接的协议，当我们向目标主机的 UDP 端口发送数据,我们并不能收到一个开放端口的确认信息,或是关闭端口的错误信息。

  - 如果收到一个 ICMP 不可到达的回应，那么则认为这个端口是关闭的
  - 没有回应的端口则认为是开放的
  - 但是如果目标主机安装有防火墙或其它可以过滤数据包的软硬件,那我们发出 UDP 数据包后,将可能得不到任何回应,我们将会见到所有的被扫描端口都是开放的。

  缺点：UDP 是不可靠的，UDP 数据包和 ICMP 错误报文都不保证到达；且 ICMP 错误消息发送效率是有限的，故而扫描缓慢；还有就是非超级用户无法直接读取端口访问错误。

- 代码

  ```python
  from scapy.all import *
  
  
  def udp_scan(dst_ip, dst_port, dst_timeout=10):
      udp_scan_resp = sr1(IP(dst=dst_ip)/UDP(dport=dst_port), timeout=dst_timeout)
      print(type(udp_scan_resp))
      if (str(type(udp_scan_resp)) == "<class 'NoneType'>"):
          print("Open|Filtered")
      elif (udp_scan_resp.haslayer(UDP)):
          print("Open")
      elif(udp_scan_resp.haslayer(ICMP)):
          if(int(udp_scan_resp.getlayer(ICMP).type) == 3 and int(udp_scan_resp.getlayer(ICMP).code) == 3):
              print("Closed")
          elif(int(udp_scan_resp.getlayer(ICMP).type) == 3 and int(udp_scan_resp.getlayer(ICMP).code) in [1, 2, 9, 10, 13]):
              print("Filtered")
          elif(udp_scan_resp.haslayer(IP) and udp_scan_resp.getlayer(IP).proto == IP_PROTOS.udp):
              print("Open")
  
  udp_scan('172.16.111.137', 53)
  ```

   [6.py](py\6.py) 

- 开放

  ![端口开放6](img/端口开放6.PNG)

  - 靶机抓包

    ![6.1靶机](img/6.1靶机.PNG)

  - 扫描端执行代码

    ![6.1扫描端](img/6.1扫描端.PNG)

  - 抓包结果

    ![6.1抓包](img/6.1抓包.PNG)

  - nmap复刻

    ![6.1nmap](img/6.1nmap.PNG)

- 关闭

  ![端口关闭6](img/端口关闭6.PNG)

  - 靶机抓包

    ![6.1靶机](img/6.1靶机.PNG)

  - 扫描端执行代码

    ![6.2扫描端](img/6.2扫描端.PNG)

  - 抓包结果

    ![6.2抓包](img/6.2抓包.PNG)

  - nmap复刻

    ![6.1nmap](img/6.1nmap.PNG)

- 过滤

  ![端口过滤6](img/端口过滤6.PNG)

  - 靶机抓包

    ![6.3扫描端](img/6.3靶机.PNG)

  - 扫描端执行代码

    ![6.3扫描端](img/6.3扫描端.PNG)

  - 抓包结果

    ![6.3抓包](img/6.3抓包.PNG)

  - nmap复刻

    ![6.3nmap](img/6.3nmap.PNG)
