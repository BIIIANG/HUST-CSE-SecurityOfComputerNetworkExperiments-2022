# 使用说明

- 根据实验报告的“测试环境搭建”创建相应网络拓扑：

```shell
# 创建docker网络extranet
root@VM:/$ sudo docker network create --subnet=10.0.2.0/24 --gateway=10.0.2.8 --opt "com.docker.network.bridge.name"="docker1" extranet
# 创建docker网络intranet
root@VM:/$ sudo docker network create --subnet=192.168.60.0/24 --gateway=192.168.60.1 --opt "com.docker.network.bridge.name"="docker2" intranet

# 创建并运行容器HostU并删除默认路由
[05/06/22]seed@VM:~$ sudo docker run -it --name=HostU --hostname=HostU --net=extranet --ip=10.0.2.7 --privileged "seedubuntu" /bin/bash
root@HostU:/# route del default
root@HostU:/# cd home
root@HostU:/home# mkdir xba
root@HostU:/home# cd xba
# 创建并运行容器HostU2并删除默认路由
[05/06/22]seed@VM:~$ sudo docker run -it --name=HostU2 --hostname=HostU2 --net=extranet --ip=10.0.2.27 --privileged "seedubuntu" /bin/bash
root@HostU2:/# route del default
root@HostU2:/# cd home
root@HostU2:/home# mkdir xba
root@HostU2:/home# cd xba
# 创建并运行容器HostV并删除默认路由
[05/06/22]seed@VM:~$ sudo docker run -it --name=HostV --hostname=HostV --net=intranet --ip=192.168.60.101 --privileged "seedubuntu" /bin/bash
root@HostV:/# route del default
root@HostV:/# route add -net 192.168.53.0/24 gw 192.168.60.1
root@HostV:/# sudo /etc/init.d/openbsd-inetd restart
```

- 解压`miniVPN_XuBiang.tar.gz`，运行`miniVPN`文件夹下的`cp.sh`脚本，编译并复制程序：

```shell
[06/12/22]seed@VM:~/.../miniVPN$ ./cp.sh 
gcc -o vpn_client vpn_client.c -lssl -lcrypto
gcc -o vpn_server vpn_server.c -lssl -lcrypto -lcrypt -lpthread
```

- 首先启动`VPN`服务器，证书口令为`xbaserver`，注意应使用`sudo`执行；
- 然后启动`VPN`客户端，证书口令为`xbaclient`，其他参数根据提示和实际情况填写，在默认情况下按照以下填写：
  - 服务器`IP/域名`：`10.0.2.8`（若配置了`HOSTS`文件可以填写对应的域名）
  - 服务器端口：`4433`
  - 证书口令：`xbaclient`
  - 用户名：`seed`
  - 密码：`dees`
  - 期望`IP`：任意填写`2~254`中的值
- 注：`CA`证书有效期为`1`个月，因此可能已经过期，若仍使用该证书可以将`client`的`call_back`函数中忽略证书过期。