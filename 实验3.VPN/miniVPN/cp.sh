#!/bin/sh

make
cd ..
sudo docker cp miniVPN HostU:/home/xba
sudo docker cp miniVPN HostU2:/home/xba
