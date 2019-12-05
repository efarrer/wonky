#!/bin/bash -e

# What interface do you want to wonk?
iface=ppp0

# The address to run the wonky server on
serveraddr=thebes.cs.utah.edu

# the username to ssh into $serveraddr
user=farrer


ipaddr=$(ifconfig | grep -A 1 "$iface" | tail -n 1 |  sed '{s/.*inet addr://g}' | sed '{s/ .*//g}')


echo "Copying over server $user@$serveraddr"
scp ./wonkyserver ${user}@${serveraddr}:
echo "Execute the following in another shell then hit enter to continue"
echo "ssh -L 8080:localhost:8080 $user@$serveraddr ./wonkyserver"
read
sudo ./wonky -d $iface -f "host $ipaddr" -u nobody -a localhost -p 8080
