#!/bin/bash

# read the syslog agent installation command from fp-csg-sentinel.yml file
agent_command=$(cat ./fp-csg-sentinel.yml | grep "SYSLOG_AGENT_INSTALLATION_COMMAND:" | awk -FSYSLOG_AGENT_INSTALLATION_COMMAND: '{print $2}' | sed  's/"//g')
sudo apt update -y
sudo apt -y install libcurl4 curl
sudo apt install software-properties-common -y
sudo systemctl start rsyslog.service
# install python
sudo apt install -y python python-ctypes
sudo apt install lsof -y

wget https://dl.google.com/go/go1.15.1.linux-amd64.tar.gz
sudo tar -zxvf go1.15.1.linux-amd64.tar.gz -C /usr/local
echo "export GOROOT=/usr/local/go" | sudo tee -a /etc/profile
echo "export PATH=$PATH:/usr/local/go/bin" | sudo tee -a /etc/profile
source /etc/profile
eval $agent_command
chmod +x fp-csg-sentinel
mkdir /var/forpcepoint-csg
mv fp-csg-sentinel.service /etc/systemd/system/
mv fp-csg-sentinel /var/forpcepoint-csg/
mv fp-csg-sentinel.yml /var/forpcepoint-csg/
sudo systemctl enable fp-csg-sentinel.service
echo "##########################################################################"
echo "#######Creating an encrypted blob to store Forcepoint CSG credentials#####"
/var/forpcepoint-csg/fp-csg-sentinel run -c
