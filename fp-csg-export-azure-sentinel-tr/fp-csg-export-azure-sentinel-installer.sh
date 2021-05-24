#!/bin/bash

if [ ! -x /usr/bin/wget ] ; then
    command -v wget >/dev/null 2>&1 || { echo >&2 "Please install wget or set it in your path. Aborting."; exit 1; }
fi
wget https://dl.google.com/go/go1.15.1.linux-amd64.tar.gz
sudo tar -zxvf go1.15.1.linux-amd64.tar.gz -C /usr/local
echo "export GOROOT=/usr/local/go" | sudo tee -a /etc/profile
echo "export PATH=$PATH:/usr/local/go/bin" | sudo tee -a /etc/profile
source /etc/profile
chmod +x fp-csg-sentinel
mkdir /var/forpcepoint-csg
mv fp-csg-sentinel.service /etc/systemd/system/
mv fp-csg-sentinel /var/forpcepoint-csg/
mv fp-csg-sentinel.yml /var/forpcepoint-csg/
sudo systemctl enable fp-csg-sentinel.service
echo "##########################################################################"
echo "#######Creating an encrypted blob to store Forcepoint CSG credentials#####"
/var/forpcepoint-csg/fp-csg-sentinel run -c
echo ""