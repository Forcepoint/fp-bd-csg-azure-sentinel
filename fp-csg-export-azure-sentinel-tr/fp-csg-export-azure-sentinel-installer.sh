#!/bin/bash

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