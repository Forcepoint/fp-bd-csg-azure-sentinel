#!/bin/bash

echo "Starting Up..."
#/opt/onboard_agent.sh --purge

echo "Update apt ..."
apt-get update > /dev/null 2>&1
service rsyslog stop > /dev/null 2>&1
apt-get update  > /dev/null 2>&1

echo "installing syslog-ng"
apt-get install syslog-ng syslog-ng-core -y > /dev/null 2>&1
service syslog-ng start

echo "installing Log Analytics Agent....please wait"
eval "$SYSLOG_AGENT_INSTALLATION_COMMAND > /dev/null 2>&1"

echo "starting the agent.."
/opt/microsoft/omsagent/bin/omsagent \
  -d /var/opt/microsoft/omsagent/"$1"/run/omsagent.pid \
  -o /var/opt/microsoft/omsagent/"$1"/log/omsagent.log \
  -c /etc/opt/microsoft/omsagent/"$1"/conf/omsagent.conf \
  --no-supervisor

echo "agent started!"
sleep 5
echo "CSG Sentinel Log Exporter Started"
/opt/scg-sentinel run
