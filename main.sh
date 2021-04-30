#!/bin/bash

work_space_id=$(echo "$SYSLOG_AGENT_INSTALLATION_COMMAND" | awk '{print $(NF-1)}')
echo "Starting Up..."
sudo service rsyslog start > /dev/null 2>&1
echo "Update apt ..."
apt-get update > /dev/null 2>&1
echo "installing Log Analytics Agent....please wait"
eval "$SYSLOG_AGENT_INSTALLATION_COMMAND > /dev/null 2>&1" > /dev/null 2>&1
echo "starting the agent.."
/opt/microsoft/omsagent/bin/omsagent \
  -d /var/opt/microsoft/omsagent/"$work_space_id"/run/omsagent.pid \
  -o /var/opt/microsoft/omsagent/"$work_space_id"/log/omsagent.log \
  -c /etc/opt/microsoft/omsagent/"$work_space_id"/conf/omsagent.conf \
  --no-supervisor

echo "agent started!"
sleep 5
echo "CSG Sentinel Log Exporter Started"
/opt/csg-sentinel run
