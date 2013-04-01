#!/usr/bin/env bash
 
# setup inbound mail server for mail processing
# will forward mail for delivery
 
yum install -y postfix mutt
postconf -e "inet_interfaces = all"
postconf -e "mynetworks_style = class"
postconf -e "mynetworks = 10.0.0.0/8"
# TODO: if sendmail running, kill it (bound to port 25)
service postfix start && chkconfig postfix on

