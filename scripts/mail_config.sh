#!/usr/bin/env bash
 
# setup inbound mail server for mail processing
# will forward mail for delivery
 
subscription-manager register --username=******@redhat.com --password=************** --autosubscribe
yum update -y
yum install -y postfix mutt
postconf -e "inet_interfaces = all"
postconf -e "mynetworks_style = class"
postconf -e "mynetworks = 10.0.0.0/8"
# if sendmail running, kill it
service postfix start && chkconfig postfix on

