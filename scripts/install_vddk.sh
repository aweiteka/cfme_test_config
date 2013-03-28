#!/usr/bin/env bash
 
# run unattended vddk install and reboot

if [ -z $1 ] ; then
   echo "Usage: ./`basename $0` <vmware-vix.tar>"
   echo "VMware-vix tar filename required."
   exit
fi

tar -xvf $1
cd vmware-vix-disklib-distrib
./vmware-install.pl EULA_AGREED=yes --default --prefix=/usr
ldconfig
reboot

