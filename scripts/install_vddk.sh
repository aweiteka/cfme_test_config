#!/usr/bin/env bash

# run unattended vddk install and reboot

VDDK_URL=${1:-"http://qeblade5.rhq.lab.eng.bos.redhat.com/isos/VMware-vix-disklib-1.2.2-702422.x86_64.tar"}
VDDK_FILE=VMware-vix-disklib.tar

curl -o $VDDK_FILE --url $VDDK_URL --insecure --fail
tar -xvf $VDDK_FILE
cd vmware-vix-disklib-distrib
./vmware-install.pl EULA_AGREED=yes --default --prefix=/usr
ldconfig
reboot

