#!/usr/bin/env bash

# update cfme vmdb.yml.db file

if [ -z $1 ] ; then
   echo "Usage: ./`basename $0` <vmdb.yml_url>"
   echo "Argument missing: vmdb.yml URL required"
   exit
fi

VMDB_URL=$1

VMDB_CONFIG_PATH=/var/www/miq/vmdb/config
CONFIG_FILE=vmdb.yml.db
UPDATE_FILE=vmdb.yml
TMP_FILE=/tmp/vmdb.yml

curl -o $TMP_FILE --url $VMDB_URL --insecure --fail
cd $VMDB_CONFIG_PATH
cat $TMP_FILE > $CONFIG_FILE
mv $CONFIG_FILE $UPDATE_FILE

# wait for CFME to rename vmdb.yml to vmdb.yml.db
while true; do
   sleep 2
   UPDATE=`ls -1 $CONFIG_FILE 2> /dev/null`
   if [ $UPDATE ]; then
      exit
   fi
done

