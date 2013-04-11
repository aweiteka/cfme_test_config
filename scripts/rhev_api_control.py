#!/usr/bin/env python

# Control RHEVM via api
# * create new guest via template
# * start and stop guest
# * get status and return IP address of running guest
# * TODO: import OVF and convert to template

from optparse import OptionParser
import sys
import json
import time
import requests
import urllib
import logging


class Connect(object):
    def __init__(self):
        logfile = "rhev_api.log"
        logger = logging.getLogger()
        fh = logging.FileHandler(logfile, mode='w')
        formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s", "%b %d %H:%M:%S")
        fh.setFormatter(formatter)
        if self.debug:
            logger.setLevel(logging.DEBUG)
        else:
            logger.setLevel(logging.INFO)
        logger.addHandler(fh)

    @property
    def opts(self):
        # TODO: validate args
        usage = """
    %prog -o <rhevm_host>
        -v <vm_name>
        -a <create|start|stop|status>
        -u <rhevm_user>
        -p <rhevm_passwd>
        [-t <template_name>]
        [-d]"""
        parser = OptionParser(usage=usage)
        parser.add_option("-o", "--host", dest="host",
                          help="RHEVM host in the form of https://localhost (without '/api')", 
                          metavar="HOST")
        parser.add_option("-t", "--template", dest="template", 
                          default="MIQ-v50029-DND",
                          help="template name", metavar="TEMP_NAME")
        parser.add_option("-v", "--vm_name", dest="vm_name", 
                          help="VM name", metavar="VM_NAME")
        parser.add_option("-a", "--action", dest="action", 
                          help="the action you want to do. create, start, stop, status", 
                          metavar="ACTION")
        parser.add_option("-u", "--user", dest="user",
                          help="RHEVM password", metavar="USER")
        parser.add_option("-p", "--pass", dest="passwd",
                          help="RHEVM password", metavar="PASS")
        parser.add_option("-d", "--debug",
                          action="store_true", dest="debug",
                          help="Turn on debug-level logging")

        (options, args) = parser.parse_args()
        return options

    @property
    def host(self):
        return self.opts.host

    @property
    def user(self):
        return self.opts.user

    @property
    def passwd(self):
        return self.opts.passwd

    @property
    def debug(self):
        return self.opts.debug

    def get(self, url):
        """Generic get request
        """
        r = requests.get(url,
                         headers=self.headers,
                         auth=(self.user, self.passwd), 
                         verify=False)
        logging.debug(r.text)
        if not self.success(r):
            return False
        else:
            return json.loads(r.text)

    def post(self, url, payload):
        """Generic post request
        """
        r = requests.post(url,
                          headers=self.headers,
                          auth=(self.user, self.passwd),
                          verify=False,
                          data=payload)
        logging.debug(r.text)
        if not self.success(r):
            return False
        else:
            return json.loads(r.text)

    @property
    def headers(self):
        """Required headers
        """
        h = {'Accept': 'application/json', 'Content-Type': 'application/xml'}
        return h

    @property
    def search_vm_url(self):
        return self.host + "/api/vms?search=" + urllib.quote('name=') + self.vm_name

    @property
    def create_vm_params(self):
        """Post request payload for creating vm
        """
        cluster = "iscsi"
        params = "<vm><name>%s</name><cluster><name>%s</name></cluster><action>start</action><template><name>%s</name></template></vm>" % \
            (self.vm_name, cluster, self.template)
        return params

    @property
    def null_param(self):
        """Post request required null payload
        """
        return "<action/>"


class Guest(Connect):

    @property
    def template(self):
        return self.opts.template

    @property
    def vm_name(self):
        return self.opts.vm_name

    @property
    def action(self):
        return self.opts.action

    @property
    def details(self):
        """Guest details
        """
        details = self.get(self.search_vm_url)
        return self.format_details(details)

    def format_details(self, d):
        form = "Guest name: {name}\nID: {vmid}\nStatus: {status}"
        return form.format(name=d['vms'][0]['name'], 
                           vmid=d['vms'][0]['id'], 
                           status=d['vms'][0]['status']['state'])

    @property
    def name(self):
        """Guest name
        """
        r = self.get(self.search_vm_url)
        return r['vms'][0]['name']

    @property
    def id(self):
        """Guest id
        """
        r = self.get(self.search_vm_url)
        return r['vms'][0]['id']

    @property
    def start_url(self):
        """Guest start/power on URL
        """
        r = self.get(self.search_vm_url)
        return r['vms'][0]['actions']['links'][4]['href']

    @property
    def stop_url(self):
        """Guest start/power on URL
        """
        r = self.get(self.search_vm_url)
        return r['vms'][0]['actions']['links'][5]['href']

    @property
    def ip_addr(self):
        """Guest IP address
        """
        # FIXME: handle missing key error when guest down
        r = self.get(self.search_vm_url)
        return r['vms'][0]['guestInfo']['ips']['ips'][0]['address']

    @property
    def status(self):
        """Guest status (up, down, wait for launch, etc)
        """
        r = self.get(self.search_vm_url)
        return r['vms'][0]['status']['state']

    def is_up(self, status):
        """True if status is up
        """
        if status == "up":
            return True
        else:
            return False

    def success(self, results):
        """Return request status
        """
        if results.status_code >= 400:
            return False
        else:
            return results.status_code

    def start(self):
        url = self.host + self.start_url
        return self.post(url, self.null_param)

    def stop(self):
        url = self.host + self.stop_url
        return self.post(url, self.null_param)


def main():
    vm = Guest()

    if vm.action == "status":
        logging.info("Guest name: " + vm.name)
        logging.info("Guest ID: " + vm.id)
        print vm.status
        if vm.status == "up":
            print vm.ip_addr
    elif vm.action == "start":
        logging.info(vm.start())
        # TODO: loop until status is up, print ip addr
    elif vm.action == "stop":
        logging.info(vm.stop())


if __name__ == '__main__':
    main()
