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
        parser = OptionParser(usage=self.usage)
        parser.add_option("-o", "--host", dest="host",
                          help="RHEVM host in the form of https://localhost (without '/api')", 
                          metavar="HOST")
        parser.add_option("-t", "--template", dest="template", 
                          default="MIQ-v50029-DND",
                          help="template name", metavar="TEMP_NAME")
        parser.add_option("-v", "--vm_name", dest="vm_name", 
                          help="VM name", metavar="VM_NAME")
        parser.add_option("-a", "--action", dest="action",
                          choices=["create", "add_nic", "start", "stop", "status"],
                          help="the action you want to do. create, add_nic, start, stop, status", 
                          metavar="ACTION")
        parser.add_option("-u", "--user", dest="user",
                          help="RHEVM password", metavar="USER")
        parser.add_option("-p", "--pass", dest="passwd",
                          help="RHEVM password", metavar="PASS")
        parser.add_option("-d", "--debug",
                          action="store_true", dest="debug",
                          help="Turn on debug-level logging")

        (options, args) = parser.parse_args()
        self.validate_args(parser, options)
        return options

    def validate_args(self, parser, options):
        mandatories = ['host', 'vm_name', 'action', 'user', 'passwd']
        for m in mandatories:
            if not options.__dict__[m]:
                parser.error("Required option missing: " + m)
        if options.action in "create" and not parser.has_option("-t"):
            parser.error("-t <template> required")

    @property
    def usage(self):
        return """
    %prog -o <rhevm_host>
        -v <vm_name>
        -a <create|add_nic|start|stop|status>
        -u <rhevm_user>
        -p <rhevm_passwd>
        [-t <template_name>]
        [-d]"""

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
    def post_url(self):
        return self.host + "/api/vms"

    @property
    def create_vm_param(self):
        """Post request payload for creating vm
        """
        param = """\
<vm><name>{name}</name><memory>{memory}</memory><cpu><topology cores='{cpus}' sockets='1'/></cpu><cluster><name>{cluster}</name></cluster><action>start</action><template><name>{template}</name></template></vm>"""
        return param.format(name=self.vm_name, 
                            memory="6442450944", # bytes
                            cpus="4", 
                            cluster="iscsi", 
                            template=self.template)

    @property
    def add_nic_param(self):
        """Post request payload for adding a NIC
        """
        network = "rhevm"
        return "<nic><name>eth0</name><network><name>%s</name></network></nic>" % network

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
    def nic_url(self):
        """Guest control NIC URL
        """
        r = self.get(self.search_vm_url)
        return r['vms'][0]['links'][1]['href']

    @property
    def start_url(self):
        """Guest start/power on URL
        """
        r = self.get(self.search_vm_url)
        return r['vms'][0]['actions']['links'][4]['href']

    @property
    def stop_url(self):
        """Guest stop on URL
        """
        r = self.get(self.search_vm_url)
        return r['vms'][0]['actions']['links'][5]['href']

    @property
    def ip_addr(self):
        """Guest IP address
        """
        r = self.get(self.search_vm_url)
        if "guestInfo" in r['vms'][0]:
            return r['vms'][0]['guestInfo']['ips']['ips'][0]['address']

    def print_ip(self):
        """Print IP if not None
        """
        ip = vm.ip_addr
        if ip is not None:
            logging.info("IP: " + ip)
            return ip

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

    def new_vm(self):
        return self.post(self.post_url, self.create_vm_param)

    def add_nic(self):
        url = self.host + self.nic_url
        return self.post(url, self.add_nic_param)

    def start(self):
        url = self.host + self.start_url
        return self.post(url, self.null_param)

    def stop(self):
        url = self.host + self.stop_url
        return self.post(url, self.null_param)


def main():
    vm = Guest()

    if vm.action == "create":
        logging.info(vm.new_vm())
        # TODO: check for nic
    elif vm.action == "add_nic":
        logging.info(vm.add_nic())
    elif vm.action == "status":
        logging.info("Guest name: " + vm.name)
        logging.info("Guest ID: " + vm.id)
        print vm.status
        if vm.status == "up":
            vm.print_ip()
    elif vm.action == "start":
        logging.info(vm.start())
        # TODO: loop until status is up, print ip addr
        if vm.status == "up":
            vm.print_ip()
    elif vm.action == "stop":
        logging.info(vm.stop())
        # TODO: validate stop

if __name__ == '__main__':
    main()
