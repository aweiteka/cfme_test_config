#!/usr/bin/env python

# Control RHEVM via api
# * create new guest from template
# * add network interface (nic)
# * start and stop guest
# * get status and return IP address of running guest

# TODO:
# * filter so less data returned in GET requests
# * remove VM

from optparse import OptionParser
import sys
import json
import time
import requests
import urllib
import logging
import inspect


class Connect(object):
    def __init__(self):
        logfile = "rhev_api.log"
        logger = logging.getLogger()
        fh = logging.FileHandler(logfile, mode='w')
        formatter = logging.Formatter("%(asctime)s %(levelname)s: %(message)s",
                                      "%b %d %H:%M:%S")
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
                          help="RHEVM host in the form of https://localhost \
                                (without '/api')",
                          metavar="HOST")
        parser.add_option("-t", "--template", dest="template",
                          help="template name", metavar="TEMP_NAME")
        parser.add_option("-v", "--vm_name", dest="vm_name",
                          help="VM name", metavar="VM_NAME")
        parser.add_option("-a", "--action", dest="action",
                          choices=["create", "add_nic", "start", "stop",
                                   "status"],
                          help="the action you want to do. create, add_nic, \
                                start, stop, status",
                          metavar="ACTION")
        parser.add_option("-u", "--user", dest="user",
                          help="RHEVM username", metavar="USER")
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
        -a <create|add_nic|start|stop|status>
        -v <vm_name>
        [-t <template_name>]
        -u <rhevm_user>
        -p <rhevm_passwd>
        [-d]

   Action 'create' will create <vm_name> from <template_name>, add a NIC
   on default RHEVM network, start guest and return IP address when running."""

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

    def pretty_json(self, j):
        return json.dumps(j, sort_keys=True, indent=4, separators=(',', ': '))

    def get(self, url):
        """Generic get request
        """
        try:
            r = requests.get(url,
                             headers=self.headers,
                             auth=(self.user, self.passwd),
                             verify=False)
            if self.success(r):
                j = r.json
                logging.debug(self.pretty_json(j))
                assert len(j['vms']) == 1, "Unexpected number of VMs returned in search"
                return j
        except KeyError as e:
            logging.exception("No VMs reaturned in search. Broaden vm_name with wildcard '-v %s*' and retry?" % (self.vm_name))
            raise e
        except AssertionError as e:
            logging.exception("VM search too broad. Refine vm_name '%s' and retry" % (self.vm_name))
            raise e

    def post(self, url, payload):
        """Generic post request
        """
        try:
            r = requests.post(url,
                              headers=self.headers,
                              auth=(self.user, self.passwd),
                              verify=False,
                              data=payload)
            if self.success(r):
                j = r.json
                logging.debug(self.pretty_json(j))
                return j
        except Exception, e:
            logging.exception("POST error: %s" % e)
            raise e

    def success(self, r):
        """Validate request
        """
        # reqeusts built-in exception handler. Is None if okay
        r.raise_for_status()
        try:
            assert r.headers['content-type'] == "application/json", \
                "Reponse is not JSON format"
        except AssertionError as e:
            logging.exception(e)
        else:
            return True

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
        # FIXME: add params for memory/cpus?
        """Post request payload for creating vm
        """
        param = """\
<vm><name>{name}</name><memory>{memory}</memory><cpu><topology cores='{cpus}' sockets='1'/></cpu><cluster><name>{cluster}</name></cluster><action>start</action><template><name>{template}</name></template></vm>"""
        return param.format(name=self.vm_name,
                            # in bytes
                            memory="6442450944",
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
    def action(self):
        return self.opts.action

    @property
    def vm_name(self):
        return self.opts.vm_name

    @property
    def template(self):
        return self.opts.template

    @property
    def name(self):
        """Guest name
        """
        r = self.get(self.search_vm_url)
        return r['vms'][0]['name']

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
        try:
            return r['vms'][0]['guestInfo']['ips']['ips'][0]['address']
        except KeyError as e:
            pass

    def print_ip(self):
        """Print IP if not None
        """
        status = self.status
        if status == "up":
            ip = self.ip_addr
            if ip is None:
                logging.info("VM is %s but ip is %s" % (status, ip))
                print status
            else:
                logging.info("VM is %s. IP: %s" % (status, ip))
                print ip
        else:
            logging.info(status)
            print status

    def verify(self, assertion):
        """General function to verify stages of VM
           assertion is one of create|up|down
        """
        max_attempts = 40
        sleep_interval = 15 
        for attempt in range(1, max_attempts+1):
            try:
                if assertion in "create":
                    assert self.status == "down", "Creating VM"
                elif assertion in "up":
                    assert self.status == "up", "powering up"
                    assert self.ip_addr is not None, "no IP address"
                elif assertion in "down":
                    assert self.status == "down", "shutting down"
            except AssertionError as e:
                if attempt < max_attempts:
                    logging.info("Waiting for VM (%s/%s): %s" % (attempt, max_attempts, e))
                    time.sleep(sleep_interval)
                    pass
                # Enough sleeping, something went wrong
                else:
                    logging.exception("Verify failed. Max attempts: %s" % max_attempts)
                    raise e
            else:
                # No exceptions raised
                logging.info("verified vm %s" % assertion)
                break

        return True

    @property
    def status(self):
        """Guest status (up, down, wait for launch, etc)
        """
        r = self.get(self.search_vm_url)
        return r['vms'][0]['status']['state']

    def create_vm_from_template(self):
        self.post(self.post_url, self.create_vm_param)
        while not self.verify("create"):
            pass
        else:
            self.add_nic()
        self.start()
        while not self.verify("up"):
            pass
        else:
            self.print_ip()

    def add_nic(self):
        url = self.host + self.nic_url
        r = self.post(url, self.add_nic_param)
        assert r['active'] is True
        logging.info("Successfully added network interface (NIC): %s %s" %
                    (r['name'], r['mac']['address']))

    def start(self):
        url = self.host + self.start_url
        r = self.post(url, self.null_param)
        #print self.pretty_json(r)
        assert r['status']['state'] == "complete"
        logging.info("Successfully requested guest start")

    def stop(self):
        url = self.host + self.stop_url
        r = self.post(url, self.null_param)
        assert r['status']['state'] == "complete"
        logging.info("Successfully requested guest stop")


def main():
    vm = Guest()

    if vm.action == "create":
        vm.create_vm_from_template()

    elif vm.action == "add_nic":
        vm.add_nic()

    elif vm.action == "status":
        vm.print_ip()

    elif vm.action == "start":
        vm.start()
        while not vm.verify("up"):
            pass
        else:
            vm.print_ip()

    elif vm.action == "stop":
        vm.stop()
        while not vm.verify("down"):
            pass
        else:
            print vm.status


if __name__ == '__main__':
    main()
