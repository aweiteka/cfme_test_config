#!/usr/bin/env python

# Control RHEVM via api
# * import template from export domain
# * create new guest from template
# * add network interface (nic)
# * start, shutdown, stop guest
# * get status and return IP address of running guest

# TODO: use ovirt sdk? http://www.ovirt.org/SDK

from optparse import OptionParser
import sys
import json
import time
import requests
import urllib
import logging
import ast
import re


class Connect(object):
    def __init__(self):
        logger = logging.getLogger()
        fh = logging.FileHandler(self.logfile, mode='w')
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
        # TODO: add support
        parser.add_option("-r", "--params", dest="params",
                          help="parameters in JSON format.", 
                          metavar="PARAMS")
        parser.add_option("-a", "--actions", dest="actions",
                          help="List of comma-separated actions you want to execute: import, new_vm, add_nic, start, shutdown, stop, remove, status.",
                          metavar="ACTIONS")
        parser.add_option("-u", "--user", dest="user",
                          help="RHEVM username", metavar="USER")
        parser.add_option("-p", "--pass", dest="passwd",
                          help="RHEVM password", metavar="PASS")
        parser.add_option("-l", "--logfile", dest="logfile", 
                          default="rhev_api.log",
                          help="Log filename", metavar="LOGFILE")
        parser.add_option("-d", "--debug",
                          action="store_true", dest="debug",
                          help="Turn on debug-level logging")

        (options, args) = parser.parse_args()
        self.validate_args(parser, options)
        return options

    def validate_args(self, parser, options):
        # TODO: improve validation for 'import' action
        mandatories = ['host', 'vm_name', 'actions', 'user', 'passwd']
        for m in mandatories:
            if not options.__dict__[m]:
                parser.error("Required option missing: " + m)
        if options.actions in "new_vm" and not parser.has_option("-t"):
            parser.error("-t <template> required")

    @property
    def usage(self):
        return """
    %prog -o <rhevm_host>
        -a <import,new_vm,add_nic,start|shutdown|stop|remove,status>
        -v <vm_name>
        [-t <template_name>]
        [-r <list_of_json_format_parameters>]
        -u <rhevm_user>
        -p <rhevm_passwd>
        [-l <logfile>]
        [-d]

   Actions accepts a comma-separated list of sequences. For example,
   --action='new_vm,add_nic,start' will perform those actions in order. Actions
   may also be called individually. 'status' redundant with start/shutdown/stop

   Some actions support passing in JSON-formatted list of parameters. 
   List of supported keys for actions with example values (memory in bytes):
       import: '{ "storage_domain" : "iscsi_data", "cluster" : "iscsi" }'
       new_vm: '{ "memory" : "6442450944", "cpu" : "4", "cluster" : "iscsi" }'
       add_nic: '{ "network" : "rhevm" }'"""

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

    @property
    def logfile(self):
        return self.opts.logfile

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
                if "import" not in self.actions:
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

    def delete(self, url, payload):
        """Generic delete request
        """
        try:
            r = requests.delete(url,
                              headers=self.headers,
                              auth=(self.user, self.passwd),
                              verify=False,
                              data=payload)
            return r
        except Exception, e:
            raise e

    def success(self, r):
        """Validate request
        """
        logging.debug("URL: " + r.request.full_url)
        logging.debug("DATA: %s" % r.request.data)
        # reqeusts built-in exception handler. Is None if okay
        r.raise_for_status()
        # additional response validation:
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
        return {'Accept': 'application/json', 'Content-Type': 'application/xml'}

    @property
    def storage_domains_search_url(self):
        return self.host + "/api/storagedomains?search" + urllib.quote('name=') + "export"

    @property
    def vm_search_url(self):
        return self.host + "/api/vms?search=" + urllib.quote('name=') + self.vm_name

    @property
    def vm_post_url(self):
        return self.host + "/api/vms"

    @property
    def import_template_param(self):
        """Post request payload for importing template from export domain
        """
        # TODO: query storage domains and clusters
        storage_domain = ""
        cluster = ""
        if self.params:
            p = self.params
            if "storage_domain" in p:
                storage_domain = p["storage_domain"]
            else:
                storage_domain = "iscsi_data"
            if "cluster" in p:
                cluster = p["cluster"]
            else:
                cluster = "iscsi"
        param = "<action><storage_domain><name>{storage_domain}</name></storage_domain><cluster><name>{cluster}</name></cluster></action>"
        return param.format(storage_domain=storage_domain,
                            cluster=cluster)

    @property
    def new_vm_param(self):
        """Post request payload for creating vm
        """
        param_str = ""
        cluster = "iscsi"
        if self.params:
            p = self.params
            if "memory" in p:
                param_str += "<memory>%s</memory>" % p['memory']
            if "cpu" in p:
                param_str += "<cpu><topology cores='%s' sockets='1'/></cpu>" % p['cpu']
            if "cluster" in p:
                cluster = p['cluster']
        param_str += "<cluster><name>%s</name></cluster>" % cluster
        param = """\
<vm><name>{name}</name>{params}<action>start</action><template><name>{template}</name></template></vm>"""
        return param.format(name=self.vm_name,
                            params=param_str,
                            template=self.template)

    @property
    def add_nic_param(self):
        """Post request payload for adding a NIC
        """
        param_str = ""
        network = "rhevm"
        if self.params:
            p = self.params
            if "network" in p:
                network = p["network"]
        param_str += "<network><name>%s</name></network>" % network
        return "<nic><name>eth0</name>%s</nic>" % param_str

    @property
    def null_param(self):
        """Post request required null payload
        """
        return "<action/>"

    @property
    def remove_param(self):
        """Delete request force remove payload
        """
        return "<action><force>true</force></action>"


class Guest(Connect):

    @property
    def actions(self):
        return re.split(r'[,\s]+', self.opts.actions)

    @property
    def vm_name(self):
        return self.opts.vm_name

    @property
    def template(self):
        return self.opts.template

    @property
    def params(self):
        if self.opts.params:
            try:
                return ast.literal_eval(self.opts.params)
            except SyntaxError as e:
                logging.exception("Problem parsing --params option: %s" % e)

    @property
    def name(self):
        """Guest name
        """
        r = self.get(self.vm_search_url)
        return r['vms'][0]['name']

    @property
    def list_templates_url(self):
        """URL to list templates in export domain
        """
        r = self.get(self.storage_domains_search_url)
        return self.host + r['storageDomains'][0]['links'][1]['href']

    @property
    def import_template_url(self):
        """Import template URL from export domain
        """
        r = self.get(self.list_templates_url)
        for template in r['templates']:
            if self.template in template['name']:
                return self.host + template['actions']['links'][0]['href']

    @property
    def nic_url(self):
        """Guest control NIC URL
        """
        r = self.get(self.vm_search_url)
        return self.host + r['vms'][0]['links'][1]['href']

    @property
    def shutdown_url(self):
        """Guest shutdown URL (graceful shutdown)
        """
        r = self.get(self.vm_search_url)
        return self.host + r['vms'][0]['actions']['links'][3]['href']

    @property
    def start_url(self):
        """Guest start/power on URL
        """
        r = self.get(self.vm_search_url)
        return self.host + r['vms'][0]['actions']['links'][4]['href']

    @property
    def stop_url(self):
        """Guest stop URL (force-off)
        """
        r = self.get(self.vm_search_url)
        return self.host + r['vms'][0]['actions']['links'][5]['href']

    @property
    def vm_url(self):
        """generic VM URL. Use for remove DELETE request
        """
        r = self.get(self.vm_search_url)
        return self.host + r['vms'][0]['href']

    @property
    def ip_addr(self):
        """Guest IP address
        """
        r = self.get(self.vm_search_url)
        try:
            return r['vms'][0]['guestInfo']['ips']['ips'][0]['address']
        except KeyError as e:
            pass

    def print_ip(self):
        """Print IP if not None
        """
        status = self.status
        if (status == "up") or (status != "down"):
            ip = self.ip_addr
            if ip is None:
                if not self.verify("ip"):
                    logging.info("VM is %s but ip is %s. Does VM have a NIC?" % (status, ip))
                    print status
            else:
                logging.info("VM is %s. IP: %s" % (status, ip))
                print ip
        else:
            logging.info(status)
            print status

    def verify(self, assertion):
        """General function to verify stages of VM
           assertion is one of new|up|down|ip
        """
        # TODO: add support for import success
        max_attempts = 40
        sleep_interval = 15 
        for attempt in range(1, max_attempts+1):
            try:
                if assertion in "new":
                    assert self.status == "down", "creating VM"
                elif assertion in "up":
                    assert self.status == "up", "powering up"
                elif assertion in "ip":
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
                    logging.exception("Verify failed. Max attempts: '%s'. Status: '%s'. IP: '%s'" % (max_attempts, self.status, self.ip_addr))
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
        r = self.get(self.vm_search_url)
        return r['vms'][0]['status']['state']

    def import_template(self):
        """Import template from export domain to ISO domain
        """
        logging.info("Import template requested")
        r = self.post(self.import_template_url, self.import_template_param)
        assert r['status']['state'] == "complete"
        logging.info("Successfully requested import")
        # TODO: verify import

    def new_vm_from_template(self):
        """Create a new VM from template
        """
        logging.info("New vm from template requested")
        r = self.post(self.vm_post_url, self.new_vm_param)
        assert r['status']['state'] in ["complete", "image_locked"]
        logging.info("Successfully requested create VM")
        while not self.verify("new"):
            pass
        else:
            logging.info("VM %s created. Status: %s" % (self.name, self.status))

    def add_nic(self):
        """Add a network interface (NIC) to the VM
        """
        logging.info("Add NIC requested")
        r = self.post(self.nic_url, self.add_nic_param)
        assert r['active'] is True
        logging.info("Successfully added network interface (NIC): %s %s" %
                    (r['name'], r['mac']['address']))

    def start(self):
        """Start guest
        """
        status = self.status
        if status != "up":
            logging.info("VM start requested")
            r = self.post(self.start_url, self.null_param)
            assert r['status']['state'] == "complete"
            logging.info("Successfully requested guest start")
            while not self.verify("up"):
                pass
            else:
                self.print_ip()
        else:
            logging.info("Guest status already %s. IP: %s. Nothing to do." % (status, self.ip_addr))

    def shutdown(self, force=None):
        """Shutdown guest or force stop
        """
        status = self.status
        if status != "down":
            if force:
                logging.info("Stop VM (force) requested")
                url = self.stop_url
            else:
                logging.info("Shutdown VM (graceful) requested")
                url = self.shutdown_url
            r = self.post(url, self.null_param)
            assert r['status']['state'] == "complete"
            logging.info("Successfully requested guest shutdown (force: %s)" % force)
            while not self.verify("down"):
                pass
            else:
                print self.status
        else:
            logging.info("Guest status already %s. Nothing to do." % status)

    def remove(self):
        """Remove (delete) guest
        """
        status = self.status
        if status != "down":
            logging.info("Remove guest requested but status is '%s'. Forcing stop before remove" % status)
            self.shutdown(force=True)
        logging.info("Remove VM requested")
        r = self.delete(self.vm_url, self.remove_param)
        logging.info("Successfully requested remove guest.")
        # TODO: verify


def main():
    vm = Guest()

    # loop through action list to retain input order
    for action in vm.actions:
        if action == "import":
            vm.import_template()
            # TODO: verify import success

        elif action == "new_vm":
            vm.new_vm_from_template()

        elif action == "add_nic":
            vm.add_nic()
            # TODO: check if nic already exists, verify

        elif action == "start":
            vm.start()

        elif action == "shutdown":
            vm.shutdown()

        elif action == "stop":
            vm.shutdown(force=True)

        elif action == "remove":
            vm.remove()
            # TODO: verify remove success

        elif action == "status":
            vm.print_ip()


if __name__ == '__main__':
    main()
