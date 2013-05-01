#!/usr/bin/env python

# parse API get requests from CFME automate
# requires:
# * python 'bottle'
# * port 8080 open
# example: curl http://localhost:8080/api/redhat/vm?event=power_on_vm

from bottle import run, route, request, response
import subprocess

@route('/api/<system>/<msg_type>')
def get_request(system, msg_type):
    event = request.query.event
    return 'System: %s, Type: %s, Event: %s)' % (system, msg_type, event)

host = subprocess.check_output('hostname').strip()
run(host=host, port=8080, debug=True)

