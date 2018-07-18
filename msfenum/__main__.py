#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" https://metasploit.help.rapid7.com/docs/standard-api-methods-reference

[ ] 01: Quick banner grab on known ports (auxiliary)
[ ] 02: Start nmap, followed by banner grab on found ports (auxiliary)
[ ] 03: Determine vulnerable servers (ftp/ssh/ftp)
[ ] 04: User enumeration

We want to be smart here:
    [ ] Create & activate a new workspace by project name in metasploit
    [ ] Perform a portscan on the ip range (either db_nmap or
        scanner/portscan/syn)
    [ ] Run auxiliary modules

Future enhancement:
    [ ] Given a http URL, perform a portscan
    [ ] Retrieve all http(s) entry points
    [ ] Run nikto/wpscan/cewl
    [ ] Create permuted wordlist using john
    [ ] Enumerate rockyou wordlist & permuted wordlist
"""
from .msfconsolerpc import MSFConsoleRPC

from argparse import ArgumentParser
from jinja2 import Template
from os import walk
from os.path import join, relpath, abspath
from shlex import split
from subprocess import Popen, PIPE
from sys import exit
from toml import loads

import logging
log = logging.getLogger(__name__)

LOG_FORMAT = '[%(asctime)s] [%(levelname)s] %(message)s'


def get_modules(modules_path, module_type):
    """TODO: Docstring for get_module.

    :returns: List with created subprocesses
    """
    modules_path = join(modules_path, module_type)
    # Process all files in modules_path
    for dirpath, dirnames, filenames in walk(modules_path):
        # Ignore any hidden files
        for filename in [f for f in filenames if not f.startswith('.')]:
            # Calculate module name
            module_name = join(module_type, relpath(join(dirpath, filename),
                                                    start=join(modules_path)))
            yield((module_name, join(dirpath, filename)))


def prepare_module(rpc, module_type, module_name, filename, replacements,
                   rhosts, threads=2, dry_run=False):
    """ TODO: Handle different module_types better """
    with open(filename, 'r') as f:
        # Open the file and replace any values
        template = Template(f.read())
        d = loads(template.render(**replacements))

    # Loaded modules and processes
    jobs = []
    processes = []

    if 'app' in d:
        # Process this module as an application
        command = d['app']['command']
        arguments = d['app']['parameters'] if 'parameters' in d['app'] else ''
        # Create a new process
        cmd = split('{c} {a}'.format(c=command, a=arguments))
        log.debug('Creating app: {c}'.format(c=' '.join(cmd)))
        processes.append(Popen(cmd, stdout=PIPE, stderr=PIPE))

    if 'datastore' in d:
        # Load the datastore options
        datastore = d['datastore'] if 'datastore' in d else {}

        if 'target' in d:
            # Check if a target is specified for this module
            services = rpc.db.services(xopts={})[b'services']
            log.debug('Services: {s}'.format(s=services))
            target = d['target']
            # Filter all services against the target in the module
            filtered = []
            for service in services:
                for k, v in service.items():
                    k = k.decode()
                    if k in target.keys() and v.decode() == target[k]:
                        # Service matches, include in filtered services
                        filtered.append(service)
            # Create a Job for each matched service
            for s in filtered:
                # Set additional variables: RHOST, RPORT, for each Job
                datastore['RHOST'] = s[b'host'].decode()
                datastore['RPORT'] = s[b'port']
                log.debug('Creating Job for: {n} ({h}:{p})'.format(
                          n=module_name, h=datastore['RHOST'],
                          p=datastore['RPORT']))
                jobs.append((module_name, datastore))
        else:
            # Add a single module for the datastore when no target is specified
            if 'RHOSTS' not in datastore:
                datastore['RHOSTS'] = rhosts
            log.debug('Creating job: {n}'.format(n=module_name))
            jobs.append((module_name, datastore))

    # Success
    return jobs, processes


def logger(options):
    """ """
    # Set up logging
    if options.log:
        handler = logging.FileHandler(options.log)
    else:
        handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(LOG_FORMAT))
    # Add handler to the root log
    logging.root.addHandler(handler)
    # Set log level
    level = logging.DEBUG if options.debug else logging.INFO
    logging.root.setLevel(level)


def parse():
    """TODO: Docstring for parse.
    :returns: TODO

    TODO: Add types & checks
    """
    parser = ArgumentParser()
    # Shared
    parser.add_argument('--debug', help='enable debug mode',
                        action="store_true", default=False)
    parser.add_argument('--dry-run', help='do a dry run, don\'t create Jobs',
                        action="store_true", default=False)
    parser.add_argument('--log', help='log file')
    parser.add_argument('--password', default='', help='RPC password')
    parser.add_argument('--modules', default='', required=True,
                        help='path to modules')
    parser.add_argument('--rhosts', required=True,
                        help='IP address or CIDR range to scan')
    parser.add_argument('--project', default='msfenum', help='project name')
    parser.add_argument('--threads', default=2, help='number of threads')
    parser.add_argument('--module', help='Single module to execute')
    # Sub parsers for run modes
    subparsers = parser.add_subparsers(help='auxiliary|exploit|post',
                                       dest='type')
    subparsers.required = True
    auxiliary = subparsers.add_parser('auxiliary',
                                      help='execute auxiliary modules')
    auxiliary.add_argument('--users', required=True, help='List of users')
    auxiliary.add_argument('--passwords', required=True,
                           help='List of passwords')
    subparsers.add_parser('exploit', help='execute an exploit')
    app = subparsers.add_parser('app', help='run an application')
    app.add_argument('--port', required=True,
                     help='Port to pass to application')
    app.add_argument('--proto', default='tcp', choices=['tcp', 'udp'],
                     help='network protocol for application')
    # Parse options
    return parser.parse_args()


def main():
    """Main entry point
    :returns: TODO
    """
    options = parse()
    try:
        # Setup logging
        logger(options)

        # Create Metasploit RPC connection
        msf = MSFConsoleRPC(password=options.password)
        # Authenticate to Metasploit
        msf.authenticate()
        # Set up a workspace based on the project name
        msf.db.add_workspace(wspace=options.project)
        msf.db.set_workspace(wspace=options.project)
        log.info('Created new workspace: "{w}"'.format(w=options.project))

        # Process command line parameters
        modules_path = abspath(options.modules)
        module_type = options.type
        rhosts = options.rhosts
        threads = options.threads
        dry_run = options.dry_run

        # Dictionary with datastore replacements
        replacements = {}
        if 'auxiliary' == module_type:
            replacements = {'users': abspath(options.users),
                            'passwords': abspath(options.passwords)}
        if 'app' == module_type:
            replacements = {'port': options.port,
                            'rhosts': rhosts}

        # Get modules to execute based on options
        modules = list(get_modules(modules_path, module_type))
        if options.module:
            # Filter modules if a single module is specified
            module_name = join(module_type, options.module)
            modules = [m for m in modules if m[0] == module_name]
            if 0 == len(modules):
                raise ValueError('No module {m} found'.format(m=module_name))

        # Prepare execution of each module
        for module_name, filename in modules:
            jobs, processes = prepare_module(msf, module_type, module_name,
                                             filename, replacements, rhosts,
                                             threads)

        # Don't do anything if this is a dry run
        if dry_run:
            return
        # Execute jobs
        for module_type, module_name, datastore in jobs:
            log.info('Executing module: {n}'.format(n=module_name))
            # Start a new Job for each prepared module
            msf.module.execute(module_type=module_type,
                               module_name=module_name, datastore=datastore)
        # Execute processes (waits till all processes are completed)
        log.info('Running applications')
        exit_codes = [p.communicate() for p in processes]
        for i, process in enumerate(processes):
            # Add result as a note (will automatically create service)
            log.info('Creating note: {n}'.format(n=module_name))
            data = exit_codes[i][0]  # stdout
            msf.db.report_note(xopts={'host': rhosts, 'port': options.port,
                                      'proto': options.proto,
                                      'type': module_name, 'data': data})

    except ValueError as e:
        log.exception(e) if options.debug else log.error(e)
        return 1


if __name__ == "__main__":
    exit(main())
