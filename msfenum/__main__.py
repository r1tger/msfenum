#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" https://metasploit.help.rapid7.com/docs/standard-api-methods-reference

    @TODO:
        Add SQLMap/XSSer/WFuzz applications
        Add user friendly reporting on notes
"""
from .msfconsolerpc import MSFConsoleRPC

from argparse import ArgumentParser
from jinja2 import Template
from os import walk
from os.path import join, relpath, abspath
from shlex import split
from subprocess import Popen, PIPE
from sys import exit
from time import time, sleep
from toml import loads

import logging
log = logging.getLogger(__name__)

LOG_FORMAT = '[%(asctime)s] [%(levelname)s] %(message)s'


def get_modules(modules_path, module_type):
    """TODO: Docstring for get_module.

    :returns: Generator with tuple ([module name], [filename])
    """
    modules_path = join(modules_path, module_type)
    # Process all files in modules_path
    for dirpath, dirnames, filenames in walk(modules_path):
        # Ignore any hidden files
        for filename in [f for f in filenames if not f.startswith('.')]:
            # Calculate module name
            module_name = relpath(join(dirpath, filename),
                                  start=join(modules_path))
            yield((module_name, join(dirpath, filename)))


def load_datastore(filename, replacements):
    """ """
    with open(filename, 'r') as f:
        # Open the file and replace any values
        template = Template(f.read())
        return loads(template.render(**replacements))


def prepare_app(filename, replacements, rhosts):
    """ """
    # Load datastore
    d = load_datastore(filename, replacements)
    processes = []
    # Process this module as an application
    command = d['app']['command']
    arguments = d['app']['parameters'] if 'parameters' in d['app'] else ''
    expr = d['app']['match'] if 'match' in d['app'] else None
    # Create a new process
    cmd = split('{c} {a}'.format(c=command, a=arguments))
    log.info('Creating app: {c}'.format(c=' '.join(cmd)))
    processes.append((Popen(cmd, stdout=PIPE, stderr=PIPE), expr))
    # Success
    return processes


def prepare_jobs(rpc, module_type, module_name, filename, replacements,
                 rhosts):
    """ """
    # Load datastore
    d = load_datastore(filename, replacements)

    # Load the datastore options (if any)
    datastore = d['datastore'] if 'datastore' in d else {}
    jobs = []

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
            log.debug('Creating Job for: {n} ({h}:{p})'.format(n=module_name,
                      h=datastore['RHOST'], p=datastore['RPORT']))
            jobs.append((module_type, module_name, datastore))
    else:
        # Add a single module for the datastore when no target is specified
        if 'RHOSTS' not in datastore:
            datastore['RHOSTS'] = rhosts
        log.debug('Creating job: {n}'.format(n=module_name))
        jobs.append((module_type, module_name, datastore))

    # Success
    return jobs


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
    parser.add_argument('--username', default='msf', help='RPC username')
    parser.add_argument('--password', default='', help='RPC password')
    parser.add_argument('--host', default='localhost', help='RPC hostname')
    parser.add_argument('--modules', default='', required=True,
                        help='path to modules')
    parser.add_argument('--project', default='msfenum', help='project name')
    parser.add_argument('--threads', default=2, help='number of threads')
    parser.add_argument('--module', help='single module to execute')
    parser.add_argument('--report', help='report on progress',
                        action='store_true', default=False)
    # Sub parsers for run modes
    subparsers = parser.add_subparsers(help='auxiliary|exploit|post',
                                       dest='type')
    subparsers.required = True
    # Auxiliary
    auxiliary = subparsers.add_parser('auxiliary',
                                      help='execute auxiliary modules')
    auxiliary.set_defaults(callback=do_auxiliary)
    auxiliary.add_argument('--rhosts', required=True,
                           help='Host to run applications for')
    auxiliary.add_argument('--users', required=True, help='List of users')
    auxiliary.add_argument('--passwords', required=True,
                           help='List of passwords')
    auxiliary.add_argument('--word-list', required=True,
                           help='Word list to process')
    # Exploit
    # exploit = subparsers.add_parser('exploit', help='execute an exploit')
    # exploit.set_defaults(callback=do_auxiliary)
    # exploit.add_argument('--rhosts', required=True,
    #                      help='Host to run applications for')
    # App
    app = subparsers.add_parser('app', help='run all applications')
    app.set_defaults(callback=do_app)
    app.add_argument('--rhost', required=True,
                     help='Host to run applications for')
    app.add_argument('--port', required=True,
                     help='Port to pass to application')
    app.add_argument('--proto', default='tcp', choices=['tcp', 'udp'],
                     help='network protocol for application')
    # Parse options
    return parser.parse_args()


def do_app(options, msf, module_type, modules):
    """ """
    # Application is run by msfenum, the result imported into Metasploit
    rhost = options.rhost
    # Set up template parameters
    replacements = {'port': options.port,
                    'rhost': options.rhost}
    # Dictionary with configuration replacements
    processes = []
    # Prepare execution of each application
    for module_name, filename in modules:
        processes.extend(prepare_app(filename, replacements, rhost))
    # Don't do anything if this is a dry run
    if options.dry_run:
        return(0)
    # Execute processes (waits till all processes are completed)
    log.info('Running applications')
    exit_codes = [p.communicate() for p, e in processes]
    # Running the application can take a long time, re-authenticate
    msf.login()
    # Process each exit code
    for i, p in enumerate(processes):
        # Add result as a note for a host
        data = exit_codes[i][0]  # stdout
        msf.report_note(module_type, module_name, rhost, data.decode(), p[1])


def do_auxiliary(options, msf, module_type, modules):
    """ """
    rhosts = options.rhosts
    jobs = []
    # Set up template parameters
    users = abspath(options.users) if options.users is not None else ''
    passwords = (abspath(options.passwords)
                 if options.passwords is not None else '')
    word_list = (abspath(options.word_list)
                 if options.word_list is not None else '')
    replacements = {'users': users,
                    'passwords': passwords,
                    'rhosts': options.rhosts,
                    'word_list': word_list}
    # Prepare execution of each auxiliary module
    for module_name, filename in modules:
        jobs.extend(prepare_jobs(msf, module_type, module_name, filename,
                                 replacements, rhosts))
    # Don't do anything if this is a dry run
    if options.dry_run:
        return(0)
    # Get active jobs
    active_jobs = msf.job.list().values()
    for module_type, module_name, datastore in jobs:
        # Check if an active job is currently running for this module
        if any([s for s in active_jobs if module_name.encode() in s]):
            log.info('Skipping module: {n}'.format(n=module_name))
            continue
        log.info('Executing module: {n}'.format(n=module_name))
        # Start a new Job for each prepared module
        msf.module.execute(module_type=module_type, module_name=module_name,
                           datastore=datastore)


def report(msf, interval=10, timeout=300):
    """ """
    notes = {}
    last_change = time()
    while True:
        # Get hosts (ip addresses)
        hosts = msf.db.hosts(xopts={})[b'hosts']
        hosts = [d[b'address'].decode() for d in hosts]
        log.debug('Hosts found: {h}'.format(h=hosts))
        # Get all notes
        for host in hosts:
            note = msf.db.get_note(xopts={'host': host})[b'note']
            log.debug('Note found for host {h}: {n}'.format(h=host, n=note))
            # Find new notes with regards to previous run
            if host not in notes:
                notes[host] = []
            for n in note:
                if n not in notes[host]:
                    log.debug('{n}'.format(n=note))
                    log.info('host={h} type={t} data={n}'.format(
                             h=host, t=n[b'ntype'].decode(),
                             n=n[b'data'].decode()))
                    notes[host].append(n)
                    last_change = time()
        # Check if we timed out
        if (time() - last_change) > timeout:
            log.info('No update received in {t}s, stopping'.format(t=timeout))
            break
        # Wait 10 seconds until next iteration
        sleep(interval - time() % interval)


def main():
    """Main entry point
    :returns: TODO
    """
    options = parse()
    try:
        # Setup logging
        logger(options)

        # Process command line parameters
        modules_path = abspath(options.modules)
        module_type = options.type

        # Get modules to execute based on options
        modules = list(get_modules(modules_path, module_type))
        if options.module:
            # Filter modules if a single module is specified
            modules = [m for m in modules if m[0] == options.module]
            if len(modules) == 0:
                raise ValueError('Unknown module {m}'.format(m=options.module))

        # Open a new connection to Metasploit and login
        with MSFConsoleRPC(host=options.host, username=options.username,
                           password=options.password) as msf:
            # Set up a workspace based on the project name
            msf.db.add_workspace(wspace=options.project)
            msf.db.set_workspace(wspace=options.project)
            log.info('Created new workspace: "{w}"'.format(w=options.project))
            # Set global number of threads
            msf.core.setg(var='THREADS', val=options.threads)
            # Execute the callback based on the requested subparser
            options.callback(options, msf, module_type, modules)
            if options.report:
                try:
                    report(msf)
                except KeyboardInterrupt:
                    log.info('Received <ctrl-c>, stopping')

        # Success
        return(0)
    except ValueError as e:
        log.exception(e) if options.debug else log.error(e)
        return(1)


if __name__ == '__main__':
    exit(main())
