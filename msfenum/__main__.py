#!/usr/bin/env python3
# -*- coding: utf-8 -*-

""" https://metasploit.help.rapid7.com/docs/standard-api-methods-reference
    https://github.com/zaproxy/zap-core-help/wiki/HelpStartConceptsConcepts

    @TODO:
        Add SQLMap/XSSer/WFuzz applications
        Add user friendly reporting on notes
"""

from .msfrpc import MsfRPC
from .zapapi import ZAPAPI

from argparse import ArgumentParser
from jinja2 import Template
from os import walk
from os.path import join, relpath, abspath
from shlex import split
from subprocess import Popen, PIPE
from sys import exit
from toml import loads
from functools import wraps
from threading import Thread
from queue import Queue, Empty
from time import sleep


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
    # Process this module as an application
    command = d['app']['command']
    arguments = d['app']['parameters'] if 'parameters' in d['app'] else ''
    # Create a new process
    cmd = split('{c} {a}'.format(c=command, a=arguments))
    log.info('Creating app: {c}'.format(c=' '.join(cmd)))
    # Success
    return Popen(cmd, stdout=PIPE, stderr=PIPE, universal_newlines=True,
                 bufsize=1)


def prepare_jobs(rpc, module_type, module_name, filename, replacements,
                 rhosts):
    """ """
    # Load datastore
    d = load_datastore(filename, replacements)
    # Load the datastore options (if any)
    datastore = d['datastore'] if 'datastore' in d else {}
    jobs = []
    # Add a single module for the datastore
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
    parser.add_argument('--api-key', default='', help='API key')
    parser.add_argument('--modules', default='', required=True,
                        help='path to modules')
    parser.add_argument('--project', default='msfenum', help='project name')
    parser.add_argument('--threads', default=2, help='number of threads')
    parser.add_argument('--module', help='single module to execute')
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
    # App
    app = subparsers.add_parser('app', help='run all applications')
    app.set_defaults(callback=do_app)
    app.add_argument('--rhost', required=True,
                     help='Host to run applications for')
    app.add_argument('--port', required=True,
                     help='Port to pass to application')
    app.add_argument('--word-list', required=True, help='Word list to use')
    # OWASP ZAProxy
    zap = subparsers.add_parser('zap', help='run OWASP ZAProxy modules')
    zap.set_defaults(callback=do_zap)
    zap.add_argument('--rhost', required=True, help='Host to run ZAProxy for')
    # Reporting
    reporting = subparsers.add_parser('report', help='report all notes')
    reporting.set_defaults(callback=do_reporting)
    # Parse options
    return parser.parse_args()


def msfrpc(func):
    """ Decorator for callbacks which use the MsfRPC API """
    @wraps(func)
    def wrapper_msfrpc(options, module_type, modules):
        with MsfRPC(host=options.host, username=options.username,
                    password=options.password) as msf:
            # Set up a workspace based on the project name
            msf.db.add_workspace(wspace=options.project)
            msf.db.set_workspace(wspace=options.project)
            log.info('Created new workspace: "{w}"'.format(w=options.project))
            # Set global number of threads
            msf.core.setg(var='THREADS', val=options.threads)
            # Call the wrapped function
            func(options, module_type, modules, msf)
    return wrapper_msfrpc


def zapapi(func):
    """ Decorator for callbacks which use the ZAP API """
    @wraps(func)
    def wrapper_zapapi(options, module_type, modules):
        zap = ZAPAPI(host=options.host, username=options.username,
                     api_key=options.api_key)
        # Create a new context for the actions
        contexts = zap.context.view.contextList()['contextList']
        if options.project not in contexts:
            log.info('Created new context: "{c}"'.format(c=options.project))
            zap.context.action.newContext(contextName=options.project)
        # Add rhost to the context
        regex = '{h}.*'.format(h=options.rhost)
        regexs = (zap.context.view.includeRegexs(
                  contextName=options.project)['includeRegexs'])
        if regex not in regexs:
            zap.context.action.includeInContext(contextName=options.project,
                                                regex=regex)
        # Call rhost to add it to the Scan Tree
        zap.core.action.accessUrl(url=options.rhost)
        # Call the wrapped function
        func(options, module_type, modules, zap)
    return wrapper_zapapi


def enqueue_stdout(module_name, out, queue):
    for line in iter(out.readline, b''):
        queue.put((module_name, line))
    out.close()


@msfrpc
def do_app(options, module_type, modules, msf):
    """ """
    # Application is run by msfenum, the result imported into Metasploit
    rhost = options.rhost
    # Set up template parameters
    replacements = {'port': options.port,
                    'rhost': options.rhost,
                    'word_list': options.word_list}
    # Don't do anything if this is a dry run
    if options.dry_run:
        return
    # Dictionary with configuration replacements
    processes = {}
    # Prepare execution of each application
    for module_name, filename in modules:
        processes[module_name] = prepare_app(filename, replacements, rhost)
    log.info('Running applications')

    q = Queue()
    for module_name, p in processes.items():
        # Start a monitoring thread for each Process
        t = Thread(target=enqueue_stdout, args=(module_name, p.stdout, q),
                   daemon=True)
        t.start()

    while True:
        # Log all stdout for all running processes in a non-blocking manner
        try:
            module_name, data = q.get_nowait()
        except Empty:
            # Check if all processes are still running
            if all([p.poll() is not None for p in processes.values()]):
                log.info('All applications terminated')
                break
            # Log heart beat
            running = [m for m, p in processes.items() if p.poll() is None]
            log.info('Running application(s): {r}'.format(
                     r=', '.join(running)))
            # Wait until next heart beat
            sleep(10)
        else:
            # Got line
            if data is not '':
                data = data.rstrip()
                # Log to stdout/log
                log.info('[{m}] {d}'.format(m=module_name, d=data))
                # Send to msfconsole
                msf.report_note(module_type, module_name, rhost, data)


@msfrpc
def do_auxiliary(options, module_type, modules, msf):
    """ """
    log.debug('Calling do_auxiliary()')
    rhosts = options.rhosts
    jobs = []
    # Set up template parameters
    users = abspath(options.users) if options.users is not None else ''
    passwords = (abspath(options.passwords)
                 if options.passwords is not None else '')
    replacements = {'users': users,
                    'passwords': passwords,
                    'rhosts': options.rhosts}
    # Prepare execution of each auxiliary module
    for module_name, filename in modules:
        jobs.extend(prepare_jobs(msf, module_type, module_name, filename,
                                 replacements, rhosts))
    # Don't do anything if this is a dry run
    if options.dry_run:
        return
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


@msfrpc
def do_reporting(options, module_type, modules, msf):
    """ """
    # Get all notes from msf
    notes = msf.db.notes(xopts={})[b'notes']
    # Sort by note type
    notes.sort(key=lambda x: x[b'type'])
    for note in notes:
        # Display notes, remove any quotes
        data = note[b'data'].decode()[1:-1]
        log.info('[{t}] {d}'.format(t=note[b'type'].decode(), d=data))


@zapapi
def do_zap(options, module_type, modules, zap):
    """" """
    # Set up template parameters
    replacements = {'rhost': options.rhost,
                    'project': options.project}
    # Process each module
    for module_name, filename in modules:
        # Load datastore
        d = load_datastore(filename, replacements)
        # Call the API method with parameters
        log.info('Executing API method: {n}'.format(n=module_name))
        zap.request(module_name, d['datastore'] if 'datastore' in d else {})


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

        # Callback for the requested subparser
        options.callback(options, module_type, modules)

        # Success
        return(0)
    except KeyboardInterrupt:
        log.info('Received <ctrl-c>, stopping')
    except Exception as e:
        log.exception(e) if options.debug else log.error(e)
    finally:
        # Return 1 on any caught exception
        return(1)


if __name__ == '__main__':
    exit(main())
