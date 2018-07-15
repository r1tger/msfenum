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

from requests import post
from msgpack import packb, unpackb
from argparse import ArgumentParser
from sys import exit
from os import walk
from os.path import join, relpath, abspath
from toml import load

import logging
log = logging.getLogger(__name__)

LOG_FORMAT = '[%(asctime)s] [%(levelname)s] %(message)s'


class MSFConsoleRPC:
    """ Wrap the MSFConsoleRPC API.

    :param host: Host name
    :param port: Port
    :param username: Username
    :param password: Password
    """
    def __init__(self, host='localhost', port=55552, username='msf',
                 password=''):
        self.url = 'http://{h}:{p}/api/'.format(h=host, p=port)
        self.username = username
        self.password = password
        self.token = False

    def __call__(self, **kwargs):
        method = '.'.join(map(str, self.n))
        self.n = []
        return MSFConsoleRPC.__dict__['request'](self, method, kwargs)

    def __getattr__(self, name):
        if 'n' not in self.__dict__:
            self.n = []
        self.n.append(name)
        return self

    def authenticate(self):
        """ """
        response = self.request('auth.login', {'username': self.username,
                                               'password': self.password})
        # Set the authentication token for use in requests
        self.token = response.get(b'token')

    def request(self, method, kwargs):
        # Create msgpack request
        data = list(kwargs.values())
        # Prepare the first indices of the values, mind the order!
        if self.token:
            data.insert(0, self.token)
        data.insert(0, method)
        log.debug(data)
        # Send data to transmission
        headers = {'Content-type': 'binary/message-pack'}
        response = post(self.url, data=packb(data), headers=headers)
        response.raise_for_status()
        # Decode and return the response
        result = unpackb(response.content)
        if result.get(b'error'):
            raise ValueError(result.get(b'error_message').decode())
        return result


class MSFConsole(object):
    """ MSFConsole. """
    def __init__(self, rpc):
        """ """
        self.rpc = rpc

    def __enter__(self):
        """ """
        # Create a new console
        response = self.rpc.console.create()
        self.console_id = response.get(b'id')
        # Return reference to MSFConsole instance
        return self

    def __exit__(self, type, value, traceback):
        """ """
        # Destroy the console session, clean up
        self.rpc.console.destroy(console_id=self.console_id)
        # Pass through all exceptions except TypeError
        return isinstance(value, TypeError)


def get_modules(modules_path, module_type):
    """TODO: Docstring for get_module.
    :returns: TODO
    """
    modules_path = join(modules_path, module_type)
    # Process all files in modules_path
    for dirpath, dirnames, filenames in walk(modules_path):
        # Ignore any hidden files
        for filename in [f for f in filenames if not f.startswith('.')]:
            # Calculate module name
            module_name = join(module_type, relpath(join(dirpath, filename),
                                                    start=modules_path))
            yield((module_name, join(dirpath, filename)))


def execute_module(rpc, module_type, module_name, filename, rhosts,
                   replacements, threads=2, dry_run=False):
    """ """
    # Load the datastore options
    d = load(filename)
    datastore = d['datastore'] if 'datastore' in d else {}
    modules = []

    # Replace values in the datastore if needed
    for key, value in datastore.items():
        if value in replacements:
            datastore[key] = replacements[value]

    # Set the global options for ip to scan and number of threads
    rpc.core.setg(key='THREADS', value=threads)

    # Check if a target is specified for this module
    if 'target' in d:
        # Get all services
        services = rpc.db.services(xopts={})[b'services']
        # log.debug('Services: {s}'.format(s=services))
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
            modules.append((module_type, module_name, datastore))
    else:
        # Add a single module for the configuration when no target is specified
        if 'RHOSTS' not in datastore:
            datastore['RHOSTS'] = rhosts
        modules.append((module_type, module_name, datastore))

    # Don't do anything if this is a dry run
    if dry_run:
        return

    for module_type, module_name, datastore in modules:
        log.info('Executing module: {n}'.format(n=module_name))
        # Start a new Job for each prepared module
        rpc.module.execute(module_type=module_type, module_name=module_name,
                           datastore=datastore)


def execute_modules(rpc, modules_path, module_type, rhosts, replacements,
                    threads=2, dry_run=False):
    """TODO: Docstring for execute_modules(rpc.
    :returns: TODO
    """
    # Find each available module
    for module_name, filename in get_modules(modules_path, module_type):
        # Execute the module
        execute_module(rpc, module_type, module_name, filename, rhosts,
                       replacements, threads, dry_run)


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
    auxiliary = subparsers.add_parser('auxiliary', help='Auxiliary')
    auxiliary.add_argument('--users', required=True, help='List of users')
    auxiliary.add_argument('--passwords', required=True,
                           help='List of passwords')
    subparsers.add_parser('exploit', help='Exploit')
    # post = subparsers.add_parser('post', help='Post')
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
            replacements = {'@@users@@': abspath(options.users),
                            '@@passwords@@': abspath(options.passwords)}

        if options.module:
            # Execute a single module
            filename = join(modules_path, options.module)
            execute_module(msf, module_type, options.module, filename,
                           rhosts, replacements, threads, dry_run)
        else:
            # Retrieve all modules to execute
            execute_modules(msf, modules_path, module_type, rhosts,
                            replacements, threads, dry_run)
    except ValueError as e:
        log.exception(e) if options.debug else log.error(e)
        return 1


if __name__ == "__main__":
    exit(main())
