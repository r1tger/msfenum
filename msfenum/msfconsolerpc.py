# -*- coding: utf-8 -*-


from requests import post
from msgpack import packb, unpackb
from socket import gethostbyname, gaierror
from re import match

import logging
log = logging.getLogger(__name__)


class MSFConsoleRPC:
    """ Wrap the MSFConsoleRPC API.

    :param host: Host name
    :param port: Port
    :param username: Username
    :param password: Password
    """
    def __init__(self, host='localhost', port=55552, username='msf',
                 password='', dry_run=False):
        self.url = 'http://{h}:{p}/api/'.format(h=host, p=port)
        self.username = username
        self.password = password
        self.dry_run = dry_run
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
        self.token = False
        response = self.request('auth.login', {'username': self.username,
                                               'password': self.password})
        # Set the authentication token for use in requests
        self.token = response.get(b'token')

    def report_note(self, module_type, module_name, rhost, data, expr=None):
        """TODO: Docstring for report_note.

        :module_name: TODO
        :rhost: TODO
        :data: TODO
        :expr: TODO
        :returns: TODO
        """
        log.info('Creating note: {n}'.format(n=module_name))
        try:
            # Try to resolve the rhosts to an ip address
            ip_address = gethostbyname(rhost)
            log.info('Resolved {r} to {i}'.format(r=rhost, i=ip_address))
        except gaierror:
            # If it didn't work, keep going with rhost
            ip_address = rhost
        # Process each line seperately if an expression to match is provided
        if expr:
            d = []
            for line in data.splitlines():
                log.debug('Matching "{li}" against "{e}"'.format(e=expr,
                                                                 li=line))
                m = match(expr, line)
                if m:
                    d.append(m[1])
            # Flatten the filtered lines, separated by a newline
            data = '\n'.join(d)

        # Process each note
        app_type = '{t}.{n}'.format(t=module_type,
                                    n=module_name.replace('/', '.'))
        self.request('db.report_note', {'xopts': {'type': app_type,
                                                  'host': ip_address,
                                                  'data': data}})

    def request(self, method, kwargs):
        # Create msgpack request
        data = list(kwargs.values())
        # Prepare the first indices of the values, mind the order!
        if self.token:
            data.insert(0, self.token)
        data.insert(0, method)
        log.debug(data)
        # Send data to msfconsole
        headers = {'Content-type': 'binary/message-pack'}
        response = post(self.url, data=packb(data), headers=headers)
        response.raise_for_status()
        # Decode and return the response
        result = unpackb(response.content)
        if result.get(b'error'):
            raise ValueError(result.get(b'error_message').decode())
        return result
