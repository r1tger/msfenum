# -*- coding: utf-8 -*-


from requests import post, RequestException
from msgpack import packb, unpackb
from socket import gethostbyname, gaierror
from re import match

import logging
log = logging.getLogger(__name__)


class MsfRPCException(Exception):
    """ Custom exception for MSFConsoleRPC """
    pass


class MsfRPC:
    """ Wrap the MsfRPC API.

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
        self._log_counter = {}

    def __enter__(self):
        """ """
        # Authenticate using password
        self.login()
        # Return MSFConsoleRPC
        return self

    def __exit__(self, type, value, traceback):
        """ """
        # Logout
        self.logout()
        # Pass through all exceptions except TypeError
        return isinstance(value, TypeError)

    def __call__(self, **kwargs):
        method = '.'.join(map(str, self.n))
        self.n = []
        return MsfRPC.__dict__['request'](self, method, kwargs)

    def __getattr__(self, name):
        if 'n' not in self.__dict__:
            self.n = []
        self.n.append(name)
        return self

    def login(self):
        """ """
        log.info('MsfRPC::Login')
        self.logout()
        response = self.request('auth.login', {'username': self.username,
                                               'password': self.password})
        # Set the authentication token for use in requests
        self.token = response.get(b'token')

    def logout(self):
        """ """
        if self.token is False:
            return
        log.info('MsfRPC::Logout')
        self.request('auth.logout', {'token': self.token})
        self.token = False

    def report_note(self, module_type, module_name, rhost, data):
        """TODO: Docstring for report_note.

        :module_type: TODO
        :module_name: TODO
        :rhost: TODO
        :data: TODO
        :returns: TODO
        """
        try:
            # Try to resolve the rhosts to an ip address
            ip_address = gethostbyname(rhost)
            log.debug('Resolved {r} to {i}'.format(r=rhost, i=ip_address))
        except gaierror:
            # If it didn't work, keep going with rhost (may error out)
            ip_address = rhost

        # Create/increment counter for this app_type
        if module_name not in self._log_counter:
            self._log_counter[module_name] = 0
        self._log_counter[module_name] += 1
        # Log to msfconsole
        app_type = '{t}.{m}.{c:03d}'.format(t=module_type,
                                            m=module_name.replace('/', '.'),
                                            c=self._log_counter[module_name])
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
        log.debug('Sending data: {d}'.format(d=data))
        # Send data to msfconsole
        headers = {'Content-type': 'binary/message-pack'}
        try:
            response = post(self.url, data=packb(data), headers=headers)
            response.raise_for_status()
        except RequestException as e:
            # Wrap any requests exceptions
            raise MsfRPCException(e)
        # Decode and return the response
        result = unpackb(response.content)
        if result.get(b'error'):
            raise MsfRPCException(result.get(b'error_message').decode())
        return result
