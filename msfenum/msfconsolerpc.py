""" """
from requests import post
from msgpack import packb, unpackb

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
        # Send data to msfconsole
        headers = {'Content-type': 'binary/message-pack'}
        response = post(self.url, data=packb(data), headers=headers)
        response.raise_for_status()
        # Decode and return the response
        result = unpackb(response.content)
        if result.get(b'error'):
            raise ValueError(result.get(b'error_message').decode())
        return result
