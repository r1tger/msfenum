# -*- coding: utf-8 -*-


import logging
log = logging.getLogger(__name__)


class ZAPAPIException(Exception):
    """ Custom exception for MSFConsoleRPC """
    pass


class ZAPAPI:
    """ Wrap the ZAProxy API.

    :param host: Host name
    :param port: Port
    :param username: Username
    :param api_key: API key
    """
    def __init__(self, host='localhost', port=8080, username='zap',
                 api_key=''):
        self.url = 'http://{h}:{p}/api/'.format(h=host, p=port)
        self.username = username
        self.api_key = api_key

    def __call__(self, **kwargs):
        method = '.'.join(map(str, self.n))
        self.n = []
        return ZAPAPI.__dict__['request'](self, method, kwargs)

    def __getattr__(self, name):
        if 'n' not in self.__dict__:
            self.n = []
        self.n.append(name)
        return self

    def request(self, method, kwargs):
        """ """
        pass
