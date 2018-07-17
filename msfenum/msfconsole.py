""" """


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
