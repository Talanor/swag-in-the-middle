class IBaseProxy(object):
    """docstring for IBaseProxy"""

    def connect(self):
        raise NotImplemented

    def send_server(self):
        raise NotImplemented

    def send_client(self):
        raise NotImplemented

    def on_connection_made(self):
        pass

    def on_connection_dropped(self):
        pass

    def on_receive(self):
        pass
