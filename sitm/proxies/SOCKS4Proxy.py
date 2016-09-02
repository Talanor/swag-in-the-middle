import socket
import struct

from twisted.internet import defer, reactor
from twisted.internet.endpoints import TCP4ServerEndpoint
from twisted.internet.protocol import (Factory, Protocol,
                                       ReconnectingClientFactory)

from .IBaseProxy import IBaseProxy


# Inspired (stolen? :p) from https://gist.github.com/fiorix/1878983
class Socks4ProxyClient(Protocol):
    """docstring for Socks4ProxyClient"""
    def __init__(self, *args, **kwargs):
        super().__init__()
        self.__debug = kwargs["debug"]
        self.__factory = kwargs["factory"]
        self.__handlers = {
            "onDataReceived": []
        }
        self.client_queue = None
        self.server_queue = None

    def connectionMade(self):
        if self.__debug:
            print("Client: connected to peer")
        self.client_queue = self.__factory.client_queue
        self.server_queue = self.__factory.server_queue
        self.client_queue.get().addCallback(self.serverDataReceived)

    def serverDataReceived(self, data):
        if data is False:
            self.client_queue = None
            if self.__debug:
                print("Client: disconnecting from peer")
            self.__factory.continueTrying = False
            self.transport.loseConnection()
        elif self.client_queue:
            if self.__debug:
                print("Client: writing %s" % data)
            self.transport.write(data)
            self.client_queue.get().addCallback(self.serverDataReceived)
        else:
            self.__factory.cli_queue.put(data)

    def dataReceived(self, data):
        if self.__debug:
            print("Client: data received")
        self.__factory.server_queue.put(data)

    def connectionLost(self, why):
        if self.client_queue:
            self.client_queue = None
        if self.__debug:
            print("Client: peer disconnected unexpectedly")


class Socks4ProxyClientFactory(ReconnectingClientFactory):
    maxDelay = 10
    continueTrying = True

    def __init__(self, server_queue, client_queue, debug=False):
        self.server_queue = server_queue
        self.client_queue = client_queue
        self.__debug = debug

    def startedConnecting(self, connector):
        if self.__debug:
            print('Client Factory: Started to connect.')

    def buildProtocol(self, addr):
        if self.__debug:
            print('Client Factory: Resetting reconnection delay')
        self.resetDelay()
        return Socks4ProxyClient(debug=self.__debug, factory=self)

    def clientConnectionLost(self, connector, reason):
        if self.__debug:
            print('Client Factory: Lost connection.  Reason:', reason)
        ReconnectingClientFactory.clientConnectionLost(
            self, connector, reason
        )

    def clientConnectionFailed(self, connector, reason):
        if self.__debug:
            print('Client Factory: Connection failed. Reason:', reason)
        ReconnectingClientFactory.clientConnectionFailed(
            self, connector, reason
        )


class Socks4Protocol(Protocol):
    COMMAND_FMT = "!ccHI"
    COMMAND_SIZE = struct.calcsize(COMMAND_FMT)
    BUFFER_MAX_LENGTH = 128

    def __init__(self, debug=False):
        self.__debug = debug
        self.__commands = {
            1: self.__handle_connect,
            2: self.__handle_bind
        }
        self.__endpoint = None
        self.__connected = False

    def connectionMade(self):
        self.__buffer = b""

        if self.__debug is not False:
            print("Connection made")

    def connectionLost(self, reason):
        if self.__debug is not False:
            print("Connection lost")
            print(reason)
        if hasattr(self, 'client_queue'):
            self.client_queue.put(False)

    def __handle_connect(self, dstip, dstport, userid):
        if self.__debug:
            print("Connecting to '%s' on port '%d'" % (dstip, dstport))
        reactor.connectTCP(
            dstip, dstport,
            Socks4ProxyClientFactory(
                self.server_queue,
                self.client_queue,
                debug=self.__debug
            )
        )
        return b"\x00\x5A\x00\x00\x00\x00\x00\x00"

    def __handle_bind(self):
        pass

    def __clientDataReceived(self, data):
        if self.__debug:
            print("Server: writing %s" % data)
        self.transport.write(data)
        self.server_queue.get().addCallback(self.__clientDataReceived)

    def __handle(self, *args, **kwargs):
        if len(args) == 6:
            vn, cd, dstport, dstip, userid, _ = args
        elif len(args) == 8:
            vn, cd, dstport, dstip, userid, _, host, _ = args

            dstip = socket.gethostbyname(host)
            if self.__debug:
                print("IP for '%s' is '%s'" % (host, dstip))
        else:
            raise RuntimeError("Wrong number of arguments")

        # Discard identd check
        assert(vn == b"\x04")

        self.server_queue = defer.DeferredQueue()
        self.client_queue = defer.DeferredQueue()
        self.server_queue.get().addCallback(self.__clientDataReceived)

        ret = self.__commands[cd](dstip, dstport, userid)
        self.transport.write(ret)
        if ret[1] == 0x5A:
            self.__connected = True
        if len(self.__buffer) > 0:
            self.client_queue.put(self.__buffer)
            self.__buffer = b""

    def __lex(self):
        if len(self.__buffer) > Socks4Protocol.COMMAND_SIZE:
            offset = self.__buffer[Socks4Protocol.COMMAND_SIZE:].find(b"\x00")
            if offset < 0:
                if len(self.__buffer) >= Socks4Protocol.BUFFER_MAX_LENGTH:
                    # Drop the connection, either user id too long, either
                    # someone trying to overload the memory
                    self.transport.loseConnection()
                else:
                    # This means we may have not received enough data so far
                    pass
            else:
                print("Lexing : '%s'" % (self.__buffer))
                fmt = Socks4Protocol.COMMAND_FMT + "%dsc" % (offset)
                socks4_packet_size = struct.calcsize(fmt)
                data = list(struct.unpack(
                    fmt,
                    self.__buffer[:socks4_packet_size]
                ))
                data[3] = data[3].to_bytes(length=4, byteorder='big')
                if data[3][0] == 0 and data[3][1] == 0 and \
                   data[3][2] == 0 and data[3][3] != 0:
                    # Socks4a support
                    offset = self.__buffer[socks4_packet_size:].find(b"\x00")
                    if offset < 0:
                        # Null byte not found, cannot find hostname
                        data = None
                    else:
                        fmt += "%dsc" % (offset)
                        socks4_packet_size = struct.calcsize(fmt)
                        data = list(struct.unpack(
                            fmt,
                            self.__buffer[:socks4_packet_size]
                        ))
                else:
                    data[3] = socket.inet_ntoa(
                        data[3]
                    )
                if data:
                    data[1] = int.from_bytes(data[1], byteorder='big')
                    self.__buffer = self.__buffer[socks4_packet_size:]
                    self.__handle(*data)

    def dataReceived(self, data):
        if self.__debug:
            print("Data received")
            print(data)

        if self.__connected is False:
            self.__buffer += data
            self.__lex()
        else:
            self.client_queue.put(data)


class Socks4ProtocolFactory(Factory):
    def __init__(self, debug=False):
        super().__init__()
        self.__debug = debug

    def buildProtocol(self, addr):
        return Socks4Protocol(debug=self.__debug)


class SOCKS4Proxy(IBaseProxy):
    """docstring for SOCKS4Proxy"""
    def __init__(self, host=None, port=None):
        super().__init__()
        self._host = host
        self._port = None if port is None else int(port)

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, value):
        self._port = int(value)

    @property
    def host(self):
        return self._host

    @host.setter
    def host(self, value):
        self._host = value

    def run(self, debug=False):
        assert(all([self.host, self.port]))

        endpoint = TCP4ServerEndpoint(reactor, self.port)
        endpoint.listen(Socks4ProtocolFactory(debug))
        reactor.run()
