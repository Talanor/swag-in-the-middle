#!/usr/bin/python3
# -*- coding: utf-8 -*-

from sitm.proxies import SOCKS4Proxy

if __name__ == '__main__':
    proxy = SOCKS4Proxy()
    proxy.host = "0.0.0.0"
    proxy.port = "8082"
    proxy.run(debug=True)
