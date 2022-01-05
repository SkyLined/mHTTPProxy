cHTTPClientSideProxyServer
===========
`cHTTPClientSideProxyServer` is a Python class that can be used to create a
HTTP/1.0&1.1 client-side proxy. SSL support is optional; it is available if the
`mSSL` module is available.

`cHTTPClientSideProxyServer` accepts connections from clients and parses
requests and will forward those requests to the correct server. It handles
`CONNECT` requests but can be used to MitM these connections, rather than
simply pass data back and forth between the client and server.
