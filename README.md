# proxyproto

[![GoDoc](https://godoc.org/github.com/yousong/proxyproto?status.svg)](http://godoc.org/github.com/yousong/proxyproto) 
[![Report card](https://goreportcard.com/badge/github.com/yousong/proxyproto)](https://goreportcard.com/report/github.com/yousong/proxyproto) 

This package implements [HAProxy PROXY](https://www.haproxy.org/download/1.8/doc/proxy-protocol.txt) support

Features

 - Compatible with standard library's net.Listener, net.Conn, net.PacketConn interface
 - Support both v1 and v2 of the protocol
 - Support both TCP and UDP

# TODO

- UnixAddr in net/unixsock.go
- af of LocalAddr() and RemoteAddr()
