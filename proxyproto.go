// Copyright 2019 Yunion
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package proxyproto

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
)

type ProxyVersion string

const (
	PROXY_V1    ProxyVersion = "v1"
	PROXY_V2    ProxyVersion = "v2"
	PROXY_V1_V2 ProxyVersion = "v1/v2"
)

const (
	PROXY_V2_SIG = "\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A"

	COMMAND_LOCAL = 0x0
	COMMAND_PROXY = 0x1

	AF_UNSPEC = 0x0
	AF_INET   = 0x1
	AF_INET6  = 0x2
	AF_UNIX   = 0x3

	L4_UNSPEC = 0x0
	L4_STREAM = 0x1
	L4_DGRAM  = 0x2
)

// proxyParser parse header and return response
type proxyParser struct {
	r    io.Reader
	once *sync.Once
	err  error

	Version ProxyVersion
	Command string

	SrcIP    net.IP
	DestIP   net.IP
	SrcPort  int
	DestPort int
}

// newProxyParser returns a proxyParser that parse PROXY protocol data from r
func newProxyParser(r io.Reader) *proxyParser {
	pp := &proxyParser{
		r:    r,
		once: &sync.Once{},
	}
	return pp
}

// parseProxyProtoOnce parse PROXY data from r once and for all
//
// Parse state and return value will not change when called multiple times
func (pp *proxyParser) parseProxyProtoOnce() error {
	pp.once.Do(func() {
		pp.err = pp.parseProxyProto()
	})
	return pp.err
}

// parseProxyProto parse PROXY v1 or v2 data
func (pp *proxyParser) parseProxyProto() error {
	buf := make([]byte, 16)
	{
		_, err := io.ReadFull(pp.r, buf[:8])
		if err != nil {
			return err
		}
		if string(buf[:6]) == "PROXY " {
			pp.Version = PROXY_V1
			return pp.parseProxyV1Proto(buf[6:])
		}
	}
	{
		_, err := io.ReadFull(pp.r, buf[8:])
		if err != nil {
			return err
		}
		if bytes.Equal(buf[:12], []byte(PROXY_V2_SIG)) {
			pp.Version = PROXY_V2
			return pp.parseProxyV2Proto(buf[12:])
		}
	}
	return fmt.Errorf("unknown PROXY protocol")
}

// parseProxyV1Proto parse PROXY v1 data
func (pp *proxyParser) parseProxyV1Proto(b []byte) error {
out:
	for cr := false; true; {
		one := []byte{0}
		n, err := pp.r.Read(one)
		if err != nil {
			return err
		}
		if n > 0 {
			c := one[0]
			switch {
			case !cr && c == '\r':
				cr = true
			case cr && c == '\n':
				break out
			case c != '\r' && c != '\n':
				if len(b) >= 107-6 {
					return fmt.Errorf("proxyv1: proxy line longer than 107 bytes")
				}
				b = append(b, c)
			default:
				return fmt.Errorf("proxy1: bad proxy line")
			}
		}
	}
	parts := strings.Split(string(b), " ")
	if len(parts) != 5 {
		return fmt.Errorf("proxy1: bad proxy line: expecting 5 elements, got %d", len(parts))
	}
	parseIP := func(s string, ver int) (net.IP, error) {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("proxy1: bad ip address: %s", s)
		}
		if (ver == 4 && len(ip) == 4) || (ver == 6 && len(ip) == 16) {
			return nil, fmt.Errorf("proxy1: bad ipv%d addr: %s", ver, s)
		}
		return ip, nil
	}
	parsePort := func(s string) (int, error) {
		i, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return 0, fmt.Errorf("proxy1: bad port %s: %v", s, err)
		}
		if i > 65535 {
			return 0, fmt.Errorf("proxy1: port out of range: %d", i)
		}
		return int(i), nil
	}
	fam := parts[0]
	var (
		af  int
		err error
	)
	switch fam {
	case "TCP4":
		af = 4
	case "TCP6":
		af = 6
	case "UNKNOWN":
		return nil
	}
	pp.SrcIP, err = parseIP(parts[1], af)
	if err != nil {
		return err
	}
	pp.DestIP, err = parseIP(parts[2], af)
	if err != nil {
		return err
	}
	pp.SrcPort, err = parsePort(parts[3])
	if err != nil {
		return err
	}
	pp.DestPort, err = parsePort(parts[4])
	if err != nil {
		return err
	}
	return nil
}

// parseProxyV1Proto parse PROXY v2 data
func (pp *proxyParser) parseProxyV2Proto(b []byte) error {
	{
		ver_cmd := uint8(b[0])
		ver := ver_cmd & 0xf0
		if ver != 0x20 {
			return fmt.Errorf("proxy2: bad version: %02x", ver_cmd)
		}
		switch ver_cmd & 0xf {
		case COMMAND_LOCAL:
			pp.Command = "LOCAL"
		case COMMAND_PROXY:
			pp.Command = "PROXY"
		default:
			return fmt.Errorf("proxy2: bad command: %02x", ver_cmd)
		}
	}
	readFunc := func(r io.Reader, size int) ([]byte, error) {
		if size < 0 {
			return nil, fmt.Errorf("negative size read")
		}
		buf := make([]byte, size)
		_, err := io.ReadFull(r, buf)
		if err != nil {
			return nil, err
		}
		return buf, nil
	}
	length := int(binary.BigEndian.Uint16(b[2:]))
	fam := uint8(b[1])
	af := (fam & 0xf0) >> 4
	switch af {
	case AF_UNSPEC, AF_UNIX:
		_, err := readFunc(pp.r, length)
		return err
	case AF_INET:
		buf, err := readFunc(pp.r, 8)
		if err != nil {
			return err
		}
		length -= 8
		pp.SrcIP = net.IP(buf[:4])
		pp.DestIP = net.IP(buf[4:])
	case AF_INET6:
		buf, err := readFunc(pp.r, 32)
		if err != nil {
			return err
		}
		length -= 32
		pp.SrcIP = net.IP(buf[:16])
		pp.DestIP = net.IP(buf[16:])
	default:
		return fmt.Errorf("proxy2: unknown address family: %02x", fam)
	}

	switch l4 := af & 0xf; l4 {
	case L4_UNSPEC:
		_, err := readFunc(pp.r, length)
		return err
	case L4_STREAM, L4_DGRAM:
		buf, err := readFunc(pp.r, 4)
		if err != nil {
			return err
		}
		length -= 4
		pp.SrcPort = int(binary.BigEndian.Uint16(buf[:2]))
		pp.DestPort = int(binary.BigEndian.Uint16(buf[2:]))
	default:
		return fmt.Errorf("proxy2: unknown transport protocol: %02x", fam)
	}
	_, err := readFunc(pp.r, length)
	return err
}

// remoteAddr returns remote address as conveyed in the PROXY header
func (pp *proxyParser) remoteAddr(orig net.Addr) net.Addr {
	if pp.SrcIP != nil {
		switch orig.(type) {
		case *net.TCPAddr:
			return &net.TCPAddr{
				IP:   pp.SrcIP,
				Port: pp.SrcPort,
			}
		case *net.UDPAddr:
			return &net.UDPAddr{
				IP:   pp.SrcIP,
				Port: pp.SrcPort,
			}
		}
	}
	return orig
}

// Listener provides PROXY-aware wrapper around existing net.Listener
type Listener struct {
	net.Listener
}

// Accept implements net.Listener
func (l *Listener) Accept() (conn net.Conn, err error) {
	conn, err = l.Listener.Accept()
	if err != nil {
		return
	}
	conn = NewConn(conn)
	return
}

// Conn provides PROXY-aware wrapper around existing net.Conn
type Conn struct {
	net.Conn

	proxyParser *proxyParser
}

// NewConn returns a new Conn
func NewConn(conn net.Conn) *Conn {
	proxyConn := &Conn{
		Conn:        conn,
		proxyParser: newProxyParser(conn),
	}
	return proxyConn
}

// Read implements net.Conn
//
// It will parse PROXY data on first call.  PROXY header will not be written
// into b and its size will not be part of the returned size.
func (conn *Conn) Read(b []byte) (n int, err error) {
	if err := conn.proxyParser.parseProxyProtoOnce(); err != nil {
		return 0, err
	}
	return conn.Conn.Read(b)
}

// RemoteAddr returns remote address as conveyed in the PROXY header
func (conn *Conn) RemoteAddr() net.Addr {
	orig := conn.Conn.RemoteAddr()
	if err := conn.proxyParser.parseProxyProtoOnce(); err != nil {
		return orig
	}
	if conn.proxyParser.SrcIP != nil {
		switch orig.(type) {
		case *net.TCPAddr:
			return &net.TCPAddr{
				IP:   conn.proxyParser.SrcIP,
				Port: conn.proxyParser.SrcPort,
			}
		case *net.UDPAddr:
			return &net.UDPAddr{
				IP:   conn.proxyParser.SrcIP,
				Port: conn.proxyParser.SrcPort,
			}
		}
	}
	return orig
}

// PacketConn provides a PROXY-aware wrapper around existing net.PacketConn
type PacketConn struct {
	net.PacketConn
}

// NewPacketConn returns a new PacketConn
func NewPacketConn(conn net.PacketConn) *PacketConn {
	packetConn := &PacketConn{
		PacketConn: conn,
	}
	return packetConn
}

// ReadFrom implements net.PacketConn
//
// It will parse PROXY header first, then copies the actual data into p.  On
// successful parse, the returned address will be of type *Addr
func (conn *PacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	hp := make([]byte, 512+len(p))
	n, orig, origErr := conn.PacketConn.ReadFrom(hp)
	if n > 0 {
		b := bytes.NewBuffer(hp[:n])
		pp := newProxyParser(b)
		err := pp.parseProxyProtoOnce()
		if err != nil {
			return 0, orig, err
		}
		n = copy(p, b.Bytes())
		return n, &Addr{
			Addr:       orig,
			remoteAddr: pp.remoteAddr(orig),
		}, origErr
	}
	return n, orig, origErr
}

// Addr provides a way for PacketConn.ReadFrom to return to its caller both the
// endpoint address and addresses in the PROXY header
type Addr struct {
	net.Addr
	remoteAddr net.Addr
}

// RemoteAddr returns remote address in PROXY header
func (pa *Addr) RemoteAddr() net.Addr {
	return pa.remoteAddr
}
