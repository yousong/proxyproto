package proxyproto

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func genpp2() [][]byte {
	var (
		cmds = []byte{
			byte((2 << 4) | COMMAND_LOCAL),
			byte((2 << 4) | COMMAND_PROXY),
		}
		fams = []byte{
			byte(AF_UNSPEC),
			byte(AF_INET),
			byte(AF_INET6),
			byte(AF_UNIX),
		}
		apd = func(a []byte, b [][]byte) [][]byte {
			r := make([][]byte, 0, len(a)*len(b))
			for _, a0 := range a {
				for _, b0 := range b {
					r0 := make([]byte, len(b0)+1)
					copy(r0, b0)
					r0[len(b0)] = a0
					r = append(r, r0)
				}
			}
			return r
		}
		apdaddr = func(b [][]byte) [][]byte {
			for i, b0 := range b {
				var (
					fam = b0[len(PROXY_V2_SIG)+1]
					adl = -1
				)
				switch fam {
				case AF_INET:
					adl = 4*2 + 2*2
				case AF_INET6:
					adl = 16*2 + 2*2
				case AF_UNIX:
					adl = 108 * 2
				case AF_UNSPEC:
					adl = 0
				default:
					panic("bad fam")
				}
				ol := len(b0)
				wl := len(b0) + 2 + adl
				if cap(b0) < wl {
					b1 := make([]byte, wl)
					copy(b1, b0)
					b0 = b1
				} else {
					b0 = b0[:wl]
				}
				binary.BigEndian.PutUint16(b0[ol:], uint16(adl))
				b[i] = b0
			}
			return b
		}
	)
	var r [][]byte
	r = apd(cmds, [][]byte{[]byte(PROXY_V2_SIG)})
	r = apd(fams, r)
	r = apdaddr(r)
	return r
}

func genpp2bad(b []byte) [][]byte {
	var (
		r [][]byte
		s = len(PROXY_V2_SIG)
		d = func(of int, v byte) {
			b0 := make([]byte, len(b))
			copy(b0, b)
			b0[of] = v
			r = append(r, b0)
		}
	)
	d(0, 0x00)   // sig
	d(s+0, 0xff) // ver|cmd
	d(s+1, 0xff) // fam
	return r
}

func TestProxyParser(t *testing.T) {
	type testC struct {
		name string
		in   string
		rem  string
		err  bool
	}
	cases := []testC{
		{
			name: "TCP/IPv4",
			in:   "PROXY TCP4 255.255.255.255 255.255.255.255 65535 65535\r\n",
		},
		{
			name: "TCP/IPv6",
			in:   "PROXY TCP6 ::1 ::1 65535 65535\r\n",
		},
		{
			name: "unknown connection (short form)",
			in:   "PROXY UNKNOWN\r\n",
		},
		{
			name: "worst case (optional fields set to 0xff)",
			in:   "PROXY UNKNOWN ::1 ::1 65535 65535\r\n",
		},
		{
			name: "normal",
			in:   "PROXY TCP4 192.168.0.1 192.168.0.11 56324 443\r\n",
		},
	}
	v2ins := genpp2()
	for _, v2in := range v2ins {
		cases = append(cases,
			testC{
				in: string(v2in),
			},
		)
		v2inbads := genpp2bad(v2in)
		for _, v2inbad := range v2inbads {
			cases = append(cases,
				testC{
					in:  string(v2inbad),
					err: true,
				},
			)
		}
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := bytes.NewBufferString(c.in)
			pp := newProxyParser(r)
			if err := pp.parseProxyProtoOnce(); err != nil {
				if !c.err {
					t.Fatalf("unexpected err: %v", err)
				}
				return
			} else if err == nil && c.err {
				t.Fatalf("want err, got nil")
			}
			if rem := r.String(); rem != c.rem {
				t.Fatalf("rem want %q, got %q", c.rem, rem)
			}
		})
	}
}
