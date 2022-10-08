package phantomtcp

import (
	"bytes"
	"encoding/binary"
	"log"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

func ReadAtLeast() {

}

func SocksProxy(client net.Conn) {
	defer client.Close()

	var conn net.Conn
	var server *PhantomInterface
	{
		var b [1500]byte
		n, err := client.Read(b[:])
		if err != nil || n < 3 {
			logPrintln(1, client.RemoteAddr(), err)
			return
		}

		host := ""
		var ip net.IP
		port := 0
		var reply []byte
		if b[0] == 0x05 {
			client.Write([]byte{0x05, 0x00})
			n, err = client.Read(b[:4])
			if err != nil || n != 4 {
				return
			}
			switch b[3] {
			case 0x01: //IPv4
				n, err = client.Read(b[:6])
				if n < 6 {
					return
				}
				ip = net.IP(b[:4])
				port = int(binary.BigEndian.Uint16(b[4:6]))

				var ok bool
				server, ok = DomainMap[ip.String()]
				if ok && server == nil {
					// 0x02: connection not allowed by ruleset
					client.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
			case 0x03: //Domain
				n, err = client.Read(b[:])
				addrLen := b[0]
				if n < int(addrLen+3) {
					return
				}
				host = string(b[1 : addrLen+1])
				port = int(binary.BigEndian.Uint16(b[n-2:]))
				server = ConfigLookup(host)
				if server == nil {
					// 0x02: connection not allowed by ruleset
					client.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
			case 0x04: //IPv6
				n, err = client.Read(b[:])
				if n < 18 {
					return
				}
				ip = net.IP(b[:16])
				port = int(binary.BigEndian.Uint16(b[16:18]))

				var ok bool
				server, ok = DomainMap[ip.String()]
				if ok && server == nil {
					// 0x02: connection not allowed by ruleset
					client.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
					return
				}
			default:
				// 0x08: address type not supported
				client.Write([]byte{5, 9, 0, 1, 0, 0, 0, 0, 0, 0})
				return
			}
			reply = []byte{5, 0, 0, 1, 0, 0, 0, 0, 0, 0}
		} else if b[0] == 0x04 {
			if n > 8 && b[1] == 1 {
				userEnd := 8 + bytes.IndexByte(b[8:n], 0)
				port = int(binary.BigEndian.Uint16(b[2:4]))
				if b[4]|b[5]|b[6] == 0 {
					hostEnd := bytes.IndexByte(b[userEnd+1:n], 0)
					if hostEnd > 0 {
						host = string(b[userEnd+1 : userEnd+1+hostEnd])
					} else {
						client.Write([]byte{0, 91, 0, 0, 0, 0, 0, 0})
						return
					}
				} else {
					if b[4] == VirtualAddrPrefix {
						index := int(binary.BigEndian.Uint16(b[6:8]))
						if index >= len(Nose) {
							return
						}
						host = Nose[index]
						server = ConfigLookup(host)
						if server == nil {
							client.Write([]byte{5, 2, 0, 1, 0, 0, 0, 0, 0, 0})
							return
						}
					} else {
						ip = net.IP(b[4:8])
					}
				}

				reply = []byte{0, 90, b[2], b[3], b[4], b[5], b[6], b[7]}
			} else {
				client.Write([]byte{0, 91, 0, 0, 0, 0, 0, 0})
				return
			}
		} else {
			return
		}

		if err != nil {
			logPrintln(1, err)
			return
		}

		if host != "" {
			if server.Hint == 0 {
				logPrintln(1, "Socks:", host, port, server)
				addr := net.JoinHostPort(host, strconv.Itoa(port))
				logPrintln(1, "Socks:", addr)
				conn, err = net.Dial("tcp", addr)
				if err != nil {
					logPrintln(1, err)
					return
				}
				_, err = client.Write(reply)
			} else {
				logPrintln(1, "Socks:", host, port, server)
				_, err = client.Write(reply)
				if err != nil {
					logPrintln(1, err)
					return
				}

				n, err = client.Read(b[:])
				if err != nil {
					logPrintln(1, err)
					return
				}

				if b[0] != 0x16 {
					if server.Hint&OPT_HTTP3 != 0 {
						HttpMove(client, "h3", b[:n])
						return
					} else if server.Hint&OPT_HTTPS != 0 {
						HttpMove(client, "https", b[:n])
						return
					} else if server.Hint&OPT_MOVE != 0 {
						HttpMove(client, server.Address, b[:n])
						return
					} else if server.Hint&OPT_STRIP != 0 {
						if server.Hint&OPT_FRONTING != 0 {
							conn, err = server.DialStrip(host, "")
							host = ""
						} else {
							conn, err = server.DialStrip(host, host)
						}

						if err != nil {
							logPrintln(1, err)
							return
						}
						_, err = conn.Write(b[:n])
					} else {
						var info *ConnectionInfo
						conn, info, err = server.Dial(host, port, b[:n])
						if err != nil {
							logPrintln(1, host, err)
							return
						}

						if info != nil {
							server.Keep(client, conn, info)
							return
						}
					}
				} else {
					conn, _, err = server.Dial(host, port, b[:n])
					if err != nil {
						logPrintln(1, host, err)
						return
					}
				}
			}
		} else {
			if server != nil {
				host = ip.String()
				logPrintln(1, "Socks:", host, port, server)
				client.Write(reply)
				n, err = client.Read(b[:])
				if err != nil {
					logPrintln(1, err)
					return
				}

				result, ok := DNSCache.Load(host)
				var addresses []net.IP
				if ok {
					records := result.(*DNSRecords)
					if records.AAAA != nil {
						addresses = make([]net.IP, len(records.AAAA.Addresses))
						copy(addresses, records.AAAA.Addresses)
					} else if records.A != nil {
						addresses = make([]net.IP, len(records.A.Addresses))
						copy(addresses, records.A.Addresses)
					}
				} else {
					conn, _, err = server.Dial(host, port, b[:n])
				}
			} else {
				logPrintln(1, "Socks:", ip, port)

				addr := net.TCPAddr{IP: ip, Port: port, Zone: ""}
				conn, err = net.DialTCP("tcp", nil, &addr)
				client.Write(reply)
			}
		}

		if err != nil {
			logPrintln(1, err)
			return
		}
	}

	defer conn.Close()

	_, _, err := relay(client, conn)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return
		}
		logPrintln(1, "relay error:", err)
	}
}

func validOptionalPort(port string) bool {
	if port == "" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
}

func splitHostPort(hostport string) (host string, port int) {
	var err error
	host = hostport
	port = 0

	colon := strings.LastIndexByte(host, ':')
	if colon != -1 && validOptionalPort(host[colon:]) {
		port, err = strconv.Atoi(host[colon+1:])
		if err != nil {
			port = 0
		}
		host = host[:colon]
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}

	return
}

func SNIProxy(client net.Conn) {
	defer client.Close()

	var conn net.Conn
	{
		var b [1500]byte
		n, err := client.Read(b[:])
		if err != nil {
			log.Println(err)
			return
		}

		var host string
		var port int
		if b[0] == 0x16 {
			offset, length := GetSNI(b[:n])
			if length == 0 {
				return
			}
			host = string(b[offset : offset+length])
			port = 443
		} else {
			offset, length := GetHost(b[:n])
			if length == 0 {
				return
			}
			host = string(b[offset : offset+length])
			portstart := strings.Index(host, ":")
			if portstart == -1 {
				port = 80
			} else {
				port, err = strconv.Atoi(host[portstart+1:])
				if err != nil {
					return
				}
				host = host[:portstart]
			}
			if net.ParseIP(host) != nil {
				return
			}
		}

		server := ConfigLookup(host)
		if server == nil {
			return
		}
		if server.Hint != 0 {
			logPrintln(1, "SNI:", host, port, server)

			if b[0] == 0x16 {
				conn, _, err = server.Dial(host, port, b[:n])
				if err != nil {
					logPrintln(1, host, err)
					return
				}
			} else {
				if server.Hint&OPT_HTTP3 != 0 {
					HttpMove(client, "h3", b[:n])
					return
				} else if server.Hint&OPT_HTTPS != 0 {
					HttpMove(client, "https", b[:n])
					return
				} else if server.Hint&OPT_MOVE != 0 {
					HttpMove(client, server.Address, b[:n])
					return
				} else if server.Hint&OPT_STRIP != 0 {
					if server.Hint&OPT_FRONTING != 0 {
						conn, err = server.DialStrip(host, "")
						host = ""
					} else {
						conn, err = server.DialStrip(host, host)
					}

					if err != nil {
						logPrintln(1, err)
						return
					}
					_, err = conn.Write(b[:n])
					if err != nil {
						logPrintln(1, err)
						return
					}
				} else {
					var info *ConnectionInfo
					conn, info, err = server.Dial(host, port, b[:n])
					if err != nil {
						logPrintln(1, host, err)
						return
					}

					if info != nil {
						server.Keep(client, conn, info)
						return
					}
				}
			}
		} else {
			host = net.JoinHostPort(host, strconv.Itoa(port))
			logPrintln(1, host)

			conn, err = net.Dial("tcp", host)
			if err != nil {
				logPrintln(1, err)
				return
			}
			_, err = conn.Write(b[:n])
			if err != nil {
				logPrintln(1, err)
				return
			}
		}
	}

	defer conn.Close()

	_, _, err := relay(client, conn)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return
		}
		logPrintln(1, "relay error:", err)
	}
}

func RedirectProxy(client net.Conn) {
	addr, err := GetOriginalDST(client.(*net.TCPConn))
	if err != nil {
		logPrintln(1, err)
		client.Close()
		return
	}

	redirect(client, addr)
}

func redirect(client net.Conn, addr *net.TCPAddr) {
	defer client.Close()

	var conn net.Conn
	var err error
	{
		var host string
		var port int
		var ips []net.IP = nil

		switch addr.IP[0] {
		case 0x00:
			index := int(binary.BigEndian.Uint32(addr.IP[12:16]))
			if index >= len(Nose) {
				return
			}
			host = Nose[index]
		case VirtualAddrPrefix:
			index := int(binary.BigEndian.Uint16(addr.IP[2:4]))
			if index >= len(Nose) {
				return
			}
			host = Nose[index]
		default:
			if addr.String() == client.LocalAddr().String() {
				return
			}
			host = addr.IP.String()
			ips = []net.IP{addr.IP}
		}
		port = addr.Port

		server := ConfigLookup(host)
		if server.Hint&OPT_NOTCP != 0 {
			time.Sleep(time.Second)
			return
		}

		if server.Protocol != 0 || server.Hint != 0 {
			var b [1500]byte
			n, err := client.Read(b[:])
			if err != nil {
				logPrintln(1, err)
				return
			}

			if b[0] == 0x16 {
				offset, length := GetSNI(b[:n])
				if length > 0 {
					host = string(b[offset : offset+length])
					server = ConfigLookup(host)
				}

				logPrintln(1, "Redirect:", client.RemoteAddr(), "->", host, port, server)
				if server == nil {
					return
				}

				conn, _, err = server.Dial(host, port, b[:n])
				if err != nil {
					logPrintln(1, host, err)
					return
				}
			} else {
				logPrintln(1, "Redirect:", client.RemoteAddr(), "->", host, port, server)
				if server.Hint&OPT_HTTP3 != 0 {
					HttpMove(client, "h3", b[:n])
					return
				} else if server.Hint&OPT_HTTPS != 0 {
					HttpMove(client, "https", b[:n])
					return
				} else if server.Hint&OPT_MOVE != 0 {
					HttpMove(client, server.Address, b[:n])
					return
				} else if server.Hint&OPT_STRIP != 0 {
					if server.Hint&OPT_FRONTING != 0 {
						conn, err = server.DialStrip(host, "")
						host = ""
					} else {
						conn, err = server.DialStrip(host, host)
					}

					if err != nil {
						logPrintln(1, err)
						return
					}
					_, err = conn.Write(b[:n])
					if err != nil {
						logPrintln(1, err)
						return
					}
				} else {
					var info *ConnectionInfo
					conn, info, err = server.Dial(host, port, b[:n])
					if err != nil {
						logPrintln(1, host, err)
						return
					}

					if info != nil {
						server.Keep(client, conn, info)
						return
					}
				}
			}
		} else if ips != nil {
			logPrintln(1, "RedirectProxy:", client.RemoteAddr(), "->", addr)
			conn, err = net.DialTCP("tcp", nil, addr)
			if err != nil {
				logPrintln(1, host, err)
				return
			}
		}
	}

	if conn == nil {
		return
	}

	defer conn.Close()

	_, _, err = relay(client, conn)
	if err != nil {
		if err, ok := err.(net.Error); ok && err.Timeout() {
			return // ignore i/o timeout
		}
		logPrintln(1, "relay error:", err)
	}
}

func QUICProxy(address string) {
	client, err := ListenUDP(address)
	if err != nil {
		logPrintln(1, err)
		return
	}
	defer client.Close()

	var UDPLock sync.Mutex
	var UDPMap map[string]net.Conn = make(map[string]net.Conn)
	data := make([]byte, 1500)

	for {
		n, clientAddr, err := client.ReadFromUDP(data)
		if err != nil {
			logPrintln(1, err)
			return
		}

		udpConn, ok := UDPMap[clientAddr.String()]

		if ok {
			udpConn.Write(data[:n])
		} else {
			SNI := GetQUICSNI(data[:n])
			if SNI != "" {
				server := ConfigLookup(SNI)
				if server.Hint&OPT_UDP == 0 {
					continue
				}
				_, ips := NSLookup(SNI, server.Hint, server.DNS)
				if ips == nil {
					continue
				}

				logPrintln(1, "[QUIC]", clientAddr.String(), SNI, ips)

				udpConn, err = net.DialUDP("udp", nil, &net.UDPAddr{IP: ips[0], Port: 443})
				if err != nil {
					logPrintln(1, err)
					continue
				}

				if server.Hint&OPT_ZERO != 0 {
					zero_data := make([]byte, 8+rand.Intn(1024))
					_, err = udpConn.Write(zero_data)
					if err != nil {
						logPrintln(1, err)
						continue
					}
				}

				UDPMap[clientAddr.String()] = udpConn
				_, err = udpConn.Write(data[:n])
				if err != nil {
					logPrintln(1, err)
					continue
				}

				go func(clientAddr net.UDPAddr) {
					data := make([]byte, 1500)
					udpConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
					for {
						n, err := udpConn.Read(data)
						if err != nil {
							UDPLock.Lock()
							delete(UDPMap, clientAddr.String())
							UDPLock.Unlock()
							udpConn.Close()
							return
						}
						udpConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
						client.WriteToUDP(data[:n], &clientAddr)
					}
				}(*clientAddr)
			}
		}
	}
}

func SocksUDPProxy(address string) {
	laddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		logPrintln(1, err)
		return
	}
	local, err := net.ListenUDP("udp", laddr)
	if err != nil {
		logPrintln(1, err)
		return
	}
	defer local.Close()

	var ConnLock sync.Mutex
	var ConnMap map[string]net.Conn = make(map[string]net.Conn)
	data := make([]byte, 1472)
	for {
		n, srcAddr, err := local.ReadFromUDP(data)
		if err != nil {
			logPrintln(1, err)
			continue
		}

		var host string
		var port int
		if n < 8 || data[0] != 4 {
			continue
		}
		switch data[1] {
		case 1:
			port = int(binary.BigEndian.Uint16(data[2:4]))
			ConnLock.Lock()
			dstAddr := net.UDPAddr{IP: data[4:8], Port: port, Zone: ""}
			key := strings.Join([]string{srcAddr.String(), dstAddr.String()}, ",")
			conn, ok := ConnMap[key]
			if ok {
				conn.Write(data[8:n])
				ConnLock.Unlock()
				continue
			}
			ConnLock.Unlock()

			var remoteConn net.Conn = nil
			if data[4] == VirtualAddrPrefix {
				index := int(binary.BigEndian.Uint32(data[6:8]))
				if index >= len(Nose) {
					return
				}
				host = Nose[index]
				server := ConfigLookup(host)
				if server.Protocol != 0 {
					continue
				}
				if server.Hint&(OPT_UDP|OPT_HTTP3) == 0 {
					continue
				}
				if server.Hint&(OPT_HTTP3) != 0 {
					if GetQUICVersion(data[:n]) == 0 {
						continue
					}
				}
				_, ips := NSLookup(host, server.Hint, server.DNS)
				if ips == nil {
					continue
				}

				logPrintln(1, "Socks4U:", srcAddr, "->", host, port)
				raddr := net.UDPAddr{IP: ips[0], Port: port}
				remoteConn, err = net.DialUDP("udp", nil, &raddr)
				if err != nil {
					logPrintln(1, err)
					continue
				}

				if server.Hint&OPT_ZERO != 0 {
					zero_data := make([]byte, 8+rand.Intn(1024))
					_, err = remoteConn.Write(zero_data)
					if err != nil {
						logPrintln(1, err)
						continue
					}
				}

				_, err = remoteConn.Write(data[8:n])
			} else {
				logPrintln(1, "Socks4U:", srcAddr, "->", dstAddr)
				remoteConn, err = net.DialUDP("udp", nil, &dstAddr)
				_, err = remoteConn.Write(data[8:n])
			}

			if err != nil {
				logPrintln(1, err)
				continue
			}

			go func(srcAddr net.UDPAddr, remoteConn net.Conn, key string) {
				data := make([]byte, 1472)
				remoteConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
				for {
					n, err := remoteConn.Read(data)
					if err != nil {
						ConnLock.Lock()
						delete(ConnMap, key)
						ConnLock.Unlock()
						remoteConn.Close()
						return
					}
					remoteConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
					local.WriteToUDP(data[:n], &srcAddr)
				}
			}(*srcAddr, remoteConn, key)
		default:
			continue
		}
	}
}

func (config ServiceConfig) StartService() {
}

func (config InterfaceConfig) StartClient() error {
	return nil
}

func (pface *PhantomInterface) DialTCP(address *net.TCPAddr) (net.Conn, error) {
	return nil, nil
}

func (pface *PhantomInterface) DialUDP(address *net.UDPAddr) (net.Conn, error) {
	return nil, nil
}
