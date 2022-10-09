//go:build wireguard
// +build wireguard

package phantomtcp

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

func (config WireGuardServiceConfig) StartService() {
	var wgIPMap [65535]bool

	laddr, err := net.ResolveUDPAddr("udp", config.Address)
	if err != nil {
		logPrintln(0, config, err)
	}

	vaddr := [4]byte{VirtualAddrPrefix, 0, 0, 0}
	prefix := netip.PrefixFrom(netip.AddrFrom4(vaddr), 32)
	tun, tnet, err := StartWireguard([]netip.Addr{prefix.Addr()}, laddr.Port, nil, config.MTU, config.PrivateKey, config.Peers)
	if err != nil {
		logPrintln(0, config, err)
	}

	tcp_redirect := func(laddr string) {
		addr, err := net.ResolveTCPAddr("tcp", laddr)
		l, err := tnet.ListenTCP(addr)
		if err != nil {
			logPrintln(0, config, err)
		}
		for {
			client, err := l.Accept()
			if err != nil {
				logPrintln(1, err)
			}
			switch addr := client.LocalAddr().(type) {
			case *net.TCPAddr:
				go redirect(client, &net.TCPAddr{IP: addr.IP.To4(), Port: addr.Port})
			}
		}
	}

	udp_redirect := func(address, host string, pface *PhantomInterface) error {
		laddr, err := net.ResolveUDPAddr("udp", address)
		if err != nil {
			return err
		}
		client, err := tnet.ListenUDP(laddr)
		if err != nil {
			return err
		}
		defer client.Close()

		var udpLock sync.Mutex
		var udpMap map[string]net.Conn = make(map[string]net.Conn)
		data := make([]byte, 1500)
		for {
			n, srcAddr, err := client.ReadFrom(data)
			if err != nil {
				continue
			}

			udpLock.Lock()
			udpConn, ok := udpMap[srcAddr.String()]

			if ok {
				udpConn.Write(data[:n])
				udpLock.Unlock()
			} else {
				udpLock.Unlock()
				if pface.Hint&OPT_UDP == 0 && pface.Hint&(OPT_HTTP3) != 0 {
					if GetQUICVersion(data[:n]) == 0 {
						logPrintln(4, "Wiregurad(UDP):", srcAddr, "->", laddr, "not h3")
						continue
					}
				}

				logPrintln(1, "Wiregurad(UDP):", srcAddr, "->", host, laddr.Port, pface)
				remoteConn, proxyConn, err := pface.DialUDPProxy(host, laddr.Port)
				if err != nil {
					logPrintln(1, err)
					continue
				}
				udpLock.Lock()
				udpMap[srcAddr.String()] = remoteConn
				udpLock.Unlock()

				if pface.Hint&OPT_ZERO != 0 {
					zero_data := make([]byte, 8+rand.Intn(1024))
					_, err = remoteConn.Write(zero_data)
					if err != nil {
						logPrintln(1, err)
						remoteConn.Close()
						if proxyConn != nil {
							proxyConn.Close()
						}
						continue
					}
				}

				_, err = remoteConn.Write(data[:n])

				if err != nil {
					logPrintln(1, err)
					remoteConn.Close()
					if proxyConn != nil {
						proxyConn.Close()
					}
					continue
				}

				go func(srcAddr net.Addr, remoteConn net.Conn) {
					data := make([]byte, 1500)
					remoteConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
					for {
						n, err := remoteConn.Read(data)
						if err != nil {
							udpLock.Lock()
							delete(udpMap, srcAddr.String())
							udpLock.Unlock()
							remoteConn.Close()
							if proxyConn != nil {
								proxyConn.Close()
							}
							return
						}
						remoteConn.SetReadDeadline(time.Now().Add(time.Minute * 2))
						client.WriteTo(data[:n], srcAddr)
					}
				}(srcAddr, remoteConn)
			}
		}
		return nil
	}

	go tcp_redirect("0.0.0.0:443")
	go tcp_redirect("0.0.0.0:80")

	wgIPMap[0] = true
	l, err := tnet.ListenUDPAddrPort(netip.AddrPortFrom(netip.AddrFrom4(vaddr), 53))
	if err != nil {
		logPrintln(0, config, err)
	}

	var buf [512]byte
	for {
		n, raddr, err := l.ReadFrom(buf[:])
		if err != nil {
			continue
		}

		index, response := NSRequest(buf[:n], true)
		vaddr := [4]byte{VirtualAddrPrefix, 0, byte(index >> 8), byte(index & 0xFF)}
		prefix := netip.PrefixFrom(netip.AddrFrom4(vaddr), 32)

		if wgIPMap[index] == false {
			netstack.AddAddress(tun, prefix.Addr())
			wgIPMap[index] = true
			host := Nose[index]
			pface := ConfigLookup(host)
			if pface.Hint&(OPT_UDP|OPT_HTTP3) != 0 {
				dst := net.JoinHostPort(prefix.Addr().String(), "443")
				go udp_redirect(dst, host, pface)
			}
		}

		l.WriteTo(response, raddr)
	}
}

var TNetMap = make(map[string]*netstack.Net)

func (config WireGuardInterfaceConfig) StartClient() error {
	var addrs []netip.Addr
	for _, addr := range strings.Split(config.Address, ",") {
		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			logPrintln(0, addr, err)
			continue
		}
		addrs = append(addrs, prefix.Addr())
	}
	_, tnet, err := StartWireguard(addrs, 0, nil, int(config.MTU), config.PrivateKey, config.Peers)
	if err == nil {
		TNetMap[config.Name] = tnet
	}
	return err
}

func (pface *WireGuardInterface) DialTCP(address *net.TCPAddr) (net.Conn, error) {
	tnet, ok := TNetMap[pface.Device]
	if ok {
		return tnet.DialTCP(address)
	}

	return nil, nil
}

func (pface *WireGuardInterface) DialUDP(address *net.UDPAddr) (net.Conn, error) {
	tnet, ok := TNetMap[pface.Device]
	if ok {
		return tnet.DialUDP(nil, address)
	}
	return nil, nil
}

func StartWireguard(Addresses []netip.Addr, ListenPort int, DNS []netip.Addr, MTU int, PrivateKey string, Peers []Peer) (tun.Device, *netstack.Net, error) {
	tun, tnet, err := netstack.CreateNetTUN(Addresses, DNS, MTU)
	if err != nil {
		return nil, nil, err
	}
	Logger := device.NewLogger(device.LogLevelSilent, "")
	if LogLevel == 1 {
		Logger = device.NewLogger(device.LogLevelError, "")
	} else if LogLevel > 1 {
		Logger = device.NewLogger(device.LogLevelVerbose, "")
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), Logger)

	PrivateKey, err = Base64ToHex(PrivateKey)
	if err != nil {
		return nil, nil, err
	}
	ipcRequest := fmt.Sprintf("private_key=%s", PrivateKey)
	if ListenPort != 0 {
		ipcRequest += fmt.Sprintf(`
listen_port=%d`, ListenPort)
	}

	err = dev.IpcSet(ipcRequest)
	if err != nil {
		return nil, nil, err
	}

	for _, peer := range Peers {
		PublicKey, err := Base64ToHex(peer.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		PreSharedKey := "0000000000000000000000000000000000000000000000000000000000000000"
		if peer.PreSharedKey != "" {
			PreSharedKey, err = Base64ToHex(peer.PreSharedKey)
			if err != nil {
				return nil, nil, err
			}
		}

		ipcRequest := fmt.Sprintf(`public_key=%s
persistent_keepalive_interval=%d
preshared_key=%s`, PublicKey, peer.KeepAlive, PreSharedKey)

		if peer.Endpoint != "" {
			ipcRequest += fmt.Sprintf(`
endpoint=%s`, peer.Endpoint)
		}

		for _, allowed_ip := range strings.Split(peer.AllowedIPs, ",") {
			if allowed_ip != "" {
				ipcRequest += fmt.Sprintf(`
allowed_ip=%s`, allowed_ip)
			}
		}

		logPrintln(4, ipcRequest)

		err = dev.IpcSet(ipcRequest)
		if err != nil {
			return nil, nil, err
		}
	}

	err = dev.Up()
	if err != nil {
		return nil, nil, err
	}

	return tun, tnet, nil
}

func Base64ToHex(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", errors.New("invalid base64 string: " + key)
	}
	if len(decoded) != 32 {
		return "", errors.New("key should be 32 bytes: " + key)
	}
	return hex.EncodeToString(decoded), nil
}
