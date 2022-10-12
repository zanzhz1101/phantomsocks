//go:build linux && rawsocket
// +build linux,rawsocket

package phantomtcp

import (
	"fmt"
	"net"
	"strconv"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

var HintMap = map[string]uint32{
	"none":   OPT_NONE,
	"ttl":    OPT_TTL,
	"mss":    OPT_MSS,
	"w-md5":  OPT_WMD5,
	"n-ack":  OPT_NACK,
	"w-ack":  OPT_WACK,
	"w-csum": OPT_WCSUM,
	"w-seq":  OPT_WSEQ,

	"udp":    OPT_UDP,
	"no-tcp": OPT_NOTCP,
	"delay":  OPT_DELAY,

	"mode2":      OPT_MODE2,
	"df":         OPT_DF,
	"sat":        OPT_SAT,
	"rand":       OPT_RAND,
	"s-seg":      OPT_SSEG,
	"1-seg":      OPT_1SEG,
	"half-tfo":   OPT_HTFO,
	"keep-alive": OPT_KEEPALIVE,
	"synx2":      OPT_SYNX2,
	"zero":       OPT_ZERO,

	"http":     OPT_HTTP,
	"https":    OPT_HTTPS,
	"h3":       OPT_HTTP3,
	"move":     OPT_MOVE,
	"strip":    OPT_STRIP,
	"fronting": OPT_FRONTING,

	"ipv4": OPT_IPV4,
	"ipv6": OPT_IPV6,
}

func DevicePrint() {
}

func connectionMonitor(device string, ipv6 bool) {
	var err error
	localaddr, err := GetLocalAddr(device, ipv6)
	if err != nil {
		logPrintln(1, device, err)
		return
	}

	var handle *net.IPConn
	if ipv6 {
		if localaddr == nil {
			logPrintln(1, "Device:", device, "no IPv6")
			return
		}
		handle, err = net.ListenIP("ip6:tcp", &net.IPAddr{IP: localaddr.IP, Zone: ""})
	} else {
		if localaddr == nil {
			logPrintln(1, "Device:", device, "no IPv4")
			return
		}
		handle, err = net.ListenIP("ip4:tcp", &net.IPAddr{IP: localaddr.IP, Zone: ""})
	}

	fmt.Printf("Device: %v (%s)\n", device, localaddr.IP.String())

	if err != nil {
		fmt.Printf("sockraw open failed: %v", err)
		return
	}
	defer handle.Close()

	buf := make([]byte, 1500)
	for {
		n, addr, err := handle.ReadFrom(buf)
		if err != nil {
			logPrintln(1, err)
			continue
		}
		if buf[13] != 18 {
			continue
		}

		var tcp layers.TCP
		tcp.DecodeFromBytes(buf[:n], gopacket.NilDecodeFeedback)
		srcPort := tcp.DstPort
		synAddr := net.JoinHostPort(addr.String(), strconv.Itoa(int(tcp.SrcPort)))
		_, ok := ConnSyn.Load(synAddr)
		if ok {
			if ipv6 {
				var ip layers.IPv6
				ip.Version = 6
				ip.TrafficClass = 5
				ip.FlowLabel = 0
				ip.Length = 0
				ip.NextHeader = 6
				ip.HopLimit = 64
				ip.SrcIP = localaddr.IP
				ip.DstIP = net.ParseIP(addr.String())
				ip.HopByHop = nil

				tcp.DstPort = tcp.SrcPort
				tcp.SrcPort = srcPort
				ack := tcp.Seq + 1
				tcp.Seq = tcp.Ack - 1
				tcp.Ack = ack

				ch := ConnInfo6[srcPort]
				connInfo := ConnectionInfo{nil, &ip, tcp}
				go func(info *ConnectionInfo) {
					select {
					case ch <- info:
					case <-time.After(time.Second * 2):
					}
				}(&connInfo)

				buf = make([]byte, 1500)
			} else {
				var ip layers.IPv4
				ip.Version = 4
				ip.IHL = 5
				ip.TOS = 0
				ip.Length = 0
				ip.Id = 0
				ip.Flags = 0
				ip.FragOffset = 0
				ip.TTL = 64
				ip.Protocol = 6
				ip.Checksum = 0
				ip.SrcIP = localaddr.IP
				ip.DstIP = net.ParseIP(addr.String())
				ip.Options = nil
				ip.Padding = nil

				tcp.DstPort = tcp.SrcPort
				tcp.SrcPort = srcPort
				ack := tcp.Seq + 1
				tcp.Seq = tcp.Ack - 1
				tcp.Ack = ack

				ch := ConnInfo4[srcPort]
				connInfo := ConnectionInfo{nil, &ip, tcp}
				go func(info *ConnectionInfo) {
					select {
					case ch <- info:
					case <-time.After(time.Second * 2):
					}
				}(&connInfo)

				buf = make([]byte, 1500)
			}
		}
	}
}

func ICMPMonitor(device string, ipv6 bool) {
	fmt.Printf("Device: %v\n", device)

	var err error
	localaddr, err := GetLocalAddr(device, ipv6)
	if err != nil {
		logPrintln(1, err)
		return
	}

	var handle *net.IPConn
	if ipv6 {
		if localaddr == nil {
			logPrintln(1, "no IPv6 on", device)
			return
		}
		handle, err = net.ListenIP("ip6:icmp", &net.IPAddr{IP: localaddr.IP, Zone: ""})
	} else {
		if localaddr == nil {
			logPrintln(1, "no IPv4 on", device)
			return
		}
		handle, err = net.ListenIP("ip4:icmp", &net.IPAddr{IP: localaddr.IP, Zone: ""})
	}

	if err != nil {
		fmt.Printf("sockraw open failed: %v", err)
		return
	}
	defer handle.Close()

	var connInfo ConnectionInfo
	data := make([]byte, 1500)
	fakepayload := make([]byte, 1024)
	df := gopacket.NilDecodeFeedback
	for {
		n, _, err := handle.ReadFrom(data)
		if err != nil {
			logPrintln(1, err)
			continue
		}
		if len(data) < 8 || !(data[0] == 11 && data[1] == 0) {
			continue
		}

		if ipv6 {
			var icmp layers.ICMPv6
			icmp.DecodeFromBytes(data[:n], df)
			var ip layers.IPv6
			if ip.DecodeFromBytes(icmp.Payload, df) == nil && ip.NextHeader == layers.IPProtocolTCP && ip.TrafficClass > 0 {
				var tcp layers.TCP
				if tcp.DecodeFromBytes(ip.Payload, df) == nil {
					ip.TrafficClass = 0
					connInfo.IP = &ip
					connInfo.TCP = tcp
					ttl := uint8(64)
					if ip.TrafficClass > 4 {
						ttl = ip.TrafficClass >> 2
					}
					ModifyAndSendPacket(&connInfo, fakepayload, OPT_TTL|OPT_WMD5, ttl, 2)
					ModifyAndSendPacket(&connInfo, connInfo.TCP.Payload, OPT_TTL, 64, 1)
				}
			}
		} else {
			var icmp layers.ICMPv4
			icmp.DecodeFromBytes(data[:n], df)
			var ip layers.IPv4
			if ip.DecodeFromBytes(icmp.Payload, df) == nil && ip.Protocol == layers.IPProtocolTCP && ip.TOS > 0 {
				var tcp layers.TCP
				if tcp.DecodeFromBytes(ip.Payload, df) == nil {
					ip.TOS = 0
					connInfo.IP = &ip
					connInfo.TCP = tcp
					ttl := uint8(64)
					if ip.TOS > 4 {
						ttl = ip.TOS >> 2
					}
					ModifyAndSendPacket(&connInfo, fakepayload, OPT_TTL|OPT_WMD5, ttl, 2)
					ModifyAndSendPacket(&connInfo, connInfo.TCP.Payload, OPT_TTL, 64, 1)
				}
			}
		}
	}
}

func ConnectionMonitor(devices []string) bool {
	if devices == nil {
		DevicePrint()
		return false
	}

	if PassiveMode {
		for i := 0; i < len(devices); i++ {
			go ICMPMonitor(devices[i], false)
		}
	} else {
		for i := 0; i < 65536; i++ {
			ConnInfo4[i] = make(chan *ConnectionInfo)
			ConnInfo6[i] = make(chan *ConnectionInfo)
		}

		for i := 0; i < len(devices); i++ {
			go connectionMonitor(devices[i], false)
			go connectionMonitor(devices[i], true)
		}
	}

	return true
}

func ModifyAndSendPacket(connInfo *ConnectionInfo, payload []byte, hint uint32, ttl uint8, count int) error {
	ipLayer := connInfo.IP

	tcpLayer := &layers.TCP{
		SrcPort:    connInfo.TCP.SrcPort,
		DstPort:    connInfo.TCP.DstPort,
		Seq:        connInfo.TCP.Seq,
		Ack:        connInfo.TCP.Ack,
		DataOffset: 5,
		ACK:        true,
		PSH:        true,
		Window:     connInfo.TCP.Window,
	}

	if hint&OPT_WMD5 != 0 {
		tcpLayer.Options = []layers.TCPOption{
			layers.TCPOption{19, 16, []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		}
	} else if hint&OPT_WTIME != 0 {
		tcpLayer.Options = []layers.TCPOption{
			layers.TCPOption{8, 8, []byte{0, 0, 0, 0, 0, 0, 0, 0}},
		}
	}

	if hint&OPT_NACK != 0 {
		tcpLayer.ACK = false
		tcpLayer.Ack = 0
	} else if hint&OPT_WACK != 0 {
		tcpLayer.Ack += uint32(tcpLayer.Window)
	}

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	var options gopacket.SerializeOptions
	options.FixLengths = true

	if hint&OPT_WCSUM == 0 {
		options.ComputeChecksums = true
	}

	if hint&OPT_WSEQ != 0 {
		tcpLayer.Seq--
		fakepayload := make([]byte, len(payload)+1)
		fakepayload[0] = 0xFF
		copy(fakepayload[1:], payload)
		payload = fakepayload
	}

	var network string
	var laddr net.IPAddr
	var raddr net.IPAddr
	switch ip := ipLayer.(type) {
	case *layers.IPv4:
		laddr = net.IPAddr{ip.SrcIP, ""}
		raddr = net.IPAddr{ip.DstIP, ""}
		network = "ip4:tcp"
	case *layers.IPv6:
		laddr = net.IPAddr{ip.SrcIP, ""}
		raddr = net.IPAddr{ip.DstIP, ""}
		network = "ip6:tcp"
	}

	conn, err := net.DialIP(network, &laddr, &raddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	if hint&OPT_TTL != 0 {
		f, err := conn.File()
		if err != nil {
			return err
		}
		defer f.Close()
		fd := int(f.Fd())
		err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IP, syscall.IP_TTL, int(ttl))
		if err != nil {
			return err
		}
	}

	tcpLayer.SetNetworkLayerForChecksum(ipLayer)
	gopacket.SerializeLayers(buffer, options,
		tcpLayer, gopacket.Payload(payload),
	)
	outgoingPacket := buffer.Bytes()
	for i := 0; i < count; i++ {
		_, err = conn.Write(outgoingPacket)
		if err != nil {
			return err
		}
	}

	return nil
}
