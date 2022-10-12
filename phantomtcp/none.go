//go:build !pcap && !rawsocket && !windivert
// +build !pcap,!rawsocket,!windivert

package phantomtcp

var HintMap = map[string]uint32{
	"none": OPT_NONE,
	"mss":  OPT_MSS,

	"udp":    OPT_UDP,
	"no-tcp": OPT_NOTCP,
	"delay":  OPT_DELAY,

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

func ConnectionMonitor(devices []string) bool {
	return false
}

func ModifyAndSendPacket(connInfo *ConnectionInfo, payload []byte, hint uint32, ttl uint8, count int) error {
	return nil
}

func Redirect(dst string, to_port int, forward bool) {
}

func RedirectDNS() {
}
