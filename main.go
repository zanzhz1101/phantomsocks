package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/signal"
	"runtime"
	"strings"

	ptcp "github.com/macronut/phantomsocks/phantomtcp"
	proxy "github.com/macronut/phantomsocks/proxy"
)

var LogLevel int = 0
var MaxProcs int = 1
var PassiveMode bool = false
var allowlist map[string]bool = nil

func ListenAndServe(listenAddr string, serve func(net.Conn)) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panic(err)
	}

	if allowlist != nil {
		for {
			client, err := l.Accept()
			if err != nil {
				log.Panic(err)
			}
			err = proxy.SetKeepAlive(client)
			if err != nil {
				log.Panic(err)
			}

			remoteAddr := client.RemoteAddr()
			remoteTCPAddr, _ := net.ResolveTCPAddr(remoteAddr.Network(), remoteAddr.String())
			_, ok := allowlist[remoteTCPAddr.IP.String()]
			if ok {
				go serve(client)
			} else {
				client.Close()
			}
		}
	} else {
		for {
			client, err := l.Accept()
			if err != nil {
				log.Panic(err)
			}
			err = proxy.SetKeepAlive(client)
			if err != nil {
				log.Panic(err)
			}

			go serve(client)
		}
	}
}

func PACServer(listenAddr string, proxyAddr string) {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Panic(err)
	}
	pac := ptcp.GetPAC(proxyAddr)
	response := []byte(fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length:%d\r\n\r\n%s", len(pac), pac))
	fmt.Println("PACServer:", listenAddr)
	for {
		client, err := l.Accept()
		if err != nil {
			log.Panic(err)
		}

		go func() {
			defer client.Close()
			var b [1024]byte
			_, err := client.Read(b[:])
			if err != nil {
				return
			}
			_, err = client.Write(response)
			if err != nil {
				return
			}
		}()
	}
}

func DNSServer(listenAddr string) error {
	addr, err := net.ResolveUDPAddr("udp", listenAddr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()

	fmt.Println("DNS:", listenAddr)
	go ListenAndServe(listenAddr, ptcp.DNSTCPServer)

	data := make([]byte, 512)
	for {
		n, clientAddr, err := conn.ReadFromUDP(data)
		if err != nil {
			continue
		}

		request := make([]byte, n)
		copy(request, data[:n])
		go func(clientAddr *net.UDPAddr, request []byte) {
			_, response := ptcp.NSRequest(request, true)
			conn.WriteToUDP(response, clientAddr)
		}(clientAddr, request)
	}
}

func StartService() {
	conf, err := os.Open("config.json")
	if err != nil {
		fmt.Println(err)
		return
	}

	bytes, err := ioutil.ReadAll(conf)
	if err != nil {
		log.Panic(err)
	}
	conf.Close()

	var ServiceConfig struct {
		ConfigFiles       string `json:"config,omitempty"`
		HostsFile         string `json:"hosts,omitempty"`
		SystemProxy       string `json:"proxy,omitempty"`
		Clients           string `json:"clients,omitempty"`
		VirtualAddrPrefix int    `json:"vaddrprefix,omitempty"`

		Services   []ptcp.ServiceConfig   `json:"services,omitempty"`
		Interfaces []ptcp.InterfaceConfig `json:"interfaces,omitempty"`
	}

	err = json.Unmarshal(bytes, &ServiceConfig)
	if err != nil {
		log.Panic(err)
	}

	if MaxProcs > 0 {
		runtime.GOMAXPROCS(MaxProcs)
	}

	ptcp.LogLevel = LogLevel
	ptcp.PassiveMode = PassiveMode
	devices := ptcp.CreateInterfaces(ServiceConfig.Interfaces)

	for _, filename := range strings.Split(ServiceConfig.ConfigFiles, ",") {
		err := ptcp.LoadConfig(filename)
		if err != nil {
			if ptcp.LogLevel > 0 {
				log.Println(err)
			}
			return
		}
	}
	if ServiceConfig.HostsFile != "" {
		err := ptcp.LoadHosts(ServiceConfig.HostsFile)
		if err != nil {
			if ptcp.LogLevel > 0 {
				log.Println(err)
			}
			return
		}
	}

	if ServiceConfig.Clients != "" {
		allowlist = make(map[string]bool)
		list := strings.Split(ServiceConfig.Clients, ",")
		for _, c := range list {
			allowlist[c] = true
		}
	}

	default_socks := ""
	for _, service := range ServiceConfig.Services {
		switch service.Protocol {
		case "dns":
			go DNSServer(service.Address)
		case "socks":
			fmt.Println("Socks:", service.Address)
			go ListenAndServe(service.Address, ptcp.SocksProxy)
			go ptcp.SocksUDPProxy(service.Address)
			default_socks = service.Address
		case "redirect":
			fmt.Println("Redirect:", service.Address)
			go ListenAndServe(service.Address, ptcp.RedirectProxy)
		case "tproxy":
			fmt.Println("TProxy:", service.Address)
			go ptcp.TProxyUDP(service.Address)
		case "wireguard":
			fmt.Println("WireGuard:", service.Address)
			wgService := ptcp.WireGuardServiceConfig{service}
			go wgService.StartService()
		case "pac":
			if default_socks != "" {
				go PACServer(service.Address, default_socks)
			}
		case "sniproxy":
			fmt.Println("SNI:", service.Address)
			go ListenAndServe(service.Address, ptcp.SNIProxy)
			go ptcp.QUICProxy(service.Address)
		}
	}

	if ServiceConfig.SystemProxy != "" {
		for _, dev := range devices {
			err := proxy.SetProxy(dev, ServiceConfig.SystemProxy, true)
			if err != nil {
				fmt.Println(err)
			}
		}
	}

	if ServiceConfig.VirtualAddrPrefix != 0 {
		ptcp.VirtualAddrPrefix = byte(ServiceConfig.VirtualAddrPrefix)
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, os.Kill)
	s := <-c
	fmt.Println(s)

	if ServiceConfig.SystemProxy != "" {
		for _, dev := range devices {
			err := proxy.SetProxy(dev, ServiceConfig.SystemProxy, false)
			if err != nil {
				fmt.Println(err)
			}
		}
	}
}

func main() {
	//log.SetFlags(log.LstdFlags | log.Lshortfile)

	var flagServiceInstall bool
	var flagServiceRemove bool
	var flagServiceStart bool
	var flagServiceStop bool

	if len(os.Args) > 1 {
		flag.IntVar(&LogLevel, "log", 0, "LogLevel")
		flag.IntVar(&MaxProcs, "maxprocs", 0, "MaxProcesses")
		flag.BoolVar(&PassiveMode, "passive", false, "PassiveMode")
		flag.BoolVar(&flagServiceInstall, "install", false, "Install service")
		flag.BoolVar(&flagServiceRemove, "remove", false, "Remove service")
		flag.BoolVar(&flagServiceStart, "start", false, "Start service")
		flag.BoolVar(&flagServiceStop, "stop", false, "Stop service")
		flag.Parse()

		if flagServiceInstall {
			proxy.InstallService()
			return
		}

		if flagServiceRemove {
			proxy.RemoveService()
			return
		}

		if flagServiceStart {
			proxy.StartService()
			return
		}

		if flagServiceStop {
			proxy.StopService()
			return
		}
	} else {
		if proxy.RunAsService(StartService) {
			return
		}
	}

	StartService()
}
