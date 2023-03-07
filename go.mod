module github.com/macronut/phantomsocks

go 1.18

require (
	github.com/chai2010/winsvc v0.0.0-20200705094454-db7ec320025c
	github.com/google/gopacket v1.1.19
	github.com/macronut/go-tproxy v0.0.0-20190726054950-ef7efd7f24ed
	github.com/macronut/godivert v0.0.0-20220121081532-78e5dd672daf
	golang.org/x/sys v0.5.0
)

require (
	github.com/williamfhe/godivert v0.0.0-20181229124620-a48c5b872c73 // indirect
	golang.org/x/net v0.7.0 // indirect
)

replace (
	golang.zx2c4.com/wireguard => github.com/macronut/wireguard-go v0.0.0-20220521185917-e58dbe0aec0c
	golang.zx2c4.com/wireguard/tun => github.com/macronut/wireguard-go/tun v0.0.0-20220521185917-e58dbe0aec0c
	golang.zx2c4.com/wireguard/tun/netstack => github.com/macronut/wireguard-go/tun/netstack v0.0.0-20220521185917-e58dbe0aec0c
)
