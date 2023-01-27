package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"

	"codeberg.org/peterzam/socks5"
	"golang.org/x/net/proxy"
	"gopkg.in/ini.v1"

	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type DeviceSetting struct {
	IpcRequest    string
	Dns           []netip.Addr
	Mtu           int
	DeviceAddress *[]netip.Addr
}
type Tnet struct {
	*netstack.Net
}

func (tnet Tnet) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {
	addrs, err := tnet.LookupContextHost(ctx, name)

	if err != nil {
		return ctx, nil, err
	}

	size := len(addrs)
	if size == 0 {
		return ctx, nil, errors.New("no address found for: " + name)
	}

	rand.Shuffle(size, func(i, j int) {
		addrs[i], addrs[j] = addrs[j], addrs[i]
	})

	var addr netip.Addr
	for _, saddr := range addrs {
		addr, err = netip.ParseAddr(saddr)
		if err == nil {
			break
		}
	}

	if err != nil {
		return ctx, nil, err
	}
	return ctx, addr.AsSlice(), nil
}

func ParseBase64Key(key string) string {

	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		log.Println("--- Invalid base64 string ---")
		log.Fatal(err)
	}
	if len(decoded) != 32 {
		log.Println("--- Key should be 32 bytes ---")
		log.Fatal(err)
	}

	return hex.EncodeToString(decoded)
}

func ResolveIPAndPort(address string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		log.Println("--- Cannot split address and port ---")
		log.Fatal(err)
	}

	ip, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		log.Println("--- Cannot resolve address ---")
		log.Fatal(err)
	}
	return net.JoinHostPort(ip.String(), port)
}

func ParseIPs(s string) []netip.Addr {
	ips := []netip.Addr{}
	for _, str := range strings.Split(s, ",") {
		str = strings.TrimSpace(str)
		if strings.Contains(str, "/") {
			cidrAddr, _, err := net.ParseCIDR(str)
			if err != nil {
				log.Println("--- Cannot parse IP CIDR ---")
				log.Fatal(err)
			}
			ipAddr, err := netip.ParseAddr(cidrAddr.String())
			if err != nil {
				log.Println("--- Cannot parse CIDR address ---")
				log.Fatal(err)
			}
			ips = append(ips, ipAddr)
		} else {
			ipAddr, err := netip.ParseAddr(str)
			if err != nil {
				log.Println("--- Cannot parse IP address ---")
				log.Fatal(err)
			}
			ips = append(ips, ipAddr)
		}
	}
	return ips
}

func CreateIPCRequest(cfg *ini.File) *DeviceSetting {

	private_key := ParseBase64Key(cfg.Section("Interface").Key("PrivateKey").String())
	address := ParseIPs(cfg.Section("Interface").Key("Address").String())
	dns := ParseIPs(cfg.Section("Interface").Key("DNS").String())
	mtu := cfg.Section("Interface").Key("MTU").MustInt(1420)
	public_key := ParseBase64Key(cfg.Section("Peer").Key("PublicKey").String())
	endpoint := ResolveIPAndPort(cfg.Section("Peer").Key("Endpoint").String())
	keep_alive := cfg.Section("Peer").Key("PersistentKeepalive").MustInt64(0)

	pre_shared_key := cfg.Section("Peer").Key("PresharedKey").String()
	if pre_shared_key == "" {
		pre_shared_key = strings.Repeat("0", 64)
	} else {
		pre_shared_key = ParseBase64Key(pre_shared_key)
	}
	request := fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
persistent_keepalive_interval=%d
preshared_key=%s
allowed_ip=0.0.0.0/0
`, private_key, public_key, endpoint, keep_alive, pre_shared_key)
	setting := &DeviceSetting{IpcRequest: request, Dns: dns, Mtu: mtu, DeviceAddress: &address}
	return setting
}

func StartWireguardClient(setting *DeviceSetting) *netstack.Net {
	tun, tnet, err := netstack.CreateNetTUN(*(setting.DeviceAddress), setting.Dns, setting.Mtu)
	if err != nil {
		log.Println("--- Cannot create TUN network ---")
		log.Fatal(err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))
	err = dev.IpcSet(setting.IpcRequest)
	if err != nil {
		log.Println("--- Cannot set IPC ---")
		log.Fatal(err)
	}

	if err = dev.Up(); err != nil {
		log.Println("--- Cannot start/up wg device ---")
		log.Fatal(err)
	}
	return tnet
}

func StartSocksServer(server_address string, tnet Tnet) {
	var auth []socks5.Authenticator

	if *user != "" {
		auth = []socks5.Authenticator{socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{
				*user: *pass,
			},
		}}
	}

	server, err := socks5.New(&socks5.Config{
		AuthMethods: auth,
	})
	if err != nil {
		log.Fatal(err)
	}
	if tnet.Net != nil {
		server, _ = socks5.New(&socks5.Config{
			Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return tnet.DialContext(ctx, network, addr)
			},
			AuthMethods: auth,
			Resolver:    tnet,
		})
	}

	if err := server.ListenAndServe("tcp", server_address); err != nil {
		log.Printf("--- SOCKS5 server cannot be started at : %s ---", server_address)
		log.Fatal(err)
	}
}

func StartWireProxyServer(bridge_address string) {

	cfg, err := ini.Load(*wg_conf_path)
	if err != nil {
		log.Println("--- Cannot load wireguard config file ---")
		log.Fatal(err)
	}

	setting := CreateIPCRequest(cfg)
	var tnet Tnet
	tnet.Net = StartWireguardClient(setting)
	StartSocksServer(bridge_address, tnet)
}

func StartFanSocksServer(path string) {

	var t []proxy.Dialer
	f, err := os.ReadFile(path)
	if err != nil {
		log.Println("--- Cannot load proxy socks csv file ---")
		log.Fatal(err)
	}
	sockstrings := bytes.Split(f, []byte("\n"))

	var b proxy.Dialer
	if *no_wire {
		b = nil
	} else {
		b, _ = proxy.SOCKS5("tcp", *bridge, &proxy.Auth{*user, *pass}, proxy.Direct)
		if err != nil {
			log.Println("--- Cannot connect to bridge ---")
			log.Fatal(err)
		}
	}

	for _, i := range sockstrings {
		j, err := proxy.SOCKS5("tcp", string(i), &proxy.Auth{}, b)
		if err != nil {
			log.Println("--- Cannot connect to proxy ---")
			log.Println(err)
		}
		t = append(t, j)
	}

	var auth []socks5.Authenticator

	if *user != "" {
		auth = []socks5.Authenticator{socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{
				*user: *pass,
			},
		}}
	}

	var i int
	server, _ := socks5.New(&socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if ctx.Done() == nil {
				i = rand.Intn(len(t))
			}
			return t[i].Dial(network, addr)
		},
		AuthMethods: auth,
	})
	err = server.ListenAndServe("tcp", *bind)
	if err != nil {
		log.Printf("--- SOCKS5 server cannot be started at : %s ---", *bind)
		log.Fatal(err)
	}
}

func StartWirefanServer() {

}

var (
	no_wire        = flag.Bool("no-wire", false, "No Wire")
	no_fan         = flag.Bool("no-fan", false, "No fan")
	bridge         = flag.String("bg", "0.0.0.0:8080", "Bridge address between wire and fan")
	bind           = flag.String("bind", "0.0.0.0:1080", "Bind address/Server listen address")
	wg_conf_path   = flag.String("wg-conf", "", "Wireguard config file path")
	proxy_csv_path = flag.String("csv", "socks.csv", "SOCKS5 server list csv file")
	user           = flag.String("user", "", "SOCKS5 Username")
	pass           = flag.String("pass", "", "SOCKS5 Password")
)

func main() {
	flag.Parse()

	if *no_fan && *no_wire {
		log.Printf("--- Server is starting at %s---\n", *bind)
		StartSocksServer(*bind, Tnet{})
		return

	} else if *no_fan {
		log.Printf("--- Server is starting at %s---\n", *bind)
		StartWireProxyServer(*bind)
		return

	} else if *no_wire {
		log.Printf("--- Server is starting at %s---\n", *bind)
		StartFanSocksServer(*proxy_csv_path)
		return
	} else {

		log.Printf("--- Bridge is starting at %s---\n", *bridge)
		go func() { StartWireProxyServer(*bridge) }()

		log.Printf("--- Server is starting at %s---\n", *bind)
		StartFanSocksServer(*proxy_csv_path)
		return
	}
}
