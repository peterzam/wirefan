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
	DeviceAddress []netip.Addr
}

type Tnet struct {
	*netstack.Net
}

// DNS resolver using netstack.Net
func (tnet Tnet) Resolve(ctx context.Context, name string) (context.Context, net.IP, error) {

	addrs, err := tnet.LookupContextHost(ctx, name)
	if err != nil {
		return ctx, nil, err
	}

	size := len(addrs)
	if size == 0 {
		return ctx, nil, errors.New("--- Error: No address found for " + name + "---")
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

// Parse wireguard key
func ParseBase64Key(key string) string {

	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		log.Println("--- Error: Invalid base64 string ---")
		log.Fatal(err)
	}
	if len(decoded) != 32 {
		log.Println("--- Error: Key should be 32 bytes ---")
		log.Fatal(err)
	}

	return hex.EncodeToString(decoded)
}

// Resolve Endpoint address to IP and port
func ResolveIPAndPort(address string) string {

	host, port, err := net.SplitHostPort(address)
	if err != nil {
		log.Println("--- Error: Cannot split address and port ---")
		log.Fatal(err)
	}

	ip, err := net.ResolveIPAddr("ip", host)
	if err != nil {
		log.Println("--- Error: Cannot resolve address ---")
		log.Fatal(err)
	}

	return net.JoinHostPort(ip.String(), port)
}

// Parse String to IPs
func ParseIPs(s string) []netip.Addr {

	ips := []netip.Addr{}
	for _, str := range strings.Split(s, ",") {
		str = strings.TrimSpace(str)
		if strings.Contains(str, "/") {
			cidrAddr, _, err := net.ParseCIDR(str)
			if err != nil {
				log.Println("--- Error: Cannot parse IP CIDR ---")
				log.Fatal(err)
			}
			ipAddr, err := netip.ParseAddr(cidrAddr.String())
			if err != nil {
				log.Println("--- Error: Cannot parse CIDR address ---")
				log.Fatal(err)
			}
			ips = append(ips, ipAddr)
		} else {
			ipAddr, err := netip.ParseAddr(str)
			if err != nil {
				log.Println("--- Error: Cannot parse IP address ---")
				log.Fatal(err)
			}
			ips = append(ips, ipAddr)
		}
	}

	return ips
}

// Start wireguard client with wgconf_path and return netstack.Net
func StartWireguardClient(wgconf_path string) (Tnet, error) {

	cfg, err := ini.Load(wgconf_path)
	if err != nil {
		return Tnet{}, fmt.Errorf("--- Error: Cannot load wireguard config file ---\n%v", err)
	}

	request := fmt.Sprintf("private_key=%s\npublic_key=%s\nendpoint=%s\npersistent_keepalive_interval=%d\npreshared_key=%s\nallowed_ip=0.0.0.0/0\n",
		ParseBase64Key(cfg.Section("Interface").Key("PrivateKey").String()),
		ParseBase64Key(cfg.Section("Peer").Key("PublicKey").String()),
		ResolveIPAndPort(cfg.Section("Peer").Key("Endpoint").String()),
		cfg.Section("Peer").Key("PersistentKeepalive").MustInt64(0),
		ParseBase64Key(cfg.Section("Peer").Key("PresharedKey").MustString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")),
	)

	setting := &DeviceSetting{
		IpcRequest:    request,
		Dns:           ParseIPs(cfg.Section("Interface").Key("DNS").String()),
		Mtu:           cfg.Section("Interface").Key("MTU").MustInt(1420),
		DeviceAddress: ParseIPs(cfg.Section("Interface").Key("Address").String()),
	}

	tun, tnet, err := netstack.CreateNetTUN((setting.DeviceAddress), setting.Dns, setting.Mtu)
	if err != nil {
		return Tnet{}, fmt.Errorf("--- Error: Cannot create TUN network ---\n%v", err)
	}

	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelError, ""))

	if err = dev.IpcSet(setting.IpcRequest); err != nil {
		return Tnet{}, fmt.Errorf("--- Error: Cannot set IPC ---\n%v", err)
	}

	if err = dev.Up(); err != nil {
		return Tnet{}, fmt.Errorf("--- Error: Cannot start/up wg device ---\n%v", err)
	}

	return Tnet{tnet}, nil
}

// Create/Start socks5 server at bind_address with tnet forward proxy. tnet value can be nil for direct proxy
func StartSocksServer(cred proxy.Auth, bind_address string, tnet Tnet) error {

	var auth []socks5.Authenticator
	if cred.User != "" {
		auth = []socks5.Authenticator{socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{
				cred.User: cred.Password,
			},
		}}
	}

	var config = &socks5.Config{
		AuthMethods: auth,
	}

	if tnet.Net != nil {
		config.Dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tnet.DialContext(ctx, network, addr)
		}
		config.Resolver = tnet
	}

	server, err := socks5.New(config)
	if err != nil {
		return fmt.Errorf("--- Error: Cannot create socks5 server with config ---\n%v", err)
	}

	protocol := "unix"
	if strings.ContainsAny(bind_address, ":") {
		protocol = "tcp"
	}

	if err := server.ListenAndServe(protocol, bind_address); err != nil {
		return fmt.Errorf("--- Error: Cannot listen socks5 server at %s ---\n%v", bind_address, err)
	}

	return nil
}

// Wireguard client to socks5 proxy. Socks5 server listen at bind_address
func StartWireProxyServer(cred proxy.Auth, bind_address string, wgconf_path string) error {

	net, err := StartWireguardClient(wgconf_path)
	if err != nil {
		return fmt.Errorf("--- Error: Cannot start wireguard client ---\n%v", err)
	}

	err = StartSocksServer(cred, bind_address, net)
	if err != nil {
		return fmt.Errorf("--- Error: Cannot start socks5 server ---\n%v", err)
	}

	return nil
}

// Rotate/fanning the socks5 clients. Socks5 server listen at bind_address with tnet forward proxy. tnet value can be nil for direct proxy
func StartFanProxyServer(cred proxy.Auth, bind_address, proxyconf_path string, tnet Tnet) error {

	f, err := os.ReadFile(proxyconf_path)
	if err != nil {
		return fmt.Errorf("--- Error: Cannot load fanproxy socks config file ---\n%v", err)
	}

	var t proxy.Dialer
	if tnet.Net != nil {
		t = tnet
	}

	var ts []proxy.Dialer
	for _, i := range bytes.Split(f, []byte("\n")) {
		j, err := proxy.SOCKS5("tcp", string(i), &proxy.Auth{}, t)
		if err != nil {
			return fmt.Errorf("--- Error: Cannot connect to proxy %s ---\n%v", string(i), err)
		}
		ts = append(ts, j)
	}

	var auth []socks5.Authenticator
	if cred.User != "" {
		auth = []socks5.Authenticator{socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{
				cred.User: cred.Password,
			},
		}}
	}

	var i = rand.Intn(len(ts))
	var config = &socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if ctx.Done() == nil {
				i = rand.Intn(len(ts))
			}
			return ts[i].Dial(network, addr)
		},
		AuthMethods: auth,
	}

	if tnet.Net != nil {
		config.Resolver = tnet
	}

	server, err := socks5.New(config)
	if err != nil {
		return fmt.Errorf("--- Error: Cannot create fanproxy server with config---\n%v", err)
	}

	protocol := "unix"
	if strings.ContainsAny(bind_address, ":") {
		protocol = "tcp"
	}

	if err := server.ListenAndServe(protocol, bind_address); err != nil {
		return fmt.Errorf("--- Error: Cannot listen fanproxy server at %s ---\n%v", bind_address, err)
	}

	return nil
}

var (
	bind_address   = flag.String("bind", "0.0.0.0:1080", "Bind address/Server listen address (also supports unix socket)")
	wgconf_path    = flag.String("wg-conf", "wg.conf", "Wireguard config file path")
	proxyconf_path = flag.String("socks-conf", "socks.conf", "SOCKS5 servers list file")
	user           = flag.String("user", "", "SOCKS5 Username")
	pass           = flag.String("pass", "", "SOCKS5 Password")
	mode           = flag.String("mode", "wirefan", "Modes - wire(wire only), fan(fan only), socks(socks only), wirefan")
)

func main() {

	flag.Parse()

	switch *mode {
	case "wire":
		log.Println("--- Running wire only mode ---")
		log.Println("--- This is the same function as wireproxy ---")
		log.Println("--- Wireproxy connects wireguard client and expose as a socks5 server ---")
		log.Printf("--- SOCKS5 server is listening at %s ---", *bind_address)
		err := StartWireProxyServer(proxy.Auth{User: *user, Password: *pass}, *bind_address, *wgconf_path)
		if err != nil {
			log.Fatal(err)
		}

	case "fan":
		log.Println("--- Running fan only mode ---")
		log.Println("--- This is the same function as fanproxy ---")
		log.Println("--- Fanproxy connects multiple socks proxy clients, fans/rotates proxies, expose as a socks5 server ---")
		log.Printf("--- SOCKS5 server is listening at %s ---", *bind_address)
		err := StartFanProxyServer(proxy.Auth{User: *user, Password: *pass}, *bind_address, *proxyconf_path, Tnet{})
		if err != nil {
			log.Fatal(err)
		}

	case "socks":
		log.Println("--- Running socks only mode ---")
		log.Println("--- This is the same function as a plain socks server ---")
		log.Printf("--- SOCKS5 server is listening at %s ---", *bind_address)
		err := StartSocksServer(proxy.Auth{User: *user, Password: *pass}, *bind_address, Tnet{})
		if err != nil {
			log.Fatal(err)
		}

	case "wirefan":
		log.Println("--- Running wirefan ---")
		log.Println("--- This is combination of wireproxy and fanproxy ---")
		log.Println("--- Wirefan connects wireguard client, connects multiple socks proxy clients within the wireguard network, fans/rotates proxies, expose as a socks5 server ---")
		log.Printf("--- SOCKS5 server is listening at %s ---", *bind_address)
		tnet, err := StartWireguardClient(*wgconf_path)
		if err != nil {
			log.Fatal(err)
		}
		err = StartFanProxyServer(proxy.Auth{User: *user, Password: *pass}, *bind_address, *proxyconf_path, tnet)
		if err != nil {
			log.Fatal(err)
		}

	default:
		flag.Usage()
	}
}
