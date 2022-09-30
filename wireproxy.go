package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	// "codeberg.org/peterzam/wireproxy/socks5"
	"codeberg.org/peterzam/socks5"
	"gopkg.in/ini.v1"

	"net/netip"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type DeviceSetting struct {
	ipcRequest string
	dns        []netip.Addr
	mtu        int
	deviceAddr *[]netip.Addr
}

func parseBase64Key(key string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		return "", errors.New("invalid base64 string")
	}
	if len(decoded) != 32 {
		return "", errors.New("key should be 32 bytes")
	}
	return hex.EncodeToString(decoded), nil
}

func resolveIP(ip string) (*net.IPAddr, error) {
	return net.ResolveIPAddr("ip", ip)
}

func resolveIPPAndPort(addr string) (string, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", err
	}

	ip, err := resolveIP(host)
	if err != nil {
		return "", err
	}
	return net.JoinHostPort(ip.String(), port), nil
}

func parseIPs(s string) ([]netip.Addr, error) {
	ips := []netip.Addr{}
	for _, str := range strings.Split(s, ",") {
		str = strings.TrimSpace(str)
		if strings.Contains(str, "/") {
			cidrAddr, _, err := net.ParseCIDR(str)
			if err != nil {
				return nil, err
			}
			ipAddr, err := netip.ParseAddr(cidrAddr.String())
			if err != nil {
				return nil, err
			}
			ips = append(ips, ipAddr)
		} else {
			ipAddr, err := netip.ParseAddr(str)
			if err != nil {
				return nil, err
			}
			ips = append(ips, ipAddr)
		}
	}
	return ips, nil
}

func createIPCRequest(cfg *ini.File) (*DeviceSetting, error) {
	prvKey, err := parseBase64Key(cfg.Section("Interface").Key("PrivateKey").String())
	if err != nil {
		return nil, err
	}

	address, err := parseIPs(cfg.Section("Interface").Key("Address").String())
	if err != nil {
		return nil, err
	}

	dns, err := parseIPs(cfg.Section("Interface").Key("DNS").String())
	if err != nil {
		return nil, err
	}
	mtu := cfg.Section("Interface").Key("MTU").MustInt(1420)

	pubKey, err := parseBase64Key(cfg.Section("Peer").Key("PublicKey").String())
	if err != nil {
		return nil, err
	}

	endpoint, err := resolveIPPAndPort(cfg.Section("Peer").Key("Endpoint").String())
	if err != nil {
		return nil, err
	}

	keepAlive := cfg.Section("Peer").Key("PersistentKeepalive").MustInt64(0)

	preSharedKey, err := parseBase64Key(cfg.Section("Peer").Key("PresharedKey").MustString(strings.Repeat("0", 64)))
	if err != nil {
		return nil, err
	}

	request := fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
persistent_keepalive_interval=%d
preshared_key=%s
allowed_ip=0.0.0.0/0
`, prvKey, pubKey, endpoint, keepAlive, preSharedKey)

	setting := &DeviceSetting{ipcRequest: request, dns: dns, mtu: mtu, deviceAddr: &address}
	return setting, nil
}

func startSocks5Server(bindAddr string, tnet *netstack.Net) error {

	var auth []socks5.Authenticator = nil

	if *user != "" {
		auth = []socks5.Authenticator{socks5.UserPassAuthenticator{
			Credentials: socks5.StaticCredentials{
				*user: *pass,
			},
		}}
	}

	server, _ := socks5.New(&socks5.Config{
		Dial: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return tnet.DialContext(ctx, network, addr)
		},
		AuthMethods: auth,
	})

	if err := server.ListenAndServe("tcp", bindAddr); err != nil {
		panic(err)
	}

	return nil
}

func startWireguardClient(setting *DeviceSetting) (*netstack.Net, error) {
	tun, tnet, err := netstack.CreateNetTUN(*(setting.deviceAddr), setting.dns, setting.mtu)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
	err = dev.IpcSet(setting.ipcRequest)
	if err != nil {
		return nil, err
	}

	if err = dev.Up(); err != nil {
		return nil, err
	}

	return tnet, nil
}

var (
	bindAddr     = flag.String("bind", "0.0.0.0:1080", "Bind Address for SOCKS5")
	wg_conf_path = flag.String("wg-conf", "", "Wireguard config file path")
	user         = flag.String("user", "", "SOCKS5 Username")
	pass         = flag.String("pass", "", "SOCKS5 Password")
)

func main() {
	flag.Parse()
	if len(*wg_conf_path) == 0 {
		flag.Usage()
		return
	}

	cfg, err := ini.Load(*wg_conf_path)
	if err != nil {
		log.Panic(err)
	}

	setting, err := createIPCRequest(cfg)
	if err != nil {
		log.Panic(err)
	}

	tnet, err := startWireguardClient(setting)
	if err != nil {
		log.Panic(err)
	}

	err = startSocks5Server(*bindAddr, tnet)
	if err != nil {
		log.Panic(err)
	}
}
