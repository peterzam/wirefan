package main

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/armon/go-socks5"
	"gopkg.in/ini.v1"

	"golang.zx2c4.com/go118/netip"
	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun/netstack"
)

type DeviceSetting struct {
	ipcRequest string
	dns        []netip.Addr
	deviceAddr *netip.Addr
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
		ip, err := netip.ParseAddr(str)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}
	return ips, nil
}

func createIPCRequest(config_path string) (*DeviceSetting, error) {
	cfg, err := ini.Load(config_path)
	if err != nil {
		return nil, err
	}

	prvKey, err := parseBase64Key(cfg.Section("Interface").Key("PrivateKey").String())
	if err != nil {
		return nil, err
	}

	address, err := netip.ParseAddr(strings.Split(cfg.Section("Interface").Key("Address").String(), "/")[0])
	if err != nil {
		return nil, err
	}

	dns, err := parseIPs(cfg.Section("Interface").Key("DNS").String())
	if err != nil {
		return nil, err
	}

	pubKey, err := parseBase64Key(cfg.Section("Peer").Key("PublicKey").String())
	if err != nil {
		return nil, err
	}

	endpoint, err := resolveIPPAndPort(cfg.Section("Peer").Key("Endpoint").String())
	if err != nil {
		return nil, err
	}

	keepAlive := cfg.Section("Peer").Key("PersistentKeepalive").MustInt64()

	var preSharedKey string
	preSharedKeyOpt := cfg.Section("Peer").Key("PresharedKey").String()
	if preSharedKeyOpt == "" {
		preSharedKey = "0000000000000000000000000000000000000000000000000000000000000000"
	} else {
		preSharedKey, err = parseBase64Key(preSharedKeyOpt)
		if err != nil {
			return nil, err
		}
	}

	allowed_ip := cfg.Section("Peer").Key("AllowedIPs").String()
	if allowed_ip == "" {
		allowed_ip = "0.0.0.0/0"
	}

	request := fmt.Sprintf(`private_key=%s
public_key=%s
endpoint=%s
persistent_keepalive_interval=%d
preshared_key=%s
allowed_ip=%s`, prvKey, pubKey, endpoint, keepAlive, preSharedKey, allowed_ip)

	setting := &DeviceSetting{ipcRequest: request, dns: dns, deviceAddr: &address}
	return setting, nil
}

func socks5Routine(bindAddr string) (func(*netstack.Net), error) {
	routine := func(tnet *netstack.Net) {
		conf := &socks5.Config{Dial: tnet.DialContext}
		server, err := socks5.New(conf)
		if err != nil {
			log.Panic(err)
		}

		if err := server.ListenAndServe("tcp", bindAddr); err != nil {
			log.Panic(err)
		}
	}
	return routine, nil
}

func startWireguard(setting *DeviceSetting) (*netstack.Net, error) {
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{*(setting.deviceAddr)}, setting.dns, 1420)
	if err != nil {
		return nil, err
	}
	dev := device.NewDevice(tun, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))
	dev.IpcSet(setting.ipcRequest)
	err = dev.Up()
	if err != nil {
		return nil, err
	}

	return tnet, nil
}

var (
	bindAddr     = flag.String("bind", "127.0.0.1:1080", "Bind Address for SOCKS5")
	wg_conf_path = flag.String("wg-conf", "", "Wireguard config file path")
)

func main() {
	flag.Parse()
	if len(*wg_conf_path) == 0 {
		flag.Usage()
		return
	}

	setting, err := createIPCRequest(*wg_conf_path)
	if err != nil {
		log.Panic(err)
	}

	var stack func(*netstack.Net)

	stack, err = socks5Routine(*bindAddr)

	tnet, err := startWireguard(setting)
	if err != nil {
		log.Panic(err)
	}
	stack(tnet)
}
