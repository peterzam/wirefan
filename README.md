# wirefan
Combination of [wireproxy](https://codeberg.org/peterzam/wireproxy) and [fansocks](https://codeberg.org/peterzam/fansocks) forked/branched from wireproxy

This software only support SOCKS5 proxy. If you want to use HTTP proxy, convert SOCKS5 to HTTP with [socks2http](https://codeberg.org/peterzam/socks2http) 



# Why you might want this
- You simply want wireguard as a way to proxy some traffic
- You don't want root permission just to change wireguard settings
- Rotate socks5 proxies within wireguard network (Mullvad, protonvpn and others support this type of proxy)

# Usage

## CLI
```
./wirefan --wg-conf=<wireguard_config_file_path> --csv=<socks address list>  --bind=<bind_address> --user=<username> --pass=<password>
```

## Docker 
```bash
# Clone wireproxy repo and cd into repo
git clone https://codeberg.org/peterzam/wirefan.git

cd wirefan

# Build Docker Image
docker build -t peterzam/wirefan .

# Run Docker Container
docker run -d -v <wireguard_config_file_path>:/wg.conf -v <socks address list>:/socks.csv -p 1080:1080 peterzam/wirefan --user=<username> --pass=<password>
```
# Note
Port forwarding function is dropped. If you want to use, check the origin repo at github.com/octeep/wireproxy.git
