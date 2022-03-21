# wireproxy
Wireguard client that exposes itself as a socks5 proxy or tunnels. This is a fork of github.com/octeep/wireproxy.git

# What is this
wireproxy is a completely userspace application that connects to a wireguard peer,
and exposes a socks5 proxy or tunnels on the machine. This can be useful if you need
to connect to certain sites via a wireguard peer, but do not want to setup a new network
interface for whatever reasons.

# Why you might want this
- You simply want wireguard as a way to proxy some traffic
- You don't want root permission just to change wireguard settings

Currently I am running wireproxy connected to a wireguard server in another country,
and configured my browser to use wireproxy for certain sites. It is pretty useful since
wireproxy is completely isolated from my network interfaces, also I don't need root to configure
anything.

# Usage
`./wireproxy --wg-conf=<wireguard_config_file_path> --bind=<bind_address>`

# Note
Port forwarding function is dropped. If you want to use, check the origin repo at github.com/octeep/wireproxy.git