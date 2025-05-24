# AnyTLS
A proxy protocol that attempts to alleviate the problem of nested TLS handshake fingerprints (TLS in TLS). anytls-go is the reference implementation of the protocol.

## Features
- Flexible packetization and padding strategies
- Connection reuse, reduce proxy latency
- Simple configuration
- User FAQ

## Protocol documentation

[User FAQ](./docs/faq.md)
[Protocol Documentation](./docs/protocol.md)
[URI Format](./docs/uri_scheme.md)

## Quick method
### Server
```sh
./anytls-server -l 0.0.0.0:8443 -p password
```
`0.0.0.0:8443` is the server listening address and port.

### Client
```sh
./anytls-client -l 127.0.0.1:1080 -s server ip:port -p password -sup socks5username,socks5password
```
`127.0.0.1:1080` is the local Socks5 proxy listening address, theoretically supporting TCP and UDP (transmitted via udp over tcp).

### sing-box
https://github.com/SagerNet/sing-box

Merged into dev-next branch. It contains the server and client of anytls protocol.

### mihomo
https://github.com/MetaCubeX/mihomo

Merged into Alpha branch. It contains the server and client of anytls protocol.

### Shadowrocket
Shadowrocket 2.2.65+ implements the client of anytls protocol.