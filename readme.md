# AnyTLS

一个试图专注于缓解 "TLS in TLS" 问题的 TLS 代理协议。`anytls-go` 是该协议的参考实现。

- 灵活的分包和填充策略
- 连接复用，降低代理延迟
- 简洁的配置

[用户常见问题](./docs/faq.md)

[协议文档](./docs/protocol.md)

## 快速食用方法

### 服务器

```
./anytls-server -l 0.0.0.0:8443 -p 密码
```

`0.0.0.0:8443` 为服务器监听的地址和端口。

### 客户端

```
./anytls-client -l 127.0.0.1:1080 -s 服务器ip:端口 -p 密码
```

`127.0.0.1:1080` 为本机 Socks5 代理监听地址，理论上支持 TCP 和 UDP(通过 udp over tcp 传输)。

### sing-box

如果你喜欢使用 sing-box，可以尝试这个 fork。它包含了 anytls 协议的服务器和客户端。

https://github.com/anytls/sing-box

### mihomo

如果你喜欢使用 mihomo，可以尝试这个 fork。它包含了 anytls 协议的客户端。

https://github.com/anytls/mihomo
