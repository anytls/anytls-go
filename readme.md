# AnyTLS

一个试图缓解 嵌套的TLS握手指纹(TLS in TLS) 问题的代理协议。`anytls-go` 是该协议的参考实现。

- 灵活的分包和填充策略
- 连接复用，降低代理延迟
- 简洁的配置

[用户常见问题](./docs/faq.md)

[协议文档](./docs/protocol.md)

[URI 格式](./docs/uri_scheme.md)

## 不怎么快速的快速食用方法

### 服务器

```
./server \
  -l 0.0.0.0:5543 \
  -p "你的强壮密码" \
  -cert "/etc/letsencrypt/live/你的域名/fullchain.pem" \
  -key "/etc/letsencrypt/live/你的域名/privkey.pem" \
  -fallback 回落地址
```

支持证书和回落。

### 客户端

```
./anytls-client -l 127.0.0.1:1080 -s 服务器ip:端口 -p 密码
```

`127.0.0.1:1080` 为本机 Socks5 代理监听地址，理论上支持 TCP 和 UDP(通过 udp over tcp 传输)。

### sing-box

https://github.com/SagerNet/sing-box

已合并至 dev-next 分支。它包含了 anytls 协议的服务器和客户端。

### mihomo

https://github.com/MetaCubeX/mihomo

已合并至 Alpha 分支。它包含了 anytls 协议的服务器和客户端。

### Shadowrocket

Shadowrocket 2.2.65+ 实现了 anytls 协议的客户端。
