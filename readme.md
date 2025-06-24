# 一个AnyTLS-go的分支

一个试图缓解 嵌套的TLS握手指纹(TLS in TLS) 问题的代理协议。`anytls-go` 是该协议的参考实现。

- 灵活的分包和填充策略
- 连接复用，降低代理延迟
- 简洁的配置
- 支持ACME、证书文件
- 支持Fallback
- 移除客户端，请使用Mihomo,Singbox等代替

[用户常见问题](./docs/faq.md)

[协议文档](./docs/protocol.md)

[URI 格式](./docs/uri_scheme.md)

## 快速部署指南

本指南将引导您在 Linux 服务器上完成 AnyTLS-Go 服务器的部署。

### 1. 准备工作

*   一台拥有公网 IP 地址的 Linux 服务器（推荐 Debian 或 Ubuntu）。
*   拥有服务器的 `root`权限。
*   **（用于 ACME 模式）** 一个域名，其 DNS `A/AAAA` 记录已指向您服务器的公网 IP。
*   **（用于 ACME 模式）** 服务器的 **80 端口** 未被其他程序占用，且防火墙已放行该端口的入站流量。

### 2. 安装

1.  **安装 Go 环境** (版本 >= 1.21):
    ```bash
    sudo apt update && sudo apt install -y golang
    ```

2.  **克隆并编译本项目**:
    ```bash
    git clone https://github.com/BadCat114514/anytls-go.git
    cd anytls-go/cmd/server
    go mod tidy
    go build
    ```
    编译成功后，您会在当前目录 (`cmd/server`) 下找到一个名为 `server` 的可执行文件。

3.  **创建安装目录**:
    ```bash
    # 创建目录
    sudo mkdir -p /usr/local/bin/anytls-server
    # 将编译好的二进制文件移动到安装目录
    sudo mv ./server /usr/local/bin/anytls-server/
    ```

### 3. 配置服务器

AnyTLS-Go 服务器由一个名为 `config.yaml` 的文件驱动。

1.  **生成默认配置文件**:
    进入安装目录，并首次运行程序。它会自动为您生成一个带详细注释的配置文件模板。
    ```bash
    cd /usr/local/bin/anytls-server
    sudo ./server
    ```
    运行后，程序会自动退出。请使用文本编辑器打开新生成的 `config.yaml` 文件。
    ```bash
    sudo nano config.yaml
    ```

2.  **编辑核心配置项**:

    *   `password`: **（必需）** 设置一个强壮的客户端连接密码。
    *   `tls`: 配置 TLS 证书模式。

    #### TLS 配置示例

    *   **模式 1：ACME (推荐)**
        ```yaml
        tls:
          mode: "acme"
          domain: "your.domain.com"      # 替换为您的域名
          email: "your-email@example.com" # 替换为您的邮箱
        ```

    *   **模式 2：文件**
        ```yaml
        tls:
          mode: "file"
          cert_file: "/path/to/your/fullchain.pem"
          key_file: "/path/to/your/privkey.pem"
        ```

    *   **模式 3：自签名 (用于测试)**
        ```yaml
        tls:
          mode: "self-signed"
        ```

    #### 回落配置示例

    将认证失败的流量转发到本地的 Nginx 服务。
    ```yaml
    fallback:
      address: "127.0.0.1:80"
      insecure_skip_verify: true
    ```

### 4. 作为 Systemd 服务运行 (生产环境推荐)

1.  **创建 Systemd 服务文件**:
    ```bash
    sudo nano /etc/systemd/system/anytls-server.service
    ```
    将以下内容粘贴进去，确保路径正确。

    ```ini
    [Unit]
    Description=AnyTLS-Go Server (BadCat's Fork)
    Documentation=https://github.com/BadCat114514/anytls-go
    After=network.target network-online.target
    Wants=network-online.target

    [Service]
    Type=simple
    # 如果使用 ACME 模式，程序需要绑定 80 端口。
    # 建议授予程序绑定低位端口的权限，而非以 root 身份运行：
    # sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/anytls-server/server
    # 然后可以取消下面两行的注释，以更安全的用户运行：
    # User=nobody
    # Group=nogroup
    ExecStart=/usr/local/bin/anytls-server/server
    WorkingDirectory=/usr/local/bin/anytls-server/
    Restart=on-failure
    RestartSec=5s
    LimitNOFILE=65535

    [Install]
    WantedBy=multi-user.target
    ```

2.  **管理服务**:
    ```bash
    # 重载 Systemd 配置
    sudo systemctl daemon-reload

    # 启动服务
    sudo systemctl start anytls-server

    # 设置开机自启
    sudo systemctl enable anytls-server

    # 查看服务状态
    sudo systemctl status anytls-server

    # 实时查看日志
    sudo journalctl -u anytls-server -f
    ```

### sing-box

https://github.com/SagerNet/sing-box

已合并至 dev-next 分支。它包含了 anytls 协议的服务器和客户端。

### mihomo

https://github.com/MetaCubeX/mihomo

已合并至 Alpha 分支。它包含了 anytls 协议的服务器和客户端。

### Shadowrocket

Shadowrocket 2.2.65+ 实现了 anytls 协议的客户端。
