# OpenFIR 加密 UDP 代理

应用连接本机 SOCKS5 端口，OpenFIR 的代理模式启动 Hysteria 2，通过 QUIC/UDP 连接远端服务器。远端再用目标应用需要的 TCP 或 UDP 协议连接目标。支持 SOCKS5 CONNECT、UDP ASSOCIATE 和固定端口转发。

## 用 Docker 部署两端（Linux）

服务端和客户端使用同一份镜像 `openfir-proxy:test`，里面包含 OpenFIR 和 Hysteria 2。两台机器都需要 Docker。下面的 Compose 命令在 `compose.yaml` 所在目录执行。

**准备镜像。** 在仓库根目录运行 `docker build -t openfir-proxy:test .`。也可以在与目标机架构相同的机器构建一次，用 `docker save openfir-proxy:test | gzip > openfir-proxy.tar.gz` 导出，将压缩包复制到另一台机器，再运行 `docker load -i openfir-proxy.tar.gz`。通过归档部署时，同时复制仓库里的 `compose.yaml`。Dockerfile 支持 Linux amd64 和 arm64，单架构归档应与目标机器匹配。

**生成配置。** 在可信机器上运行一次。把示例域名替换为服务器公网地址，确保服务端安全组和防火墙允许对应 UDP 端口入站。生成的配置包含密码和私钥。

```sh
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$PWD:/work" openfir-proxy:test \
  -mode proxy-init -server relay.example.org:443 -proxy-dir /work/profiles
```

**服务端。** 通过可信通道将 `profiles/server/` 放到服务端的 `compose.yaml` 旁边，保留目录结构。在每台机器上，以拥有对应配置文件的用户运行下面的命令。要让配置在不同终端中持续生效，可将 `OPENFIR_UID`、`OPENFIR_GID` 和自定义端口的值写入 Compose 的 `.env`。

```sh
export OPENFIR_UID="$(id -u)" OPENFIR_GID="$(id -g)"
docker compose --profile server up -d
docker compose logs server
```

若生成配置时使用了其他端口，在启动服务端前设置相同的 `OPENFIR_UDP_PORT`，例如 `export OPENFIR_UDP_PORT=8443`。

**客户端。** 将 `profiles/client/` 放到客户端的 `compose.yaml` 旁边，然后运行：

```sh
export OPENFIR_UID="$(id -u)" OPENFIR_GID="$(id -g)"
docker compose --profile client up -d
docker compose logs client
curl --noproxy '' --proxy socks5h://127.0.0.1:1080 https://example.org/
```

客户端使用 Linux 主机网络，在宿主机回环地址上提供 SOCKS5。这样宿主机应用也能访问 UDP ASSOCIATE 协商出的动态端口。固定 TCP/UDP 转发也直接监听配置中的宿主机地址。停止对应角色可运行 `docker compose --profile server down` 或 `docker compose --profile client down`。

## 直接运行可执行文件

1. 两端各准备一份 OpenFIR 和 Hysteria 2。OpenFIR 可在仓库根目录用 `go build -o openfir .` 编译。下载对应平台的 Hysteria 2，将可执行文件命名为 `hysteria`（Windows 用 `hysteria.exe`），放到 PATH 中。本仓库用 Hysteria 2.14.0 做了本地互通测试。[Hysteria 2 官方安装说明](https://v2.hysteria.network/zh/docs/getting-started/Installation/)
2. 在一台可信设备上运行下面的命令一次。将 `relay.example.org` 换成客户端实际访问的服务器域名或 IP，将 `443` 换成服务器能监听且网络允许入站的 **UDP** 端口。IPv6 地址用方括号包围。使用 443 等低端口时，服务端进程需要对应的绑定权限。

   ```sh
   ./openfir -mode proxy-init -server relay.example.org:443 -proxy-dir profiles
   ```

3. 用可信通道将整个 `profiles/server/` 目录复制到服务器，将整个 `profiles/client/` 目录复制到客户端。两个目录都含有访问密码。服务端私钥只在服务端目录里。两个启动命令里的路径对应各自设备上的文件位置。

   服务端运行

   ```sh
   ./openfir -mode proxy-server -proxy-config profiles/server/config.json
   ```

   客户端运行

   ```sh
   ./openfir -mode proxy-client -proxy-config profiles/client/config.json
   ```

生成的客户端配置使用配对的证书校验服务端身份，证书有效期为两年。更换主机名、凭据或到期证书时，可在新目录生成并部署一对新配置。配置默认启用 Salamander 混淆。实际连通性取决于客户端到服务器的 UDP 路径、端口和网络策略，需在实际使用的网络验证。

## 使用和验证

应用的 SOCKS5 地址填 `127.0.0.1:1080`。生成配置时可用 `-socks 127.0.0.1:1081` 换一个本地端口。下面的命令让远端解析目标域名，可以在客户端网络验证 TCP 转发。

```sh
curl --proxy socks5h://127.0.0.1:1080 https://example.org/
```

支持 SOCKS5 UDP ASSOCIATE 的应用可通过同一入口转发 UDP。需要固定端口转发时，在客户端已有的 `config.json` 顶层加入需要的字段，然后重启代理客户端。例如，下面两个字段分别将本地 TCP 端口 8080 转到服务端视角下的 `127.0.0.1:8000`，将本地 UDP 端口 5353 转到指定的 DNS 服务器。保留已生成的 server、tls、auth、obfs 和 socks5 字段。

```json
{
  "tcpForwarding": [{"listen": "127.0.0.1:8080", "remote": "127.0.0.1:8000"}],
  "udpForwarding": [{"listen": "127.0.0.1:5353", "remote": "1.1.1.1:53"}]
}
```

启用上述 UDP 转发后，可以用 `dig @127.0.0.1 -p 5353 example.org A` 验证 DNS 请求和响应。UDP 入口也适合无法配置 SOCKS5 的应用。[Hysteria 2 客户端配置](https://v2.hysteria.network/zh/docs/advanced/Full-Client-Config/)

**已测边界。** 在 Hysteria 2.14.0 的本地回环测试中，SOCKS5 UDP 有效负载为 32、1500 和 3000 字节时往返成功，空载荷和 4096 字节载荷未收到回包。SOCKS5 TCP 正常双向读写通过，客户端发送后立即半关闭写端的测试未能读完整响应。依赖这些行为的应用需要单独验证。
