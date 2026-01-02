# NEKO 配置文档（neko-lite）

本文档适用于本项目内的 neko-lite 实现（`type: neko`）。neko-lite 保留 framing + padding、nonce/tag 混淆、基础 replay、防 TCP/UDP，移除了 noise/persona/复杂 HTTP 伪装。旧字段 `noise-ratio` / `persona` / `http-response` 仍可被解析，但会被忽略并打印 warn。

## PSK 要求

- 必须是 32 字节密钥。
- 支持 64 位十六进制（hex）或 base64。

## 客户端（proxies）字段

必填：
- `name`：代理名称。
- `type: neko`
- `server`：服务器 IP/域名。
- `port`：服务端端口。
- `psk`：32 字节 PSK（hex/base64）。
- `cipher`：`aes-128-gcm` / `aes-256-gcm` / `chacha20-poly1305` / `xchacha20-poly1305`

可选：
- `udp`：是否开启 UDP。
- `window-size`：时间窗口大小（秒），默认 30。
- `max-offset`：握手 offset 最大值，默认 64。
- `shaping`：
  - `enabled`：是否启用分帧/抖动。
  - `jitter-range`：抖动区间（毫秒），如 `[5, 20]`。
  - `max-frame-len`：最大帧长度（包含 meta + payload），默认 1400。
  - `noise-ratio` / `persona`：已弃用（忽略）。
- `transport`：
  - `tcp-nodelay`：是否开启 TCP_NODELAY，默认 true。
  - `keep-alive-secs`：TCP keepalive 秒数。

## 服务端（listeners）字段

必填：
- `name`
- `type: neko`
- `listen`：监听地址（如 `0.0.0.0`）。
- `port`：监听端口。
- `psk` / `cipher`

可选：
- `window-size` / `max-offset`
- `handshake-candidate-span`：时间候选跨度（1 表示 `[-1,0,1]`，2 表示 `[-2..2]`），默认 1。
- `replay-capacity`：每个 window 的容量，默认 8192。
- `replay-windows`：窗口数量，默认 4。
- `shaping`：同客户端。
- `fallback`：
  - `dest`：fallback 目标（如 `127.0.0.1:80`）。
  - `whitelist`：允许直入的源 IP 列表。
  - `http-response`：已弃用（忽略）。
- `transport`：同客户端。
- `proxy`：入站流量路由目标（如 `DIRECT`）。

## 示例配置

客户端示例见：`docs/neko_client_example.yaml`  
服务端示例见：`docs/neko_server_example.yaml`
