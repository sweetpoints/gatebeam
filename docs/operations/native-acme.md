# 原生业务 Nginx 与网关客户端身份

业务节点只使用原版 Nginx 和标准 ACME 模块。Gatebeam 不安装业务 Agent，不通过 SSH 写业务配置。部署示例由业务运维人工审阅、替换地址及路径后安装；示例不是可直接投入现网的凭据或部署脚本。

网关 worker 的 provider account 选择 `internal-client`，服务端账号选择 `internal-server`。两者固定映射 operator bootstrap `ca_origin` 下的 `/acme/client/directory` 和 `/acme/server/directory`。API 不接受自定义目录、CSR 签发通道、profile 或私有请求头。一次性 EAB grant 的名称、用途和目录必须匹配；client spec 必须有显式 trust revision，不能回退到公开 CA。worker 使用原版 lego，`certificate_acme_transport_trust_file` 是内部 ACME HTTPS 的公开信任文件；不填时采用系统 HTTPS 信任。业务服务器自行持有自己的 ACME account/leaf 私钥与独立持久化 state。

worker 只持有 provider 私有 age identity 和 leaf 公钥 recipient。新客户端私钥加密给 edge leaf recipient，edge 仅解密当前授权版本；API 仅持有两种公钥 recipient。实际 key identity 必须不同，不能靠不同文件名共用密钥。先准备 certificate/trust，再引用到 target 的 `client_certificate`，并人工发布所选草稿。

## 独立 TLS 名称、SNI 与 HTTP Host

Nginx 原生 HTTP 客户端证书验证存在 SNI/Host 限制：在有虚拟主机选择时，发送 `SNI=a.internal.example` 与 `Host=shop.example.com` 可能返回 421，即便两个名称属于同一个 server。参见 [Nginx 请求处理源码](https://github.com/nginx/nginx/blob/release-1.31.8/src/http/ngx_http_request.c) 和 [proxy_ssl_server_name](https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_ssl_server_name)。单一监听器的简化夹具不一定触发该分支，不能据此承诺跨虚拟主机兼容。

专用私网业务 mTLS 监听器可在 target 显式选择 `tls_server_name_mode: verify_only`。Gatebeam 仍以成员 `tls_name`（或固定 `tls_name`）校验证书名称、有效期、链和完整 CRL，并发送客户端证书，保留原始业务 Host；只把 `proxy_ssl_server_name` 设为 `off`。`proxy_ssl_name` 和 `proxy_ssl_verify on` 不变。其他目标默认 `send`。模式变化属于草稿修订，必须发布，不是自动续期操作。

不发送 SNI 时业务默认 TLS 虚拟主机必须展示预期的内部证书。该专用监听器所有 Host 可选虚拟主机必须使用同一强制 clientAuth、信任和吊销策略；未知 Host 必须拒绝，禁止放置绕过 mTLS 的公开 vhost。连接地址可以与证书 DNS 名称不同。业务 A/B 分别使用 `a.internal.example` / `b.internal.example`，各自独立的 state/EAB，内部 DNS 的 80 端口必须到达对应主机。不能把所有挑战统一转发给 A。

## 人工部署与只读验收

1. 运维预先确认内部 DNS、CA HTTPS 信任、标准 HTTP-01 80 端口路由和持久化目录权限。按各节点名称授权标准 EAB grant；秘密文件仅本机 Nginx 可读，不进入 Git。
2. 按 [业务原生示例](../../deploy/examples/business-native-acme.conf) 和 [HTTP-01 示例](../../deploy/examples/business-acme-challenge.conf) 人工安装配置。首次签发前业务 TLS listener 可能尚无证书，这是显式不可用状态。
3. 运维执行本机 `nginx -t`、reload，并确认旧 worker 退出、新证书实际生效。维护完整 issuer/root CRL 集合；不能只更新磁盘而不 reload。业务端 OCSP `on` 要求叶证书与中间 CA 整链标准 AIA、受限 DNS、根直签委派 responder 和当前根 CRL；P4 的完整链就绪条件适用。OCSP/CRL 有标准缓存窗口，不承诺已建立连接即时撤销。
4. 使用已授权客户端身份只读探测，核对返回内容、证书链、明确验证名称及业务 Host；验证缺失/吊销客户端、错误验证名称、跨 Host/SNI 和未知 Host 均不能访问。不得用关闭 TLS/CRL 校验或伪造 Cloudflare/AOP 请求头取得“成功”。
5. 如使用 Cloudflare，直连夹具不能证明真实 Cloudflare 路径。缺少授权的 CF/AOP/入口 mTLS 探针身份显示 `policy_refused`；不能把本地管理版本当业务验收。

## 发布后的路由证据

edge 在本机应用锁内分两次短事务核对权限、lease 和材料。先激活并确认原生 worker/version，保留 `verifying` / pending journal；数据库锁外最多 5 秒、并发 8 探测整个候选的域名和路由，最后再次核对当前权威状态才提交 heads/job receipt。实际 TLS/HTTP 失败或预算耗尽触发以最新安全材料恢复上个已验证逻辑配置；未提交候选重启后也不能靠 private version 自行成功。

只有显式 `target.health.enabled=true` 的 health GET path 被视为允许的只读路径。strip-prefix 路由反向映射为外层路径，并再次检查最长前缀/精确路由选择，防止探测其他目标；不可映射或未配置时记录 `unavailable`，不猜测 `/`。部署方应配置真实无副作用的 health path。维护/停用策略、缺少授权身份与已验证业务健康分别展示。已知不可探测可以配置应用成功，但 `business_verified=false`；任何已执行探针失败都不能被另一条 unavailable 结果掩盖。

deployment 保存 artifact/version/generation、站点/目标修订、Host/SNI、路径、固定结果与时间；当前结果按当前 artifact 绑定读取，旧失败证据不会覆盖新版本。结果不保存请求/响应正文或秘密。O5 应使用 owning `CurrentRouteVerification` 读契约展示业务验证不完整。

`./scripts/check-pki.sh native-integration` 只测试拥有的本地 PostgreSQL、自研 CA、原版 Nginx ACME、原版 lego 与实际编译出的网关 Nginx。它不连接业务服务器、公开 CA 或 Cloudflare；不替代 O6 worker 进程首次 webroot/DNS-01 生命周期验收。

P6 原生验收还对实际 lego/ACME 签发的 clientAuth 叶证书检查标准 AIA，并通过同一受限 CA 进程的生产 OCSP／CRL 服务、根直签委派 responder 与根 CRL 完成业务 Nginx `ssl_ocsp on` 的整链 Good／Revoked 验证。该吊销用例关闭业务 OCSP cache、TLS session reuse 和 HTTP keepalive，保证请求建立新的业务 TLS 连接；吊销拒绝发生在 CRL 更新或 reload 之前。Nginx 自 1.29.7 默认启用上游 keepalive，新客户端连接不代表新回源连接。因此该结果不承诺共享状态缓存或已建立连接即时失效，也不改变既有连接运维策略。
