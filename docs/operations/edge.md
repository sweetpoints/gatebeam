# 本机 edge supervisor

`gatebeam --config /run/gatebeam/edge.json` 是 Linux edge 容器的父进程，直接持有同 UID 的非 root Nginx 子进程。API 是独立容器；只在声明的私有管理地址监听，不发布主机端口。业务系统不需要安装 Agent。edge 不使用 Docker socket、远程执行或命令字符串接口。

## 启动和管理 HTTPS

先运行数据库迁移、既有本地交互 bootstrap，准备 API 的 identity secret 和独立数据库凭据。`deploy/edge/edge.example.json` 与 `api.example.json` 给出路径及网络示例。真实配置和材料放在 Git 忽略的 `secrets/edge`、`secrets/api`；目录和文件必须对容器 UID 101 可读，私钥不得交给 API。API 只需要 management 公开证书及信任链，edge 需要其私钥。运行目录及完整 journal 使用持久卷，不放在临时目录。

在登录前手动导入所拥有管理域名的有效服务器证书、匹配私钥及信任链。edge 编译时检查名称、链、用途、时间和私钥匹配；管理 TLS 仅监听 8443，固定代理到私有 API 8080。API 启动和 `/readyz` 都实际连接管理 HTTPS，核验链、名称、已配置叶证书及固定 readiness 响应。旧 `https_gateway_ready` 字段仍可读取以兼容旧配置，但不能声明 TLS 已就绪。没有公开 HTTP bootstrap 登录入口。

构建顺序和固定镜像清单见 [完整部署手册](deploy.md)。`scripts/build-system.sh` 独立构建运行镜像，API 从 web 构建阶段复制 bundle，Compose 不构建镜像。复制 `.env.example` 为 `.env` 后集中选择镜像和 `EDGE_BIND`、`EDGE_HTTP_PORT`、`EDGE_HTTPS_PORT`；为兼容已有部署，缺省主机端口仍只绑定 loopback。域名、网络和数据库凭据使用各进程的独立配置。

手动 management TLS 导入不充当站点证书材料服务。普通站点证书/吊销材料或 Cloudflare generation 缺失时明确 unavailable；I5 的 DNS/health 绑定由独立 worker 提供；不生成可发布占位材料。后台 derived 操作只允许 certificate、revocation、health、dns、cloudflare，读取当前已验证用户配置，不能发布草稿，也不依赖旧发布者会话继续存活。

## 应用和恢复边界

首次发布排队保存可信认证产生的 UserID、AuthVersion、CredentialKind、CredentialID，绝不保存原始 Cookie/Token，重复排队不替换最初发布者。edge 仅领取固定 apply、generation、rotate_logs 类型。最终应用按 identity → ingress 图 WRITE → 当前安全材料 → deployment/任务租约顺序重新核对；编译、写入 artifact 和 `nginx -t` 均在最终授权事务之前。

最终授权事务最多 15 秒，涵盖重新核对、原子 current 切换、HUP、新 worker/旧 worker 监听 socket 退出屏障、新连接版本探针，以及 ingress 拥有者的发布 head/domain claim、release/runtime 和 job 回执。授权变更可能等待此短事务；它不等待旧 WS/SSE 请求全部结束。任务完成使用实际 wall clock 检查租约，事务中途过期也回滚全部数据库回执。

数据库事务不能回滚文件或已经收到 HUP 的 Nginx。每个阶段先写入并 fsync 本地 `apply-journal.jsonl`，再原子保存 `journal.json` checkpoint；artifact 文件、目录和 current symlink 切换均有持久化屏障。锁覆盖单机执行任务。`receipt_pending` 明确表示 OS 效果尚未获得数据库确认。API 的 `effective`、`observed_version`、`restored_version` 只描述数据库确认的回执，不冒充实时进程探针。

异常后核对实际私有 `/version`、本地 journal 和数据库回执。不能仅凭 current 目录或旧成功响应启动历史配置。回退重新读取当前已验证逻辑配置和当前有效安全绑定，重新编译、`-t`、切换与验证；缺失/失效安全材料使恢复失败，不能复活旧材料。结果区分 failed（未应用）、restored（恢复成功）、restore_failed（恢复失败）。数据库断开只阻止后续控制动作，已经运行的 Nginx 不因控制数据库故障退出。初次启动或重建进程仍须能核验当前安全状态。

## 日志和固定控制动作

生产 access/error 日志固定落在运行卷 `logs`。访问日志采用固定 JSON schema，包含站点 ID、请求 ID、时间、方法、规范化无 query 路径、路由维度、状态、字节数、延迟、上游地址、代理来源及限流结果；不记录 query、Authorization 或请求正文。HTTP 请求级原始 Nginx error 文本固定丢弃，避免上游/限流错误夹带完整 URI；主进程启动/重载错误仍保留在 error.log，安全结构化访问字段保留状态、上游和限流结果。因此部分请求错误细节不可用，不声称提供完整诊断。日志轮转先 fsync 旧文件、改名并同步目录，再 USR1，核验父子进程已经释放旧日志描述符。旧段留给 O1 的持久化、聚合和归档流程；此任务不删除段或声称已实现归档保留策略。

Stop 仅向所拥有子进程发送固定 QUIT；超出有界退出预算后终止其专属进程组。普通 HUP 验证的是旧 worker 已停止接受新连接，并非全部旧请求或进程已退出。

## 本地验证

`./scripts/check-edge.sh supervisor` 运行领域/文件系统测试、固定镜像内真实父子进程的 `-t`/HUP/recovery/USR1 测试，并运行独立 API/edge/真实 PostgreSQL 的 TLS 与数据库连接中断验收。测试仅创建自己命名的有界容器/网络，清理仅针对这些资源。`./scripts/check-db.sh ./internal/integration/publication ./internal/modules/ingress/application ./internal/platform/jobs` 验证同 Scope、当前授权、草稿保护和租约 fencing。测试不包含生产操作、云端 ACME 或断电硬件故障注入。

## 健康、私网 DNS 与渐进迁移检测

edge profile 的独立 worker 只需自己的数据库凭据与 `worker.json`，不读取 API identity key、management 私钥或 CA signer；示例见 `deploy/edge/worker.example.json`。worker 没有 Docker socket，不执行 Nginx。`protected_networks` 必须覆盖实际 API、数据库、CA 和其他控制服务；管理 API 的单地址也自动保护，metadata、loopback、link-local 始终拒绝。目标私网 CIDR 仍取已验证目标组配置，每次 DNS 刷新重新核验全部答案，错误或混合不安全答案使整次刷新失败，不接受部分安全答案。

健康默认间隔 5 秒、单探针超时 2 秒、连续 3 次失败剔除、连续 2 次成功恢复，可用目标组 health policy 配置。worker 轮转检查当前已验证快照，一组间隔指上次完成后的最小等待，组数或慢探针会使实际间隔更长。每组最多 8 个并发探针，事务外整组 DNS 解析共享最多 5 秒预算。所需组预算为 `ceil(解析后端点数/8) × timeout + 5秒`，下限 30 秒、上限 65 秒；默认 2 秒超时最多支持 240 个解析端点（100 个端点预算 31 秒），60 秒超时最多支持 8 个端点。候选 DNS 准备及最终绑定在激活前拒绝超容量组，错误要求减少成员/DNS 答案或缩短 health timeout；不把不能完成采样的组伪装成健康。显式合法超时保留，组预算取消时不提交部分结果。HTTP Host、连接 IP 和 TLS 验证名称独立，使用标准 HTTPS 链/名称验证与配置的标准客户端证书，不跟随跳转、不重试、不注入特殊标头。当前站点材料缺失时 HTTPS 健康检查明确 unavailable，不以跳过验证取得成功。

成员状态或 DNS 答案变化才产生 runtime generation；连续成功/失败计数持久化但不触发每次重载。事务内记录 dirty 标记，worker 每秒最多合并排队一个固定 generation 任务；排队失败保留标记以便下次重试。旧发布、目标修订、成员/端口/TLS/策略指纹、DNS/健康状态 token 或重复序号不匹配的结果被忽略。自动任务与手动发布共用 edge artifact 锁和最终 generation fencing，永远重新读取最后已验证快照，不推进 ingress 草稿。首次发布私网名称时，在已认证且租约有效的候选读取后，事务外准备 DNS；之后再次核验候选、身份和租约，最终应用仍比较完整 artifact。

`POST /sites/{id}/preflight` 以当前 View 范围分别检查 `role=old|new`、`mode=direct|cloudflare` 和明确的 IP:TLS端口（例如 443 或 8443）；`domain` 必须是该站点的已发布域名，作为正确 HTTP Host 与 SNI，`path` 是不含 query/fragment 的只读 GET 路径。只返回指定入口的检测结果，不更改业务 DNS、源站、证书或访问策略。POST 使用既有认证及 CSRF 保护；探针前后都重新核验当前凭据/站点范围。

结果 `passed` 表示实际 HTTPS GET 得到 2xx，`failed` 表示真实 TLS/HTTP 探针失败。`policy_refused` 是当前 CF/AOP/mTLS 策略缺少授权探针身份的前提拒绝，并非声称已发送请求或观察到远端拒绝；`unavailable/cloudflare_provider_unavailable` 表示尚无权威 Cloudflare 地址绑定，提供者实现前不能认定用户给出的 IP 是 CF 入口。报告保留 direct/cloudflare 和 old/new，不能把直连成功解释为 CF/AOP 成功。API/worker scratch 镜像携带标准系统 CA bundle；不接受请求传入的 trust、客户端私钥、任意请求头、body 或跳过 TLS 选项。

`./scripts/check-edge.sh runtime` 运行纯领域/应用/探针测试、真实 PostgreSQL 条件更新，以及固定 Nginx 镜像的全不健康 503、恢复权重和标准 TLS/mTLS/CF 拒绝测试。测试使用临时生成的自有 CA/证书；这些 fixture 不进入生产材料服务。
