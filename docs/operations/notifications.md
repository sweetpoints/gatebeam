# 告警与通知

通知由独立 worker 循环消费持久化 outbox，按资源、种类和指纹合并失败，并仅对状态转变创建通知。每个事件的 `notification/v1` consumer receipt 与 incident、transition、独立渠道 delivery 和 `notification.delivery` job 同事务提交。旧序号和重复事件不能重新激活已恢复的 incident。首次正常观测不发恢复通知。

先应用迁移 `00019_notifications.sql`，并由专用迁移身份以 `migrate_roles: true` 执行内嵌 `db/roles` goose 权限迁移，补齐通知及既有 certificates/observability 能力角色。新通知角色不赋予 identity/ingress 任意写入、CA 或证书秘密能力；API/worker 的平台 jobs/audit 与当前身份/引用查询权限沿用既有独立能力。

API 配置 `notification_recipient` 为专用 age X25519 公钥。worker 配置相同公钥及 `notification_identity_file` 私钥文件；该身份必须独立于 API、CA、叶证书和证书提供商身份。API 没有通知解密能力，数据库仅保存密文。worker 缺少通知私钥配置时不发送，其他工作循环照常运行。通道未填写收件人会留下 `no_recipient` 结果，不假称成功。

`GET /alert-channels` 和 `GET /alerts` 使用当前交互管理员权限，只读、不消费 TOTP；响应不含密文、密码、Bot token、原始日志、provider response 或站点详情。各列表最多 100 条；`/alerts` 返回 `incidents` 和 `deliveries`，未配置渠道时仍可查看安全事件状态。`PUT /alert-channels` 创建或更新渠道，正文包含 `channel`、`expected_revision`、可选 `secret` 和新鲜 `totp`；新建 expected 为 0，更新附带 channel.id 和现有 revision。`channel.owner_id` 和 `channel.revision` 不允许由请求指定。新的 channel 必须提供 secret；更新省略 secret 保留已有密文。通道 owner 固定为创建时的当前管理员账号，其他当前管理员可维护既有通道但不会变更 owner。

通道字段：`kind` 为 `telegram` 或 `smtp`，`enabled`、`recipient`，以及互斥的非空 `site_ids` 或 `system: true`。系统通道不接收站点、目标和证书告警；空 site scope 不表示全部站点。SMTP 另需 `host`、`port`、`tls_mode`（`starttls` 或 `implicit`）、`from`、可选 `username`；secret 是邮件认证密码。Telegram secret 是 Bot token，recipient 是数字 chat ID。SMTP 严格验证证书链和名称，TLS 完成前不 AUTH；Telegram 只访问固定 HTTPS provider，不跟随重定向。无任意正文、命令或 URL 输入。

`POST /alert-channels/{id}/test` 只接受 `totp`，在审计与 job 提交后返回 202。它异步发送固定安全测试正文，API 不执行外部 I/O。所有写操作需要当前交互管理员、CSRF 和一次性 TOTP，并与审计同事务。停用也通过带新 expected_revision 的 PUT。

投递前以 identity → ingress → notification 顺序冻结当前权限和引用，检查 owner 当前 active/admin 状态、当前站点存在性、通道明确 scope，以及资源全部 draft/published 站点引用。创建者 session 到期不会中止持久通道；账号禁用、降权或 TOTP 重置为 pending 会拒绝发送。权限事务在网络 I/O 前结束；无法撤回已被外部渠道接受的在途消息。网络完成后再核对 lease 和当前渠道 revision；成功但渠道已变化记为 `accepted_previous_revision`。

每渠道独立最多 5 次尝试，失败退避 2、4、8、16 秒。已成功的 Telegram 不因 SMTP 失败重发。发送过程中崩溃或 provider 已接受而本地提交结果未知时，lease 到期后的重试可能重复发送；旧 attempt 标记 `commit_unknown`。这是可审计的至少一次尝试，不保证外部 exactly-once。禁用、范围拒绝、未配置收件人均留下明确终态。暂时无法查询权限时回滚 claim，保留 pending，不当作永久拒绝。

实际来源：

- I5 健康阈值沿用目标策略；成功样本和 DNS 失败均核对当前发布、目标绑定及采样序号。DNS 失败只推进观测序号，不改变有效路由或上次有效解析。
- P5 续期失败／恢复来自 lease-fenced Commit/Fail；到期阈值是 7 天，包括显式 published 历史修订和最多 1000 个当前已签发规格。新草稿不覆盖旧发布修订的告警指纹。
- O1 拒绝日志记录后，下一次无拒绝的已提交批次恢复。采集延迟阈值为 60 秒：只有读后仍有未读字节时，计算最新已读有效日志时间与当前时间之差；无流量、无 backlog 不构成延迟。仅畸形记录且无有效时间、仍有未读字节的批次属于未知延迟，保留既有延迟状态并由拒绝记录告警表示；仅在 backlog 已清空或重新获得低于阈值的有效时间观测时恢复。
- O1/O2 流水线故障采用拥有者的单调 outcome 序号。成功的实际日志批次、归档清单提交后的本地清理／源段退休完成和查询执行回执分别作为恢复依据；空闲轮询不伪造恢复。查询权限拒绝或 busy 不算基础设施故障。

所有展示正文使用固定模板，采集延迟只带秒数；外发不含资源 ID、站点名、输入 message 或异常正文。独立循环只领取 `notification.delivery`，不会阻塞或领取健康、证书、日志、归档、查询工作。O5 页面尚未交付时，上述管理 API 已可使用。
