# 运营控制台

统计、历史日志、告警、备份、账号和审计页面使用管理 API 的所属上下文应用接口。每次请求保留完整 UserID/AuthVersion/CredentialKind/CredentialID；API Token 的站点和动作限制始终与账号当前权限取交集。账号、审计、渠道与备份报告需要当前交互管理员。审计通过 platform/audit 的有界元数据 Reader 查询；identity 保持当前授权核验，Reader 的 SQL 与 DTO 均不读取 payload，只返回 ID/动作/操作者/时间。渠道变更/测试、账号变更/Token 管理仍需新的 TOTP；一次性资料与未提交秘密在操作后、离开页面和 pagehide 清除，不进入 Query/Pinia 或持久存储。

历史查询是异步任务，只接受固定过滤条件和 `source: archive|local`。API 没有 SQL、文件路径、对象 key 或查询执行凭据接口。最多 31 天、100 站点、4096 对象、2 GiB 扫描、10000 行；结果每页 100 行，任务到期 10 分钟。任务列表每次最多扫描 limit+1 条当前凭据的记录；当前权限过滤后即使 items 为空，也根据服务端 has_more / next_offset 继续翻页，不能用可见条数推断末页。超限失败无成功结果。`succeeded` 仅表示冻结对象上的查询执行完成。`archived_only` 和 `local_only` 均不能证明采集完整；统计水位是最新贡献 bucket 的采集时间，百分位为直方图近似值。

本地查询新增 query 进程的 `query_local_directory`，指向只读 Parquet spool 挂载；在线 API 不配置此项。创建任务与归档清理共用 lifecycle 锁，queued/running 本地任务持有对象引用直到结束或到期。query-worker 从固定根打开不可变对象并核对冻结字节数和 SHA256，继承已验证文件描述符供固定 DuckDB CLI 读取；不复制扫描字节到有界 tmpfs。打开的 inode 在查询期间保留，清理不能改变查询所读的对象；不接受 API 文件路径。取消持久化并取消租约，worker 以有界轮询取消运行上下文，晚到结果不能覆盖 cancelled。查询进程总预算、独立 tmpfs 和内存限制继续生效，API 与 query-worker 仍分别运行。

部署详情显示实际 executor 记录的安全阶段/固定原因、平台任务状态和尝试次数；旧任务没有报告时明确 unavailable。运行证据必须绑定当前 artifact + version + generation，仅输出当前授权受影响站点的路由。配置已加载与业务路由已验证分别展示；缺少受保护入口身份、缺少只读 GET 路径或预期 maintenance 503 不会变成健康业务后端。恢复失败不能通过 observed_version 推断恢复成功。

备份页面只读查询 `backup_runs` 交付记录，所有记录均要求重新离线验证加密产物。恢复导入的历史回执没有逐文件详情时显示 `detail_status=omitted_for_recovery`、`artifact_verification=required`，不冒称 restorable。

本地 `backup-restore` 可配置 `recovery_report_directory`，在固定文件 `latest-recovery-report.json` 原子覆盖最近一次安全报告。报告包含随机命令 ID、产物 ID（仅已验证后）、UTC 时间、固定 configuration/verify/stage 阶段与失败/isolated_staged 结果、固定原因，绝不包含路径、密钥、DSN 或原始错误。仅 `backup-restore` 写入该目录；API 用同一路径的只读挂载读取，目录应位于共享安全报告卷，不能挂载恢复私钥或完整离线目录。未配置/未运行时显示 unavailable。文件损坏或不可读时拒绝展示报告。该报告不是业务激活凭证；隔离暂存后仍需本地人工 rebootstrap、信任/凭据轮换、安全水位核验与单独入口/业务验收。Web API 不提供恢复或恢复私钥上传动作。

迁移 00021 属于 observability 查询取消与 deployment 诊断元数据。由专用迁移身份以 `migrate_roles: true` 执行内嵌 `db/roles` goose 权限迁移：API 仅有本地对象元数据只读权限，备份 reader 仅可读备份回执，诊断 reader/writer 分别授予 API/edge 能力角色。诊断表进入受控恢复表清单，但恢复隔离清理会删除旧运行诊断，避免历史报告误当当前生效证据。

本地验收：`GATEBEAM_BROWSER_CHANNEL=chrome ./scripts/check-web.sh operations` 使用新浏览器配置、真实 PostgreSQL 18、S3 兼容夹具、独立 query-worker / DuckDB、实际本地恢复 CLI 失败与本地通知 provider 失败，不接入生产/云或真实 Telegram/邮件。所有夹具有时间、内存、进程和日志大小限制；不录制截图、视频、trace 或 storage state。
