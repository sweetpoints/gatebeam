# Gatebeam 双实例部署与升级

这是部署输入及执行手册，不是已部署记录。部署示例使用同一个 GCP 可用区内两台独立网关 VM，每台一个独立 Compose project，均运行 `nginx`、`management`、`background-jobs`、`log-query`。PostgreSQL 是外部 Cloud SQL 依赖，生产 Compose 不包含数据库。独立部署 [Gatebeam CA](../../gatebeam-ca/README.md)，为它配置单独的 PostgreSQL 数据库和账号。网关通过内网 DNS 访问 CA 的 ACME、OCSP 和 CRL 地址。本文中的项目名、域名、地址、资源引用和 digest 必须替换并核对；示例没有创建或保留任何云资源。

## 显式节点清单

`render-node` 可用 `nodes` 提供完整清单，并用 `node` 指定要渲染的本机记录。清单至少有一台，受每角色 32 个 age 收件人的现有上限约束。旧双节点输入仍可用 `peer_node`。每个节点先配置计划中的内网管理上游和保护网段，再用 `activate-nodes` 提交全部已就绪节点。该命令只添加成员。新节点须实际加载当前发布，之后才能参与接流量。扩容前在 Nginx、管理 API 和后台任务的 `protected_networks` 配置中预防性保护专用网关子网。新增节点的 IP 可以在该子网内临时分配。对各现有 Nginx 的受控 Unix socket 执行 `POST /management-peers`，请求体为 `{"address":"10.42.0.32:9443"}`，等待实际加载返回的 `desired_digest`。新上游初始处于排除状态。新节点通过本机配置、mTLS 和实际能力验证并激活后，执行 `POST /management-upstreams`，请求体附同一 `address` 及 `"unavailable":false`，再次确认实际加载摘要。新增地址若超出现有保护子网，先按受控部署流程同步三类角色的保护策略。

升级清单包含当时的全部节点，顺序就是升级顺序。请求可用 `target` 指定单台节点的 ID 和代次。只有一台时，先加入临时节点再开始整机维护。退出使用 `scope:retire` 和 `target`，从管理上游、公网及私网入口摘流并完成日志收尾后，撤销目标节点的成员资格。保留盘和历史日志按现有运维流程处理。升级和退出批次会阻止常规节点登记或激活改变成员清单。

生产容量报告继续记录每台节点当时的镜像、机型和资源限制。新清单的容量报告需提供 `expires_at`。若需要多台共同承接峰值，在 `groups` 中记录经同一入口实测的组合及负载指标。每个成员记录 `node` 和 `images`，与单机记录对应。升级器检查每次摘流后实际存活的组合与测量证据，并在生成在途操作前暂停不满足门槛的摘流。生产验收仍需要实际 GCP 入口及业务负载。 在开始排空前，若剩余容量下降且原节点仍以清单中的镜像健康运行，执行器会重新验证并按已确认的摘流记录恢复原节点。恢复成功后批次记为回退并停止。既有请求 ID 和批次日志保留，下一次尝试使用新批次。排空已开始、原节点镜像或健康状态不符，以及操作结果未知时，批次暂停并保留证据。

## 服务及入口

| 服务 | 每台 VM 的职责 | 对外连接 |
|---|---|---|
| nginx | 同一进程树内的 Go supervisor 和 Nginx，确认后的本地启动基线、TLS/mTLS、OCSP DER 缓存、日志轮转 | 公网 80/443 映射容器 8080/8443；私网健康端口默认 19091 |
| management | 同一个逻辑管理后台的两个 API/Web 副本，账号及会话共享 | 本机及对端网关通过私网 9443 和标准 mTLS 访问；健康端口默认 19092 |
| background-jobs | PG 租约协调的全局任务，以及按节点归属的采集、归档和本地查询 | 外部 PG、供应商、R2；仅通过同机 Unix socket 访问 query；健康端口默认 19093 |
| log-query | 同机 worker 调用的受限 DuckDB，R2 只读和同机 spool 只读 | 查询仅 Unix socket，不提供查询网络 API、不含 DB 登录；私网只读健康端口默认 19095 |

公网入口使用 regional external passthrough Network Load Balancer，TLS 在 Nginx 终止。私网 CA 使用独立稳定的内部 L4 入口，逻辑 ACME/状态域名保持稳定，TLS 在 CA 终止。在网关模板的 `protected_networks` 中填写独立 CA 及其内网入口的地址或网段，防止将这些地址设为业务上游。渲染节点配置时会保留这些网段，并补充两台网关的内网地址。节点 manifest 分别记录网关公网和私网入口的 backend service，以及本节点 instance group。滚动升级按节点摘除这两个网关入口的成员，独立 CA 的入口不参与变更。GCP LB、instance group、health check、DNS、TLS/防火墙和保留磁盘需单独准备，本地构建及测试不会修改它们。

网关入口健康检查使用 `/readyz/data`。独立 CA 的验收使用 ACME 目录和签名 OCSP 响应。健康端口只绑定 VM 私网地址并由防火墙限定来源。健康监听只有 GET 探针；维护、排空、管理上游排除只能通过角色专属的 0600 Unix socket。控制 socket 不属于公开管理账号权限。

容器中的 `172.31.0.x` 和 query 的 `172.29.0.x` 是各主机本地绑定，跨机上游必须使用 VM 的互通内网地址。两个宿主机可以有相同容器地址；地址不作为节点身份。节点/代次、PG 连接身份和注册的独立加密身份共同约束本地任务、证书信封及发布回执。

## 构建、迁移、初始化、运行分别执行

1. 在 CI 或构建机器运行 `scripts/build-system.sh`，评审源 commit、检查结果和 `.work/artifacts/manifest.json`，发布获准的固定 registry digest。生产 manifest 的五个镜像（四个网关角色加独立 CA）都要求 `repository@sha256:...`；`.env.example` 的占位符不能用于部署。Compose 没有 build，也不会隐式迁移或初始化。
2. 单独使用 `deploy/migration.example.json` 运行 `gatebeam --config ...`。配置的 mode 是 migrate，`migrate_roles` 显式开启时才执行 goose 的角色迁移；DDL 凭据只供这次操作。普通运行身份不具备 DDL/角色管理权限。将模式为 migrate、只引用 node-admin DB 文件的独立配置用于 `gatebeam-admin register-node/activate-nodes`，这两个命令不会执行迁移。
3. 为两台 VM、每个角色、每次替换分别准备登录身份及独立 age 身份。运行组是受限 NOLOGIN 能力组；实际 LOGIN 由运维单独授权。登记 edge principal 和 background-jobs principal。不能把同一登录身份跨角色/跨节点复用，替换节点也不能只修改自报 epoch。
4. 本机使用所属角色的一次性准备容器或该受控 OS 身份执行 `gatebeam-admin --operation prepare-role --config <该角色受控配置>`，只返回 public recipient。它保留已存在的密钥，不输出私钥，不把 A 的私钥复制到 B。准备配置需要真实 node_id/epoch 和本角色私有文件引用；准备目录只在这一步对所属身份可写，不使用生产的只读 secrets 挂载。公共 recipient 汇总后先生成全新的配置树，再将本机准备的秘密安装到对应本机角色目录；不能从对端复制私钥。prepare-role 不会要求尚未生成的 identity/signer 文件预先存在，也不连接数据库。不得给 query、management 或普通 worker 配置 CA 签名私钥。
5. 使用本机和对端的公共 node manifest、完整公共角色 recipient policy、本机自己的 public recipient 映射构造 `render-node` 请求。`gatebeam-admin --operation render-node --request <文件>` 一次生成新目录内的四个角色 JSON 和相邻 `.env`；拒绝覆盖既有目录或环境文件。`node`、`peer_node`、`templates_directory`、`output_directory`、`recipients`、`node_recipients` 是请求字段；备份另提供离线 `backup_recipient` 和共同 `backup_epoch`。`NodeDeployment.roles[*].config_file` 必须与输出路径对应，`environment_file` 为 `<output_directory>.env`。A/B 的 API 上游顺序、UUID、健康端口和镜像 digest 由清单生成，不能直接将 A 的生成结果复制给 B。
6. 独立安装本角色的 DB 文件、TLS/信任材料及 R2 权限文件；模板中的 `age1_REPLACE...`、域名、角色文件路径等必须替换。生成配置只有秘密引用，不会替用户生成或复制这些实际秘密。容器 UID/GID 为 101，角色目录及私有文件应由该身份读取；公共配置由本地受控部署身份管理，容器挂载只读。迁移、node-admin、离线恢复凭据不挂载给运行角色。

`deploy/nodes/a.example.json` 和 `b.example.json` 是两个受控节点清单，示例私网地址为 10.42.0.30/31。`deploy/nodes/*.registration.example.json` 使用当前 owner 的登记结构；其中 `BootArtifactID` 填入下述登记参考值，`BridgeImages` 填入清单中获准镜像的 sha256 部分，`EncryptionRecipients` 填本机各角色的公共身份，`RolePrincipals.background-jobs` 填本机该代次的真实 DB 登录。

## 保留存储和启动前提

`gatebeam-admin --operation provision-node --request <storage.json>` 的输入是 `{ "node": <完整节点清单>, "storage_root": "/mnt/gatebeam/a" }`。运维预先准备以下子目录，权限 0700、UID 101：

```
edge-runtime  edge-logs  log-spool  query-socket  acme-challenges  management-acme
nginx-control  management-control  background-jobs-control   log-query-control
api-capsules  edge-capsules  worker-capsules  backup-spool
```

raw logs 和 spool 必须位于与 runtime 不同的文件系统设备，可将专门日志盘上的目录 bind mount 到上述固定路径。配置持久挂载和磁盘保留，替换容器、升级、重启不得删除这些数据。未挂载磁盘时不能让同名空目录退回启动状态所在文件系统。`provision-node` 在任何写入前检查所有目录、全部现有卷的 node/epoch/class 标签与 bind 路径；只创建缺少的固定卷，创建后重新检查，不接管未知卷、不递归改权、不删除卷或日志。相同输入可重试；未知结果先重新观察，不能据超时判定创建未执行。

每次宿主启动先执行只读 `gatebeam-admin --operation verify-storage --request <storage.json>`；例如用 `deploy/host/gatebeam-node.service.example` 作为受控 systemd 启动模板，并配置真实挂载依赖。容器使用有界 `on-failure:5`，宿主 oneshot unit 只负责挂载校验和启动，不另建与 Docker 竞争的循环进程管理器。Docker daemon 重启不会通过该策略自动恢复容器；标准 unit 与 docker.service 关联后重新执行前提校验。不要改为可绕过这些前提的 `always`/`unless-stopped`。对应语义见 [Docker 官方重启策略说明](https://docs.docker.com/engine/containers/start-containers-automatically/)。Nginx 启动还检查日志卷的 node stamp，缺失或其他节点的卷不能冒充本机日志源。

边缘本地轮转不依赖 PG/R2/job；默认轮转水位 64 MiB，日志采集容量水位 1 GiB/2048 文件，可在受控配置中调整。达到水位会记录本地容量状态并发出有界诊断，采集拒绝继续增长，不删除未归档文件。专门日志盘还必须设置实际容量及告警，spool 使用独立预算；永久 R2 故障不能保证日志无限保存。磁盘耗尽期间可能出现未写下的新日志，容量告警及缺口必须保留。Compose 的内存、CPU、PID、查询扫描/临时目录/打开文件上限独立约束各角色。

## 首次授权和本地基线

- 先通过导入管理入口证书，或标准 DNS-01 获得该入口的 TLS 材料。API 和每台网关的私网 mTLS 身份也独立授权；两台 API 可以使用同一受信服务 DNS 名，但私钥独立。CA 只使用标准 X.509、ACME v2/EAB、CRL/OCSP；离线根私钥不进入任何网关运行容器。
- 在 edge 角色容器中先执行 `gatebeam-admin --operation prepare-management --config /run/gatebeam/edge.json`，创建初始私有上游维护状态；已有排除项/版本不会被重置。随后执行 `gatebeam --config /run/gatebeam/edge.json --preview-edge`。已有已验证发布时返回它的 artifact 参考；全新安装则编译本机管理入口的最小配置。它不启动 Nginx，不建立本机成功回执。参考用于受控登记，随后仍需真实验证。
- 本地 operator 使用独立 node-admin DB 配置，执行 `gatebeam-admin --operation register-node --config <node-admin配置> --request <节点registration文件>`。没有登记/连接身份不符不能加载业务材料。
- 在该节点执行 `docker compose --env-file <本机env> -f <compose文件> run --no-deps --rm nginx --config /run/gatebeam/edge.json --initialize-edge`。初始化在线重新检查授权，Nginx 实际校验、加载和探测后，保存完整本地材料/确认凭据及单调安全下限；同时建立本机标准 OCSP DER 缓存和新日志卷归属。已存在确认凭据时，初始化会拒绝，应走普通重启/升级流程。
- `gatebeam-admin --operation inspect-boot --config <edge配置>` 输出确认的公开证据，不输出 PEM、私钥或业务材料。`docker compose ... up -d --no-build --no-deps nginx management background-jobs log-query` 启动四个角色。确认每个角色、mTLS、管理会话和日志查询链路。
- 两节点准备完毕，使用 `{ "nodes": [<A完整清单>, <B完整清单>] }` 请求执行 `gatebeam-admin --operation activate-nodes --config <node-admin配置> --request <文件>`。命令检查两台网关的八个私网角色探针及当前确认 artifact/镜像/代次；有缺口拒绝激活。它只修改受控节点成员状态，不创建 LB/DNS、不替代实际业务验收。

普通 `gatebeam --config edge.json` 从本机已确认基线先启动 Nginx，之后才尝试数据库/control 连接。PG、API、jobs、R2、CA 不可用不阻止已有基线重启；新盘、身份不符、损坏/恢复的旧基线或不可信时间不能假装普通离线重启。未知、缺失、过期或不匹配的 OCSP 证明拒绝受影响连接，不进行离线签名。配置回退不回退安全时间、已知吊销及信任下限。WebSocket/SSE/长请求不承诺一直保持。

## 历史秘密迁移和备份

对原始持有者的所属角色执行 `gatebeam-admin --operation rewrap-role --config <本角色maintenance配置>`，将历史密文重封装给授权的 A/B public recipients。API 处理 TOTP，worker 处理供应商及通知秘密。重封装使用单独授予的维护 DB 登录；普通 worker 不获得此写能力。CA 的 EAB 和签名密钥由独立 CA 部署管理。保留原始持有者直至每个 B 角色执行 `--operation verify-role` 成功；验证使用只读事务、不重封装、不改变业务版本、订单或账号权限。不能只改公共 recipient 列表就认定历史数据可读。

每个角色只写自己的 sealed capsule 卷。snapshot exporter 作为独立、有界的一次性任务，挂载三个网关 capsule 子目录只读和本节点 backup-spool 可写，使用专属只读 snapshot DB 登录；不用运行角色拿到其他角色的明文私钥。上传由 worker 只读取密文 spool、使用限定 R2 backup 权限执行；query 使用另一个 R2 只读身份，日志归档 writer 也使用独立范围。`deploy/backup/` 提供 exporter/timer 模板，应绑定本节点命名卷与受控配置。备份 node/epoch 必须一致；混入另一节点 capsule 会被拒绝。离线恢复 private identity 不放在网关，recovery public recipient 也不能复用任何在线角色身份。

备份按明确 schema 契约导出/恢复，未知版本拒绝；恢复到隔离的新数据库/目录，所有 owner 再次隔离旧账号、节点、查询/任务租约与不可信 CA 权威。恢复的密钥是历史材料，不授权新节点自动上线；必须重新登记、核对水位、轮换/验证需要的材料并重新初始化。普通镜像回退不运行 restore 或 goose down。

## 渐进业务迁移

先逐站点保存、审阅差异、校验，再由有发布权限的账号发布；两节点结果分别显示，部分成功不能当成全部成功。配置加载和路由证据不等于支付回调/业务验收。证书正常续期走既有自动申请/加载流程，不要求人工重新发布业务配置。

Cloudflare DNS 仍由管理员手工切换，可保留两条入口记录，让新旧网关重叠工作，逐个域名/回调验证。已有服务通过互通的私网回源。日志写入可使用私网域名，网页访问可经过 Gatebeam。在全部站点、回调和过渡路径完成前，不自动关闭旧公网入口或修改业务服务器防火墙。本工具不向业务主机安装/SSH 推送组件，不管理出站。

## 程序升级及宿主维护

后续受控升级执行器使用同一份节点清单及固定镜像证据。逐节点、逐选中角色执行：兼容性/空间/另一节点预检；将目标 API 从两台 Nginx 管理上游排除并等待双方实际应用 digest；摘除公网及私网成员；有界排空（默认 60 秒）；日志收尾；只替换 digest 改变的角色；独立验证 API、CA、query、Nginx 本地基线与 TLS；恢复私网及公网成员；观察默认 120 秒；成功后才操作另一节点。WebSocket/SSE/长请求到期允许关闭，不能等无限连接归零。

控制面失联会暂停新升级，不阻止已有节点本地重启。命令超时记为结果未知，后续先观察其 operation/主机命令是否收敛。旧执行端未被确认失效、在途操作未完成时，不自动接管；数据库 TTL 也不能代替此证据。宿主维护需要恢复系统挂载/标准服务，再按相同角色就绪门槛重新加入。仅修改管理或 worker 不要求重启数据面。详细可执行计划及故障恢复命令随升级执行器交付；当前手册不代表已执行任何生产升级。

备份宿主模板按 UID/GID 101 运行，仅把本节点受控 `storage_root` 下三个 sealed capsule 目录绑定为只读，backup-spool 绑定为可写。`deploy/backup/gatebeam-backup-export.service` 的 `/srv/gatebeam/storage` 必须与 provision-node 的实际根目录一致；启用 timer 前核对只读 snapshot DB 文件、恢复公共 recipient/epoch、主机上的固定版本二进制与输出目录权限。模板不会读取四个在线秘密目录。

启用业务 mTLS 之前，需在 edge、管理和 worker 的受控配置中提供 `certificate_status_profiles_file`。该文件绑定实际 CA 的标准 OCSP/CRL 地址和可信发行者；不能把示例域名直接当成已配置的证书状态服务。首次空配置仅提供管理入口，不代表业务 mTLS 或 Cloudflare 凭据已完成接入。

升级工具使用 `sh scripts/build-deploy.sh` 单独构建 `gatebeam-deploy` 和 `gatebeam-deploy-host`。前者运行在专用执行 VM；该 VM 不能是两台网关之一。后者仅作为网关宿主 root 拥有的一次性命令安装到 `/usr/local/bin/gatebeam-deploy-host`，不安装常驻服务，不接触业务服务器。在两台网关分别准备 root 只读受控 `/etc/gatebeam/host.json`，字段为 `node`（本机完整 NodeDeployment）和 `storage_root`（provision-node 的同一根目录），并创建 root 拥有的 0700 `/var/lib/gatebeam-upgrades`。使用 GCP OS Login/IAM、私网 SSH 和已核对的主机密钥；工具强制严格主机密钥检查。

先用独立迁移身份执行现有 goose 命令，将 schema 扩展到 27、角色迁移到 7。升级批次自身依赖该日志表，不能先开始未记录的操作再创建日志。部署身份需读取 goose 版本记录并具有受控节点管理能力；普通运行角色不具有升级日志写权限。恢复到隔离数据库时，历史升级批次会被隔离，不能直接继续原批次。

`gatebeam-deploy --dry-run --intent /path/intent.json` 只读取显式输入并向 stdout 输出计划。intent 包含 `request` 和 `inventory`；request 提供 `batch_id`、专用 `executor_instance`、`scope`（node、role 或 host）、role 模式下的 `role`，以及变更角色的固定 `images`。inventory 提供两台完整 `nodes`、`schema:27`、`role_schema:7`（升级前的角色版本 6 也可生成计划）、已审阅桥接兼容性的 `compatible:true`。缺输入或错误拓扑会失败；该标记仍需实际执行的版本、角色、原镜像和健康检查佐证。dry-run 不读取 DB 密钥，不调用 gcloud，不创建锁、日志、缓存或临时文件。

确认输出后，实际运行命令为 `gatebeam-deploy --intent /path/intent.json --config /path/deployment-db.json --executor-instance projects/PROJECT/zones/ZONE/instances/EXECUTOR`。默认每节点排空 60 秒、重新加入后观察 120 秒，显式 drain_seconds/observe_seconds 可在受控范围调整。仅替换 digest 变化的角色；不执行 Compose build/down，不删除 runtime、日志或 spool。镜像先在两边预拉取，外层和私网成员均摘除后等待有限排空；冻结本节点有限的日志偏移，等待实际持久化游标；配置了归档时还必须取得对应批次已提交的归档凭据。worker 在维护模式下停止全局领任务，保留本地收尾，完成后再进入排空。任何缺失凭据都会暂停，不能把 fsync 视为已归档。

计划先从两台 Nginx 的管理上游移除目标 API，并分别等到本机已确认配置的 digest；随后执行外层与私网成员变更、排空、日志同步、受批次约束的镜像批准和目标角色更新。API、私网 CA、公网原生 TLS 分别验证，再分别恢复管理上游和 LB 成员，等待云端健康检查与观察窗口。A 全部通过之前不开始 B。宿主维护使用分别记录的 GCE stop/start，启动继续依赖保留磁盘和本地已生效基线。

当前云适配器接受同项目、同可用区的两台 VM、各含一台 VM 的专用实例组，外部 EXTERNAL TCP 与内部 INTERNAL TCP 的区域透传 backend。成员使用 CONNECTION 模式且无自定义容量/故障转移字段；非此受控基线拒绝自动更新，避免加入时丢失原策略。云写操作使用标准 Compute Engine REST `requestId`、backend fingerprint 和 operation，认证使用 gcloud；不会把代理型 LB 当成透传入口。[Compute Engine backend PATCH](https://cloud.google.com/compute/docs/reference/rest/v1/regionBackendServices/patch) 提供请求标识及操作资源。

操作失败或结果未知时批次暂停，并保留唯一活动批次及 pending step。重复运行相同批次不会重发命令，也不按 TTL 自动接管。恢复使用新的专用执行 VM，提供 `--resume <batch UUID> --proof /path/proof.json --executor-instance <新 VM>`；proof 包含 batch_id、previous_executor、日志的 revision，以及在途 step_id 对应的 cloud_operation 或 host_command_id。实际适配器必须确认旧执行 VM 已 TERMINATED，云操作的 clientOperationId 对应原步骤且目标和最终成员状态正确，或原宿主记录已成功且意图摘要相同。只有非空字符串、未知/失败的宿主记录或仍运行的旧执行端都不能恢复。找不到完成证据时保留暂停状态，不能猜测未执行后重试。

本文命令、IAM、宿主 systemd 和真实 LB 路径仍需在明确授权的云环境验收；本次开发只操作隔离测试资源。

若新容器已完成更新，但第一轮只读验证明确失败，此时管理上游和两个 LB 成员尚未加回，执行器会记录补偿步骤，仅恢复该节点原先批准的镜像，重新完成 API/私网/公网验证、加入和观察，最终批次标为 `rolled_back` 并返回非零结果，另一节点不升级。原计划与补偿步骤同时保留。更新命令的未知结果不能按“验证失败”处理；回退过程本身失败也会暂停。已经重新加回后的观察或基础设施故障会保留健康节点并暂停，需核对具体外部结果后处理。所有回退保留本地证书、撤销和时钟下限，不自动恢复旧 PG 或执行 goose down。

实际预检还会在无网络、只读文件系统、无秘密/持久卷、cap-drop-ALL 的一次性容器中调用当前与候选固定镜像的 `gatebeam --runtime-contract`。输出必须声明本次 schema/角色迁移范围、runtime protocol 1、boot format 1 和 configuration format 2；不能仅凭 inventory 的兼容性确认绕过。该命令在读取任何配置之前返回编译清单。缺少该命令或不满足契约的镜像会被预检拒绝。

实际云端执行还必须提供容量资格记录。可在 intent 增加 `capacity_report_file` 指向受保护 JSON；其内容为 `kind:production`、真实 `required_peak_rps` 和 `trials`。每份 trial 绑定 `node{id,epoch}`、完整 GCP `machine_type` 资源名、四个角色的精确 `images`、每角色 `limits{memory_bytes,nano_cpus,pids}`、`duration_seconds`、`requests`、`errors`、`p95_millis` 和实际 `workload` 描述。各节点的当前及候选镜像组合均须覆盖，相同组合可复用同一 trial。每份至少 10 秒且零错误。每次摘流后由已测的单机或已测的组合承担声明峰值。工具固化规范化内容摘要，并在云端重新核对 VM 类型、宿主实际容器资源限制和固定镜像。该记录必须来自可信的实际测量及人工核对，工具不会凭一个“兼容”确认推断真实业务峰值。没有记录时仍可查看 dry-run 计划，但实际执行会在读取 DB 配置/进行云操作之前被拒绝。

本地完整双节点关卡为：`sh scripts/check-multinode.sh --manifest .work/artifacts/manifest.json --nodes tests/fixtures/multinode/config.json --budget tests/fixtures/multinode/budget.json`。先执行 `sh scripts/build-system.sh` 取得五个固定预构建镜像及 manifest；关卡核对真实镜像 ID、二进制摘要、离线契约和不变资源预算，不用替换二进制绕过最终镜像。可用 `--suite runtime|control|upgrade|capacity|inventory` 单独运行；每个场景拥有独立外部测试 PG，使用统一数据库批次的300秒整包累计保护（命令315秒），由完整验收执行器运行时，原双节点场景和新增清单场景共享900秒阶段保护；这些是 CI 总钟，明确的请求、故障、续期及查询功能期限和角色资源预算保留，缺场景不能以“无测试”通过。节点输入仅接受维护中的隔离双 Compose 模板，不接受生产主机。辅助 S3 使用固定 RustFS 测试镜像及一次性凭据，不代表已验收 Cloudflare IAM。

容量关卡停止 B 的四个角色，由 A 承担新的业务 TLS 连接和真实 S3 归档/DuckDB 查询，记录每档并发、错误、延迟、吞吐、查询完成数及 Docker 资源。测量报告位于 `.work/system-acceptance/multinode/single-node-capacity.json`，明确为 `kind:fixture`，真实业务峰值未知；该报告不能用于生产资格。测试环境是同一个 Docker/Lima VM，包含本地 S3 和私网 HTTP 测试后端，其网络和硬件条件不同于 GCP/R2。报告的是这些条件下的实测值，不是生产容量承诺。节点级故障通过四个角色及网络的销毁/重建、保留卷和断开控制连接模拟；真实 GCP 内核重启、LB 数据路径、供应商权限及逐站 DNS 迁移仍须在后续明确授权的环境验收。


## 升级的功能验证与凭据

两台节点清单中的 `canary_file` 指向各宿主 root 拥有、0600 的受控 JSON，格式见 `deploy/host/upgrade-canary.example.json`。先通过管理后台创建名称以 `gatebeam-upgrade-canary-` 开头、尚未发布且草稿关闭的专用站点，准备具有该站点读写权限的有效会话及匹配 CSRF。凭据只保留在宿主受控文件中，不写入计划、数据库升级日志或镜像。升级前核对会话有效期覆盖整批操作；过期或权限不足会阻断预检。

`business_host` / `business_path` / `business_sha256` 必须对应实际已迁移业务的只读检查地址和预期完整响应体。请求直接连接本节点私网地址的 443，仍验证域名与完整 TLS 链；私有根可通过 `business_trust_file` 提供。业务入口要求客户端 mTLS 时，另外提供 `business_client_certificate_file` 和 0600 的 `business_client_key_file`。检查不发起支付或其他业务写入。

实际预检必须完成业务响应、已登录管理读取、私网标准 OCSP 状态以及 worker 的真实查询和对象存储能力检查。替换 API 后，还通过正常 ACL、CSRF 和幂等接口保存上述关闭站点的现有草稿，验证实际管理写入；不会发布该站点。worker 使用自己节点的一份实际 Parquet 对象调用运行中的查询进程，配置 R2 时还在专属随机 canary 对象上验证条件写入、读取和删除，不创建 bucket、不覆盖历史日志。独立组件初始化或运行失败会使 worker 整体不就绪，但不阻止其他健康组件完成本节点日志查询与收尾。A 验证及观察完整通过后才处理 B。

执行激活前，宿主的一次性 `gatebeam-deploy-host` 工具和受控配置必须已经安装。激活会通过标准私网 SSH 观察真实容器镜像并核对注册的固定摘要，不能以清单中填写的镜像充当运行证据；API、worker 还要验证本角色历史密文确实可解密及自己的注册 recipient/epoch。未完成历史重封装的 B 不能接管。

## 私网角色证书的标准自动续期

管理 API 的服务端证书和网关连接 API 的客户端证书分别由所属进程使用标准 ACME v2/EAB 客户端续期；不增加业务端组件或自创证书协议。首次由管理员按确切内网 DNS 名称及 serverAuth/clientAuth 用途授权并创建标准 EAB，向该角色交付自己的有效初始证书、私钥、EAB 文件和内部 CA 根。管理 API 在 bootstrap 配置中启用续期时使用本机挑战卷。

```json
"private_tls_renewal": {
  "origin": "https://ca.internal.example:8444",
  "email": "REPLACE_WITH_OPERATOR_EMAIL",
  "eab_file": "/run/gatebeam/acme-eab.json",
  "trust_file": "/run/gatebeam/ca-root.pem",
  "http01_webroot": "/var/lib/gatebeam/management-acme"
}
```

`origin` 为现有内部 CA 根地址，客户端按用途选择标准目录。默认每 60 秒检查，在证书剩余有效期进入原有效期三分之一时续期；测试中的短周期不是生产承诺。初次启用后自动取得正式证书，后续使用原 ACME 账号和本角色既有私钥续期，EAB 无须每次人工重建。续期后的证书原子写入本角色保留 capsule 目录的 `renewed-tls.pem`，API 在 TLS 握手时自动加载，网关自动触发本节点派生配置加载，无须手工发布业务配置。失败时保留仍有效的已加载证书，过期则不再就绪。

网关节点的私网 mTLS 客户端使用节点专属 DNS 名称，CA 经 TCP 80 验证其 HTTP-01 响应。管理 API 使用本地挑战目录时，证书中的每个 DNS 名称都必须能把该客户端的 HTTP-01 请求路由到正确节点。专用管理目录只在相应的 HTTP 虚拟主机暴露挑战路径。CA 的 ACME 与状态端口由独立 CA 主机提供。按 [CA 部署说明](../../gatebeam-ca/README.md) 续期和更新 CA 服务本身的 HTTPS 证书，CA 在握手时重新读取 PEM 文件。CA 的数据库和签名材料由 CA 运维单独备份。

API 私网 mTLS 的信任链与撤销信息会自动重读；受控 `certificate_status_profiles_file` 中指定可信发行者及固定 CRL 地址，程序定期获取原始签名 CRL，禁止使用客户端自带 AIA 指挥出站。完整链逐级检查签名、用途、时效和撤销；只把自签名根作为锚点。`api_tls_crl_file` 提供初始 CRL，`api_tls_state_file` 必须位于本 API 的独立保留私有卷，保存与节点/epoch 绑定的撤销和时间下限。缺失、过期、篡改或回退的状态拒绝新连接；会话票据关闭，避免恢复会话绕过检查。已建立的连接按原连接生命周期结束。

本地生效配置同样在切换指针前持久化安全下限。当前配置损坏时，其他逻辑发布版本不能被自动认定安全而回退；同一发布中不再符合安全绑定的证书/信任/撤销材料仅关闭受影响站点。这个选择可能让该节点等待修复，但不能恢复已撤销的访问。另一节点继续服务。

capsule 的不可变 epoch 约束的是网关角色的解密身份；证书、信任和管理摘流状态变化会产生同 epoch 的新密封快照，保留历史密钥快照。旧格式缺少密钥指纹时，只允许原样读取，发生变化需要受控的新备份 epoch。正常摘流、证书续期和角色重启不会把可变状态误当作密钥替换。

本次增强要求 configuration format 2。早期 protocol 1 开发镜像缺少新的证书配置/安全契约，也不能作为本版本自动回退目标；上线前必须确认当前与候选镜像都符合完整离线契约。配置与撤销下限不随程序回退而降低。

GCP 内网 DNS 可使用平台元数据 DNS 地址 `169.254.169.254:53` 或 `[fd20:ce::254]:53`；这里只为固定 DNS 目标开放 53，未开放元数据 HTTP 地址或任意 link-local 目标。[GCP 内网 DNS 官方说明](https://docs.cloud.google.com/compute/docs/internal-dns)。

本地重启已生效且未变化的工件时，仍先保存可信时间和已有安全下限，再执行原生配置校验、切换、激活和实际观察。完成后仅通过已确认工件的专用确认路径原子更新 checkpoint 中的本轮观察时间，不在开始提供流量后再次推进授权或撤销下限。该路径必须匹配原有 Current/Previous 的完整 manifest 和 MetadataDigest，并重新核对安全下限未变化；同授权名称的新 staged candidate 不能借此成为生效配置。当前或 Previous 的最高已记录完成时间均约束后续启动，安全 fallback 不得绕过时钟回退检查。在线发布、受限新工件确认，以及前置安全下限写入中断后的拒绝启动规则保留。磁盘格式及 RuntimeProtocol 不变。
