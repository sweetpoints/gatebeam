# Gatebeam 中文认证控制台

当前交付只有登录、首次绑定、恢复及真实身份/会话概览。账号、站点、发布等后续界面尚未交付；页面不制造业务数据。权限和会话状态始终由 identity API 判定。

## 构建与本地预览

从仓库根目录运行。Node **26.13.x**、pnpm **12.16.1**；packageManager、直接依赖与锁文件固定。`pnpm-workspace.yaml` 仅允许 vue-demi 已审查的安装脚本。Lucide 官方已经将 `lucide-vue-next` 标为废弃，因此采用官方替代包 `@lucide/vue`。TypeScript 使用已验证兼容当前 Volar 的 5.9.3（Volar 的 peer 声明 `<7`，不采用不兼容的 TypeScript 7）。

```sh
python3 scripts/bounded-command.py 180 pnpm --dir web install --frozen-lockfile --store-dir "$PWD/.work/pnpm-store"
python3 scripts/bounded-command.py 90 pnpm --dir web typecheck
python3 scripts/bounded-command.py 90 pnpm --dir web build
```

API 从启动工作目录的固定 `web/dist` 提供可信构建产物。部署应将这些文件与程序放在同一发布包中，并从该发布根目录启动。没有构建产物时，Go 的构建/单元测试仍正常，管理页面明确返回 503；API 本身继续正常服务。仅 `/`、`/login`、`/enroll`、`/recover` 返回入口页面，`/assets/` 只提供构建产物中的普通文件。未知/API 路径不会回退至 HTML，不存在请求指定文件系统根目录的参数。

现有本地 API 的 JSON 配置需要 `environment=development`、`mode=api`、实际 `database_file`、`identity_file`、回环 `api_listen`，以及**与浏览器访问地址完全相同**的 `api_origin`。按照现有迁移及显式交互式 bootstrap 流程初始化，再从发布根目录运行 `go run ./cmd/gatebeam -config <本地配置>`，访问其 API 地址，即为同源完整预览。bootstrap 的终端保护保持不变。

可用 `docker compose --profile preview run --rm web-build` 在独立、有 180 秒上限及 CPU/内存限制的 Node 容器构建相同产物，随后由宿主 API 同源提供。此服务只负责构建；不会初始化数据库或自动创建账号。它使用独立依赖卷，避免复用宿主 macOS 的原生模块。需要 Node 镜像和 npm registry 可访问。compose 预览构建配置不代表生产部署。

如需热更新，`pnpm --dir web dev` 将 `/auth` 等 API 路径转发到 `GATEBEAM_DEV_API`（默认 `http://127.0.0.1:8080`）；API 的 `api_origin` 必须显式配置为 Vite 实际浏览器地址，代理不改写 Origin。不要放宽服务端来源策略。

## 一次性资料与会话

初始资料直接接受真实 bootstrap 或管理员创建返回的 JSON：`invite_id`、`provisioning_uri`、`expires`。可粘贴在首次绑定页面，或在 `/enroll#bundle=<encodeURIComponent(JSON)>` 的 fragment 中传递。fragment 读取后立即通过 replaceState 清除，绝不将邀请或 URI 放入路径/query；URI 只在当前页面内存中显示，可隐藏。恢复页面使用真实 `/auth/recover` 响应，在内存中传递到绑定页面。离开或刷新会丢弃资料；重新绑定完成后的恢复码只显示一次。

密码、TOTP seed、邀请、恢复码、会话 bearer 均不进入 localStorage/sessionStorage/持久化 Pinia。会话 Cookie 由后端设置为 HttpOnly、SameSite=Strict，生产 Secure；前端只在标签页 sessionStorage 中保存 `csrf_token`。这是已有登录响应，**没有扩展后端契约或弱化校验**，刷新后可退出。新标签页或清除该值后不能完成退出写操作，界面要求重新登录以取得新的 CSRF 资料，不假报退出成功。无法通过 CSRF 校验的写操作不会重试。后端当前会话、禁用、恢复及权限版本是权威。

控制台在进入路由、窗口聚焦、每 15 秒及手动刷新时重新验证会话；会话拒绝后清理本地状态并返回登录。已经渲染的身份信息不构成管理授权。没有后续业务功能导航或模拟统计。

## 真实浏览器验收

```sh
GATEBEAM_BROWSER_CHANNEL=chrome scripts/check-web.sh auth
# CI/portable：先安装锁定版本 Playwright 对应的 Chromium，再运行：
python3 scripts/bounded-command.py 180 pnpm --dir web exec playwright install chromium
scripts/check-web.sh auth
```

默认不指定 channel，使用锁定 Playwright Chromium；本地显式指定 `chrome` 使用系统 Chrome 的全新隔离 profile，不接触现有浏览器资料。macOS 沙箱若阻止 Chrome 启动，需要允许该有界本地浏览器进程，不应将启动失败误报为行为红灯。

`check-web.sh` 先做冻结安装、类型检查及构建，再复用 `check-db.sh` 只启动本次拥有的 PostgreSQL 18 容器（随机回环端口、512 MiB、1 CPU、128 PID、临时数据库、精确清理）。Go integration fixture 使用真实 identity Bootstrap 和真实 HTTP handler；不调用终端 bootstrap、不修改 TTY 保护，也不向产品添加测试端点。浏览器直接调用真实认证 API，使用 RFC 6238 SHA-1 六位/30 秒标准动态码；为了不等待时间窗口，登录用服务端本来允许的下一时间步，不修改产品时钟。禁用用测试夹具写权威数据库状态，验证后续 API/页面拒绝；并未测试管理员禁用操作界面。

一次性 fixture 数据仅写入测试独占临时目录（0600），测试结束删除。浏览器输出经过秘密脱敏；截图、录像、trace 与自动页面快照关闭，错误上下文输出也在临时目录删除。测试没有提交固定密码、seed、邀请、会话或恢复码。默认 GOCACHE 不变，Go 测试保持 `-p 2 -timeout 90s`。

覆盖：pending 禁止管理、绑定与恢复码关闭、密码/TOTP 登录、HttpOnly Cookie、刷新会话与退出、缺失 CSRF 的管理写与退出拒绝、错误 Origin 拒绝、CSRF 资料丢失不假报退出、退出后原凭据拒绝、真实恢复并重新绑定、禁用后原页面请求拒绝。仅验收当前认证基础，不声称后续控制台业务、生产 TLS/反代、跨浏览器或部署已通过。

技术依据：[Vue TypeScript](https://vuejs.org/guide/typescript/overview)、[Vite](https://vite.dev/guide/)、[Tailwind Vite](https://tailwindcss.com/docs/installation/using-vite)、[TanStack Vue Query](https://tanstack.com/query/latest/docs/framework/vue/overview)、[Lucide Vue](https://lucide.dev/guide/packages/lucide-vue)、npm 官方 registry 的各固定版本元数据。
