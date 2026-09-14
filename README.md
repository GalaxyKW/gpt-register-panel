# gpt-register-panel

gpt_register 与 Sub2API 的账号、token 差异管理面板。

当前功能：

- 读取 gpt_register 的 tokens、use_token、username.json。
- 读取 Sub2API 管理 API 的账号和统计元数据。
- 优先使用 chatgpt_account_id、chatgpt_user_id 做强身份匹配；只有两侧都没有强身份时才允许 email 回退匹配。
- 输出脱敏快照和差异结果。
- 账号表格显示 Sub2API 的历史累计统计和当前账号窗口统计（接口可用时）。
- 独立 SQLite 保存快照、任务状态和审计记录；不会保存 token 原文。
- 差异预览、导入任务、批量 Phase 3 和过期 token 清理入口已接好，但默认关闭所有写操作；不选择账号时的预览表示“查看全部”，导入仍强制要求至少一个选择。
- 工具栏支持选择模型后批量测试已选的上游账号（包括 `error` 和非 `error` 状态）。测试请求复用 Sub2API 的账号测试接口；`error` 账号只有在 SSE 测试成功、状态恢复并确认 `schedulable=true` 后才算成功，非 `error` 账号成功后保留原状态和调度设置，失败账号不由面板主动修改。
- 导入预览只允许把 token 更新到 Sub2API 不可用（状态非 active、不可调度、临时不可调度或已过期）的账号；可用账号即使本地 token 指纹不同也会跳过。来源 token 已过期时也会跳过，需先运行 Phase 3。
- 来源文件的 `expired` 只描述本地 token，不等于 Sub2API 账号已失效；Sub2API 的 OAuth credential 过期时间与账号手动 `expires_at` 分开处理，后者只有在 `auto_pause_on_expired` 开启时才影响调度判断。

## 本地只读快照

默认只读取 gpt_register 文件：

    PANEL_ENV_FILE=/etc/gpt-register-panel/panel.env npm run snapshot

同时读取 Sub2API 管理 API：

    SUB2API_BASE_URL=http://127.0.0.1:8080 \
    SUB2API_ADMIN_API_KEY=... \
    PANEL_ENV_FILE=/etc/gpt-register-panel/panel.env \
    npm run snapshot:sub2api

也可以使用 SUB2API_JWT 代替管理员 API key。输出只包含邮箱、编号、状态、过期时间、统计和 token 指纹，不包含 token 原文、密码或验证码。

## WebUI（默认只读）

先安装 Node.js 18.17 或更高版本，并按锁文件安装依赖：

    node --version
    npm ci

敏感配置必须位于支持 Unix 权限的文件系统，文件由启动面板的账号持有且权限不宽于 `0600`，父目录也不能由不可信用户替换。可用 `PANEL_ENV_FILE` 指定绝对路径；显式路径不存在或不安全时面板会拒绝启动。不要在 NTFS 上的项目目录中继续使用无法落实私有权限的 `.env`：

    sudo install -d -o root -g root -m 0700 /etc/gpt-register-panel
    sudo install -o root -g root -m 0600 .env.example /etc/gpt-register-panel/panel.env
    sudoedit /etc/gpt-register-panel/panel.env
    sudo env PANEL_ENV_FILE=/etc/gpt-register-panel/panel.env npm start

在 `panel.env` 中填写有效的 Sub2API 管理 API key 或 JWT，以及至少 16 位的随机 `PANEL_ADMIN_TOKEN`。项目本地 `.env` 只保留为开发兼容默认值，也必须满足相同权限检查；父进程已有的环境变量优先于文件中的同名配置。

默认只监听 127.0.0.1:4170。在服务器本机打开 http://127.0.0.1:4170/ 即可查看账号表格；另一台电脑浏览器里的 `127.0.0.1` 指向那台电脑本身，并不是服务器。远程管理优先保持面板监听回环地址并建立 SSH 隧道：

    ssh -N -L 4170:127.0.0.1:4170 user@server

随后在本机浏览器打开同一地址。页面支持筛选、搜索、勾选、差异预览、上游账号测试和任务查询；模型列表会优先从 Sub2API 读取，并保证可选择 `5.6-luna`（实际请求 ID 为 `gpt-5.6-luna`）。

## systemd 服务

仓库提供 `deploy/gpt-register-panel.service`。该 unit 直接执行固定的 `/usr/bin/node` 和 `backend/server.js`，通过非敏感的 `PANEL_ENV_FILE` 路径让应用读取 `/etc/gpt-register-panel/panel.env`；不会把管理员令牌或 Sub2API 凭据复制到 unit 或 systemd 环境中。项目目录中的旧 `.env` 会对服务隐藏，避免 NTFS 挂载权限把秘密暴露给其他本机用户。当前生产目录由 root 持有，因此模板暂时使用 `User=root`，但 capability bounding set 与 ambient capabilities 均为空。Phase3 会把已验证的脚本、Node 可执行文件和源码根目录直接继承为子进程 fd 3、4、5，不需要访问父进程 fd 或保留 `CAP_SYS_PTRACE`。迁移到专用服务账号仍是更稳妥的最终方案；迁移时必须同步调整 `panel.env`、`gpt_register`、`runtime`、日志、备份和隔离目录的所有权及权限。

首次安装前先确认 `/mnt/nvme/gpt_register` 中存在 `index.js`、`src/`、`node_modules/`、`package.json` 和所需配置，并创建 unit 要求的运行目录。若已有项目本地 `.env`，可在不打印内容的情况下把它迁移为私有配置，然后立即更换过短或已暴露的令牌：

    cd /mnt/nvme/item/gpt-register-panel
    npm ci
    sudo install -d -o root -g root -m 0700 runtime /etc/gpt-register-panel
    sudo test -d /mnt/nvme/tmp
    sudo install -o root -g root -m 0600 .env /etc/gpt-register-panel/panel.env
    sudoedit /etc/gpt-register-panel/panel.env

迁移完成后应轮换其中全部秘密，并在确认新服务正常后退役项目目录中的旧 `.env`；仅在 unit 中隐藏旧文件不能阻止其他本机用户直接读取 NTFS 上的副本。确认新配置属于实际服务账号且权限为 `0600` 后，再安装并启用：

    sudo install -o root -g root -m 0644 deploy/gpt-register-panel.service /etc/systemd/system/gpt-register-panel.service
    sudo systemctl daemon-reload
    sudo systemd-analyze verify /run/systemd/generator/mnt-nvme.mount /etc/systemd/system/gpt-register-panel.service
    sudo systemctl enable --now gpt-register-panel.service

常用操作：

    systemctl status gpt-register-panel.service --no-pager
    sudo systemctl restart gpt-register-panel.service
    sudo systemctl stop gpt-register-panel.service
    journalctl -u gpt-register-panel.service -n 100 --no-pager

服务不仅声明 `RequiresMountsFor=/mnt/nvme`，还绑定对应 mount unit，并要求该路径确实是可写挂载点：这既避免磁盘未挂载时把生产数据写入根分区下的同名目录，也会在运行中挂载消失时停止面板。异常退出会自动重启；停止时先向主进程发送 SIGTERM，应用默认等待任务 10 秒且硬上限为 12 秒，45 秒总期限到达后 systemd 会清理整个 cgroup。挂载消失后，即使磁盘稍后恢复，也不能假定面板会自动回来；先用 `findmnt` 确认同一设备已在 `/mnt/nvme` 可写挂载，再检查并显式启动服务。

unit 使用只读文件系统视图，只开放以下默认写路径：

- `/mnt/nvme/item/gpt-register-panel/runtime`
- `/mnt/nvme/gpt_register`
- `/mnt/nvme/tmp`

`gpt_register` 根目录必须可写，因为 Phase3 会在其中原子替换 `username.json` 等状态文件；unit 会把 `index.js`、`src`、`node_modules`、包清单和配置文件重新覆盖为只读，并隐藏两个项目的 `.git`。同时启用私有设备视图、禁止子进程新建 namespace、禁用 core dump、限制进程数和 socket address family；保留 Chromium/Xvfb 所需的 Unix、IPv4、IPv6 与 netlink socket。上线新版 unit 前仍应在真实环境跑一次非破坏性的 Phase3 验证，因为 Chromium 或显示环境升级可能引入新的设备需求。

模板按上述固定默认路径收口。若 `panel.env` 或 `gpt_register/config.json` 把数据库、日志、备份、隔离目录、控制面锁、token 输出目录、浏览器 profile 或截图目录移到其他位置，只改应用配置还不够；应在 unit 中加入对应的精确可信路径，并保留代码及配置的只读覆盖。若 `GPT_REGISTER_ROOT` 或挂载点变化，还必须同步修改全部启动检查、`RequiresMountsFor`、`BindsTo` 和读写路径；不能直接把 `/`、`/mnt` 或整个 `/mnt/nvme` 设为可写。所有列入 `ReadWritePaths` 的目录必须在服务启动前存在且由服务账号安全持有。

修改 `/etc/gpt-register-panel/panel.env` 或应用代码后使用 `systemctl restart` 生效。修改仓库中的 unit 时，必须重新执行 `install`、`systemctl daemon-reload`、静态校验和维护窗口重启；单独 `restart` 不会安装仓库副本。不要把真实凭据写入 unit 或提交到仓库。安装前可做静态校验：

    systemd-analyze verify /run/systemd/generator/mnt-nvme.mount deploy/gpt-register-panel.service

该校验也会确认 `/mnt/nvme` 已由 systemd 的挂载生成器管理；找不到 `mnt-nvme.mount` 时应先修正挂载配置，不能删除 unit 的挂载绑定来绕过。安装后的沙箱评分可用 `systemd-analyze security gpt-register-panel.service` 查看。仓库中的 unit 更新不会自动覆盖 `/etc/systemd/system` 里已安装的版本，更新时需重新执行 `install`、`daemon-reload`，再在维护窗口重启。

## 全程结构化日志

面板会把服务启动、每个 HTTP 请求、快照、差异预览、导入、备份、逐账号处理、Phase 3 子进程、过期 token 清理以及成功/失败和耗时写入 JSON Lines 日志。默认路径为 `runtime/panel.log`，也可用以下变量调整：

    PANEL_LOG_PATH=/mnt/nvme/item/gpt-register-panel/runtime/panel.log
    PANEL_LOG_LEVEL=info       # debug / info / warn / error
    PANEL_LOG_MAX_BYTES=10485760
    PANEL_LOG_ROTATIONS=5
    PANEL_LOG_CONSOLE=1        # 同时输出到面板进程终端

日志文件权限为 0600；日志目录必须由服务用户持有且不可由组或其他用户写入，默认新建为 0700。达到大小上限后保留 `.1` 至 `.5` 轮转文件。上游账号测试的每个账号、模型、结果、恢复状态和耗时都会单独记录。查看最近 200 条记录：

    tail -n 50 runtime/panel.log
    curl 'http://127.0.0.1:4170/api/logs?limit=200'

配置了 `PANEL_ADMIN_TOKEN` 或启用 `PANEL_REQUIRE_AUTH=1` 后，所有 `/api/*` 接口都需要通过 `x-panel-token` 或 `Authorization: Bearer ...` 访问；WebUI 收到 401 会提示输入令牌并仅保存在当前浏览器会话。客户端不能通过 `x-panel-actor` 伪造审计操作者，日志中的操作者只会是 `panel-admin`、`local` 或 `anonymous`。认证失败按来源地址限流，超过阈值会短暂返回 429。日志会自动脱敏 access/refresh/id token、JWT、Bearer、API key、密码和 Phase 3 输出，不记录请求体或 token 原文。

示例配置默认 `PANEL_REQUIRE_AUTH=1`。`PANEL_ADMIN_TOKEN` 应使用至少 16 个字符的随机值，并放在仓库外的私有 `panel.env` 中。非回环监听始终要求有效管理员令牌，而且还必须显式设置 `PANEL_ALLOW_INSECURE_REMOTE=1` 来确认明文 HTTP 风险；这个开关不能绕过认证。更安全的做法是保持回环监听，通过 SSH 隧道访问，或让同机 HTTPS 反向代理连接回环地址。

`PANEL_PORT` 留空时使用 4170；部署配置只接受 1–65535 的十进制端口，避免空值意外变成随机端口。只有程序化测试通过 `startServer({ port: 0 })` 时才允许由系统选择临时端口。

## 写入开关

写入必须由服务端显式开启，并同时配置面板令牌：

    PANEL_ADMIN_TOKEN=请换成随机长令牌
    PANEL_WRITE_ENABLED=1
    PANEL_PHASE3_ENABLED=1       # 只有确实需要自动跑 phase3 时才开启
    npm start

导入流程会重新读取并比较快照版本，先通过 Sub2API 管理 API 导出备份，再逐项处理：已有且明确不可用的账号按精确 ID 更新 OAuth 凭据；新账号才调用 `import/codex-session`，并显式禁止该请求退化为更新。新账号名称从现有最大编号后按候选稳定顺序分配为 `free00001` 形式。每次远程写入前都会再次核对来源文件版本、强身份和目标可用性；可用或状态无法可靠判断的账号都会跳过。创建响应必须明确且一致地报告单个新账号，不能把更新、跳过或已存在 ID 伪装成创建成功。失败项写入独立审计表。未配置备份或来源版本变化时不会写入。浏览器不会接触 Sub2API API key、JWT 或 token 原文。导入、Phase 3 和账号测试对共享目标使用数据库 claim；同一目标重复提交会返回 409，不会创建多份任务。SQLite 写入使用跨进程 bakery 租约和事务，锁目录必须由服务用户持有且不可由其他用户写入；服务重启时未完成任务会标记为 `interrupted`。

同一身份有多个来源 token 时，导入计划按以下稳定顺序选择唯一赢家：过期字段未标记为无效（有效或缺失）优先于无效值、未过期优先于已过期、未禁用优先于已禁用，然后依次比较过期时间、刷新时间和文件修改时间（均以较新者优先）。只有这些刷新度信号完全相同时，才依次以存在 access 凭据、存在 refresh 凭据、位于 `tokens` 目录和相对路径自然排序作为决胜项；最终只写入赢家，其他版本会跳过。

文件名符合 `old_codex-*` 或 `old_codex_*` 的 token 会被识别为历史备份。默认快照不会把它们计入差异或导入候选，原文件仍保留；WebUI 勾选“显示历史备份”后可查看这些文件。接口也可使用 `/api/snapshot?withSub2api=1&includeHistorical=1` 查看历史备份，历史备份不会参与导入。

没有 `access_token` 或可匹配身份的来源文件会标记为“文件异常”，不会进入导入计划；过期字段存在但无法解析的文件会单独标记为“过期时间无效”，同样禁止自动导入。导入任务只把远程接口的计数、状态和账号 ID 保存到面板 SQLite，不保存远程返回中的凭据字段。统计接口部分账号失败时，概览和对应单元格都会明确显示读取失败，不会伪装成 `0`。

Phase 3 的逻辑接口固定为 `node /mnt/nvme/gpt_register/index.js --phase3 --email=...` 或 `--phone=...`，禁止 shell 拼接和任意路径；实际启动前会分别打开并验证 Node、`index.js` 和源码根目录，再通过继承的 `/proc/self/fd/4`、fd 3 与 `/proc/self/fd/5` 执行，避免路径在校验后被替换。`gpt_register` 的非交互参数向后兼容原有交互选择。成功后会要求对应 token 指纹发生变化；识别到账号被删除/停用时，会把 `username.json` 标记为 `account_deleted` 和 `phase3Disposition=discard`，后续不会重复排队。面板允许一次提交最多 100 个账号，但仍按共享浏览器 profile 串行执行；队列总量也受 `PANEL_PHASE3_MAX_ACTIVE_JOBS` 限制。同一请求和已有队列中的重复账号会逐项返回并跳过，浏览器刷新后会恢复整批任务状态。Phase 3 对 `username.json` 使用 32 MiB 不可上调硬上限；TERM/KILL 后仍未关闭管道时会在最终期限强制收口任务。

“清理过期 token”只扫描 `GPT_REGISTER_ROOT/tokens` 和 `GPT_REGISTER_ROOT/use_token` 下的普通 JSON 文件，要求能解析且明确存在过期时间；扫描结果带版本号，确认操作时会重新校验版本，文件发生变化就拒绝处理。所谓删除实际是移动到 `GPT_REGISTER_ROOT/.panel-quarantine/expired-tokens`（或 `PANEL_TOKEN_QUARANTINE_DIR` 指定的目录），并按批次保留原相对路径，便于恢复；跨文件系统时会先完整复制并刷盘，再移除来源。删除列表、跳过项和操作者会写入结构化日志与 SQLite 审计，不会记录 token 原文；无 access token、无法解析、无过期时间或未过期文件不会处理。恢复时将隔离目录中的文件移回原来的 `tokens/` 或 `use_token/` 目录。

导入和 Phase 3 任务会先记录为 `queued`，执行阶段改为 `running`，结束为 `succeeded`、`partial`、`failed` 或 `interrupted`。服务重启不会假装恢复浏览器/远程 API 操作，旧的 queued/running 任务会明确标记为 `interrupted`；WebUI 会轮询任务终态后再刷新账号表。

浏览器刷新后，WebUI 会自动接回最近的 queued/running 任务；任务状态接口短暂失败时会有限重试，避免把仍在执行的任务误显示成失败。

独立 SQLite 默认位置由 `PANEL_DB_PATH` 指定，建议使用项目 `runtime/panel.sqlite3` 并保持 0600 权限；`PANEL_DB_MAX_BYTES` 只能在代码硬上限内调整加载上限。备份默认写入 `PANEL_BACKUP_DIR`，目录必须为当前用户所有且权限不宽于 0700，并由保留天数、文件数和总字节上限共同约束；这些运行态路径已加入 `.gitignore`。跨进程任务锁默认派生自数据库路径，也可通过 `PANEL_CONTROL_LOCK_PATH` 指定；等待时间和轮询间隔可分别用 `PANEL_CONTROL_LOCK_TIMEOUT_MS`、`PANEL_CONTROL_LOCK_POLL_MS` 调整。Phase 3 的输出保留量和终止宽限时间由 `PANEL_PHASE3_MAX_OUTPUT_BYTES`、`PANEL_PHASE3_KILL_GRACE_MS` 限制；TERM 宽限硬上限为 4 秒，随后最多再用 1 秒执行 KILL 和进程树核验，为默认 10 秒的服务停止窗口保留 token 核对与终态落盘时间。账号测试批次由 `PANEL_ACCOUNT_TEST_JOB_TIMEOUT_MS` 设置总时限。源 token 和 `username.json` 的单文件读取上限可通过 `GPT_REGISTER_TOKEN_MAX_BYTES`、`GPT_REGISTER_USERNAME_MAX_BYTES` 下调，`username.json` 的账号数还受 `GPT_REGISTER_USERNAME_MAX_RECORDS` 限制；token 扫描另受 `GPT_REGISTER_TOKEN_MAX_FILES` 与 `GPT_REGISTER_TOKEN_TOTAL_MAX_BYTES` 约束，代码仍会执行不可突破的硬上限。

Sub2API 管理地址使用明文 HTTP 时只允许回环主机；其他主机必须使用 HTTPS。仅在完全受控网络中才能显式设置 `SUB2API_ALLOW_INSECURE_HTTP=1`，该开关会让管理凭据和 OAuth 更新暴露于明文链路，因此不建议启用。

生产环境的 API 凭据应放在仓库外的私有 `panel.env` 中，`PANEL_ADMIN_TOKEN` 至少 16 个随机字符（建议使用更长的高熵值），并保持 `PANEL_ALLOW_INSECURE_WRITE=0`。建议 `panel.env`、`username.json`、token JSON、日志、SQLite 和备份文件权限为 0600，包含它们的 `tokens`、`use_token`、`runtime`、备份及隔离目录权限为 0700，并使用专用低权限服务账号运行。若挂载参数、ACL 或文件系统无法落实这些权限，应先修正挂载策略或把敏感文件迁移到支持权限隔离的存储，再开放网络访问。公开 GitHub 仓库不应包含 tokens、use_token、browser-profile、备份、SQLite 数据库或日志。Sub2API 升级后先运行 `npm test` 和只读快照，确认管理员 API 契约再打开写入开关。
