# gpt_register WebUI 项目计划书

版本：v0.1（方案评审稿）
日期：2026-08-17
项目目录：/mnt/nvme/item/gpt-register-panel

## 1. 项目目标

建设一个独立的 gpt_register WebUI 面板，用来管理 gpt_register 产生的上游账号和 token，并在确认后同步到 Sub2API。

面板需要完成以下闭环：

1. 读取 Sub2API 中 free00001、free00002 等上游账号，展示状态和使用统计。
2. 读取 /mnt/nvme/gpt_register/tokens 和 /mnt/nvme/gpt_register/use_token，识别 token 来源、身份、过期时间和异常。
3. 支持状态/来源/差异筛选、搜索、勾选账号和分页。
4. 对 token 文件、use_token 和 Sub2API 账号做差异检查，在写入前展示 dry-run 结果。
5. 按稳定身份幂等导入新 token；新增账号按文件名顺序分配下一个 free 编号。
6. 对过期或需要更新的账号，通过受控方式运行 node index.js --phase3，完成后校验并同步 Sub2API。
7. 记录任务进度、操作人、结果、失败原因和审计日志，提供备份与回滚路径。
8. 面板作为独立项目维护，具备独立 Git 仓库，不把运行态 token 或账号密码提交到仓库。

## 2. 当前阶段边界

M1 只读适配器已经完成，M2 任务和安全骨架已经落地。生产写入仍默认关闭：

- 只读快照读取 `tokens`、`use_token`、`username.json` 和 Sub2API 管理 API。
- 独立 SQLite 只保存快照摘要、任务、账号映射和审计，不保存 token 原文。
- 差异预览、Sub2API 导入和 Phase 3 入口存在，但必须由服务端显式打开并配置面板管理员令牌。
- 未执行生产导入、数据库直连、Phase 3、邮箱验证码或 token 刷新；本仓库不包含运行态凭据。

## 3. 已确认的现状

### 3.1 gpt_register

- 源码目录：/mnt/nvme/gpt_register。
- 已有 Git 远程：https://github.com/luoganzhi/gpt_register.git。
- 当前仓库有运行态修改和敏感文件，不能把整个运行目录直接提交。
- 主程序是 CommonJS 的 /mnt/nvme/gpt_register/index.js。
- --phase3 当前会从 username.json 中按创建时间倒序列出有邮箱和密码的记录，交互输入序号、邮箱或手机号选择账号。
- 随后通过浏览器完成 Codex OAuth 和邮箱验证码，调用 OAuth token 接口，并写入 tokens/codex-<email>-free.json。
- 成功后会更新对应 username.json 记录的状态。
- src/oauthService.js 会写入 access_token、refresh_token、id_token、邮箱、账号 ID、过期时间等字段。
- 这是交互式程序，不应让 Web 请求直接拼接任意 shell 命令。

### 3.2 Sub2API

- 源码目录：/mnt/nvme/sub2api。
- 部署目录：/service/sub2api-deploy，应用和 PostgreSQL 通过 Docker 网络通信。
- 账号业务编号为 free00001 这种格式，不能把数据库自增 ID 当作业务编号。
- 现有账号统计相关改动和运行态未提交修改不在本阶段处理。
- 过去的 token 导入曾直接写 PostgreSQL；这可以作为受控恢复脚本，但不能暴露给浏览器。

## 4. 总体架构

项目独立放在 /mnt/nvme/item/gpt-register-panel，建议结构：

    gpt-register-panel/
    ├── backend/       HTTP API、认证、差异计算、审计
    ├── frontend/      账号表格、差异预览、任务页面
    ├── worker/        导入和 Phase 3 后台任务
    ├── adapters/      Sub2API、gpt_register 文件系统适配器
    ├── migrations/    面板自己的任务和审计表
    ├── docs/
    ├── tests/
    ├── .env.example
    ├── docker-compose.yml
    └── README.md

建议技术栈为 Node.js + TypeScript + Fastify，前端使用 React + Vite + TypeScript。面板自身的任务、快照和审计数据第一版可用独立 SQLite；不复用 Sub2API 业务表。导入和 Phase 3 使用独立 worker，并默认串行执行。

数据流：

    浏览器
      ↓ HTTPS/认证
    Web API
      ├─ gpt_register 文件适配器 → tokens、use_token、username.json
      ├─ Sub2API 适配器          → 管理 API（首选）或窄权限内部接口
      └─ Worker                  → 固定的 Phase 3 任务、导入任务、审计

浏览器不能直接访问 token 文件、PostgreSQL、Docker socket 或执行命令。

## 5. Sub2API 集成策略

已检查当前 Sub2API 源码和随项目提供的管理员 CLI，确认已有可用管理 API，因此不需要新增内部接口，也不需要把 PostgreSQL 作为常规通道。面板适配器优先使用：

- `GET /api/v1/admin/accounts`、`GET /api/v1/admin/accounts/:id`：账号和凭据元数据读取。
- `GET /api/v1/admin/accounts/:id/stats`、`GET /api/v1/admin/accounts/:id/today-stats`、批量 today-stats：历史和当前周期统计。
- `POST /api/v1/admin/accounts/import/codex-session`：新 Codex session 的幂等导入，支持 `update_existing`、`group_ids`、`skip_default_group_bind` 等字段。
- `POST /api/v1/admin/accounts/:id/apply-oauth-credentials`：指定账号的 OAuth 凭据原子更新，只接受 `type`、`credentials`、`extra`，并由 Sub2API 负责清理错误和失效 token 缓存。
- `GET /api/v1/admin/groups/all`：动态读取 `share` 分组 ID，不在前端写死数字。
- `POST /api/v1/admin/accounts/:id/refresh`：需要时触发已有 refresh token 的刷新。

管理员 CLI 支持 `x-api-key` 或管理员 JWT。面板服务端保存最小权限凭据，浏览器不接触 API key、JWT 或原始 token。

所有写入都必须有备份或可逆变更记录，完成后复读账号、刷新缓存并做健康检查。只有管理 API 不可用时，才把最小权限 PostgreSQL worker 作为人工恢复兜底。

这样面板与 Sub2API 解耦，Sub2API 后续升级不会覆盖面板；升级时重点验证上述 API 契约和响应字段。

## 6. 数据模型和敏感信息边界

### 6.1 稳定身份

账号匹配不能只依赖 free 编号。身份键按以下优先级计算：

    chatgpt_account_id
    → chatgpt_user_id
    → 规范化后的 email

辅助字段包括 access_token_sha256、refresh_token_sha256、source_file、文件修改时间、Sub2API 账号 ID、过期时间和最近同步时间。

### 6.2 面板自身数据表

至少包含：

- sync_snapshots：某次读取的来源摘要和版本。
- sync_items：差异项目、身份键、来源、风险等级和处理结果。
- sync_jobs：导入或 Phase 3 任务的状态、参数摘要、时间和错误摘要。
- audit_events：操作人、动作、目标身份、前后指纹、结果和关联任务。
- account_links：gpt_register 记录、token 文件和 Sub2API 账号的稳定映射。

原始 token 只在后端受控读取和写入时存在，不返回前端、不写普通日志、不保存进面板数据库。确需临时落盘时使用专用目录和 0600 权限，任务结束后清理。

## 7. 账号管理界面

首屏直接进入“账号管理”。表格建议支持可选列：

- Sub2API 账号名，例如 free00001。
- 邮箱或脱敏邮箱。
- Sub2API 状态。
- token 来源：tokens、use_token、两边都有、仅 Sub2API。
- token 有效期、距离过期时间、最近更新时间。
- 历史累计使用量。
- 当前刷新周期使用量。
- 请求数、token 数、成本。
- 差异状态、风险等级和复选框。

筛选项包括账号状态、token 来源、差异类型、是否过期、是否缺少 refresh token、创建时间和关键字。列表使用服务端分页，避免一次性返回所有敏感元数据。

批量入口包括刷新差异、查看勾选项差异、预览导入、确认导入、排队 Phase 3、查看任务日志。写操作显示数量、目标账号和差异摘要，不提供一个无确认的“全部同步”。

## 8. 差异检查算法

每次检查生成不可变快照，分别读取：

1. tokens：按文件名排序，解析 JSON 和 JWT payload。
2. use_token：使用同一解析器，记录来源目录和文件时间。
3. Sub2API：通过适配器读取账号、凭据摘要、业务名称、状态和分组。

差异类型至少包括：

- token_only：只在 token 目录存在。
- sub2api_only：只在 Sub2API 存在。
- token_changed：身份相同但 token 指纹不同。
- expired：token 已过期或过期时间无法解析。
- missing_refresh_token：缺少 refresh token。
- duplicate_identity：多个文件对应同一身份。
- invalid_file：JSON、JWT 或必需字段解析失败。
- status_abnormal：Sub2API 账号状态异常或被禁用。
- mapping_conflict：邮箱、account ID 等字段互相冲突。

tokens 和 use_token 同一身份出现多个版本时，默认只把修改时间较新的有效记录作为候选，但必须明确标记冲突，不能静默覆盖。

## 9. 新 token 导入流程

### 9.1 预览

1. 用户刷新来源快照并选择账号。
2. 后端解析、归一化身份、检查重复和冲突。
3. 返回 dry-run：新增、更新、跳过、冲突、格式错误和预计编号。
4. 前端只显示 token 指纹变化，不显示原文。

### 9.2 确认

1. 创建全局同步锁，禁止并发导入。
2. 重新校验快照版本，防止确认旧数据。
3. 导入前执行 pg_dump 或调用 Sub2API 导出接口，备份文件权限为 0600。
4. 对已有身份幂等更新；不重复创建账号，不覆盖无关分组和使用统计。
5. 新身份按文件名顺序分配编号，从当前最大 free 编号加一开始，例如 free00151、free00152。
6. 第一版不自动重命名已有账号、不填补历史空洞，避免破坏外部引用。
7. 绑定配置中的 share 分组并记录实际 group ID，不能把数字写死在前端。
8. 刷新缓存、健康检查、复读验证。
9. 写审计日志并返回每个账号的成功、跳过或失败原因。

### 9.3 幂等和回滚

使用“快照版本 + 身份键 + token 指纹”作为幂等键，重复点击不能重复建号。回滚优先使用导入前备份；API 更新则保存旧指纹和可逆变更清单。回滚同样必须经过 worker、权限检查和审计。

## 10. Phase 3 更新流程

### 10.1 推荐改造

给 gpt_register 增加向后兼容的非交互参数，例如：

    node index.js --phase3 --email=example@example.com

也可以使用 username 记录 ID。参数只能匹配后端从 username.json 读取并校验过的记录，不能接收任意路径、命令或 shell 片段。建议增加机器可读的结果摘要，便于 worker 判断成功、失败和写入的 token 文件。

### 10.2 Worker 约束

- 使用 spawn 或 execFile，禁止 shell: true 和字符串拼接命令。
- 打开并校验 /mnt/nvme/gpt_register 后，将其固定为继承的子进程目录 fd，并通过 `/proc/self/fd` 作为工作目录；环境变量只允许必要配置。
- 任务默认串行，避免共享 browser-profile、邮箱验证码和临时状态。
- 设置超时、取消、重试上限和任务锁。
- stdout/stderr 进入脱敏日志，过滤 access token、refresh token、验证码、密码和 OAuth code。
- 成功后检查 token 文件修改时间、稳定身份和必需字段，不能只看进程退出码。
- 新 token 身份必须与选择的账号一致；不一致就停止导入。
- 通过同一导入适配器更新 Sub2API，重要变更再次显示 dry-run 并确认。

如果暂时不能改 gpt_register，可用受控 pseudo-terminal 选择序号，但只能作为过渡方案，不能允许用户提交任意输入串。

## 11. 安全模型

- 面板必须有管理员认证和角色权限，写操作至少需要管理员角色。
- 使用 HttpOnly、Secure、SameSite cookie，启用 CSRF 防护和登录限流。
- 前端只显示脱敏邮箱、过期时间、状态和 token 指纹前后几位。
- 文件路径仅允许白名单目录，拒绝任意路径。
- Web API 不挂载 Docker socket，浏览器不连接 PostgreSQL。
- Phase 3 只允许固定程序和固定参数，禁止任意命令执行。
- token、密码、验证码、OAuth code 不进入日志、错误响应或 Git。
- .env、config.server.json、tokens、use_token、browser-profile、备份和日志全部排除出 Git。
- PostgreSQL 兜底账号使用最小权限；备份和密钥文件限制为服务用户可读。
- 导入、更新、回滚、删除和认证失败都写审计。
- 同步任务使用全局锁、账号级锁和超时，防止重复导入或同时刷新 profile。

直接改数据库的风险仍然存在：拥有 Docker、PostgreSQL 凭据或宿主机 root 权限的人可以绕过 Sub2API 业务校验和审计。因此数据库直连只能是后端 worker 的最后兜底，不能成为 WebUI 的常规路径。

## 12. Git 和更新兼容性

面板使用独立的 GitHub **公开仓库**，仓库名暂定为 `gpt-register-panel`。仓库只保存代码、迁移、测试、文档和脱敏配置模板，不保存运行态账号和 token。

至少排除：

    .env
    .env.*
    !.env.example
    tokens/
    use_token/
    browser-profile/
    logs/
    backups/
    *.sql
    *.sql.gz
    *.sqlite
    *.sqlite3
    data/
    runtime/
    node_modules/
    dist/

## 13. 实现状态与下一步

已完成：文件系统与 Sub2API 只读适配器、稳定身份差异引擎、历史/当前窗口统计列、筛选和勾选 WebUI、独立 SQLite 任务/审计表、快照版本校验、备份前置检查、受控导入任务、Phase 3 非交互选择参数、默认关闭的管理员认证与写入开关。

上线前仍需在本机完成：配置有效的 Sub2API 管理 API 凭据、确认 `share` 分组策略、用测试账号做一次导入和回滚演练、决定是否启用 Phase 3，并完成 GitHub 仓库的首次推送。Sub2API 后续更新不会覆盖本项目；只需复核管理员 API 契约和接口响应字段。
当前本机 Git 身份和 GitHub CLI 账号名都是 `wskk267`，远程候选地址为 `https://github.com/wskk267/gpt-register-panel.git`。本机保存的 GitHub CLI token 已失效，推送前需要重新登录或提供可用 SSH/Token；在凭据恢复前不会把任何敏感文件上传。

面板独立目录和独立仓库，Sub2API 更新不会覆盖面板代码。若只使用管理 API，升级时验证 API 契约即可；若增加 Sub2API 内部接口，则保留小补丁和契约测试，升级后先跑适配器测试。每次升级前后做只读差异检查，确认账号数、身份键和分组没有异常变化。

## 14. 分阶段里程碑

### M0：方案和边界（已完成）

已完成计划书、字段清单和风险确认；已确认 Sub2API 管理 API、GitHub 公开仓库方向、非交互 Phase 3 参数、最大编号加一、SQLite 和备份方案。

### M1：只读适配器（基础层已完成）

已建立独立项目和 .gitignore，完成 token、use_token、username.json 的脱敏读取、JWT 身份归一化、token 指纹和差异引擎；已实现 Sub2API 管理 API 的只读账号/分组/统计客户端。线上 smoke test 仍需有效的管理员 API 凭据。

### M2：账号管理界面（已完成）

完成服务端分页、筛选、列选择、状态和 token 元数据显示，接入历史累计使用量和当前刷新周期使用量。

### M3：dry-run 和导入（骨架已完成）

完成差异预览、选择性导入、编号分配、幂等更新和备份前置检查；真实账号的缓存刷新、健康检查和回滚演练待 staging 验证。

### M4：Phase 3 任务（骨架已完成）

完成 gpt_register 非交互参数、worker、串行锁、超时和日志脱敏；需在 staging 账号上验证浏览器流程和 Sub2API 更新闭环。

### M5：上线和运维

配置反向代理、认证、备份保留和监控，建立 Sub2API 升级后的契约测试、回归清单和私有 CI。

## 15. 测试计划

### 单元测试

覆盖 JSON/JWT 解析、时间判断、身份归一化、文件名排序、free 编号分配、重复身份、坏文件、差异分类、幂等键、日志脱敏和路径白名单。

### 集成测试

使用脱敏 fixture 模拟 tokens、use_token 和 Sub2API，测试新增、更新、跳过、冲突、过期、回滚、API 超时、缓存刷新失败、重复提交和 Phase 3 worker 异常。

### 端到端测试

覆盖账号筛选、勾选、差异预览、任务进度、权限拦截、敏感数据不泄露、桌面/移动端表格布局，以及 Sub2API 升级后的 staging 回归。

## 16. 风险、回滚和监控

- Sub2API API 字段变化：适配器版本化、契约测试、升级前只读检查。
- 身份字段缺失或冲突：阻止自动导入，要求人工选择。
- token 过期或 refresh token 无效：标记风险，不覆盖有效凭据。
- Phase 3 浏览器或验证码卡住：超时、释放锁、保留脱敏日志、可手工重试。
- 导入中途崩溃：事务或可逆清单、导入前备份、启动时扫描未完成任务。
- 凭据泄露：最小权限、日志过滤、私有仓库和密钥轮换。
- 误操作：默认 dry-run、明确勾选范围、写入前摘要和二次确认。

监控记录任务成功率、导入数量、冲突数量、Phase 3 耗时、失败原因、Sub2API 健康状态和备份结果，不记录原始 token。

## 17. 已确认的选项和剩余问题

已确认：

1. 使用 GitHub 公开仓库，仓库名暂定为 `gpt-register-panel`。
2. 接受给 gpt_register 增加 `--phase3 --email=...` 这类向后兼容参数。
3. 已确认 Sub2API 有管理员 API，面板直接复用，不新增内部接口。
4. 新账号编号采用“当前最大编号 + 1”，不填补旧空洞、不重命名已有账号。
5. `tokens` 与 `use_token` 冲突时，以较新的有效 token 作为候选，但必须人工确认。
6. 面板任务和审计数据使用独立 SQLite。
7. 保留每次导入前的 Sub2API 管理 API 导出备份；只有 API 不可用且人工执行恢复时才使用 SQL 压缩备份，计划按 30 天保留。

只剩下两个部署参数需要在上线前确定：

1. 面板只允许本机/内网访问，还是需要公网域名和 HTTPS？
2. 备份保留天数是否采用默认 30 天？

## 18. 下一步
先用有效管理员 API 凭据完成线上只读契约检查，再用单个 staging 账号演练预览、备份、导入和回滚；确认结果后再分别开启 M3 写入和 M4 Phase 3。
