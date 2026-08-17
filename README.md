# gpt-register-panel

gpt_register 与 Sub2API 的账号、token 差异管理面板。

当前阶段是 M1 只读适配器：

- 读取 gpt_register 的 tokens、use_token、username.json。
- 读取 Sub2API 管理 API 的账号和统计元数据。
- 使用 chatgpt_account_id、chatgpt_user_id、email 做稳定身份匹配。
- 输出脱敏快照和差异结果。
- 当前不执行导入、数据库写入、Phase 3 或任意 shell 命令。

## 本地只读快照

默认只读取 gpt_register 文件：

    npm run snapshot

同时读取 Sub2API 管理 API：

    SUB2API_BASE_URL=http://127.0.0.1:8080 \
    SUB2API_ADMIN_API_KEY=... \
    npm run snapshot:sub2api

也可以使用 SUB2API_JWT 代替管理员 API key。输出只包含邮箱、编号、状态、过期时间和 token 指纹，不包含 token 原文、密码或验证码。

生产环境的 API 凭据应放在未提交的 .env 中。公开 GitHub 仓库不应包含 tokens、use_token、browser-profile、备份、SQLite 数据库或日志。

