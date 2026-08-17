# gpt-register-panel

gpt_register 与 Sub2API 的账号、token 差异管理面板。

当前已完成 M1 只读适配器和 M2 受控任务骨架：

- 读取 gpt_register 的 tokens、use_token、username.json。
- 读取 Sub2API 管理 API 的账号和统计元数据。
- 使用 chatgpt_account_id、chatgpt_user_id、email 做稳定身份匹配。
- 输出脱敏快照和差异结果。
- 账号表格显示 Sub2API 的历史累计统计和当前账号窗口统计（接口可用时）。
- 独立 SQLite 保存快照、任务状态和审计记录；不会保存 token 原文。
- 差异预览、导入任务和 Phase 3 入口已接好，但默认关闭所有写操作。

## 本地只读快照

默认只读取 gpt_register 文件：

    npm run snapshot

同时读取 Sub2API 管理 API：

    SUB2API_BASE_URL=http://127.0.0.1:8080 \
    SUB2API_ADMIN_API_KEY=... \
    npm run snapshot:sub2api

也可以使用 SUB2API_JWT 代替管理员 API key。输出只包含邮箱、编号、状态、过期时间、统计和 token 指纹，不包含 token 原文、密码或验证码。

## 只读 WebUI

    cp .env.example .env
    # 在 .env 中填写有效的 Sub2API 管理 API key 或 JWT
    npm start

默认只监听 127.0.0.1:4170，打开 http://127.0.0.1:4170/ 即可查看账号表格。页面支持筛选、搜索、勾选、差异预览和任务查询。

## 写入开关

写入必须由服务端显式开启，并同时配置面板令牌：

    PANEL_ADMIN_TOKEN=请换成随机长令牌
    PANEL_WRITE_ENABLED=1
    PANEL_PHASE3_ENABLED=1       # 只有确实需要自动跑 phase3 时才开启
    npm start

导入流程会重新读取并比较快照版本，先通过 Sub2API 管理 API 导出备份，再逐项调用 `import/codex-session`，失败项写入独立审计表。未配置备份或来源版本变化时不会写入。浏览器不会接触 Sub2API API key、JWT 或 token 原文。

Phase 3 由固定的 `node /mnt/nvme/gpt_register/index.js --phase3 --email=...` 启动，禁止 shell 拼接和任意路径；`gpt_register` 的非交互邮箱参数向后兼容原有交互选择。

独立 SQLite 默认位置由 `PANEL_DB_PATH` 指定，建议使用项目 `runtime/panel.sqlite3` 并保持 0600 权限；备份默认写入 `PANEL_BACKUP_DIR`，这些运行态路径已加入 `.gitignore`。

生产环境的 API 凭据应放在未提交的 `.env` 中。公开 GitHub 仓库不应包含 tokens、use_token、browser-profile、备份、SQLite 数据库或日志。Sub2API 升级后先运行 `npm test` 和只读快照，确认管理员 API 契约再打开写入开关。
