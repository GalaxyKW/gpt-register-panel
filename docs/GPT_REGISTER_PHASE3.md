# gpt_register Phase 3 接口约定

面板的 Phase 3 worker 只允许以下固定逻辑命令：

```text
node /mnt/nvme/gpt_register/index.js --phase3 --email=<已校验邮箱>
```

实际启动不会在校验后重新按路径打开这些对象。worker 会分别打开并验证 Node 可执行文件、`index.js` 与 `gpt_register` 根目录，将它们直接继承为子进程 fd 4、3、5，并通过 `/proc/self/fd` 执行。这样既不需要 shell，也不需要访问父进程的 fd 或授予 `CAP_SYS_PTRACE`。

`/mnt/nvme/gpt_register/index.js` 已增加向后兼容的参数：

- `--email=<邮箱>`：按 `username.json` 中的邮箱精确匹配；
- `--phone=<手机号>`：按手机号匹配；
- `--username-index=<序号>`：按 Phase 3 候选列表序号匹配。

没有这些参数时，原有交互选择行为保持不变。面板不会把用户输入拼接成 shell 命令，也不会允许任意脚本路径。

这项改动位于 `gpt_register` 独立工作树，不属于 Sub2API，也不应把 `gpt_register` 的运行态文件提交到本仓库。更新 `gpt_register` 后请检查上述参数是否仍存在；若上游覆盖了它们，可按本文件恢复相同逻辑。恢复前先保留现有 `index.js` 和 `username.json` 备份。

启用面板任务前必须同时设置：

```text
PANEL_WRITE_ENABLED=1
PANEL_ADMIN_TOKEN=<随机长令牌>
PANEL_PHASE3_ENABLED=1
```

默认值均关闭，避免 Web 请求意外触发浏览器登录、邮箱验证码或 token 刷新。
