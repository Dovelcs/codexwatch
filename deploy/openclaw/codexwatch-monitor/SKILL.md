---
name: codexwatch-monitor
description: 查询 CodexWatch 中真实 Codex 对话的任务状态、原始标题、attempt、事件、错误、捕获健康状态，或请求客户端上传指定任务内容。用户询问 Codex 任务是否完成、哪个对话异常、错误原因或监控状态时使用。
---

# CodexWatch Monitor

使用 `/usr/local/bin/codexwatch-notifier` 查询，配置和 Token 已由系统服务管理，不要读取、显示或复制配置文件。

## 命令

- 最近任务：`codexwatch-notifier tasks`
- 指定 session：`codexwatch-notifier tasks --session-id <session_id>`
- 任务详情：`codexwatch-notifier task '<task_ref>'`
- attempt：`codexwatch-notifier attempts '<task_ref>'`
- 状态事件：`codexwatch-notifier events '<task_ref>'`
- 错误证据：`codexwatch-notifier errors '<task_ref>'`
- session：`codexwatch-notifier session '<session_id>' --thread-id '<thread_id>'`
- 抓包健康：`codexwatch-notifier capture-health`
- 请求本地全文：`codexwatch-notifier request-content '<task_ref>' --parts request,response`

## 解释规则

- 对话名称只使用 `conversation_title`；不要从用户消息生成标题。
- `phase=running|awaiting_tool|retrying` 表示任务尚未结束。
- 只有 `phase=terminal` 才是整个 turn 终态；`terminal` 为 `completed|failed|aborted|terminated|lost`。
- `response.completed` 且 `end_turn=true`、当前 attempt 无工具调用时表示整个 turn 完成；有工具调用或 `end_turn=false` 时仍未结束。
- 异常原因优先引用 `last_error`、`errors` 和 `events` 的原始字段，不自行推断。
- `integrity=degraded|lost|unsupported_build` 表示捕获证据不完整，不能伪装成模型失败。
- 返回结果时优先给出 `conversation_title`、`session_id`、`turn_id`、终态、时间和直接错误原因。

完成/异常飞书提醒由独立 systemd 服务发送，不需要也不要启动 agent、cron 或模型任务。
