# OpenClaw Piper 🎯

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org/)

**OpenClaw Prompt Injection 监控系统** - 实时监测 Prompt Injection 攻击，发出告警。

> **定位**：仅监测和告警，不影响 OpenClaw 行为。所有检测基于静态规则，无 AI 分析。

## 🎯 功能特性

- **规则检测引擎** - 8 类预定义规则，覆盖常见 Prompt Injection 攻击模式
- **实时监控** - 通过 WebSocket 实时连接 Gateway，即时捕获可疑输入
- **持久化存储** - SQLite 数据库存储历史事件，重启不丢失
- **可视化面板** - 清晰的 Web UI 展示告警详情和统计数据
- **分级告警** - Critical / High / Medium / Low 四级严重程度
- **可靠传输** - 使用成熟的 ws 库，正确处理大消息和长连接
- **易于扩展** - JSON 格式规则文件，方便添加自定义检测规则

## 🚀 快速开始

### 安装

```bash
# 克隆仓库
git clone https://github.com/leonardeee/openclaw-piper.git
cd openclaw-piper

# 安装依赖
npm install

# （可选）创建全局命令
npm link
```

### 使用

```bash
# 启动 Piper（默认端口 3457）
piper

# 或直接运行
node piper.js

# 自定义配置
piper --port 8080 --gateway http://localhost:18789
```

启动后会自动打开监控面板 `http://localhost:3457`

### 命令行参数

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `-p, --port <端口>` | 监控面板端口 | 3457 |
| `-g, --gateway <URL>` | OpenClaw Gateway 地址 | http://localhost:18789 |
| `-d, --db <路径>` | 数据库路径 | ~/.openclaw/piper/events.db |
| `--no-open` | 不自动打开浏览器 | - |
| `-h, --help` | 显示帮助信息 | - |

## 📋 检测规则

Piper 内置 8 类检测规则：

| 类别 | 描述 | 严重级别 | 示例模式 |
|------|------|----------|----------|
| **角色扮演绕过** | 尝试通过角色扮演绕过系统限制 | 🔴 Critical | `ignore instructions`, `pretend to be`, `act as` |
| **系统提示词泄露** | 尝试获取系统提示词 | 🔴 Critical | `show your system prompt`, `what are your instructions` |
| **越狱尝试** | 经典越狱/逃逸攻击 | 🔴 Critical | `DAN mode`, `developer mode`, `jailbreak` |
| **指令注入** | 注入伪指令标记 | 🟠 High | `[SYSTEM]`, `###INSTRUCTION`, `<\|system\|>` |
| **数据渗出尝试** | 窃取或渗出数据 | 🟠 High | `encode and send`, `base64 output` |
| **权限提升尝试** | 尝试提升权限 | 🟠 High | `sudo`, `chmod 777`, `enable root` |
| **持久化尝试** | 建立持久化访问 | 🟡 Medium | `crontab`, `startup script` |
| **可疑上下文模式** | 可能用于注入的可疑引用 | 🟡 Medium | `above instruction`, `remember that` |

## 🏗️ 项目结构

```
openclaw-piper/
├── piper.js            # 主程序（检测引擎 + HTTP/WS 服务）
├── piper               # 启动脚本
├── package.json        # 包配置
├── README.md           # 说明文档
├── LICENSE             # MIT 许可证
├── rules/
│   └── injection.json  # 检测规则配置
└── web/
    ├── index.html      # 监控面板 HTML
    ├── style.css       # 样式表
    └── app.js          # 前端逻辑
```

## 🔧 扩展规则

编辑 `rules/injection.json` 添加自定义规则：

```json
{
  "id": "custom_rule",
  "name": "自定义规则名称",
  "severity": "high",
  "patterns": [
    "可疑模式1",
    "可疑模式2"
  ],
  "description": "规则描述"
}
```

### 规则字段说明

| 字段 | 类型 | 说明 |
|------|------|------|
| `id` | string | 规则唯一标识 |
| `name` | string | 规则显示名称 |
| `severity` | string | 严重级别：`critical` / `high` / `medium` / `low` |
| `patterns` | string[] | 正则表达式数组（不区分大小写） |
| `description` | string | 规则描述 |

### 白名单配置

在 `rules/injection.json` 中配置白名单，跳过无害消息：

```json
{
  "whitelist": {
    "patterns": [
      "^\\s*$",
      "^(hi|hello|thanks)[\\s!.]*$"
    ]
  }
}
```

## 🌐 API 端点

| 端点 | 方法 | 说明 |
|------|------|------|
| `/api/events` | GET | 获取最近的事件列表和统计 |
| `/api/stats` | GET | 获取统计数据 |
| `/api/config` | GET | 获取当前配置 |
| `/ws` | WebSocket | 实时事件推送 |

## 🔄 工作原理

```
┌─────────────┐     WebSocket      ┌─────────────┐
│   Gateway   │ ──────────────────>│    Piper    │
│  (OpenClaw) │                    │  监控服务   │
└─────────────┘                    └──────┬──────┘
                                          │
                                          ▼
                                   ┌─────────────┐
                                   │  检测引擎   │
                                   │  规则匹配   │
                                   └──────┬──────┘
                                          │
                                   ┌──────┴──────┐
                                   ▼             ▼
                            ┌──────────┐  ┌──────────┐
                            │ SQLite   │  │  Web UI  │
                            │ 持久化    │  │  实时告警 │
                            └──────────┘  └──────────┘
```

### 检测流程

1. **消息捕获** - Piper 通过 WebSocket 连接 Gateway，监听入站消息
2. **规则匹配** - 检测引擎对消息进行正则匹配，识别可疑模式
3. **风险评估** - 根据匹配到的规则计算风险分数和严重级别
4. **告警生成** - 可疑消息触发告警，存入数据库并推送到 Web UI

## 🛠️ 前置要求

- [OpenClaw](https://github.com/openclaw/openclaw) Gateway 服务
- Node.js 18+

## 📝 后续计划

- [ ] 告警通知（发送到 Telegram/邮件等渠道）
- [ ] 更多检测规则（覆盖新兴攻击模式）
- [ ] 统计分析面板

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

[MIT License](LICENSE)

## 🙏 致谢

- [OpenClaw](https://github.com/openclaw/openclaw) - 开源 AI 助手框架
- 所有 Prompt Injection 研究者和安全社区

---

Created by [Dr. Graaff](https://github.com/leonardeee) 🎓