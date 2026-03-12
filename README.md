<a id="english"></a>
# OpenClaw Piper 🎯

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org/)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-Compatible-blue.svg)](https://github.com/openclaw/openclaw)

**English** | [中文](#chinese)

---

A real-time **Prompt Injection monitoring and alerting system** for OpenClaw. Detect suspicious inputs without affecting agent behavior.

## 🎯 Features

- **Rule-based Detection** - 8 built-in rule categories covering common Prompt Injection patterns
- **Real-time Monitoring** - Directly monitors OpenClaw session transcript files
- **Persistent Storage** - SQLite database ensures alerts survive restarts
- **Visual Dashboard** - Clean Web UI for viewing alerts and statistics
- **Severity Levels** - Critical / High / Medium / Low classification
- **Reliable Transport** - Uses mature `ws` library with proper long message handling
- **Extensible Rules** - JSON-based rule files for easy customization

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/leonardeee/openclaw-piper.git
cd openclaw-piper

# Install dependencies
npm install

# (Optional) Create global command
npm link
```

### Usage

```bash
# Start Piper (default port 3457)
piper

# Or run directly
node piper.js

# Custom configuration
piper --port 8080 --gateway http://localhost:18789
```

The dashboard will be available at `http://localhost:3457`

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-p, --port <port>` | Dashboard port | 3457 |
| `-g, --gateway <url>` | OpenClaw Gateway URL | http://localhost:18789 |
| `-d, --db <path>` | Database path | ~/.openclaw/piper/events.db |
| `--no-open` | Don't auto-open browser | - |
| `-h, --help` | Show help | - |

## 📋 Detection Rules

Piper includes 8 built-in rule categories:

| Category | Description | Severity | Example Patterns |
|----------|-------------|----------|------------------|
| **Role Bypass** | Attempts to bypass restrictions via role-play | 🔴 Critical | `ignore instructions`, `pretend to be`, `act as` |
| **System Prompt Leak** | Attempts to extract system prompts | 🔴 Critical | `show your system prompt`, `what are your instructions` |
| **Jailbreak** | Classic jailbreak/escape attacks | 🔴 Critical | `DAN mode`, `developer mode`, `jailbreak` |
| **Instruction Injection** | Fake instruction markers | 🟠 High | `[SYSTEM]`, `###INSTRUCTION`, `<\|system\|>` |
| **Data Exfiltration** | Data theft or exfiltration attempts | 🟠 High | `encode and send`, `base64 output` |
| **Privilege Escalation** | Attempts to elevate privileges | 🟠 High | `sudo`, `chmod 777`, `enable root` |
| **Persistence** | Establishing persistent access | 🟡 Medium | `crontab`, `startup script` |
| **Suspicious Context** | Suspicious context references | 🟡 Medium | `above instruction`, `remember that` |

## 🏗️ Project Structure

```
openclaw-piper/
├── piper.js            # Main program (detection engine + HTTP/WS server)
├── piper               # Startup script
├── package.json        # Package configuration
├── README.md           # Documentation
├── LICENSE             # MIT License
├── test.js             # Test suite (21 test cases)
├── rules/
│   └── injection.json  # Detection rules configuration
└── web/
    ├── index.html      # Dashboard HTML
    ├── style.css       # Stylesheet
    └── app.js          # Frontend logic
```

## 🔧 Extending Rules

Edit `rules/injection.json` to add custom rules:

```json
{
  "id": "custom_rule",
  "name": "Custom Rule Name",
  "severity": "high",
  "patterns": [
    "suspicious_pattern_1",
    "suspicious_pattern_2"
  ],
  "description": "Rule description"
}
```

### Rule Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique rule identifier |
| `name` | string | Display name |
| `severity` | string | `critical` / `high` / `medium` / `low` |
| `patterns` | string[] | Regex patterns (case-insensitive) |
| `description` | string | Rule description |

### Whitelist Configuration

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

## 🌐 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/events` | GET | Recent events and statistics |
| `/api/stats` | GET | Statistics only |
| `/api/config` | GET | Current configuration |
| `/ws` | WebSocket | Real-time event stream |

## 🔄 How It Works

```
┌─────────────────┐                    ┌─────────────┐
│  OpenClaw       │  writes to         │  Transcript │
│  Sessions       │ ─────────────────> │  Files      │
└─────────────────┘                    └──────┬──────┘
                                              │
                                              │ monitors
                                              ▼
                                       ┌─────────────┐
                                       │   Piper     │
                                       │  Detection  │
                                       └──────┬──────┘
                                              │
                                    ┌─────────┴─────────┐
                                    ▼                   ▼
                             ┌──────────┐       ┌──────────┐
                             │  SQLite  │       │  Web UI  │
                             │ Storage  │       │ Dashboard│
                             └──────────┘       └──────────┘
```

### Detection Flow

1. **Message Capture** - Piper monitors OpenClaw transcript files (`~/.openclaw/agents/*/sessions/*.jsonl`)
2. **Rule Matching** - Detection engine performs regex matching to identify suspicious patterns
3. **Risk Assessment** - Calculates risk score and severity level based on matched rules
4. **Alert Generation** - Suspicious messages trigger alerts, stored in SQLite and pushed to Web UI

## 🛠️ Requirements

- [OpenClaw](https://github.com/openclaw/openclaw) Gateway
- Node.js 18+

## 📝 Roadmap

- [ ] Alert notifications (Telegram, email, etc.)
- [ ] More detection rules (emerging attack patterns)
- [ ] Statistical analysis dashboard
- [ ] Export alerts to CSV/JSON

## 🤝 Contributing

Issues and Pull Requests are welcome!

## 📄 License

[MIT License](LICENSE)

## 🙏 Acknowledgments

- [OpenClaw](https://github.com/openclaw/openclaw) - Open-source AI assistant framework
- Prompt Injection research community

---
<a id="chinese"></a>
# 中文文档 🎯

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)](https://nodejs.org/)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-兼容-blue.svg)](https://github.com/openclaw/openclaw)

[English](#english) | **中文**

---

OpenClaw 的实时 **Prompt Injection 监测和告警系统**。检测可疑输入，不影响 Agent 行为。

## 🎯 功能特性

- **规则检测引擎** - 8 类内置规则，覆盖常见 Prompt Injection 攻击模式
- **实时监控** - 直接监控 OpenClaw 会话 transcript 文件
- **持久化存储** - SQLite 数据库存储告警，重启不丢失
- **可视化面板** - 清晰的 Web UI 展示告警详情和统计数据
- **分级告警** - Critical / High / Medium / Low 四级严重程度
- **可靠传输** - 使用成熟的 `ws` 库，正确处理大消息
- **易于扩展** - JSON 格式规则文件，方便自定义

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

启动后访问 `http://localhost:3457` 查看监控面板。

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
├── test.js             # 测试脚本（21 个测试用例）
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
┌─────────────────┐                    ┌─────────────┐
│  OpenClaw       │  写入              │  Session    │
│  会话           │ ─────────────────> │  文件       │
└─────────────────┘                    └──────┬──────┘
                                              │
                                              │ 监控
                                              ▼
                                       ┌─────────────┐
                                       │   Piper     │
                                       │  检测引擎   │
                                       └──────┬──────┘
                                              │
                                    ┌─────────┴─────────┐
                                    ▼                   ▼
                             ┌──────────┐       ┌──────────┐
                             │  SQLite  │       │  Web UI  │
                             │  持久化   │       │  监控面板 │
                             └──────────┘       └──────────┘
```

### 检测流程

1. **消息捕获** - Piper 监控 OpenClaw transcript 文件 (`~/.openclaw/agents/*/sessions/*.jsonl`)
2. **规则匹配** - 检测引擎对消息进行正则匹配，识别可疑模式
3. **风险评估** - 根据匹配到的规则计算风险分数和严重级别
4. **告警生成** - 可疑消息触发告警，存入数据库并推送到 Web UI

## 🛠️ 前置要求

- [OpenClaw](https://github.com/openclaw/openclaw) Gateway
- Node.js 18+

## 📝 后续计划

- [ ] 告警通知（Telegram、邮件等渠道）
- [ ] 更多检测规则（覆盖新兴攻击模式）
- [ ] 统计分析面板
- [ ] 导出告警到 CSV/JSON

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

## 📄 许可证

[MIT License](LICENSE)

## 🙏 致谢

- [OpenClaw](https://github.com/openclaw/openclaw) - 开源 AI 助手框架
- Prompt Injection 研究者和安全社区

---

Created by [Dr. Graaff](https://github.com/leonardeee) 🎓
