#!/usr/bin/env node
/**
 * OpenClaw Piper - Prompt Injection 监控系统
 * 
 * 实时监测 Prompt Injection 攻击，发出告警。
 * 仅监测和告警，不影响 OpenClaw 行为。
 * 
 * 用法:
 *   piper                      # 启动监控 (默认端口 3457)
 *   piper --port 8080          # 指定端口
 *   piper --gateway URL        # 指定 Gateway
 *   piper --db /path/to/db     # 指定数据库路径
 */

import http from 'node:http';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import { spawn } from 'node:child_process';
import { homedir } from 'node:os';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ===== 配置 =====
const args = process.argv.slice(2);
const config = {
  port: 3457,
  gateway: 'http://localhost:18789',
  open: true,
  db: null  // 默认使用 ~/.openclaw/piper/events.db
};

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--port' || arg === '-p') {
    config.port = parseInt(args[++i], 10) || 3457;
  } else if (arg === '--gateway' || arg === '-g') {
    config.gateway = args[++i];
  } else if (arg === '--db' || arg === '-d') {
    config.db = args[++i];
  } else if (arg === '--no-open') {
    config.open = false;
  } else if (arg === '--help' || arg === '-h') {
    console.log(`
OpenClaw Piper - Prompt Injection 监控系统

用法:
  piper [选项]

选项:
  -p, --port <端口>      监控面板端口 (默认: 3457)
  -g, --gateway <URL>    OpenClaw Gateway URL (默认: http://localhost:18789)
  -d, --db <路径>        数据库路径 (默认: ~/.openclaw/piper/events.db)
  --no-open              不自动打开浏览器
  -h, --help             显示帮助信息
`);
    process.exit(0);
  }
}

// 默认数据库路径
if (!config.db) {
  config.db = path.join(homedir(), '.openclaw', 'piper', 'events.db');
}

// ===== 动态导入依赖 =====
let WebSocket, WebSocketServer, Database;

async function loadDependencies() {
  try {
    const wsModule = await import('ws');
    WebSocket = wsModule.WebSocket;
    WebSocketServer = wsModule.WebSocketServer;
    console.log('✅ 已加载 ws 库');
  } catch (err) {
    console.error('❌ 无法加载 ws 库，请运行: npm install ws');
    process.exit(1);
  }

  try {
    const sqliteModule = await import('better-sqlite3');
    Database = sqliteModule.default;
    console.log('✅ 已加载 better-sqlite3 库');
  } catch (err) {
    console.error('❌ 无法加载 better-sqlite3 库，请运行: npm install better-sqlite3');
    process.exit(1);
  }
}

// ===== 规则加载 =====
const rulesPath = path.join(__dirname, 'rules', 'injection.json');
let rules = { rules: [], whitelist: { patterns: [] } };

try {
  const rulesData = fs.readFileSync(rulesPath, 'utf-8');
  rules = JSON.parse(rulesData);
  console.log(`✅ 已加载 ${rules.rules.length} 条检测规则`);
} catch (err) {
  console.error('⚠️  无法加载规则文件:', err.message);
}

// ===== 数据库初始化 =====
let db = null;

function initDatabase() {
  const dbDir = path.dirname(config.db);
  
  // 确保目录存在
  if (!fs.existsSync(dbDir)) {
    fs.mkdirSync(dbDir, { recursive: true });
    console.log(`📁 创建数据库目录: ${dbDir}`);
  }

  db = new Database(config.db);
  
  // 创建表
  db.exec(`
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY,
      timestamp TEXT NOT NULL,
      type TEXT NOT NULL,
      source TEXT,
      risk_level TEXT NOT NULL,
      risk_score INTEGER NOT NULL,
      text TEXT,
      findings TEXT,
      context TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    
    CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
    CREATE INDEX IF NOT EXISTS idx_events_risk_level ON events(risk_level);
    CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
  `);
  
  console.log(`✅ 数据库已初始化: ${config.db}`);
}

// ===== 事件存储 =====
const emitter = new EventEmitter();
const MAX_EVENTS_IN_MEMORY = 100;

// 从数据库加载最近的事件到内存
function loadRecentEvents() {
  if (!db) return [];
  
  const rows = db.prepare(`
    SELECT * FROM events 
    ORDER BY timestamp DESC 
    LIMIT ?
  `).all(MAX_EVENTS_IN_MEMORY);
  
  return rows.map(row => ({
    id: row.id,
    timestamp: row.timestamp,
    type: row.type,
    source: row.source,
    risk: { level: row.risk_level, score: row.risk_score },
    text: row.text,
    findings: row.findings ? JSON.parse(row.findings) : [],
    context: row.context ? JSON.parse(row.context) : {}
  }));
}

// 保存事件到数据库
function saveEvent(event) {
  if (!db) return;
  
  db.prepare(`
    INSERT INTO events (id, timestamp, type, source, risk_level, risk_score, text, findings, context)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    event.id,
    event.timestamp,
    event.type,
    event.source || null,
    event.risk?.level || 'low',
    event.risk?.score || 0,
    event.text || null,
    event.findings ? JSON.stringify(event.findings) : null,
    event.context ? JSON.stringify(event.context) : null
  );
}

// 添加事件
function addEvent(event) {
  event.id = crypto.randomUUID();
  event.timestamp = new Date().toISOString();
  
  // 保存到数据库
  saveEvent(event);
  
  // 通知前端
  emitter.emit('event', event);
}

// ===== 检测引擎 =====
class DetectionEngine {
  constructor() {
    this.compiledRules = this.compileRules();
  }

  compileRules() {
    return rules.rules.map(rule => ({
      ...rule,
      regexes: rule.patterns.map(p => new RegExp(p, 'gi'))
    }));
  }

  // 规则检测
  detectByRules(text) {
    if (!text || typeof text !== 'string') return [];
    
    // 检查白名单
    for (const pattern of rules.whitelist.patterns) {
      try {
        if (new RegExp(pattern, 'i').test(text)) return [];
      } catch {}
    }

    const findings = [];
    
    for (const rule of this.compiledRules) {
      const matches = [];
      for (const regex of rule.regexes) {
        const match = regex.exec(text);
        if (match) {
          matches.push({
            pattern: regex.source,
            matched: match[0],
            index: match.index
          });
        }
        regex.lastIndex = 0; // 重置
      }
      
      if (matches.length > 0) {
        findings.push({
          rule: rule.id,
          name: rule.name,
          severity: rule.severity,
          description: rule.description,
          matches
        });
      }
    }
    
    return findings;
  }

  // 计算风险分数
  calculateRiskScore(findings) {
    if (!findings.length) return { score: 0, level: 'none' };
    
    const severityScores = {
      critical: 100,
      high: 70,
      medium: 40,
      low: 20
    };
    
    let maxScore = 0;
    for (const f of findings) {
      const score = severityScores[f.severity] || 20;
      if (score > maxScore) maxScore = score;
    }
    
    let level = 'low';
    if (maxScore >= 100) level = 'critical';
    else if (maxScore >= 70) level = 'high';
    else if (maxScore >= 40) level = 'medium';
    
    return { score: maxScore, level };
  }

  // 综合检测（纯静态规则，无 AI）
  analyze(text, context = {}) {
    const ruleFindings = this.detectByRules(text);
    const risk = this.calculateRiskScore(ruleFindings);
    
    return {
      text: text.slice(0, 500),  // 截断长文本
      ruleFindings,
      risk,
      context
    };
  }
}

// ===== 分析函数 =====
function analyzeInput(text, context) {
  const result = detector.analyze(text, context);
  
  if (result.risk.level !== 'none') {
    const event = {
      type: 'alert',
      source: 'input',
      risk: result.risk,
      findings: result.ruleFindings,
      text: result.text,
      context: {
        sessionKey: context.sessionKey,
        channel: context.channel
      }
    };
    
    addEvent(event);
    
    // 高危告警输出
    if (result.risk.level === 'critical' || result.risk.level === 'high') {
      console.log(`🚨 [${result.risk.level.toUpperCase()}] 检测到可疑输入!`);
      console.log(`   规则: ${result.ruleFindings.map(f => f.name).join(', ')}`);
      console.log(`   内容: ${text.slice(0, 100)}...`);
    }
  }
}

function analyzeToolCall(msg) {
  const toolName = msg.name || msg.tool || '';
  const args = msg.arguments || msg.args || {};
  
  // 检查高危工具
  const dangerousTools = ['exec', 'shell', 'bash', 'terminal'];
  const isDangerous = dangerousTools.some(t => toolName.toLowerCase().includes(t));
  
  if (isDangerous) {
    addEvent({
      type: 'tool_alert',
      source: 'tool_call',
      tool: toolName,
      args: JSON.stringify(args).slice(0, 200),
      risk: { level: 'medium', score: 40 },
      context: { sessionKey: msg.sessionKey }
    });
  }
}

// ===== 统计数据 =====
function getStats() {
  if (!db) {
    return {
      totalAlerts: 0,
      lastHour: 0,
      bySeverity: { critical: 0, high: 0, medium: 0, low: 0 },
      byType: { input: 0, tool: 0 }
    };
  }

  const hourAgo = new Date(Date.now() - 3600000).toISOString();
  
  return {
    totalAlerts: db.prepare('SELECT COUNT(*) as count FROM events').get()?.count || 0,
    lastHour: db.prepare('SELECT COUNT(*) as count FROM events WHERE timestamp > ?').get(hourAgo)?.count || 0,
    bySeverity: {
      critical: db.prepare("SELECT COUNT(*) as count FROM events WHERE risk_level = 'critical'").get()?.count || 0,
      high: db.prepare("SELECT COUNT(*) as count FROM events WHERE risk_level = 'high'").get()?.count || 0,
      medium: db.prepare("SELECT COUNT(*) as count FROM events WHERE risk_level = 'medium'").get()?.count || 0,
      low: db.prepare("SELECT COUNT(*) as count FROM events WHERE risk_level = 'low'").get()?.count || 0
    },
    byType: {
      input: db.prepare("SELECT COUNT(*) as count FROM events WHERE source = 'input'").get()?.count || 0,
      tool: db.prepare("SELECT COUNT(*) as count FROM events WHERE source = 'tool_call'").get()?.count || 0
    }
  };
}

// ===== HTTP 服务器 =====
let server;
let wss; // WebSocket 服务器
let gatewayClient; // Gateway 连接

function createHTTPServer() {
  server = http.createServer((req, res) => {
    const webDir = path.join(__dirname, 'web');
    
    // CORS 头
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
    
    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }
    
    // API 端点
    if (req.url === '/api/events') {
      const events = loadRecentEvents();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ events, stats: getStats() }));
      return;
    }
    
    if (req.url === '/api/stats') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(getStats()));
      return;
    }
    
    if (req.url === '/api/config') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        gateway: config.gateway,
        rulesCount: rules.rules.length,
        dbPath: config.db
      }));
      return;
    }
    
    // 静态文件
    let filePath = path.join(webDir, req.url === '/' ? 'index.html' : req.url || 'index.html');
    
    if (!filePath.startsWith(webDir)) {
      res.writeHead(403);
      res.end('Forbidden');
      return;
    }
    
    const ext = path.extname(filePath);
    const mimeTypes = {
      '.html': 'text/html; charset=utf-8',
      '.css': 'text/css; charset=utf-8',
      '.js': 'application/javascript; charset=utf-8',
      '.json': 'application/json'
    };
    
    fs.readFile(filePath, (err, data) => {
      if (err) {
        res.writeHead(404);
        res.end('Not Found');
        return;
      }
      res.writeHead(200, { 
        'Content-Type': mimeTypes[ext] || 'application/octet-stream',
        'Cache-Control': 'no-cache'
      });
      res.end(data);
    });
  });
}

// ===== WebSocket 服务器 =====
function createWebSocketServer() {
  wss = new WebSocketServer({ server, path: '/ws' });
  
  wss.on('connection', (ws) => {
    console.log('📡 前端客户端已连接');
    
    // 发送最近事件
    const recentEvents = loadRecentEvents().slice(0, 20);
    ws.send(JSON.stringify({ type: 'init', data: recentEvents }));
    
    // 订阅新事件
    const onEvent = (event) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'event', data: event }));
      }
    };
    emitter.on('event', onEvent);
    
    ws.on('close', () => {
      emitter.off('event', onEvent);
      console.log('📡 前端客户端已断开');
    });
    
    ws.on('error', (err) => {
      console.error('WebSocket 错误:', err.message);
    });
  });
}

// ===== Gateway WebSocket 客户端 =====
function connectToGateway() {
  const wsUrl = config.gateway.replace(/^http/, 'ws') + '/ws';
  console.log(`📡 连接到 Gateway: ${wsUrl}`);
  
  gatewayClient = new WebSocket(wsUrl);
  
  gatewayClient.on('open', () => {
    console.log('✅ 已连接到 Gateway');
  });
  
  gatewayClient.on('message', (data) => {
    try {
      const msg = JSON.parse(data.toString());
      
      // 监听入站消息（用户输入）
      if (msg.type === 'inbound' || msg.type === 'user_message' || msg.role === 'user') {
        const text = msg.content || msg.message || msg.text;
        if (text) {
          analyzeInput(text, msg);
        }
      }
      
      // 监听工具调用
      if (msg.type === 'tool_call' || msg.type === 'tool_use') {
        analyzeToolCall(msg);
      }
    } catch (e) {
      // 非 JSON 消息，忽略
    }
  });
  
  gatewayClient.on('close', () => {
    console.log('⚠️  Gateway 连接断开，5秒后重连...');
    setTimeout(connectToGateway, 5000);
  });
  
  gatewayClient.on('error', (err) => {
    console.error('❌ Gateway 连接错误:', err.message);
  });
}

// ===== 主程序 =====
async function main() {
  console.log('');
  console.log('🎯 OpenClaw Piper 启动中...');
  console.log('');

  // 加载依赖
  await loadDependencies();
  
  // 初始化数据库
  initDatabase();
  
  // 创建检测引擎
  const detector = new DetectionEngine();
  global.detector = detector; // 供分析函数使用
  
  // 启动 HTTP 服务器
  createHTTPServer();
  await new Promise(resolve => server.listen(config.port, resolve));
  
  // 启动 WebSocket 服务器
  createWebSocketServer();
  
  console.log('┌─────────────────────────────────────────┐');
  console.log('│                                         │');
  console.log('│   🎯 Piper 已启动                       │');
  console.log('│                                         │');
  console.log(`│   监控面板: http://localhost:${config.port}    │`);
  console.log(`│   Gateway: ${config.gateway.padEnd(28)}│`);
  console.log(`│   数据库: ${config.db.slice(0, 28).padEnd(28)}│`);
  console.log('│                                         │');
  console.log('│   按 Ctrl+C 停止                        │');
  console.log('│                                         │');
  console.log('└─────────────────────────────────────────┘');
  console.log('');

  // 连接到 Gateway
  connectToGateway();

  // 打开浏览器
  if (config.open) {
    const url = `http://localhost:${config.port}`;
    const platform = process.platform;
    const cmd = platform === 'darwin' ? 'open' : platform === 'win32' ? 'start' : 'xdg-open';
    spawn(cmd, [url], { detached: true, stdio: 'ignore' }).unref();
  }

  // 优雅关闭
  process.on('SIGINT', () => {
    console.log('\n🛑 正在关闭...');
    if (gatewayClient) gatewayClient.close();
    if (wss) wss.close();
    if (server) server.close();
    if (db) db.close();
    process.exit(0);
  });
}

main().catch(err => {
  console.error('启动失败:', err);
  process.exit(1);
});