#!/usr/bin/env node
/**
 * OpenClaw Guardian - 安全监控服务
 * 
 * 检测 Prompt Injection 等可疑行为
 * 
 * 用法:
 *   guardian                     # 启动监控 (默认端口 3457)
 *   guardian --port 8080         # 指定端口
 *   guardian --gateway URL       # 指定 Gateway
 *   guardian --no-ai             # 禁用 AI 分析
 */

import http from 'node:http';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import fs from 'node:fs';
import { spawn } from 'node:child_process';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ===== 配置 =====
const args = process.argv.slice(2);
const config = {
  port: 3457,
  gateway: 'http://localhost:18789',  // 默认 Gateway 端口
  open: true,
  enableAI: true,
  aiModel: null  // 使用 Gateway 默认模型
};

for (let i = 0; i < args.length; i++) {
  const arg = args[i];
  if (arg === '--port' || arg === '-p') {
    config.port = parseInt(args[++i], 10) || 3457;
  } else if (arg === '--gateway' || arg === '-g') {
    config.gateway = args[++i];
  } else if (arg === '--no-open') {
    config.open = false;
  } else if (arg === '--no-ai') {
    config.enableAI = false;
  } else if (arg === '--help' || arg === '-h') {
    console.log(`
OpenClaw Guardian - 安全监控服务

用法:
  guardian [选项]

选项:
  -p, --port <端口>      监控面板端口 (默认: 3457)
  -g, --gateway <URL>    OpenClaw Gateway URL (默认: http://localhost:18789)
  --no-open              不自动打开浏览器
  --no-ai                禁用 AI 智能分析
  -h, --help             显示帮助信息
`);
    process.exit(0);
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

// ===== 事件存储 =====
const events = [];
const MAX_EVENTS = 1000;

function addEvent(event) {
  event.id = crypto.randomUUID();
  event.timestamp = new Date().toISOString();
  events.unshift(event);
  if (events.length > MAX_EVENTS) events.pop();
  emitter.emit('event', event);
}

const emitter = new EventEmitter();

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

  // 综合检测
  async analyze(text, context = {}) {
    const ruleFindings = this.detectByRules(text);
    const risk = this.calculateRiskScore(ruleFindings);
    
    const result = {
      text: text.slice(0, 500),  // 截断长文本
      ruleFindings,
      risk,
      aiAnalysis: null,
      context
    };
    
    // AI 分析（如果启用且风险不为 none）
    if (config.enableAI && risk.level !== 'none') {
      // 稍后实现 AI 分析
      // result.aiAnalysis = await this.analyzeWithAI(text);
    }
    
    return result;
  }
}

const detector = new DetectionEngine();

// ===== WebSocket 客户端 (简易版) =====
class SimpleWebSocketClient {
  constructor(url) {
    this.url = url;
    this.ws = null;
    this.connected = false;
  }

  connect() {
    const url = new URL(this.url);
    
    const requestOptions = {
      hostname: url.hostname,
      port: url.port || 18789,
      path: url.pathname,
      method: 'GET',
      headers: {
        'Upgrade': 'websocket',
        'Connection': 'Upgrade',
        'Sec-WebSocket-Key': crypto.randomBytes(16).toString('base64'),
        'Sec-WebSocket-Version': '13'
      }
    };

    const req = http.request(requestOptions);

    req.on('upgrade', (res, socket) => {
      this.socket = socket;
      this.connected = true;
      console.log('✅ 已连接到 Gateway');
      this.setupSocket();
    });

    req.on('error', (err) => {
      console.log('❌ Gateway 连接失败:', err.message);
      this.connected = false;
      // 重连
      setTimeout(() => this.connect(), 5000);
    });

    req.end();
  }

  setupSocket() {
    this.buffer = Buffer.alloc(0);
    
    this.socket.on('data', (data) => {
      this.buffer = Buffer.concat([this.buffer, data]);
      this.parseFrames();
    });

    this.socket.on('close', () => {
      this.connected = false;
      console.log('⚠️  Gateway 连接断开');
      setTimeout(() => this.connect(), 5000);
    });

    this.socket.on('error', (err) => {
      console.error('WebSocket 错误:', err.message);
    });
  }

  parseFrames() {
    while (this.buffer.length >= 2) {
      const firstByte = this.buffer[0];
      const secondByte = this.buffer[1];
      const masked = (secondByte & 0x80) !== 0;
      let payloadLen = secondByte & 0x7f;
      let offset = 2;

      if (payloadLen === 126) {
        if (this.buffer.length < 4) return;
        payloadLen = this.buffer.readUInt16BE(2);
        offset = 4;
      } else if (payloadLen === 127) {
        if (this.buffer.length < 10) return;
        payloadLen = Number(this.buffer.readBigUInt64BE(2));
        offset = 10;
      }

      if (masked) offset += 4;
      if (this.buffer.length < offset + payloadLen) return;

      const payload = this.buffer.slice(offset, offset + payloadLen);
      this.buffer = this.buffer.slice(offset + payloadLen);

      const opcode = firstByte & 0x0f;
      if (opcode === 1) { // Text frame
        try {
          const text = payload.toString('utf-8');
          const msg = JSON.parse(text);
          this.handleMessage(msg);
        } catch (e) {
          // 非 JSON 消息
        }
      } else if (opcode === 8) { // Close
        this.connected = false;
      }
    }
  }

  handleMessage(msg) {
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
  }

  send(data) {
    if (!this.connected || !this.socket) return;
    
    const payload = Buffer.from(JSON.stringify(data), 'utf-8');
    const frame = Buffer.alloc(2 + payload.length);
    frame[0] = 0x81;
    frame[1] = payload.length;
    payload.copy(frame, 2);
    this.socket.write(frame);
  }
}

// ===== 分析函数 =====
async function analyzeInput(text, context) {
  const result = await detector.analyze(text, context);
  
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
      tool: toolName,
      args: JSON.stringify(args).slice(0, 200),
      risk: { level: 'medium', score: 40 },
      context: { sessionKey: msg.sessionKey }
    });
  }
}

// ===== 统计数据 =====
function getStats() {
  const now = Date.now();
  const hourAgo = now - 3600000;
  
  const recentEvents = events.filter(e => 
    new Date(e.timestamp).getTime() > hourAgo
  );
  
  return {
    totalAlerts: events.length,
    lastHour: recentEvents.length,
    bySeverity: {
      critical: events.filter(e => e.risk?.level === 'critical').length,
      high: events.filter(e => e.risk?.level === 'high').length,
      medium: events.filter(e => e.risk?.level === 'medium').length,
      low: events.filter(e => e.risk?.level === 'low').length
    },
    byType: {
      input: events.filter(e => e.source === 'input').length,
      tool: events.filter(e => e.type === 'tool_alert').length
    }
  };
}

// ===== HTTP 服务器 =====
const server = http.createServer((req, res) => {
  const webDir = path.join(__dirname, 'web');
  
  // API 端点
  if (req.url === '/api/events') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ events: events.slice(0, 100), stats: getStats() }));
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
      enableAI: config.enableAI,
      rulesCount: rules.rules.length
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

// ===== WebSocket 服务器 (实时推送) =====
server.on('upgrade', (req, socket, head) => {
  if (req.url !== '/ws') {
    socket.destroy();
    return;
  }

  const key = req.headers['sec-websocket-key'];
  const acceptKey = crypto
    .createHash('sha1')
    .update(key + '258EAFA5-E914-47DA-95CA-C5AB0DC85B11')
    .digest('base64');

  socket.write([
    'HTTP/1.1 101 Switching Protocols',
    'Upgrade: websocket',
    'Connection: Upgrade',
    `Sec-WebSocket-Accept: ${acceptKey}`,
    '',
    ''
  ].join('\r\n'));

  // 简易 WebSocket 处理
  const client = { socket, readyState: 1 };
  
  const sendToClient = (data) => {
    if (client.readyState !== 1) return;
    const payload = Buffer.from(JSON.stringify(data), 'utf-8');
    const frame = Buffer.alloc(2 + payload.length);
    frame[0] = 0x81;
    frame[1] = payload.length;
    payload.copy(frame, 2);
    socket.write(frame);
  };
  
  // 订阅事件
  const onEvent = (event) => sendToClient({ type: 'event', data: event });
  emitter.on('event', onEvent);
  
  socket.on('data', () => {}); // 忽略客户端消息
  
  socket.on('end', () => {
    client.readyState = 3;
    emitter.off('event', onEvent);
  });
});

// ===== 主程序 =====
async function main() {
  console.log('');
  console.log('🛡️  OpenClaw Guardian 启动中...');
  console.log('');

  // 启动 HTTP 服务器
  await new Promise(resolve => server.listen(config.port, resolve));
  
  console.log('┌─────────────────────────────────────────┐');
  console.log('│                                         │');
  console.log('│   🛡️  Guardian 已启动                   │');
  console.log('│                                         │');
  console.log(`│   监控面板: http://localhost:${config.port}    │`);
  console.log(`│   Gateway: ${config.gateway.padEnd(28)}│`);
  console.log(`│   AI分析: ${config.enableAI ? '已启用'.padEnd(28) : '已禁用'.padEnd(28)}│`);
  console.log('│                                         │');
  console.log('│   按 Ctrl+C 停止                        │');
  console.log('│                                         │');
  console.log('└─────────────────────────────────────────┘');
  console.log('');

  // 连接到 Gateway
  const wsUrl = config.gateway.replace(/^http/, 'ws') + '/ws';
  console.log(`📡 连接到 Gateway: ${wsUrl}`);
  
  const gatewayClient = new SimpleWebSocketClient(wsUrl);
  gatewayClient.connect();

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
    server.close();
    process.exit(0);
  });
}

main().catch(err => {
  console.error('启动失败:', err);
  process.exit(1);
});