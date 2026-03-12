/**
 * Piper 监控面板前端
 */

// DOM 元素
const elements = {
  connectionDot: document.getElementById('connectionDot'),
  connectionText: document.getElementById('connectionText'),
  criticalCount: document.getElementById('criticalCount'),
  highCount: document.getElementById('highCount'),
  mediumCount: document.getElementById('mediumCount'),
  totalAlerts: document.getElementById('totalAlerts'),
  alertsList: document.getElementById('alertsList'),
  detailContent: document.getElementById('detailContent'),
  gatewayUrl: document.getElementById('gatewayUrl'),
  rulesCount: document.getElementById('rulesCount'),
  dbPath: document.getElementById('dbPath'),
  refreshBtn: document.getElementById('refreshBtn')
};

// 状态
let alerts = [];
let selectedAlertId = null;
let ws = null;

// ===== 工具函数 =====
function formatTime(isoString) {
  const date = new Date(isoString);
  return date.toLocaleTimeString('zh-CN', { 
    hour: '2-digit', 
    minute: '2-digit', 
    second: '2-digit' 
  });
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function truncate(text, maxLen = 100) {
  if (!text) return '';
  return text.length > maxLen ? text.slice(0, maxLen) + '...' : text;
}

// ===== WebSocket 连接 =====
function connectWebSocket() {
  const wsUrl = `ws://${location.host}/ws`;
  
  ws = new WebSocket(wsUrl);
  
  ws.onopen = () => {
    elements.connectionDot.classList.add('connected');
    elements.connectionDot.classList.remove('disconnected');
    elements.connectionText.textContent = '监控中';
  };
  
  ws.onmessage = (event) => {
    try {
      const data = JSON.parse(event.data);
      if (data.type === 'init') {
        // 初始化数据
        alerts = data.data || [];
        renderAlerts();
        updateStatsFromAlerts();
      } else if (data.type === 'event') {
        // 新事件
        addAlert(data.data);
      }
    } catch (e) {
      console.error('消息解析错误:', e);
    }
  };
  
  ws.onclose = () => {
    elements.connectionDot.classList.remove('connected');
    elements.connectionDot.classList.add('disconnected');
    elements.connectionText.textContent = '已断开';
    // 重连
    setTimeout(connectWebSocket, 3000);
  };
  
  ws.onerror = () => {
    elements.connectionText.textContent = '连接错误';
  };
}

// ===== 数据加载 =====
async function loadData() {
  try {
    const response = await fetch('/api/events');
    const data = await response.json();
    
    alerts = data.events || [];
    updateStats(data.stats);
    renderAlerts();
    
    // 更新配置信息
    loadConfig();
  } catch (e) {
    console.error('加载数据失败:', e);
  }
}

async function loadConfig() {
  try {
    const response = await fetch('/api/config');
    const config = await response.json();
    
    elements.gatewayUrl.textContent = config.gateway;
    elements.rulesCount.textContent = config.rulesCount;
    elements.dbPath.textContent = config.dbPath ? config.dbPath.split('/').pop() : '-';
  } catch (e) {
    console.error('加载配置失败:', e);
  }
}

// ===== 更新统计 =====
function updateStats(stats) {
  elements.criticalCount.textContent = stats?.bySeverity?.critical || 0;
  elements.highCount.textContent = stats?.bySeverity?.high || 0;
  elements.mediumCount.textContent = stats?.bySeverity?.medium || 0;
  elements.totalAlerts.textContent = stats?.totalAlerts || 0;
}

function updateStatsFromAlerts() {
  const stats = {
    totalAlerts: alerts.length,
    bySeverity: {
      critical: alerts.filter(a => a.risk?.level === 'critical').length,
      high: alerts.filter(a => a.risk?.level === 'high').length,
      medium: alerts.filter(a => a.risk?.level === 'medium').length,
      low: alerts.filter(a => a.risk?.level === 'low').length
    }
  };
  updateStats(stats);
}

// ===== 渲染告警列表 =====
function renderAlerts() {
  if (!alerts.length) {
    elements.alertsList.innerHTML = `
      <div class="empty-state">
        <span class="icon">✅</span>
        <p>暂无告警</p>
        <p class="hint">系统正在监控中...</p>
      </div>
    `;
    return;
  }
  
  elements.alertsList.innerHTML = alerts.map(alert => {
    const severity = alert.risk?.level || 'low';
    const title = alert.findings?.[0]?.name || '可疑输入';
    const preview = truncate(alert.text, 80);
    const time = formatTime(alert.timestamp);
    
    const tags = alert.findings?.slice(0, 3).map(f => 
      `<span class="tag ${f.severity}">${f.name}</span>`
    ).join('') || '';
    
    return `
      <div class="alert-item ${severity} ${alert.id === selectedAlertId ? 'selected' : ''} new"
           data-id="${alert.id}">
        <div class="alert-header">
          <span class="alert-title">${title}</span>
          <span class="alert-time">${time}</span>
        </div>
        <div class="alert-preview">${escapeHtml(preview)}</div>
        <div class="alert-tags">${tags}</div>
      </div>
    `;
  }).join('');
  
  // 绑定点击事件
  document.querySelectorAll('.alert-item').forEach(item => {
    item.addEventListener('click', () => {
      const id = item.dataset.id;
      selectAlert(id);
    });
  });
}

// ===== 添加新告警 =====
function addAlert(alert) {
  // 避免重复
  if (alerts.find(a => a.id === alert.id)) return;
  
  alerts.unshift(alert);
  if (alerts.length > 100) alerts.pop();
  
  updateStatsFromAlerts();
  renderAlerts();
}

// ===== 选择告警 =====
function selectAlert(id) {
  selectedAlertId = id;
  const alert = alerts.find(a => a.id === id);
  
  // 更新选中状态
  document.querySelectorAll('.alert-item').forEach(item => {
    item.classList.toggle('selected', item.dataset.id === id);
  });
  
  if (!alert) return;
  
  // 渲染详情
  const severity = alert.risk?.level || 'low';
  const time = new Date(alert.timestamp).toLocaleString('zh-CN');
  
  let findingsHtml = '';
  if (alert.findings?.length) {
    findingsHtml = alert.findings.map(f => `
      <div class="finding-item">
        <div class="finding-name">${f.name}</div>
        <div class="finding-desc">${f.description}</div>
        ${f.matches?.length ? `
          <div class="finding-match">
            匹配: "${escapeHtml(f.matches[0].matched)}"
          </div>
        ` : ''}
      </div>
    `).join('');
  }
  
  elements.detailContent.innerHTML = `
    <div class="detail-section">
      <h3>概览</h3>
      <div class="finding-item">
        <span class="tag ${severity}">${severity.toUpperCase()}</span>
        <span style="margin-left: 12px; color: var(--text-secondary);">${time}</span>
      </div>
    </div>
    
    <div class="detail-section">
      <h3>检测到的威胁</h3>
      ${findingsHtml || '<p style="color: var(--text-muted);">无详细信息</p>'}
    </div>
    
    <div class="detail-section">
      <h3>用户输入</h3>
      <div class="detail-text">${escapeHtml(alert.text || '(无内容)')}</div>
    </div>
    
    ${alert.context && Object.keys(alert.context).length ? `
      <div class="detail-section">
        <h3>上下文</h3>
        <div class="detail-text">${escapeHtml(JSON.stringify(alert.context, null, 2))}</div>
      </div>
    ` : ''}
  `;
}

// ===== 事件绑定 =====
elements.refreshBtn.addEventListener('click', loadData);

// ===== 初始化 =====
function init() {
  loadData();
  connectWebSocket();
  
  // 定期刷新
  setInterval(loadData, 30000);
}

init();