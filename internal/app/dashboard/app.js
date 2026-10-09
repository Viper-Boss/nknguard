const byId = id => document.getElementById(id);
const setText = (id, value) => { byId(id).textContent = value ?? '—'; };
const pathLabel = path => ({'direct-wg':'WireGuard 直连','nkn-relay':'NKN 中继','none':'等待连接'})[path] || '等待连接';
const stateLabel = state => ({'DIRECT':'已直连','RELAY':'已中继','PUNCHING':'正在打洞','RELAY_CONNECTING':'建立中继','OFFLINE':'离线'})[state] || '连接中';
const natLabel = value => ({'endpoint-independent':'端点无关型','address-dependent':'对称型','open':'无需 NAT','unknown':'未知'})[value] || '未知';
const natHint = value => ({'endpoint-independent':'映射稳定 · 利于直连','address-dependent':'映射受限 · 可能需要中继','open':'直接连接公网','unknown':'等待自动探测'})[value] || '等待自动探测';
let currentStatus = null;
let currentUsage = null;
window.addEventListener('nknguard-network-ready', () => {
  if (currentStatus) window.dispatchEvent(new CustomEvent('nknguard-status', {detail:currentStatus}));
  if (currentUsage) window.dispatchEvent(new CustomEvent('nknguard-usage', {detail:currentUsage}));
});
let lastUpdate = 0;
let inviteURI = '';
let firstPairCheck = true;

function toast(message) {
  const element = byId('toast');
  element.textContent = message;
  element.classList.add('visible');
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => element.classList.remove('visible'), 3400);
}

function changeView(name) {
  document.querySelectorAll('.view').forEach(element => element.classList.toggle('active', element.id === name));
  document.querySelectorAll('.nav-item').forEach(element => element.classList.toggle('active', element.dataset.view === name));
  setText('page-title', ({overview:'连接总览',devices:'设备列表',pairing:'配对与授权',paths:'链路状态',logs:'运行日志',security:'安全设置'})[name]);
  if (name === 'logs') refreshLogs();
  if (name === 'pairing') refreshPairState();
}

function formatHandshake(value) {
  if (!value || value.startsWith('0001-')) return '尚未握手';
  const age = Math.max(0, Math.floor((Date.now() - Date.parse(value)) / 1000));
  if (!Number.isFinite(age)) return '尚未握手';
  return age < 60 ? `${age} 秒前` : age < 3600 ? `${Math.floor(age / 60)} 分钟前` : `${Math.floor(age / 3600)} 小时前`;
}

function badge(path) {
  const element = document.createElement('span');
  element.className = `mini-path ${path === 'direct-wg' || path === 'nkn-relay' ? path : 'none'}`;
  element.textContent = pathLabel(path);
  return element;
}

function renderDevices(peers) {
  const recent = byId('recent-devices');
  const table = byId('device-table');
  recent.replaceChildren();
  table.replaceChildren();
  setText('devices-count', `${peers.length} 台设备`);
  if (!peers.length) {
    const empty = document.createElement('div'); empty.className = 'empty'; empty.textContent = '暂时没有对端设备。配对后会显示在这里。'; recent.append(empty);
    const row = table.insertRow(); const cell = row.insertCell(); cell.colSpan = 5; cell.className = 'empty'; cell.textContent = '暂无已验证设备';
    return;
  }
  peers.slice(0, 3).forEach(peer => {
    const item = document.createElement('div'); item.className = 'device-item';
    const icon = document.createElement('span'); icon.className = 'device-icon'; icon.textContent = '▣';
    const info = document.createElement('div');
    const name = document.createElement('b'); name.textContent = peer.name || peer.device_id;
    const sub = document.createElement('small'); sub.textContent = `${peer.virtual_ip || '无虚拟 IP'} · ${stateLabel(peer.state)}`;
    info.append(name, sub); item.append(icon, info, badge(peer.path)); recent.append(item);
  });
  peers.forEach(peer => {
    const row = table.insertRow();
    const name = row.insertCell(); const strong = document.createElement('b'); strong.textContent = peer.name || peer.device_id; name.append(strong);
    row.insertCell().textContent = peer.virtual_ip || '—';
    row.insertCell().append(badge(peer.path));
    row.insertCell().textContent = formatHandshake(peer.last_handshake);
    const action = row.insertCell(); const button = document.createElement('button'); button.className = 'secondary-button'; button.textContent = '重试直连';
    button.disabled = peer.path === 'direct-wg';
    button.addEventListener('click', () => reconnect(peer.device_id)); action.append(button);
  });
}

function render(status) {
  currentStatus = status;
  const peers = Array.isArray(status.peers) ? status.peers : [];
  const direct = peers.filter(p => p.path === 'direct-wg').length;
  const relay = peers.filter(p => p.path === 'nkn-relay').length;
  const online = direct + relay;
  setText('side-version', status.version || '—');
  setText('online-count', `${online} / ${peers.length}`);
  setText('total-count', peers.length ? `${peers.length} 台已验证设备` : '等待设备配对');
  setText('direct-count', direct);
  setText('relay-count', relay);
  setText('nat-state', natLabel(status.nat_behaviour));
  setText('nat-note', natHint(status.nat_behaviour));
  setText('hero-device-name', status.device_name || '我的飞牛 NAS');
  const nknVerified = status.nkn_connected === true;
  byId('nkn-sidebar-state').textContent = nknVerified ? 'NKN 已连接' : status.nkn_connection?.state === 'checking' ? '正在验证 NKN' : 'NKN 连接待恢复';
  document.querySelector('.sidebar').dataset.connection = nknVerified ? 'online' : 'offline';
  setText('route-direct', direct);
  setText('route-relay', relay);
  setText('route-idle', peers.length - online);
  const pill = byId('overall-pill');
  const wgReady = status.wireguard?.state === 'up';
  const beaconReady = nknVerified;
  pill.className = `pill ${wgReady && beaconReady ? 'good' : 'warn'}`;
  pill.replaceChildren(); const dot = document.createElement('i'); pill.append(dot, document.createTextNode(!wgReady ? '检查 WireGuard' : beaconReady ? 'NAS 已就绪' : '等待 NKN 信标 · 本地管理可用'));
  setText('detail-name', status.device_name);
  setText('detail-id', status.device_id);
  setText('detail-ip', status.virtual_ip);
  setText('overview-nas-ip', status.virtual_ip);
  setText('overview-cidr', status.overlay_cidr);
  window.dispatchEvent(new CustomEvent('nknguard-status', {detail: status}));
  setText('overview-fnos-address', status.virtual_ip ? `${status.virtual_ip}:5666` : '等待 NAS 虚拟 IP');
  byId('copy-fnos-address').disabled = !status.virtual_ip;
  setText('detail-nkn', status.nkn_address);
  setText('overview-nkn-address', status.nkn_address || 'NKN 尚未连接');
  byId('copy-nkn-address').disabled = !status.nkn_address;
  setText('detail-uptime', status.uptime);
  setText('detail-wg', status.wireguard?.state);
  setText('detail-port', status.wireguard?.listen_port);
  setText('detail-nat', natLabel(status.nat_behaviour));
  setText('detail-punch', status.metrics?.punch_success);
  setText('detail-fallback', status.metrics?.relay_fallback_count);
  renderDevices(peers);
  lastUpdate = Date.now();
  setText('updated', '刚刚更新');
}

async function refresh() {
  try {
    const response = await fetch('/api/status', {cache:'no-store'});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
  } catch (error) {
    currentStatus = null;
    window.dispatchEvent(new Event('nknguard-status-unavailable'));
    const pill = byId('overall-pill'); pill.className = 'pill bad'; pill.textContent = '状态不可用';
    setText('updated', '连接中断');
  }
}

async function refreshLogs() {
  try {
    const response = await fetch('/api/logs', {cache:'no-store'});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const lines = await response.json();
    setText('log-lines', Array.isArray(lines) && lines.length ? lines.slice(-300).join('\n') : '暂无日志');
  } catch (error) { setText('log-lines', '读取日志失败'); }
}

async function reconnect(id) {
  try {
    const response = await fetch(`/api/peers/${encodeURIComponent(id)}/reconnect`, {method:'POST',headers:{'X-NKNGuard-UI':'1'}});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    toast('已安排重新尝试直连');
    setTimeout(refresh, 700);
  } catch (error) { toast('重试失败，请查看日志'); }
}

async function changePassword(event) {
  event.preventDefault();
  const current = byId('current-password').value;
  const next = byId('new-password').value;
  const confirmation = byId('confirm-password').value;
  const message = byId('password-message');
  if ([...next].length < 12) { message.textContent = '新密码至少需要 12 个字符。'; return; }
  if (next !== confirmation) { message.textContent = '两次输入的新密码不一致。'; return; }
  try {
    const response = await fetch('/api/admin/password', {method:'POST',headers:{'Content-Type':'application/json','X-NKNGuard-UI':'1'},body:JSON.stringify({current,new:next})});
    if (!response.ok) throw new Error((await response.text()).trim() || `HTTP ${response.status}`);
    byId('password-form').reset();
    message.textContent = '密码已更新。请刷新页面并使用新密码登录。';
    toast('管理密码已更新');
  } catch (error) { message.textContent = `修改失败：${error.message}`; }
}

const countText = value => (typeof value === 'number' ? value.toLocaleString('zh-CN') : '—');

function renderUsage(status) {
  currentUsage = status;
  window.dispatchEvent(new CustomEvent('nknguard-usage', {detail: status}));
  const counts = status.counts || {};
  setText('usage-day', countText(counts.day));
  setText('usage-month', countText(counts.month));
  setText('usage-quarter', countText(counts.quarter));
  let note;
  if (!status.enabled) note = '本机未参与统计。人数仍可查看。';
  else if (status.last_check_in) note = `本机已参与统计 · 上次签到 ${new Date(status.last_check_in).toLocaleString()}`;
  else note = '本机已参与统计 · 等待首次签到（写入区块约需 1 分钟）';
  if (counts.error) note += ` · 部分数据读取失败：${counts.error}`;
  else if (status.last_error) note += ` · 签到失败，稍后重试：${status.last_error}`;
  setText('usage-note', note);
}

async function refreshUsage(force) {
  try {
    const response = await fetch(`/api/usage${force ? '?refresh=1' : ''}`, {cache:'no-store'});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    renderUsage(await response.json());
  } catch (error) {
    currentUsage = null;
    window.dispatchEvent(new CustomEvent('nknguard-usage', {detail: {}}));
    setText('usage-note', '读取使用人数失败');
  }
}

async function postAction(route) {
  const response = await fetch(route, {method:'POST',headers:{'X-NKNGuard-UI':'1'}});
  if (!response.ok) throw new Error((await response.text()).trim() || `HTTP ${response.status}`);
  return response.json();
}

async function newInvite() {
  try {
    const result = await postAction('/api/pair/invite');
    inviteURI = result.uri;
    const qr = document.createElement('img'); qr.src = result.qr_data_url; qr.alt = 'NKNGuard 一次性配对二维码';
    qr.tabIndex = 0;
    qr.setAttribute('role', 'button');
    qr.setAttribute('aria-label', '放大配对二维码');
    const enlarge = () => { byId('qr-large').src = qr.src; byId('qr-dialog').showModal(); };
    qr.addEventListener('click', enlarge);
    qr.addEventListener('keydown', event => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); enlarge(); } });
    byId('qr-large').src = qr.src;
    byId('qr-wrap').replaceChildren(qr);
    byId('copy-invite').disabled = false;
    setText('invite-link', result.uri);
    byId('invite-link-box').hidden = false;
    setText('invite-expiry', `有效至 ${new Date(result.expires_at).toLocaleTimeString()} · 需要本机批准`);
    toast('二维码已生成，请现场扫码');
  } catch (error) { toast('生成失败：' + error.message); }
}

async function refreshPairState() {
  try {
    const response = await fetch('/api/pair/state', {cache:'no-store'});
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    const state = await response.json();
    const pending = Array.isArray(state.pending) ? state.pending : [];
    const approved = Array.isArray(state.approved) ? state.approved : [];
    setText('pending-count', pending.length);
    const pendingList = byId('pending-list'); pendingList.replaceChildren();
    if (!pending.length) { const empty = document.createElement('div'); empty.className = 'empty'; empty.textContent = '暂无配对申请'; pendingList.append(empty); }
    pending.forEach(entry => {
      const item = document.createElement('div'); item.className = 'pending-item';
      const icon = document.createElement('span'); icon.className = 'device-icon'; icon.textContent = '▣';
      const copy = document.createElement('div'); copy.className = 'pending-copy';
      const name = document.createElement('b'); name.textContent = entry.name;
      const id = document.createElement('small'); id.textContent = entry.device_id;
      copy.append(name,id);
      const code = document.createElement('span'); code.className = 'verify-code'; code.textContent = entry.code;
      const button = document.createElement('button'); button.className = 'primary-button'; button.textContent = '核对后批准';
      button.addEventListener('click', async () => {
        if (!confirm(`请确认新设备上显示的验证码也是 ${entry.code}，并且设备名为 ${entry.name}。确认批准？`)) return;
        try { await postAction(`/api/pair/${encodeURIComponent(entry.device_id)}/approve`); toast('设备已授权'); refreshPairState(); refresh(); }
        catch (error) { toast('批准失败：' + error.message); }
      });
      item.append(icon,copy,code,button); pendingList.append(item);
    });
    const approvedList = byId('approved-list'); approvedList.replaceChildren();
    if (!approved.length) { const empty = document.createElement('div'); empty.className = 'empty'; empty.textContent = '暂无已授权设备'; approvedList.append(empty); }
    approved.forEach(id => {
      const item = document.createElement('div'); item.className = 'approved-item';
      const icon = document.createElement('span'); icon.className = 'device-icon'; icon.textContent = '✓';
      const copy = document.createElement('div'); copy.className = 'pending-copy';
      const name = document.createElement('b'); name.textContent = currentStatus?.peers?.find(p => p.device_id === id)?.name || '已授权设备';
      const device = document.createElement('small'); device.textContent = id; copy.append(name,device);
      const button = document.createElement('button'); button.className = 'danger-button'; button.textContent = '撤销';
      button.addEventListener('click', async () => {
        if (!confirm(`撤销 ${id} 的连接权限？`)) return;
        try { await postAction(`/api/pair/${encodeURIComponent(id)}/revoke`); toast('授权已撤销'); refreshPairState(); refresh(); }
        catch (error) { toast('撤销失败：' + error.message); }
      });
      item.append(icon,copy,button); approvedList.append(item);
    });
    if (firstPairCheck) {
      firstPairCheck = false;
      if (state.is_owner && !approved.length && !pending.length) { changeView('pairing'); newInvite(); }
    }
  } catch (error) { toast('读取配对状态失败'); }
}

document.querySelectorAll('.nav-item').forEach(button => button.addEventListener('click', () => changeView(button.dataset.view)));
document.querySelectorAll('[data-go]').forEach(button => button.addEventListener('click', () => changeView(button.dataset.go)));
byId('refresh').addEventListener('click', refresh);
byId('refresh-logs').addEventListener('click', refreshLogs);
byId('refresh-usage').addEventListener('click', () => refreshUsage(true));
byId('password-form').addEventListener('submit', changePassword);
byId('new-invite').addEventListener('click', newInvite);
byId('copy-invite').addEventListener('click', () => {
  if (!navigator.clipboard) { selectInviteLink(); toast('已选中配对链接，请按 Ctrl+C 复制'); return; }
  navigator.clipboard.writeText(inviteURI).then(() => toast('配对链接已复制')).catch(() => { selectInviteLink(); toast('已选中配对链接，请按 Ctrl+C 复制'); });
});
byId('invite-link').addEventListener('click', selectInviteLink);
function selectInviteLink() {
  const range = document.createRange();
  range.selectNodeContents(byId('invite-link'));
  const selection = window.getSelection();
  selection.removeAllRanges();
  selection.addRange(range);
}
byId('copy-nkn-address').addEventListener('click', () => {
  const address = currentStatus?.nkn_address;
  if (address) navigator.clipboard.writeText(address).then(() => toast('NKN 地址已复制')).catch(() => toast('复制失败'));
});
byId('close-qr').addEventListener('click', () => byId('qr-dialog').close());
byId('copy-fnos-address').addEventListener('click', async () => {
  if (!currentStatus?.virtual_ip) return;
  const value = `${currentStatus.virtual_ip}:5666`;
  try { await navigator.clipboard.writeText(value); toast('飞牛地址已复制'); }
  catch (_) {
    const range = document.createRange(); range.selectNodeContents(byId('overview-fnos-address'));
    const selection = window.getSelection(); selection.removeAllRanges(); selection.addRange(range);
    toast('已选中飞牛地址，请手动复制');
  }
});
refresh();
refreshPairState();
refreshUsage(false);
setInterval(refresh, 3000);
setInterval(() => refreshUsage(false), 60000);
setInterval(refreshPairState, 3000);
setInterval(() => { if (lastUpdate) setText('updated', `${Math.round((Date.now()-lastUpdate)/1000)} 秒前更新`); }, 1000);
