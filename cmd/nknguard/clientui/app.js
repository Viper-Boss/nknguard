const byId = id => document.getElementById(id);
let latest = {};

async function action(route, payload) {
  const response = await fetch(route, {
    method: 'POST',
    headers: {'X-NKNGuard-Client':'1','Content-Type':'application/json'},
    body: JSON.stringify(payload || {})
  });
  if (!response.ok) throw new Error((await response.text()).trim() || '操作失败');
}

function pathText(value) {
  return {'direct-wg':'WireGuard 直连','nkn-relay':'NKN 加密中继','none':'正在寻找链路'}[value] || '正在寻找链路';
}

function draw(state) {
  latest = state;
  const connected = !!state.connected;
  const paired = !!state.paired;
  const path = state.path || 'none';
  byId('top-state').textContent = connected ? '客户端已运行' : paired ? '等待连接' : '尚未配对';
  byId('top-state').classList.toggle('on', connected);
  byId('state-title').textContent = !paired ? '请先配对 NAS' : !connected ? state.connecting ? '正在建立连接' : '已断开' : path === 'direct-wg' ? '已安全直连' : path === 'nkn-relay' ? '已通过 NKN 中继' : '正在建立安全链路';
  byId('state-copy').textContent = state.message || (connected ? '现在可以正常使用飞牛客户端。' : paired ? '点击连接后将尝试上次链路和最新信标。' : '复制 NAS 面板上的配对内容到下方。');
  byId('route-label').textContent = connected ? pathText(path) : '尚未连接';
  byId('connect').disabled = !paired || connected || !!state.connecting;
  byId('disconnect').disabled = !connected;
  byId('pair').disabled = paired || !!state.pairing;
  byId('pair-card').hidden = paired;
  byId('error').textContent = state.error || '';
  byId('nas-address').textContent = state.nas_address || '未配对';
  byId('local-address').textContent = state.local_nkn_address || '连接后显示';
  byId('virtual-ip').textContent = state.virtual_ip || '—';
  byId('nas-ip').textContent = state.nas_ip || '—';
  byId('pair-progress').textContent = state.pairing ? state.message || '等待 NAS 批准…' : '二维码只用于发起申请，必须由 NAS 主人批准。';
  byId('code-panel').hidden = !state.pair_code;
  byId('pair-code').textContent = state.pair_code || '';
}

async function refresh() {
  try {
    const response = await fetch('/api/state', {cache:'no-store'});
    if (!response.ok) throw new Error('状态不可用');
    draw(await response.json());
  } catch (error) {
    byId('error').textContent = error.message;
  }
}

byId('pair').addEventListener('click', async () => {
  try {
    await action('/api/pair', {invitation:byId('invitation').value.trim(), name:byId('device-name').value.trim()});
    await refresh();
  } catch (error) { byId('error').textContent = error.message; }
});
byId('connect').addEventListener('click', async () => {
  try { await action('/api/connect'); await refresh(); }
  catch (error) { byId('error').textContent = error.message; }
});
byId('disconnect').addEventListener('click', async () => {
  try { await action('/api/disconnect'); await refresh(); }
  catch (error) { byId('error').textContent = error.message; }
});
function copy(value) {
  if (value && value !== '未配对' && value !== '连接后显示') navigator.clipboard.writeText(value);
}
byId('copy-nas').addEventListener('click', () => copy(latest.nas_address));
byId('copy-local').addEventListener('click', () => copy(latest.local_nkn_address));
refresh();
setInterval(refresh, 2200);
