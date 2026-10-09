// NasSimHub's original drawings and card states, adapted to NKNGuard's API.
import {buildGlobe} from './animations/networkGlobeGeometry.js';
import {paintGlobe} from './animations/networkGlobePainter.js';
import {buildField, advance} from './animations/dhtMeshField.js';
import {paintMesh} from './animations/dhtMeshPainter.js';

const panel = document.getElementById('network-animations');
const globe = document.getElementById('nkn-globe');
const mesh = document.getElementById('dht-mesh');
const points = buildGlobe();
const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
const text = (id, value) => { document.getElementById(id).textContent = value; };
const metric = value => typeof value === 'number' ? value.toLocaleString('zh-CN') : '—';
let field, fieldSize = '', status = {}, time = 0, previous = 0, inViewport = true;

function updateStates() {
  const nknActive = status.nkn_connected === true;
  const known = typeof status.dht_enabled === 'boolean';
  const ready = status.dht_enabled && status.dht_peers > 0;
  const badge = !known ? '未知' : !status.dht_enabled ? '已关闭' : ready ? '网络健康' : '运行中，未找到任何人';
  globe.closest('.net-card').dataset.state = nknActive ? 'online' : 'offline';
  mesh.closest('.net-card').dataset.state = ready ? 'online' : 'offline';
  text('nkn-animation-state', nknActive ? '已连接' : ({checking:'验证连接中',reconnecting:'重新连接中',closed:'未连接',unavailable:'状态不可用'})[status.nkn_connection?.state] || '等待 NKN');
  document.getElementById('nkn-animation-state').title = status.nkn_connection?.last_success && !status.nkn_connection.last_success.startsWith('0001-') ? `最近确认：${new Date(status.nkn_connection.last_success).toLocaleString()} · 自检往返 ${status.nkn_connection.latency_ms} 毫秒` : '等待消息经过 NKN 返回后确认连接';
  text('nkn-path-state', nknActive ? '连接正常' : '等待连接');
  text('nkn-visual-note', nknActive ? '全球连接 · 持续在线' : '全球节点示意');
  text('nkn-dht-state', !known ? '第二通路尚未启用' : !status.dht_enabled ? 'DHT 已关闭' : ready ? '可用 · 自动协同' : '孤立——没有找到任何节点');
  text('dht-animation-state', badge);
  text('dht-discovery-state', ready ? '持续发现邻居' : '节点发现已暂停');
  text('dht-second-state', !status.dht_enabled && known ? 'DHT 已关闭' : ready ? '已启用' : badge);
  document.getElementById('dht-signal-note').hidden = !ready;
  document.getElementById('nkn-path-state').closest('.net-row').classList.toggle('is-off', !nknActive);
  for (const id of ['nkn-dht-state', 'dht-discovery-state', 'dht-second-state']) {
    document.getElementById(id).closest('.net-row').classList.toggle('is-off', !ready);
  }
  text('dht-peer-count', metric(status.dht_peers));
  text('dht-route-count', metric(status.dht_routes));
  // Older daemons do not expose a LAN count; do not manufacture a zero.
  text('dht-lan-count', metric(status.dht_lan_peers));
}

window.addEventListener('nknguard-status', event => { status = event.detail; updateStates(); render(); });
window.addEventListener('nknguard-status-unavailable', () => { status = {...status,nkn_connected:false,nkn_connection:{state:'unavailable'}}; updateStates(); render(); });
window.addEventListener('nknguard-usage', event => {
  const counts = event.detail.counts || {};
  text('nkn-active-day', metric(counts.day));
  text('nkn-active-month', metric(counts.month));
  text('nkn-active-quarter', metric(counts.quarter));
});

function surface(canvas) {
  const width = canvas.clientWidth, height = canvas.clientHeight;
  if (!width || !height) return null;
  const ratio = Math.min(window.devicePixelRatio || 1, 2);
  const w = Math.round(width * ratio), h = Math.round(height * ratio);
  if (canvas.width !== w) canvas.width = w;
  if (canvas.height !== h) canvas.height = h;
  const context = canvas.getContext('2d');
  if (!context) return null;
  context.setTransform(1,0,0,1,0,0);
  context.clearRect(0,0,w,h);
  context.setTransform(ratio,0,0,ratio,0,0);
  return {context, width, height};
}
function drawable() {
  return !document.hidden && inViewport && document.getElementById('overview').classList.contains('active');
}
function render() {
  if (!drawable()) return;
  const nknActive = status.nkn_connected === true;
  const ready = status.dht_enabled && status.dht_peers > 0;
  const g = surface(globe);
  if (g) paintGlobe(g.context, points, {width:g.width,height:g.height,time,strength:nknActive ? 1 : .42,
    palette:{halo:'#5dbfe5',dot:'133 208 245',marker:'#a4e9ff',bodyNear:'rgb(32 73 101 / 13%)',bodyFar:'rgb(9 23 40 / 20%)',rim:'rgb(120 205 239 / 13%)'}});
  const m = surface(mesh);
  if (m) {
    const size = `${m.width}:${m.height}`;
    if (!field || size !== fieldSize) { field = buildField(m.width,m.height); fieldSize = size; }
    advance(field,time,!!ready);
    paintMesh(m.context,field,{width:m.width,height:m.height,time,strength:ready ? 1 : .22,
      palette:{strand:'124 169 217',nodeBloom:'120 191 239',nodeCore:'161 215 249',ring:'143 225 255',signal:'255 214 124',signalCore:'255 228 167'}});
  }
}
function tick(now) {
  if (drawable() && !reduced.matches) {
    if (previous) time += Math.min((now - previous)/1000,.05);
    render();
  }
  previous = now;
  requestAnimationFrame(tick);
}
new ResizeObserver(render).observe(panel);
new IntersectionObserver(entries => { inViewport = entries[0].isIntersecting; render(); }).observe(panel);
document.addEventListener('visibilitychange', render);
reduced.addEventListener('change', render);
new MutationObserver(render).observe(document.getElementById('overview'), {attributes:true,attributeFilter:['class']});
updateStates();
window.dispatchEvent(new Event('nknguard-network-ready'));
requestAnimationFrame(tick);
