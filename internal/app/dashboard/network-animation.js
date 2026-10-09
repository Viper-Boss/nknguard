import {buildGlobe} from './animations/networkGlobeGeometry.js';
import {paintGlobe} from './animations/networkGlobePainter.js';
import {buildField, advance} from './animations/dhtMeshField.js';
import {paintMesh} from './animations/dhtMeshPainter.js';
import {paintConnectionFlow} from './animations/connectionFlow.js';

const globe = document.getElementById('nkn-globe');
const mesh = document.getElementById('dht-mesh');
const points = buildGlobe(3600);
const reduced = window.matchMedia('(prefers-reduced-motion: reduce)');
let field, fieldSize = '', status = {}, time = 0, previous = 0;
window.addEventListener('nknguard-status', event => { status = event.detail; render(); });
function surface(canvas) {
  const {width, height} = canvas.getBoundingClientRect();
  if (!width || !height) return null;
  const ratio = Math.min(window.devicePixelRatio || 1, 1.5);
  const w = Math.round(width * ratio), h = Math.round(height * ratio);
  if (canvas.width !== w) canvas.width = w;
  if (canvas.height !== h) canvas.height = h;
  const context = canvas.getContext('2d');
  context.setTransform(1,0,0,1,0,0); context.clearRect(0,0,w,h);
  context.setTransform(ratio,0,0,ratio,0,0);
  return {context, width, height};
}
function render() {
  if (document.hidden || !document.getElementById('overview').classList.contains('active')) return;
  const relayReady = (status.peers || []).some(peer => peer.path === 'nkn-relay');
  const directReady = (status.peers || []).some(peer => peer.path === 'direct-wg');
  const mode = directReady ? 'direct' : relayReady ? 'relay' : status.nkn_address ? 'waiting' : 'offline';
  const dhtReady = status.dht_enabled && status.dht_peers > 0;
  document.getElementById('nkn-animation-state').textContent = directReady && relayReady ? '直连 + NKN 中继' : directReady ? 'WireGuard 直连' : relayReady ? 'NKN 中继可用' : status.nkn_address ? '身份地址已就绪' : '等待 NKN';
  document.getElementById('dht-animation-state').textContent = !status.dht_enabled ? '未启用' : dhtReady ? '已连接节点' : '运行中，暂无节点';
  document.getElementById('dht-peer-count').textContent = status.dht_peers || 0;
  document.getElementById('dht-route-count').textContent = status.dht_routes || 0;
  const g = surface(globe);
  if (g) {
    paintGlobe(g.context, points, {width:g.width, height:g.height, time,
      strength:relayReady || directReady ? 1 : 0.42, palette:{halo:'#5dbfe5',dot:'133 208 245',marker:'#b0ecff',bodyNear:'#17334b',bodyFar:'#102135',rim:'#31556b'}});
    paintConnectionFlow(g.context, {width:g.width,height:g.height,time,mode});
  }
  const m = surface(mesh);
  if (m) {
    const size = `${Math.round(m.width)}:${Math.round(m.height)}`;
    if (!field || size !== fieldSize) { field = buildField(m.width,m.height); fieldSize = size; }
    // Blue discovery paths are an explicitly labelled illustration while
    // isolated. Amber paths are enabled only with actual local DHT peers.
    advance(field,time,!!status.dht_enabled);
    paintMesh(m.context,field,{width:m.width,height:m.height,time,strength:dhtReady ? 1 : status.dht_enabled ? .65 : .22,
      illustration:!!status.dht_enabled && !dhtReady,
      palette:{strand:'124 169 217',nodeBloom:'120 191 239',nodeCore:'161 215 249',ring:'143 225 255',signal:dhtReady ? '255 214 124' : '133 208 245',signalCore:dhtReady ? '255 228 167' : '195 235 255'}});
  }
}
function tick(now) {
  if (now - previous >= 50) {
    if (!document.hidden && !reduced.matches) time += Math.min((now - previous)/1000,0.1);
    previous = now; render();
  }
  requestAnimationFrame(tick);
}
new ResizeObserver(render).observe(document.getElementById('network-animations'));
requestAnimationFrame(tick);
