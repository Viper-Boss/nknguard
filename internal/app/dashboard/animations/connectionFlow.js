// Connection illustration; colors follow the observed path, positions do not
// represent geography and moving beads are not a packet or throughput counter.
export function paintConnectionFlow(context, {width, height, time, mode}) {
  if (mode === 'offline') return;
  const x = width / 2, y = height / 2 - 8;
  const radius = Math.min(width * .355, height * .426) * (1 + .012 * Math.sin(time * .6));
  const color = mode === 'direct' ? '#65e5bb' : mode === 'relay' ? '#ffd67c' : '#85d0f5';
  const routes = [
    [[-.62,.35],[-.25,-.9],[.63,-.25]],
    [[-.62,.35],[.35,.68],[.63,-.25]],
    [[-.62,.35],[-.62,-.7],[.05,-.57]],
  ];
  const position = (route, p) => {
    const q = 1 - p;
    return [x + radius * (q*q*route[0][0] + 2*q*p*route[1][0] + p*p*route[2][0]),
      y + radius * (q*q*route[0][1] + 2*q*p*route[1][1] + p*p*route[2][1])];
  };
  context.save();
  context.lineCap = 'round';
  routes.forEach((route, index) => {
    const start = position(route, 0), end = position(route, 1);
    context.beginPath(); context.moveTo(...start);
    context.quadraticCurveTo(x + route[1][0]*radius, y + route[1][1]*radius, ...end);
    context.strokeStyle = color + '55'; context.lineWidth = 1;
    context.setLineDash(mode === 'waiting' ? [4,6] : []); context.stroke(); context.setLineDash([]);
    const progress = (time * .23 + index * .31) % 1;
    for (let segment = 0; segment < 12; segment++) {
      const p = progress - segment * .012;
      if (p < 0) break;
      const a = position(route, p), b = position(route, Math.max(0,p-.012));
      context.beginPath(); context.moveTo(...a); context.lineTo(...b);
      context.strokeStyle = color; context.globalAlpha = (1 - segment/12)*.8;
      context.lineWidth = 2.4; context.stroke();
    }
    context.globalAlpha = 1;
    const head = position(route, progress);
    context.shadowColor = color; context.shadowBlur = 10;
    context.fillStyle = '#efffff'; context.beginPath(); context.arc(...head,2.4,0,Math.PI*2); context.fill();
    for (const point of [start,end]) {
      context.fillStyle = color; context.beginPath(); context.arc(...point,3,0,Math.PI*2); context.fill();
      context.shadowBlur = 0; context.strokeStyle = color + '88'; context.lineWidth = 1;
      context.beginPath(); context.arc(...point,6 + 2*Math.sin(time*2+index),0,Math.PI*2); context.stroke();
    }
    context.shadowBlur = 0;
  });
  context.restore();
}
