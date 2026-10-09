// Adapted from the owner-provided NasSimHub source. See ANIMATIONS.md.
import { defaultMeshOptions, hopGlow, signalHead } from './dhtMeshField.js';
export function paintMesh(context, field, options) {
    const { palette, strength, time } = options;
    const mesh = options.mesh ?? defaultMeshOptions;
    const live = strength > 0.999 || options.illustration === true;
    context.lineWidth = 0.8;
    for (const [a, b] of field.edges){
        const from = field.nodes[a];
        const to = field.nodes[b];
        if (!from || !to) continue;
        const alpha = 0.22 * Math.min(from.alpha, to.alpha) * strength;
        context.beginPath();
        context.moveTo(from.px, from.py);
        context.lineTo(to.px, to.py);
        context.strokeStyle = channels(palette.strand, alpha);
        context.stroke();
    }
    for (const node of field.nodes){
        const alpha = node.alpha * strength;
        fill(context, node.px, node.py, 5.5, channels(palette.nodeBloom, alpha * 0.055));
        fill(context, node.px, node.py, 1.65, channels(palette.nodeCore, alpha * 0.74));
        if (!live || !node.changing || node.to !== 1) continue;
        const progress = clamp01((time - node.start) / mesh.fadeDuration);
        context.beginPath();
        context.arc(node.px, node.py, 4 + 12 * progress, 0, Math.PI * 2);
        context.strokeStyle = channels(palette.ring, Math.sin(progress * Math.PI) * 0.5);
        context.lineWidth = 1;
        context.stroke();
        context.lineWidth = 0.8;
    }
    if (!live) return;
    for (const signal of field.signals){
        const head = signalHead(signal, time, mesh);
        for(let hop = 0; hop < signal.path.length - 1; hop += 1){
            const glow = hopGlow(signal, hop, time, mesh);
            if (glow <= 0.01) continue;
            const from = field.nodes[signal.path[hop]];
            const to = field.nodes[signal.path[hop + 1]];
            if (!from || !to) continue;
            const reach = hop === head.hop && !head.arrived ? head.fraction : 1;
            const tipX = from.px + (to.px - from.px) * reach;
            const tipY = from.py + (to.py - from.py) * reach;
            const gradient = context.createLinearGradient(from.px, from.py, tipX + 0.001, tipY + 0.001);
            gradient.addColorStop(0, channels(palette.signal, glow * 0.15));
            gradient.addColorStop(1, channels(palette.signal, glow));
            context.beginPath();
            context.moveTo(from.px, from.py);
            context.lineTo(tipX, tipY);
            context.strokeStyle = gradient;
            context.lineWidth = 1.8;
            context.lineCap = 'round';
            context.stroke();
        }
        for(let step = 0; step <= head.hop + (head.fraction > 0.92 || head.arrived ? 1 : 0); step += 1){
            const node = field.nodes[signal.path[step]];
            if (!node) continue;
            const glow = step === 0 ? hopGlow(signal, 0, time, mesh) : hopGlow(signal, step - 1, time, mesh);
            if (glow <= 0.01) continue;
            fill(context, node.px, node.py, 4.6, channels(palette.signal, glow * 0.14));
            fill(context, node.px, node.py, 1.9, channels(palette.signalCore, glow));
        }
        if (head.arrived) continue;
        const from = field.nodes[signal.path[head.hop]];
        const to = field.nodes[signal.path[head.hop + 1]];
        if (!from || !to) continue;
        const headX = from.px + (to.px - from.px) * head.fraction;
        const headY = from.py + (to.py - from.py) * head.fraction;
        fill(context, headX, headY, 5, channels(palette.signal, 0.075));
        fill(context, headX, headY, 2.3, channels(palette.signalCore, 1));
    }
}
function channels(rgb, alpha) {
    return `rgb(${rgb} / ${(clamp01(alpha) * 100).toFixed(2)}%)`;
}
function clamp01(value) {
    return Math.max(0, Math.min(1, value));
}
function fill(context, x, y, radius, colour) {
    context.beginPath();
    context.arc(x, y, radius, 0, Math.PI * 2);
    context.fillStyle = colour;
    context.fill();
}
