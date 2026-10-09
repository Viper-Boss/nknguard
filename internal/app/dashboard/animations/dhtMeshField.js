// Adapted from the owner-provided NasSimHub source. See ANIMATIONS.md.
export const defaultMeshOptions = {
    spacing: 59,
    drift: 9,
    driftSpeed: 0.22,
    signalInterval: 0.72,
    signalDuration: 0.3,
    minHops: 3,
    maxHops: 6,
    trailFade: 1.1,
    lifecycleInterval: 4.5,
    fadeDuration: 3.2,
    seed: 9014
};
export function seeded(seed) {
    let state = seed >>> 0;
    return ()=>{
        state = state * 1664525 + 1013904223 >>> 0;
        return state / 4294967296;
    };
}
export function smooth(fraction) {
    return fraction * fraction * (3 - 2 * fraction);
}
function clamp(value, low, high) {
    return Math.max(low, Math.min(high, value));
}
export function buildField(width, height, options = defaultMeshOptions) {
    const random = seeded(options.seed);
    const { spacing } = options;
    const columns = Math.ceil(width / spacing) + 3;
    const rows = Math.ceil(height / spacing) + 3;
    const nodes = [];
    for(let row = 0; row < rows; row += 1){
        for(let column = 0; column < columns; column += 1){
            const x = (column - 1) * spacing + row % 2 * spacing * 0.5 + (random() - 0.5) * 25;
            const y = (row - 1) * spacing + (random() - 0.5) * 20;
            nodes.push({
                x,
                y,
                phase: random() * Math.PI * 2,
                alpha: random() < 0.09 ? 0.08 : 1,
                from: 1,
                to: 1,
                start: -100,
                changing: false,
                px: x,
                py: y
            });
        }
    }
    const edges = [];
    const add = (a, b)=>{
        if (b < nodes.length && random() > 0.16) edges.push([
            a,
            b
        ]);
    };
    for(let row = 0; row < rows; row += 1){
        for(let column = 0; column < columns; column += 1){
            const index = row * columns + column;
            if (column < columns - 1) add(index, index + 1);
            if (row < rows - 1) {
                add(index, index + columns);
                if (row % 2 && column < columns - 1) add(index, index + columns + 1);
                else if (!(row % 2) && column > 0) add(index, index + columns - 1);
            }
        }
    }
    const neighbours = nodes.map(()=>[]);
    for (const [a, b] of edges){
        neighbours[a].push(b);
        neighbours[b].push(a);
    }
    const insetX = width * 0.12;
    const insetY = height * 0.12;
    const interior = [];
    nodes.forEach((node, index)=>{
        if (node.x >= insetX && node.x <= width - insetX && node.y >= insetY && node.y <= height - insetY) {
            interior.push(index);
        }
    });
    return {
        nodes,
        edges,
        interior,
        neighbours,
        signals: [],
        nextSignal: 0,
        nextLife: options.lifecycleInterval,
        picks: 0
    };
}
export function advance(field, time, live, options = defaultMeshOptions) {
    if (live && time >= field.nextLife) {
        const node = field.nodes[Math.floor(draw(field, options) * field.nodes.length)];
        if (node && !node.changing) {
            node.from = node.alpha;
            node.to = node.alpha > 0.5 ? 0.08 : 1;
            node.start = time;
            node.changing = true;
        }
        field.nextLife = time + options.lifecycleInterval;
    }
    for (const node of field.nodes){
        if (node.changing) {
            const progress = clamp((time - node.start) / options.fadeDuration, 0, 1);
            node.alpha = node.from + (node.to - node.from) * smooth(progress);
            if (progress === 1) node.changing = false;
        }
        node.px = node.x + Math.sin(time * options.driftSpeed + node.phase) * options.drift + Math.sin(time * 0.09 + node.y * 0.01) * 12;
        node.py = node.y + Math.cos(time * options.driftSpeed * 0.8 + node.phase) * options.drift;
    }
    for(let index = field.signals.length - 1; index >= 0; index -= 1){
        const signal = field.signals[index];
        const span = (signal.path.length - 1) * options.signalDuration + options.trailFade;
        if (time - signal.start >= span) field.signals.splice(index, 1);
    }
    if (!live) {
        field.signals.length = 0;
        return;
    }
    if (time >= field.nextSignal && field.edges.length > 0) {
        const path = planRoute(field, options);
        if (path) field.signals.push({
            path,
            start: time
        });
        field.nextSignal = time + options.signalInterval;
    }
}
function planRoute(field, options) {
    const bright = (index)=>{
        const node = field.nodes[index];
        return node !== undefined && node.alpha > 0.6;
    };
    if (field.interior.length === 0) return null;
    const first = field.interior[Math.floor(draw(field, options) * field.interior.length)];
    if (!bright(first)) return null;
    const heading = draw(field, options) * Math.PI * 2;
    const headingX = Math.cos(heading);
    const headingY = Math.sin(heading);
    const span = options.maxHops - options.minHops + 1;
    const wanted = options.minHops + Math.floor(draw(field, options) * span);
    const path = [
        first
    ];
    const visited = new Set([
        first
    ]);
    for(let hop = 0; hop < wanted; hop += 1){
        const current = path[path.length - 1];
        const open = field.neighbours[current].filter((candidate)=>bright(candidate) && !visited.has(candidate));
        if (open.length === 0) break;
        let next;
        if (open.length === 1 || draw(field, options) < 0.7) {
            const from = field.nodes[current];
            let best = open[0];
            let bestScore = -Infinity;
            for (const candidate of open){
                const to = field.nodes[candidate];
                const dx = to.x - from.x;
                const dy = to.y - from.y;
                const length = Math.hypot(dx, dy) || 1;
                const score = dx / length * headingX + dy / length * headingY;
                if (score > bestScore) {
                    bestScore = score;
                    best = candidate;
                }
            }
            next = best;
        } else {
            next = open[Math.floor(draw(field, options) * open.length)];
        }
        path.push(next);
        visited.add(next);
    }
    return path.length > options.minHops ? path : null;
}
function draw(field, options) {
    field.picks += 1;
    return seeded((options.seed ^ field.picks * 2654435761) >>> 0)();
}
export function signalHead(signal, time, options = defaultMeshOptions) {
    const hops = signal.path.length - 1;
    const elapsed = Math.max(0, time - signal.start);
    const travel = hops * options.signalDuration;
    if (elapsed >= travel) {
        return {
            hop: hops - 1,
            fraction: 1,
            arrived: true
        };
    }
    const hop = Math.min(hops - 1, Math.floor(elapsed / options.signalDuration));
    return {
        hop,
        fraction: (elapsed - hop * options.signalDuration) / options.signalDuration,
        arrived: false
    };
}
export function hopGlow(signal, hop, time, options = defaultMeshOptions) {
    const head = signalHead(signal, time, options);
    if (hop > head.hop) return 0;
    if (hop === head.hop) return head.arrived ? 1 : Math.max(0.35, head.fraction);
    const landed = signal.start + (hop + 1) * options.signalDuration;
    const age = time - landed;
    return clamp(1 - age / options.trailFade, 0, 1);
}
