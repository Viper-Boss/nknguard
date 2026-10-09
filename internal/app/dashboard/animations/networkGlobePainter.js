// Adapted from the owner-provided NasSimHub source. See ANIMATIONS.md.
import { HORIZON, MARKER_HORIZON, MARKER_LATITUDES, markerAt } from './networkGlobeGeometry.js';
const ROTATION_PER_SECOND = 0.045;
const BREATH = 0.012;
export function globeAngle(time) {
    return time * ROTATION_PER_SECOND - 1.65;
}
export function paintGlobe(context, points, options) {
    const { width, height, time, palette, strength } = options;
    const centreX = width / 2;
    const centreY = height / 2 - 8;
    const radius = Math.min(width * 0.355, height * 0.426) * (1 + BREATH * Math.sin(time * 0.6));
    const angle = globeAngle(time);
    const cos = Math.cos(angle);
    const sin = Math.sin(angle);
    const halo = context.createRadialGradient(centreX, centreY, radius * 0.7, centreX, centreY, radius * 1.17);
    halo.addColorStop(0, `${palette.halo}00`);
    halo.addColorStop(0.65, `${palette.halo}0a`);
    halo.addColorStop(0.85, `${palette.halo}15`);
    halo.addColorStop(1, `${palette.halo}00`);
    fillCircle(context, centreX, centreY, radius * 1.17, halo);
    const body = context.createRadialGradient(centreX - radius * 0.3, centreY - radius * 0.3, 0, centreX, centreY, radius);
    body.addColorStop(0, palette.bodyNear);
    body.addColorStop(1, palette.bodyFar);
    fillCircle(context, centreX, centreY, radius, body);
    for (const point of points){
        const turnedX = point.x * cos + point.z * sin;
        const depth = point.z * cos - point.x * sin;
        if (depth < HORIZON) continue;
        const screenY = point.y * 0.98 - turnedX * 0.14;
        const screenX = turnedX * 0.99 + point.y * 0.14;
        const alpha = ((point.land ? 0.3 : 0.055) + Math.max(0, depth) * (point.land ? 0.58 : 0.13)) * strength;
        fillCircle(context, centreX + screenX * radius, centreY - screenY * radius, point.land ? 0.85 + depth * 0.35 : 0.55, `rgb(${palette.dot} / ${(alpha * 100).toFixed(1)}%)`);
    }
    context.beginPath();
    context.ellipse(centreX, centreY, radius, radius, 0, 0, Math.PI * 2);
    context.strokeStyle = palette.rim;
    context.lineWidth = 1;
    context.stroke();
    if (strength < 0.999) return;
    for(let index = 0; index < MARKER_LATITUDES.length; index += 1){
        const marker = markerAt(index, angle * 180 / Math.PI, centreX, centreY, radius);
        if (marker.z < MARKER_HORIZON) continue;
        fillCircle(context, marker.x, marker.y, 3, palette.marker);
        context.beginPath();
        context.arc(marker.x, marker.y, 7 + 3 * Math.sin(time * 1.2 + index), 0, Math.PI * 2);
        context.strokeStyle = `${palette.halo}55`;
        context.lineWidth = 1;
        context.stroke();
    }
}
function fillCircle(context, x, y, radius, fill) {
    context.beginPath();
    context.arc(x, y, radius, 0, Math.PI * 2);
    context.fillStyle = fill;
    context.fill();
}
