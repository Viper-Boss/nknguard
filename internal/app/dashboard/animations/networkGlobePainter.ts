// The dotted globe's painting.
//
// Pulled out of the component for the same reason the mesh painter was: a
// drawing decision made inside a requestAnimationFrame callback can only be
// checked by watching the screen and hoping. Out here the shipping code can be
// pointed at a canvas of known size with a known palette.
//
// It draws and nothing else: no sizing, no clearing, no clock. The caller owns
// the canvas and passes the time.

import {
  HORIZON,
  MARKER_HORIZON,
  MARKER_LATITUDES,
  markerAt,
  type SpherePoint
} from './networkGlobeGeometry'

export interface GlobePalette {
  /** Rim glow and the marker rings. Hex, six digits: alpha is appended. */
  halo: string
  /** The dots. Space-separated RGB channels; alpha is composed per dot. */
  dot: string
  /** The marker core. */
  marker: string
  /** The sphere's own faint body, drawn under the dots. */
  bodyNear: string
  bodyFar: string
  /** The circle around the limb. */
  rim: string
}

export interface GlobePaintOptions {
  width: number
  height: number
  /** Seconds. Drives the rotation, the breath and the marker pulse. */
  time: number
  palette: GlobePalette
  /**
   * 0 dims the whole picture and drops the markers, 1 draws it fully.
   *
   * This is the honesty control. The markers pulse like something is happening
   * there, so they may only be drawn while the channel really is up -- a globe
   * with markers blinking on it while NKN is disconnected is the card claiming
   * activity it does not have. The reference build left them always on; here
   * they follow the real state, the way the mesh card's signals already do.
   */
  strength: number
}

const ROTATION_PER_SECOND = 0.045
const BREATH = 0.012

/** Radians of turn at a given moment. The offset just picks a nicer opening. */
export function globeAngle(time: number): number {
  return time * ROTATION_PER_SECOND - 1.65
}

export function paintGlobe(
  context: CanvasRenderingContext2D,
  points: SpherePoint[],
  options: GlobePaintOptions
): void {
  const { width, height, time, palette, strength } = options
  const centreX = width / 2
  // Lifted a little: the card's caption sits under the drawing, and an
  // optically centred globe reads as centred where a mathematically centred
  // one reads as low.
  const centreY = height / 2 - 8
  // Breathing, slowly. It is what keeps the globe from looking like a still
  // image on a slow machine, and it is small enough not to read as zooming.
  const radius =
    Math.min(width * 0.355, height * 0.426) * (1 + BREATH * Math.sin(time * 0.6))
  const angle = globeAngle(time)
  const cos = Math.cos(angle)
  const sin = Math.sin(angle)

  // Rim glow first, so everything else sits on top of it. The stops rise and
  // fall rather than fading straight out, which puts the brightest ring just
  // inside the limb -- that is what reads as atmosphere instead of a blur.
  const halo = context.createRadialGradient(
    centreX, centreY, radius * 0.7,
    centreX, centreY, radius * 1.17
  )
  halo.addColorStop(0, `${palette.halo}00`)
  halo.addColorStop(0.65, `${palette.halo}0a`)
  halo.addColorStop(0.85, `${palette.halo}15`)
  halo.addColorStop(1, `${palette.halo}00`)
  fillCircle(context, centreX, centreY, radius * 1.17, halo)

  // The body, lit from the upper left so the sphere has a near side.
  const body = context.createRadialGradient(
    centreX - radius * 0.3, centreY - radius * 0.3, 0,
    centreX, centreY, radius
  )
  body.addColorStop(0, palette.bodyNear)
  body.addColorStop(1, palette.bodyFar)
  fillCircle(context, centreX, centreY, radius, body)

  for (const point of points) {
    const turnedX = point.x * cos + point.z * sin
    const depth = point.z * cos - point.x * sin
    if (depth < HORIZON) continue
    const screenY = point.y * 0.98 - turnedX * 0.14
    const screenX = turnedX * 0.99 + point.y * 0.14
    // Land is drawn brighter and larger than sea, and both fade toward the
    // limb. The fade is the whole reason a flat orthographic projection reads
    // as a sphere: without it the dots look painted on a disc.
    const alpha =
      ((point.land ? 0.3 : 0.055) + Math.max(0, depth) * (point.land ? 0.58 : 0.13)) *
      strength
    fillCircle(
      context,
      centreX + screenX * radius,
      centreY - screenY * radius,
      point.land ? 0.85 + depth * 0.35 : 0.55,
      `rgb(${palette.dot} / ${(alpha * 100).toFixed(1)}%)`
    )
  }

  context.beginPath()
  context.ellipse(centreX, centreY, radius, radius, 0, 0, Math.PI * 2)
  context.strokeStyle = palette.rim
  context.lineWidth = 1
  context.stroke()

  // Markers only while the channel is up. See strength, above.
  if (strength < 0.999) return
  for (let index = 0; index < MARKER_LATITUDES.length; index += 1) {
    const marker = markerAt(index, (angle * 180) / Math.PI, centreX, centreY, radius)
    if (marker.z < MARKER_HORIZON) continue
    fillCircle(context, marker.x, marker.y, 3, palette.marker)
    context.beginPath()
    context.arc(marker.x, marker.y, 7 + 3 * Math.sin(time * 1.2 + index), 0, Math.PI * 2)
    context.strokeStyle = `${palette.halo}55`
    context.lineWidth = 1
    context.stroke()
  }
}

function fillCircle(
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
  radius: number,
  fill: string | CanvasGradient
): void {
  context.beginPath()
  context.arc(x, y, radius, 0, Math.PI * 2)
  context.fillStyle = fill
  context.fill()
}
