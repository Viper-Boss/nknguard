// The DHT fishnet's painting.
//
// Extracted from the component for the same reason the geometry was: a drawing
// decision made inside a requestAnimationFrame callback can only be checked by
// watching the screen and hoping. Out here the same code that ships can be
// pointed at a canvas of known size with a known palette, which is how the
// composition below was reviewed rather than guessed at.
//
// It draws and nothing else: no sizing, no clearing, no clock. The caller owns
// the canvas and has already advanced the field.
//
// Every colour comes in as space-separated RGB channels rather than as a
// finished colour, because almost every mark here composes its own alpha: the
// strand from its dimmer end, the node from its fade, the bead from its bloom.
// A palette of finished `rgba(...)` strings cannot be dimmed without string
// surgery, which is how a drawing ends up with a colour nobody can re-theme.

import {
  defaultMeshOptions,
  hopGlow,
  signalHead,
  type MeshField,
  type MeshOptions
} from './dhtMeshField'

/** The roles in the picture. One set is illustration, one is a claim. */
export interface MeshPalette {
  /** The strands between nodes. */
  strand: string
  /** The soft halo around a node. */
  nodeBloom: string
  /** The node itself. */
  nodeCore: string
  /** The ring that expands once as a node appears. */
  ring: string
  /** Traffic: the bead's trail and its halo. The only claim in here. */
  signal: string
  /** The bead's bright centre. */
  signalCore: string
}

export interface PaintOptions {
  width: number
  height: number
  /** Seconds. The same clock the field was advanced on. */
  time: number
  palette: MeshPalette
  /**
   * 1 while the DHT is ready, lower while it is not.
   *
   * The whole net dims rather than disappearing, so the card keeps its shape
   * and the reader can see there is a picture there at all -- what goes away is
   * the traffic and the arrival rings, which are the parts that claim something
   * happened.
   */
  strength: number
  /** Explicitly labelled discovery illustration while no peers are connected. */
  illustration?: boolean
  mesh?: MeshOptions
}

export function paintMesh(
  context: CanvasRenderingContext2D,
  field: MeshField,
  options: PaintOptions
): void {
  const { palette, strength, time } = options
  const mesh = options.mesh ?? defaultMeshOptions
  const live = strength > 0.999 || options.illustration === true

  // Strands first, so nodes sit on top of them.
  context.lineWidth = 0.8
  for (const [a, b] of field.edges) {
    const from = field.nodes[a]
    const to = field.nodes[b]
    if (!from || !to) continue
    // A strand is only as bright as its dimmer end, which is what makes a node
    // fading out take its strands with it instead of leaving them hanging.
    const alpha = 0.22 * Math.min(from.alpha, to.alpha) * strength
    context.beginPath()
    context.moveTo(from.px, from.py)
    context.lineTo(to.px, to.py)
    context.strokeStyle = channels(palette.strand, alpha)
    context.stroke()
  }

  for (const node of field.nodes) {
    const alpha = node.alpha * strength
    // Two circles rather than a canvas shadow: a wide faint disc for the bloom
    // and a tight one for the core. Shadows on a few hundred nodes a frame are
    // the one thing in this drawing expensive enough to drop frames on a
    // NAS-class browser, and this reads the same.
    fill(context, node.px, node.py, 5.5, channels(palette.nodeBloom, alpha * 0.055))
    fill(context, node.px, node.py, 1.65, channels(palette.nodeCore, alpha * 0.74))
    // A node arriving gets one ring that expands and fades. It reads as
    // "something appeared here", so it is drawn only on the way IN, and only
    // while the card is live.
    if (!live || !node.changing || node.to !== 1) continue
    const progress = clamp01((time - node.start) / mesh.fadeDuration)
    context.beginPath()
    context.arc(node.px, node.py, 4 + 12 * progress, 0, Math.PI * 2)
    context.strokeStyle = channels(palette.ring, Math.sin(progress * Math.PI) * 0.5)
    context.lineWidth = 1
    context.stroke()
    context.lineWidth = 0.8
  }

  if (!live) return

  // Routes last, over everything, because they are the thing to look at --
  // and the only mark in this picture that claims a packet moved.
  //
  // Each one is a lookup walking several hops. Drawing it is three passes over
  // the same path, and the order matters: the strands it has crossed, then the
  // nodes it has touched, then the bead itself on the hop it is currently
  // crossing. Strands ahead of the bead are never drawn -- lighting the path in
  // advance would show where the lookup is going before it has been there.
  for (const signal of field.signals) {
    const head = signalHead(signal, time, mesh)

    for (let hop = 0; hop < signal.path.length - 1; hop += 1) {
      const glow = hopGlow(signal, hop, time, mesh)
      if (glow <= 0.01) continue
      const from = field.nodes[signal.path[hop]!]
      const to = field.nodes[signal.path[hop + 1]!]
      if (!from || !to) continue

      // The hop the bead is on is drawn only as far as the bead has got, so the
      // strand is being painted in rather than switched on.
      const reach = hop === head.hop && !head.arrived ? head.fraction : 1
      const tipX = from.px + (to.px - from.px) * reach
      const tipY = from.py + (to.py - from.py) * reach

      // The end points are nudged apart: a gradient between two identical
      // points is rejected by the canvas and the whole strand silently
      // disappears, which is exactly the case on a hop's first frame.
      const gradient = context.createLinearGradient(from.px, from.py, tipX + 0.001, tipY + 0.001)
      gradient.addColorStop(0, channels(palette.signal, glow * 0.15))
      gradient.addColorStop(1, channels(palette.signal, glow))
      context.beginPath()
      context.moveTo(from.px, from.py)
      context.lineTo(tipX, tipY)
      context.strokeStyle = gradient
      context.lineWidth = 1.8
      context.lineCap = 'round'
      context.stroke()
    }

    // A touched node gets a small flare, so the route reads as a sequence of
    // stops rather than as a line that happens to bend. The last node the bead
    // has reached is the brightest; the ones behind it fade with their strand.
    for (let step = 0; step <= head.hop + (head.fraction > 0.92 || head.arrived ? 1 : 0); step += 1) {
      const node = field.nodes[signal.path[step]!]
      if (!node) continue
      const glow = step === 0
        ? hopGlow(signal, 0, time, mesh)
        : hopGlow(signal, step - 1, time, mesh)
      if (glow <= 0.01) continue
      fill(context, node.px, node.py, 4.6, channels(palette.signal, glow * 0.14))
      fill(context, node.px, node.py, 1.9, channels(palette.signalCore, glow))
    }

    // The bead. Held at the last node once the route has landed would leave a
    // bright dot sitting there while the trail fades, so it stops being drawn
    // the moment it arrives -- the flare above is what marks the arrival.
    if (head.arrived) continue
    const from = field.nodes[signal.path[head.hop]!]
    const to = field.nodes[signal.path[head.hop + 1]!]
    if (!from || !to) continue
    const headX = from.px + (to.px - from.px) * head.fraction
    const headY = from.py + (to.py - from.py) * head.fraction
    fill(context, headX, headY, 5, channels(palette.signal, 0.075))
    fill(context, headX, headY, 2.3, channels(palette.signalCore, 1))
  }
}

function channels(rgb: string, alpha: number): string {
  return `rgb(${rgb} / ${(clamp01(alpha) * 100).toFixed(2)}%)`
}

function clamp01(value: number): number {
  return Math.max(0, Math.min(1, value))
}

function fill(
  context: CanvasRenderingContext2D,
  x: number,
  y: number,
  radius: number,
  colour: string
): void {
  context.beginPath()
  context.arc(x, y, radius, 0, Math.PI * 2)
  context.fillStyle = colour
  context.fill()
}
