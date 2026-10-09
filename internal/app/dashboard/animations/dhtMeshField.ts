// The DHT fishnet's geometry and life-cycle.
//
// This lives apart from the component for one reason: the interesting parts --
// which nodes are linked, when a node fades, when a signal is allowed to travel
// -- are decisions, and decisions inside a requestAnimationFrame callback can
// only be checked by watching the screen and hoping. Here they can be run on a
// fixed clock and asserted.
//
// The layout, the drift, the fade timings and the signal rate all come from the
// operator's own reference build of this card. What is added is the module
// boundary, the types, the per-build generator, and the one thing the reference
// left open: this card is wired to a real DHT, so the traffic has to follow it.
//
// WHAT IS REAL AND WHAT IS SCENERY, stated plainly because it would otherwise
// be guesswork, and because most of this picture is scenery:
//
//   the NET -- where the nodes sit, which ones are tied together, how they
//   drift, and which ones are dim -- is illustration. It is a sample of a mesh
//   drawn to fill the card. It is NOT this gateway's routing table: a DHT has
//   no directory, and this gateway does not know who most of the network is.
//   The card's caption says so, and no figure is ever drawn on the picture.
//
//   the SIGNALS -- the amber beads travelling a strand -- are the one mark that
//   means "traffic", and they are gated on the real DHT being ready with peers.
//   With the DHT off, starting, isolated or failed, the net dims and nothing
//   travels. The reference build ran the signals unconditionally off a timer;
//   that is fine in a demo and would be invented telemetry here.

/** A node in the net. Resting position, plus where the drift has put it. */
export interface MeshNode {
  /** Resting position in CSS pixels, in the canvas's own coordinates. */
  x: number
  y: number
  /** Drift offset, so the nodes do not all sway in step. */
  phase: number
  /** 0.08 dim, 1 bright. Chases `to` while `changing`. */
  alpha: number
  from: number
  to: number
  /** Seconds at which the current fade began. */
  start: number
  changing: boolean
  /** Position after the drift, filled in by advance(). */
  px: number
  py: number
}

/** A strand, by node index. */
export type MeshEdge = [number, number]

/**
 * A lookup in flight: a route through several nodes, hop by hop.
 *
 * This replaced a single-edge bead, and the reason is worth keeping. One edge
 * at 0.48s across a 59px strand reads, on screen, as a dot twitching once and
 * vanishing -- the operator's words were "it looks like it only jumps one node
 * and then stops", which is exactly what it did. A DHT lookup is not one hop:
 * it is a walk, each step landing nearer the key, and a walk is also the thing
 * an eye can follow across the card.
 *
 * `path` is node indices, first to last, and consecutive entries are always a
 * real strand in `edges` -- the bead travels the net rather than cutting across
 * it. A node never appears twice: a route that doubles back reads as lost.
 */
export interface MeshSignal {
  path: number[]
  /** Seconds at which the FIRST hop set off. */
  start: number
}

export interface MeshField {
  nodes: MeshNode[]
  edges: MeshEdge[]
  /**
   * The nodes that fall inside the visible canvas, by index.
   *
   * The net deliberately overhangs every edge, which is what makes it read as a
   * piece cut out of something larger -- but it means a good share of the nodes
   * are off screen, and a route STARTED out there spends its hops where nobody
   * can see them. Measured on a 300px panel only 57% of nodes were inside.
   * Routes are launched from this list instead.
   */
  interior: number[]
  /**
   * Who each node can reach, by index. Built once with the net.
   *
   * A route has to pick a neighbour at every hop, and scanning all the edges
   * for each one is the difference between planning a route in a few
   * microseconds and doing it in a millisecond, every 0.7 seconds, forever.
   */
  neighbours: number[][]
  signals: MeshSignal[]
  /** Seconds after which another signal may be created. */
  nextSignal: number
  /** Seconds after which another node may change brightness. */
  nextLife: number
  /**
   * How many choices have been drawn so far.
   *
   * The net's own randomness is spent at build time; this is the stream the
   * life-cycle and the signals draw from afterwards. Kept as a count on the
   * field rather than as a closure so the field stays plain data -- which is
   * what lets a test and the preview harness run it forward on a fixed clock
   * and get the same picture every time.
   */
  picks: number
}

export interface MeshOptions {
  /** Grid pitch in CSS pixels. Smaller is denser. */
  spacing: number
  /** How far a node wanders from its resting position, in pixels. */
  drift: number
  driftSpeed: number
  /** Seconds between attempts to launch a signal. */
  signalInterval: number
  /** Seconds a signal takes to cross ONE strand of its route. */
  signalDuration: number
  /** Fewest and most hops in a route. A one-hop route is not a route. */
  minHops: number
  maxHops: number
  /** Seconds a traversed strand stays lit behind the bead. */
  trailFade: number
  /** Seconds between one node changing brightness. */
  lifecycleInterval: number
  /** Seconds a node takes to fade in or out. */
  fadeDuration: number
  seed: number
}

export const defaultMeshOptions: MeshOptions = {
  spacing: 59,
  drift: 9,
  driftSpeed: 0.22,
  signalInterval: 0.72,
  // Faster per hop than the old single-edge bead, because a route now strings
  // several of them together: at 0.48s a six-hop route took nearly three
  // seconds to cross the card, which reads as slow rather than as busy.
  signalDuration: 0.3,
  minHops: 3,
  maxHops: 6,
  trailFade: 1.1,
  lifecycleInterval: 4.5,
  fadeDuration: 3.2,
  seed: 9014
}

/**
 * A small deterministic generator.
 *
 * One per build, rather than one shared with the draw loop. The reference build
 * drew the layout and the runtime picks from the same stream, which means the
 * net comes out differently every time the card is rebuilt -- and it is rebuilt
 * on every resize, so dragging a window reshuffles the whole picture. Seeded
 * per build, a given card size always produces the same net.
 */
export function seeded(seed: number): () => number {
  let state = seed >>> 0
  return () => {
    state = (state * 1664525 + 1013904223) >>> 0
    return state / 4294967296
  }
}

/** Smoothstep. Eases both ends of a fade so a node does not snap into motion. */
export function smooth(fraction: number): number {
  return fraction * fraction * (3 - 2 * fraction)
}

function clamp(value: number, low: number, high: number): number {
  return Math.max(low, Math.min(high, value))
}

/**
 * buildField lays out the net for a canvas of the given size.
 *
 * The grid runs one cell PAST every edge, and odd rows are offset by half a
 * cell. Both matter: the overhang is what makes the net read as a piece cut out
 * of something larger rather than a panel with a border of loose ends, and the
 * half-cell offset turns square cells into triangles, which is what a net looks
 * like and a lattice does not.
 */
export function buildField(
  width: number,
  height: number,
  options: MeshOptions = defaultMeshOptions
): MeshField {
  const random = seeded(options.seed)
  const { spacing } = options
  const columns = Math.ceil(width / spacing) + 3
  const rows = Math.ceil(height / spacing) + 3
  const nodes: MeshNode[] = []
  for (let row = 0; row < rows; row += 1) {
    for (let column = 0; column < columns; column += 1) {
      const x =
        (column - 1) * spacing + (row % 2) * spacing * 0.5 + (random() - 0.5) * 25
      const y = (row - 1) * spacing + (random() - 0.5) * 20
      nodes.push({
        x,
        y,
        phase: random() * Math.PI * 2,
        // A few nodes start dim. It is what gives the net texture before the
        // first fade has had time to happen.
        alpha: random() < 0.09 ? 0.08 : 1,
        from: 1,
        to: 1,
        start: -100,
        changing: false,
        px: x,
        py: y
      })
    }
  }

  // Strands: across, down, and one diagonal per cell, with about a sixth
  // dropped. The dropped ones are the difference between a net someone tied
  // and a mesh a computer generated.
  const edges: MeshEdge[] = []
  const add = (a: number, b: number): void => {
    if (b < nodes.length && random() > 0.16) edges.push([a, b])
  }
  for (let row = 0; row < rows; row += 1) {
    for (let column = 0; column < columns; column += 1) {
      const index = row * columns + column
      if (column < columns - 1) add(index, index + 1)
      if (row < rows - 1) {
        add(index, index + columns)
        // The diagonal leans the way the half-cell offset went, so it joins the
        // two nodes that actually sit either side of it.
        if (row % 2 && column < columns - 1) add(index, index + columns + 1)
        else if (!(row % 2) && column > 0) add(index, index + columns - 1)
      }
    }
  }

  const neighbours: number[][] = nodes.map(() => [])
  for (const [a, b] of edges) {
    neighbours[a]!.push(b)
    neighbours[b]!.push(a)
  }

  // Inset rather than the exact bounds: a route that starts one pixel inside
  // the frame is barely better than one that starts outside it.
  const insetX = width * 0.12
  const insetY = height * 0.12
  const interior: number[] = []
  nodes.forEach((node, index) => {
    if (
      node.x >= insetX && node.x <= width - insetX &&
      node.y >= insetY && node.y <= height - insetY
    ) {
      interior.push(index)
    }
  })

  return {
    nodes,
    edges,
    interior,
    neighbours,
    signals: [],
    nextSignal: 0,
    nextLife: options.lifecycleInterval,
    picks: 0
  }
}

/**
 * advance moves the net on to the given moment.
 *
 * Absolute time in seconds rather than a delta, so a stalled frame does not
 * make the drift lurch and a fast display does not speed it up -- and so the
 * same moment always produces the same picture, which is what makes the preview
 * harness able to render a frame at all.
 *
 * `live` is the honesty gate. False -- the DHT is off, starting, isolated or
 * failed -- freezes the life-cycle, clears the signals in flight and refuses
 * new ones. The net still drifts, because the net is illustration; the traffic
 * does not, because traffic is a claim.
 */
export function advance(
  field: MeshField,
  time: number,
  live: boolean,
  options: MeshOptions = defaultMeshOptions
): void {
  if (live && time >= field.nextLife) {
    const node = field.nodes[Math.floor(draw(field, options) * field.nodes.length)]
    if (node && !node.changing) {
      node.from = node.alpha
      node.to = node.alpha > 0.5 ? 0.08 : 1
      node.start = time
      node.changing = true
    }
    field.nextLife = time + options.lifecycleInterval
  }

  for (const node of field.nodes) {
    if (node.changing) {
      const progress = clamp((time - node.start) / options.fadeDuration, 0, 1)
      node.alpha = node.from + (node.to - node.from) * smooth(progress)
      if (progress === 1) node.changing = false
    }
    // Two sways. The small one is per node and gives the net its shimmer; the
    // large slow one varies with y, so whole bands of the net lean together --
    // that is what reads as the sheet moving rather than the dots vibrating.
    node.px =
      node.x +
      Math.sin(time * options.driftSpeed + node.phase) * options.drift +
      Math.sin(time * 0.09 + node.y * 0.01) * 12
    node.py = node.y + Math.cos(time * options.driftSpeed * 0.8 + node.phase) * options.drift
  }

  // A route lives until its LAST hop lands, plus the time its trail takes to
  // fade -- the painter needs it after the bead has arrived, or the lit path
  // behind it would blink out the instant the lookup finished.
  for (let index = field.signals.length - 1; index >= 0; index -= 1) {
    const signal = field.signals[index]!
    const span = (signal.path.length - 1) * options.signalDuration + options.trailFade
    if (time - signal.start >= span) field.signals.splice(index, 1)
  }

  if (!live) {
    field.signals.length = 0
    return
  }

  if (time >= field.nextSignal && field.edges.length > 0) {
    const path = planRoute(field, options)
    // A route that could not reach its minimum is not launched at all. Drawing
    // the stub would put back exactly the one-hop twitch this replaced.
    if (path) field.signals.push({ path, start: time })
    field.nextSignal = time + options.signalInterval
  }
}

/**
 * planRoute walks a lookup across the net.
 *
 * Every node on it is bright, because a bead leaving a dim node reads as
 * traffic appearing out of nothing -- and the dim nodes are the part of the
 * picture that explicitly says "we do not know who this is".
 *
 * The walk is given a HEADING at launch and prefers, at each hop, the
 * neighbour that lies most along it. That is what makes a route read as going
 * somewhere: an unbiased random walk on a net this dense spends its hops
 * circling one cell, which looks aimless and, worse, looks like a bug. A DHT
 * lookup does converge on a key, so a route that travels is also the truer
 * picture. Three hops in ten are still taken at random, or every route would
 * be a straight line.
 */
function planRoute(field: MeshField, options: MeshOptions): number[] | null {
  const bright = (index: number): boolean => {
    const node = field.nodes[index]
    return node !== undefined && node.alpha > 0.6
  }

  if (field.interior.length === 0) return null
  const first = field.interior[Math.floor(draw(field, options) * field.interior.length)]!
  if (!bright(first)) return null

  const heading = draw(field, options) * Math.PI * 2
  const headingX = Math.cos(heading)
  const headingY = Math.sin(heading)
  const span = options.maxHops - options.minHops + 1
  const wanted = options.minHops + Math.floor(draw(field, options) * span)

  const path = [first]
  const visited = new Set([first])
  for (let hop = 0; hop < wanted; hop += 1) {
    const current = path[path.length - 1]!
    const open = field.neighbours[current]!.filter(
      candidate => bright(candidate) && !visited.has(candidate)
    )
    if (open.length === 0) break

    let next: number
    if (open.length === 1 || draw(field, options) < 0.7) {
      const from = field.nodes[current]!
      let best = open[0]!
      let bestScore = -Infinity
      for (const candidate of open) {
        const to = field.nodes[candidate]!
        const dx = to.x - from.x
        const dy = to.y - from.y
        const length = Math.hypot(dx, dy) || 1
        const score = (dx / length) * headingX + (dy / length) * headingY
        if (score > bestScore) {
          bestScore = score
          best = candidate
        }
      }
      next = best
    } else {
      next = open[Math.floor(draw(field, options) * open.length)]!
    }
    path.push(next)
    visited.add(next)
  }

  return path.length > options.minHops ? path : null
}

/** draw takes the next choice from the field's own stream. */
function draw(field: MeshField, options: MeshOptions): number {
  field.picks += 1
  // Re-seeded from the count rather than kept as a running generator, for the
  // same reason `picks` is a number: the field has to stay plain data. The
  // multiply is what keeps consecutive counts from giving neighbouring values,
  // which a linear generator seeded 1, 2, 3 would.
  return seeded((options.seed ^ (field.picks * 2654435761)) >>> 0)()
}

/** Where the bead of a route is: which hop, and how far along that hop. */
export interface SignalHead {
  /** Index into path: the bead is between path[hop] and path[hop + 1]. */
  hop: number
  /** 0 at path[hop], 1 at path[hop + 1]. */
  fraction: number
  /** True once the bead has landed and only the trail is still fading. */
  arrived: boolean
}

/**
 * signalHead locates a route's bead at a moment.
 *
 * Derived from the clock rather than stored on the signal, for the same reason
 * the drift is: the same moment has to produce the same picture, or a stalled
 * frame makes the bead jump and the preview harness cannot render a frame at
 * all.
 */
export function signalHead(
  signal: MeshSignal,
  time: number,
  options: MeshOptions = defaultMeshOptions
): SignalHead {
  const hops = signal.path.length - 1
  const elapsed = Math.max(0, time - signal.start)
  const travel = hops * options.signalDuration
  if (elapsed >= travel) {
    return { hop: hops - 1, fraction: 1, arrived: true }
  }
  const hop = Math.min(hops - 1, Math.floor(elapsed / options.signalDuration))
  return {
    hop,
    fraction: (elapsed - hop * options.signalDuration) / options.signalDuration,
    arrived: false
  }
}

/**
 * hopGlow is how lit a strand of the route is, 0 to 1.
 *
 * A strand lights as the bead crosses it and fades behind, which is what turns
 * a moving dot into a visible ROUTE -- the whole point of the change. Strands
 * ahead of the bead are dark: lighting the path in advance would show where the
 * lookup is going before it has been there.
 */
export function hopGlow(
  signal: MeshSignal,
  hop: number,
  time: number,
  options: MeshOptions = defaultMeshOptions
): number {
  const head = signalHead(signal, time, options)
  if (hop > head.hop) return 0
  if (hop === head.hop) return head.arrived ? 1 : Math.max(0.35, head.fraction)
  // Behind the bead: fades from the moment that hop landed.
  const landed = signal.start + (hop + 1) * options.signalDuration
  const age = time - landed
  return clamp(1 - age / options.trailFade, 0, 1)
}
