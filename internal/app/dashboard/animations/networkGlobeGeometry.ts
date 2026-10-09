// The dotted globe's geometry.
//
// Kept apart from the component because a projection that puts points on the
// wrong side of the sphere looks perfectly plausible in a screenshot and is
// obviously wrong in motion -- out here it can be pinned on fixed inputs.
//
// The sphere sampling, the continent outlines and the projection all come from
// the operator's own reference build of these two cards; what is added here is
// the module boundary, the types, and the tests that hold the projection still.
//
// The outlines are decorative. They are a hand-simplified silhouette of the
// continents so the globe reads as the Earth, and they map nothing about any
// peer: this gateway never learns where its peers are, and a map pin for one
// would be a lie dressed up as telemetry.

export interface LatLon {
  lat: number
  lon: number
}

/** A sampled point on the sphere, with whether it falls on land. */
export interface SpherePoint extends LatLon {
  /** Unit position, x right, y north, z toward the viewer at longitude 0. */
  x: number
  y: number
  z: number
  land: boolean
}

export interface Projected {
  x: number
  y: number
  /** Unit depth: 1 facing the viewer, negative behind the sphere. */
  z: number
  visible: boolean
}

const DEGREES = 180 / Math.PI

/**
 * spherePoints spreads n points evenly over the sphere.
 *
 * A latitude/longitude grid piles points onto the poles, which reads as two
 * bright caps. The Fibonacci spiral -- equal steps in y, each turned by the
 * golden angle -- gives an even covering with no seam and no cap.
 */
export function spherePoints(count: number): LatLon[] {
  const golden = Math.PI * (3 - Math.sqrt(5))
  const points: LatLon[] = []
  for (let index = 0; index < count; index += 1) {
    const y = 1 - (2 * (index + 0.5)) / count
    const latitude = Math.asin(Math.min(1, Math.max(-1, y)))
    const longitude = ((index * golden) % (2 * Math.PI)) - Math.PI
    points.push({ lat: latitude * DEGREES, lon: longitude * DEGREES })
  }
  return points
}

/**
 * buildGlobe samples the sphere once and keeps the unit positions with it.
 *
 * The land test is the expensive part -- a point against a dozen polygons --
 * and it is answered once at build rather than every frame. The unit position
 * is cached with it for the same reason: the draw loop then only rotates.
 */
export function buildGlobe(count = 5200): SpherePoint[] {
  return spherePoints(count).map(point => {
    const latitude = point.lat / DEGREES
    const longitude = point.lon / DEGREES
    return {
      ...point,
      x: Math.cos(latitude) * Math.sin(longitude),
      y: Math.sin(latitude),
      z: Math.cos(latitude) * Math.cos(longitude),
      land: isLand(point)
    }
  })
}

// Hand-simplified continent silhouettes, in longitude/latitude pairs.
// Decorative geometry, not a geographic dataset and not node locations.
const LAND: Array<Array<[number, number]>> = [
  [[-168, 70], [-140, 71], [-128, 57], [-110, 52], [-95, 51], [-82, 60], [-58, 51],
    [-67, 44], [-82, 25], [-99, 18], [-111, 29], [-124, 40], [-132, 54], [-166, 60]],
  [[-81, 12], [-66, 10], [-50, 0], [-35, -7], [-42, -23], [-54, -35], [-68, -55],
    [-75, -42], [-79, -15]],
  [[-53, 60], [-43, 60], [-20, 76], [-38, 83], [-61, 79]],
  [[-17, 35], [5, 37], [30, 31], [35, 15], [50, 11], [41, -12], [30, -34], [18, -35],
    [8, -20], [-4, 4], [-17, 15]],
  [[-10, 36], [-9, 44], [5, 49], [9, 58], [25, 71], [45, 68], [61, 73], [95, 77],
    [138, 71], [178, 65], [163, 53], [144, 47], [139, 35], [123, 25], [110, 20],
    [106, 3], [98, 8], [90, 22], [80, 7], [70, 24], [53, 26], [44, 12], [34, 29],
    [28, 41], [15, 39]],
  [[112, -11], [131, -12], [141, -10], [154, -25], [146, -39], [130, -33], [114, -35]],
  [[47, -13], [50, -16], [48, -26], [44, -24]],
  [[130, 32], [142, 44], [146, 43], [140, 34]],
  [[96, 5], [109, -6], [120, -8], [130, -4], [140, -6], [148, -10], [132, -11],
    [113, -9], [103, -4]],
  [[-8, 50], [-3, 59], [1, 58], [1, 51]],
  [[166, -34], [178, -38], [173, -47], [166, -45]]
]

function inPolygon(x: number, y: number, polygon: Array<[number, number]>): boolean {
  let inside = false
  for (let index = 0, previous = polygon.length - 1; index < polygon.length; previous = index++) {
    const a = polygon[index]!
    const b = polygon[previous]!
    if (
      a[1] > y !== b[1] > y &&
      x < ((b[0] - a[0]) * (y - a[1])) / (b[1] - a[1]) + a[0]
    ) {
      inside = !inside
    }
  }
  return inside
}

/** isLand answers whether a coordinate falls inside the decorative outlines. */
export function isLand(point: LatLon): boolean {
  return LAND.some(polygon => inPolygon(point.lon, point.lat, polygon))
}

// The globe is tipped slightly rather than drawn face on, which is what stops
// it reading as a flat disc of dots. The pair below is a shear, not a rotation:
// it leans the axis toward the viewer's right and lifts the north pole. The
// coefficients are just under one, so a projected point always lands inside the
// disc -- asserted in the contract tests, because a dot outside the rim reads
// as a rendering fault.
const TILT = 0.14
const KEEP_X = 0.99
const KEEP_Y = 0.98

/**
 * project turns a unit sphere position into canvas coordinates.
 *
 * Orthographic: no perspective, which is right for a globe drawn as dots --
 * perspective would swell the middle and the dots would stop reading as an even
 * covering. Depth comes back as z so the caller can fade the limb.
 */
export function project(
  point: LatLon | SpherePoint,
  rotationDegrees: number,
  centreX: number,
  centreY: number,
  radius: number
): Projected {
  let unitX: number
  let unitY: number
  let unitZ: number
  if ('x' in point) {
    unitX = point.x
    unitY = point.y
    unitZ = point.z
  } else {
    const latitude = point.lat / DEGREES
    const longitude = point.lon / DEGREES
    unitX = Math.cos(latitude) * Math.sin(longitude)
    unitY = Math.sin(latitude)
    unitZ = Math.cos(latitude) * Math.cos(longitude)
  }

  const angle = rotationDegrees / DEGREES
  const cos = Math.cos(angle)
  const sin = Math.sin(angle)
  const turnedX = unitX * cos + unitZ * sin
  const depth = unitZ * cos - unitX * sin

  const screenX = turnedX * KEEP_X + unitY * TILT
  const screenY = unitY * KEEP_Y - turnedX * TILT

  return {
    x: centreX + screenX * radius,
    y: centreY - screenY * radius,
    z: depth,
    // A shade past the limb rather than exactly at it: the last dots fade out
    // instead of the covering ending on a hard edge.
    visible: depth >= HORIZON
  }
}

/** How far past the limb a dot is still drawn. */
export const HORIZON = -0.1

/**
 * The three markers that ride the sphere.
 *
 * Fixed latitudes turning with the globe, spaced so one is usually in view.
 * They are ornament -- a globe of dots with nothing on it looks unfinished --
 * and they are drawn only while the channel is actually up, because a marker
 * pulsing on a disconnected globe is the picture claiming activity.
 */
export const MARKER_LATITUDES = [0.58, 0.1, -0.43]

export interface Marker {
  x: number
  y: number
  z: number
}

export function markerAt(
  index: number,
  rotationDegrees: number,
  centreX: number,
  centreY: number,
  radius: number
): Marker {
  const angle = rotationDegrees / DEGREES + index * 1.8
  const latitude = MARKER_LATITUDES[index % MARKER_LATITUDES.length]!
  const unitX = Math.sin(angle) * Math.cos(latitude)
  const unitY = Math.sin(latitude)
  const depth = Math.cos(angle) * Math.cos(latitude)
  return {
    x: centreX + (unitX * KEEP_X + unitY * TILT) * radius,
    y: centreY - (unitY * KEEP_Y - unitX * TILT) * radius,
    z: depth
  }
}

/** A marker nearer the limb than this is not drawn at all. */
export const MARKER_HORIZON = 0.15
