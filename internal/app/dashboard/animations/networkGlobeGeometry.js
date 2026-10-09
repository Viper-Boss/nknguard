// Adapted from the owner-provided NasSimHub source. See ANIMATIONS.md.
const DEGREES = 180 / Math.PI;
export function spherePoints(count) {
    const golden = Math.PI * (3 - Math.sqrt(5));
    const points = [];
    for(let index = 0; index < count; index += 1){
        const y = 1 - 2 * (index + 0.5) / count;
        const latitude = Math.asin(Math.min(1, Math.max(-1, y)));
        const longitude = index * golden % (2 * Math.PI) - Math.PI;
        points.push({
            lat: latitude * DEGREES,
            lon: longitude * DEGREES
        });
    }
    return points;
}
export function buildGlobe(count = 5200) {
    return spherePoints(count).map((point)=>{
        const latitude = point.lat / DEGREES;
        const longitude = point.lon / DEGREES;
        return {
            ...point,
            x: Math.cos(latitude) * Math.sin(longitude),
            y: Math.sin(latitude),
            z: Math.cos(latitude) * Math.cos(longitude),
            land: isLand(point)
        };
    });
}
const LAND = [
    [
        [
            -168,
            70
        ],
        [
            -140,
            71
        ],
        [
            -128,
            57
        ],
        [
            -110,
            52
        ],
        [
            -95,
            51
        ],
        [
            -82,
            60
        ],
        [
            -58,
            51
        ],
        [
            -67,
            44
        ],
        [
            -82,
            25
        ],
        [
            -99,
            18
        ],
        [
            -111,
            29
        ],
        [
            -124,
            40
        ],
        [
            -132,
            54
        ],
        [
            -166,
            60
        ]
    ],
    [
        [
            -81,
            12
        ],
        [
            -66,
            10
        ],
        [
            -50,
            0
        ],
        [
            -35,
            -7
        ],
        [
            -42,
            -23
        ],
        [
            -54,
            -35
        ],
        [
            -68,
            -55
        ],
        [
            -75,
            -42
        ],
        [
            -79,
            -15
        ]
    ],
    [
        [
            -53,
            60
        ],
        [
            -43,
            60
        ],
        [
            -20,
            76
        ],
        [
            -38,
            83
        ],
        [
            -61,
            79
        ]
    ],
    [
        [
            -17,
            35
        ],
        [
            5,
            37
        ],
        [
            30,
            31
        ],
        [
            35,
            15
        ],
        [
            50,
            11
        ],
        [
            41,
            -12
        ],
        [
            30,
            -34
        ],
        [
            18,
            -35
        ],
        [
            8,
            -20
        ],
        [
            -4,
            4
        ],
        [
            -17,
            15
        ]
    ],
    [
        [
            -10,
            36
        ],
        [
            -9,
            44
        ],
        [
            5,
            49
        ],
        [
            9,
            58
        ],
        [
            25,
            71
        ],
        [
            45,
            68
        ],
        [
            61,
            73
        ],
        [
            95,
            77
        ],
        [
            138,
            71
        ],
        [
            178,
            65
        ],
        [
            163,
            53
        ],
        [
            144,
            47
        ],
        [
            139,
            35
        ],
        [
            123,
            25
        ],
        [
            110,
            20
        ],
        [
            106,
            3
        ],
        [
            98,
            8
        ],
        [
            90,
            22
        ],
        [
            80,
            7
        ],
        [
            70,
            24
        ],
        [
            53,
            26
        ],
        [
            44,
            12
        ],
        [
            34,
            29
        ],
        [
            28,
            41
        ],
        [
            15,
            39
        ]
    ],
    [
        [
            112,
            -11
        ],
        [
            131,
            -12
        ],
        [
            141,
            -10
        ],
        [
            154,
            -25
        ],
        [
            146,
            -39
        ],
        [
            130,
            -33
        ],
        [
            114,
            -35
        ]
    ],
    [
        [
            47,
            -13
        ],
        [
            50,
            -16
        ],
        [
            48,
            -26
        ],
        [
            44,
            -24
        ]
    ],
    [
        [
            130,
            32
        ],
        [
            142,
            44
        ],
        [
            146,
            43
        ],
        [
            140,
            34
        ]
    ],
    [
        [
            96,
            5
        ],
        [
            109,
            -6
        ],
        [
            120,
            -8
        ],
        [
            130,
            -4
        ],
        [
            140,
            -6
        ],
        [
            148,
            -10
        ],
        [
            132,
            -11
        ],
        [
            113,
            -9
        ],
        [
            103,
            -4
        ]
    ],
    [
        [
            -8,
            50
        ],
        [
            -3,
            59
        ],
        [
            1,
            58
        ],
        [
            1,
            51
        ]
    ],
    [
        [
            166,
            -34
        ],
        [
            178,
            -38
        ],
        [
            173,
            -47
        ],
        [
            166,
            -45
        ]
    ]
];
function inPolygon(x, y, polygon) {
    let inside = false;
    for(let index = 0, previous = polygon.length - 1; index < polygon.length; previous = index++){
        const a = polygon[index];
        const b = polygon[previous];
        if (a[1] > y !== b[1] > y && x < (b[0] - a[0]) * (y - a[1]) / (b[1] - a[1]) + a[0]) {
            inside = !inside;
        }
    }
    return inside;
}
export function isLand(point) {
    return LAND.some((polygon)=>inPolygon(point.lon, point.lat, polygon));
}
const TILT = 0.14;
const KEEP_X = 0.99;
const KEEP_Y = 0.98;
export function project(point, rotationDegrees, centreX, centreY, radius) {
    let unitX;
    let unitY;
    let unitZ;
    if ('x' in point) {
        unitX = point.x;
        unitY = point.y;
        unitZ = point.z;
    } else {
        const latitude = point.lat / DEGREES;
        const longitude = point.lon / DEGREES;
        unitX = Math.cos(latitude) * Math.sin(longitude);
        unitY = Math.sin(latitude);
        unitZ = Math.cos(latitude) * Math.cos(longitude);
    }
    const angle = rotationDegrees / DEGREES;
    const cos = Math.cos(angle);
    const sin = Math.sin(angle);
    const turnedX = unitX * cos + unitZ * sin;
    const depth = unitZ * cos - unitX * sin;
    const screenX = turnedX * KEEP_X + unitY * TILT;
    const screenY = unitY * KEEP_Y - turnedX * TILT;
    return {
        x: centreX + screenX * radius,
        y: centreY - screenY * radius,
        z: depth,
        visible: depth >= HORIZON
    };
}
export const HORIZON = -0.1;
export const MARKER_LATITUDES = [
    0.58,
    0.1,
    -0.43
];
export function markerAt(index, rotationDegrees, centreX, centreY, radius) {
    const angle = rotationDegrees / DEGREES + index * 1.8;
    const latitude = MARKER_LATITUDES[index % MARKER_LATITUDES.length];
    const unitX = Math.sin(angle) * Math.cos(latitude);
    const unitY = Math.sin(latitude);
    const depth = Math.cos(angle) * Math.cos(latitude);
    return {
        x: centreX + (unitX * KEEP_X + unitY * TILT) * radius,
        y: centreY - (unitY * KEEP_Y - unitX * TILT) * radius,
        z: depth
    };
}
export const MARKER_HORIZON = 0.15;
