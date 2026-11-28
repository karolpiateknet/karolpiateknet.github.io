// 8-bit icons, drawn on a 16 x 16 grid. Each row is one line of pixels:
// '.' empty, 'k' ink, 'b' ultramarine. Only the two inks, never orange:
// orange stays reserved for the current step and the one primary action.

export const pixelIcons = {
  // Level 1, You and the agent: the agent itself.
  agent: [
    '.......kk.......',
    '.......kk.......',
    '.......bb.......',
    '..kkkkkkkkkkkk..',
    '..k..........k..',
    '..k.bbb..bbb.k..',
    '..k.bbb..bbb.k..',
    '..k..........k..',
    '..k...kkkk...k..',
    '..k..........k..',
    '..kkkkkkkkkkkk..',
    '.....k....k.....',
    '...kkkkkkkkkk...',
    '...k.bbbbbb.k...',
    '...k.bbbbbb.k...',
    '...kkkkkkkkkk...',
  ],
  // Level 2, Guardrails: a shield with a check.
  guardrails: [
    '.kkkkkkkkkkkkkk.',
    '.kbbbbbbbbbbbbk.',
    '.kbbbbbbbbbbbbk.',
    '.kbbbbbbbbb..bk.',
    '.kbbbbbbbb..bbk.',
    '.kbbbbbbb..bbbk.',
    '.kb..bbb..bbbbk.',
    '.kbb..b..bbbbbk.',
    '.kbbb...bbbbbbk.',
    '.kbbbb.bbbbbbbk.',
    '.kbbbbbbbbbbbbk.',
    '..kbbbbbbbbbbk..',
    '...kbbbbbbbbk...',
    '....kbbbbbbk....',
    '.....kbbbbk.....',
    '......kkkk......',
  ],
  // Level 3, The team flow: three people moving one way.
  team: [
    '......bbbb......',
    '.kkk..bbbb..kkk.',
    '.kkk..bbbb..kkk.',
    '.kkk..bbbb..kkk.',
    '................',
    '.....bbbbbb.....',
    'kkkk.bbbbbb.kkkk',
    'kkkk.bbbbbb.kkkk',
    'kkkk.bbbbbb.kkkk',
    'kkkk.bbbbbb.kkkk',
    '................',
    '............k...',
    '............kk..',
    'kkkkkkkkkkkkkkk.',
    '............kk..',
    '............k...',
  ],
  // Level 4, The platform: a server rack.
  platform: [
    '.kkkkkkkkkkkkkk.',
    '.k............k.',
    '.k.bb..kkkkkk.k.',
    '.k............k.',
    '.kkkkkkkkkkkkkk.',
    '.k............k.',
    '.k.bb..kkkkkk.k.',
    '.k............k.',
    '.kkkkkkkkkkkkkk.',
    '.k............k.',
    '.k.bb..kkkkkk.k.',
    '.k............k.',
    '.kkkkkkkkkkkkkk.',
    '..kk........kk..',
    '..kk........kk..',
    '................',
  ],
  // 404: the agent, lost.
  lost: [
    '.......kk.......',
    '.......kk.......',
    '.......bb.......',
    '..kkkkkkkkkkkk..',
    '..k..........k..',
    '..k.b.b..b.b.k..',
    '..k..b....b..k..',
    '..k.b.b..b.b.k..',
    '..k..........k..',
    '..k...kkkk...k..',
    '..k..k....k..k..',
    '..k..........k..',
    '..kkkkkkkkkkkk..',
    '.....k....k.....',
    '...kkkkkkkkkk...',
    '...kkkkkkkkkk...',
  ],
  // Closing invitation: two speech bubbles, comparing notes.
  chat: [
    '.kkkkkkkkk......',
    'k.........k.....',
    'k.k..k..k.k.....',
    'k.........k.....',
    '.kkkkkkkkk......',
    '..kk............',
    '..k.............',
    '......bbbbbbbbb.',
    '.....bbbbbbbbbbb',
    '.....bb.bb.bb.bb',
    '.....bbbbbbbbbbb',
    '......bbbbbbbbb.',
    '............bb..',
    '.............b..',
    '................',
    '................',
  ],
  // Pointer for the selected level tab: a thin chevron arrow (8 x 7).
  arrow: [
    '....k...',
    '.....k..',
    '......k.',
    'kkkkkkkk',
    '......k.',
    '.....k..',
    '....k...',
  ],
} as const;

export type PixelIconName = keyof typeof pixelIcons;

// The four series levels, in order.
export const levelIcons: PixelIconName[] = ['agent', 'guardrails', 'team', 'platform'];

export function pixelSize(name: PixelIconName) {
  const grid = pixelIcons[name];
  return { w: grid[0].length, h: grid.length };
}

// Runs of same-colour pixels on each row, so an icon is a few dozen rects.
export function pixelRuns(name: PixelIconName) {
  const runs: { x: number; y: number; w: number; ink: 'k' | 'b' }[] = [];
  (pixelIcons[name] as readonly string[]).forEach((row, y) => {
    let x = 0;
    while (x < row.length) {
      const c = row[x];
      let w = 1;
      while (row[x + w] === c) w++;
      if (c === 'k' || c === 'b') runs.push({ x, y, w, ink: c });
      x += w;
    }
  });
  return runs;
}
