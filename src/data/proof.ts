// Measured outcomes shown as figures. Only facts Karol has confirmed
// (see PRODUCT.md, Evidence on Hand). Each one names where it was measured
// and, when a post explains it, links to that post.

export interface ProofFigure {
  value: string;
  label: string;
  where: string;
  // Named version of `where`, used only on About. Home never names the
  // company, so `where` stays anonymous.
  whereNamed?: string;
  source: string;
  read?: { title: string; href: string };
}

export const homeFigures: ProofFigure[] = [
  {
    value: '100%',
    label: 'daily AI usage across the iOS guild',
    where: 'Measured across the iOS guild',
    whereNamed: 'TransferGo iOS guild',
    source: 'Daily AI usage across the iOS guild after the team-wide AI rollout.',
    read: { title: 'AI is a system, not a skill', href: '/ai-is-a-system' },
  },
  {
    value: '17',
    label: 'custom skills in the team’s daily workflow',
    where: 'Measured in the iOS team',
    whereNamed: 'TransferGo iOS team',
    source: 'Skills, rules and commands the team uses in its daily workflow.',
    read: { title: 'AI is a system, not a skill', href: '/ai-is-a-system' },
  },
  {
    value: '~40%',
    label: 'of manual regression work moved to the agent',
    where: 'Measured in iOS release testing',
    whereNamed: 'TransferGo iOS release testing',
    source: 'Share of manual regression checks the agent now runs, from the flow described in the post.',
    read: { title: 'Invisible QA: testing as a side effect', href: '/invisible-qa-ai-sdlc' },
  },
];

export const aboutFigures: ProofFigure[] = [
  ...homeFigures.map((f) => ({ ...f, where: f.whereNamed ?? f.where })),
  {
    value: '5→50%',
    label: 'test coverage in one year on a complex production app',
    where: 'Netguru',
    source: 'Coverage on a production client app I worked on at Netguru, measured over one year.',
  },
  {
    value: '40s',
    label: 'cut from every clean build, for every developer',
    where: 'TransferGo',
    source: 'Clean-build time saved by build configuration work.',
  },
];
