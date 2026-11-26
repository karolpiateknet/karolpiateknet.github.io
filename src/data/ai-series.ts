// The "AI for teams" series: the single list that drives the series page
// and the step box in each post. A step with a `slug` links to that post
// once the post exists in the content collection; until then it shows as
// "coming soon".

export interface SeriesStep {
  title: string;
  slug?: string;
  blurb: string;
}

export interface SeriesLevel {
  name: string;
  summary: string;
  steps: SeriesStep[];
}

export const seriesTitle = 'AI for teams';
export const seriesPath = '/ai-for-teams';

export const seriesStart: SeriesStep = {
  title: 'AI is a system, not a skill',
  slug: 'ai-is-a-system',
  blurb: 'The map of the whole path: why one piece alone never moves the needle, and how the pieces feed each other.',
};

export const seriesLevels: SeriesLevel[] = [
  {
    name: 'You and the agent',
    summary: 'Habits one engineer can start tomorrow, with no team buy-in.',
    steps: [
      {
        title: 'Green is not proof: make the agent prove its own tests',
        slug: 'prove-ai-written-tests',
        blurb: 'Tests that must fail first, reports that say what was not checked, and a video of every feature.',
      },
      {
        title: 'Your ticket is a prompt now',
        blurb: 'A vague ticket used to cost a question. Now it costs a confidently wrong pull request.',
      },
      {
        title: 'Shared instructions: one CLAUDE.md for the whole team',
        blurb: 'Instructions as team code in the repo, so every agent starts from the same map.',
      },
      {
        title: 'One skills folder, every tool',
        blurb: 'One folder of skills, symlinked into Claude Code, Codex and Cursor.',
      },
    ],
  },
  {
    name: 'Guardrails',
    summary: 'Catch mistakes with tools before a human has to.',
    steps: [
      {
        title: 'The guardrails pyramid',
        slug: 'ai-guardrails-pyramid',
        blurb: 'Compiler, formatter, linter, Danger and hooks: push every rule as low as it will go.',
      },
      {
        title: 'Evals are not scary: ask the AI to test your skill',
        blurb: 'Five real cases, a fresh agent and one question: where did the skill get it wrong?',
      },
      {
        title: 'Every review comment you repeat is a bug in your guardrails',
        slug: 'mine-review-comments-with-ai',
        blurb: 'A weekly run that turns repeated review comments into rules.',
      },
    ],
  },
  {
    name: 'The team flow',
    summary: 'How testing, bugs and other teams fit around agents.',
    steps: [
      {
        title: 'Invisible QA: testing as a side effect',
        slug: 'invisible-qa-ai-sdlc',
        blurb: 'Every step a developer already takes with an agent leaves a test artifact behind.',
      },
      {
        title: 'You are no longer blocked',
        slug: 'you-are-no-longer-blocked',
        blurb: 'Open the backend PR instead of filing the ticket.',
      },
      {
        title: 'From crash to pull request',
        blurb: 'A crash alert turns into a draft PR with a failing test and a fix, for a human to check.',
      },
      {
        title: 'Who fixes a red UI test?',
        blurb: 'Agent triage for failing UI tests: app bug, backend change or flaky.',
      },
    ],
  },
  {
    name: 'The platform',
    summary: 'Owning AI like CI: background agents, workflow, measurement and cost.',
    steps: [
      {
        title: 'Migrate your codebase automatically, 1% a day',
        slug: 'migrate-codebase-with-ai',
        blurb: 'A bucket of small tasks and a background agent that drains it, one PR at a time.',
      },
      {
        title: 'The AI tooling engineer',
        blurb: 'Change the workflow once, and every agent on the team follows.',
      },
      {
        title: 'Skills are code',
        blurb: 'Review them, version them, test them with evals.',
      },
      {
        title: 'Measuring AI in a team without lying to yourself',
        blurb: 'Throughput next to quality, and why "lines written by AI" is useless.',
      },
      {
        title: 'What agents cost a team',
        blurb: 'Tokens, CI minutes and review attention, and where it pays back.',
      },
      {
        title: 'Team security rules for agents',
        blurb: 'Tickets as data, not instructions, and what agents may touch.',
      },
    ],
  },
];

/** Every step in reading order, starting with the hub. */
export const allSteps: SeriesStep[] = [seriesStart, ...seriesLevels.flatMap((level) => level.steps)];
