import { getCollection } from 'astro:content';
import { seriesLevels, seriesStart, type SeriesStep } from './ai-series';

// Audience for each level, in level order.
export const levelAudience = ['For engineers', 'For EMs and leads', 'For EMs and leads', 'For EMs and leads'];

export interface StepStatus extends SeriesStep {
  number: number;
  live: boolean;
}

export interface LevelStatus {
  number: number;
  name: string;
  summary: string;
  audience: string;
  steps: StepStatus[];
  liveCount: number;
}

export async function getSeriesStatus() {
  const published = new Set((await getCollection('posts')).map((post) => post.id));
  const isLive = (step: SeriesStep) => !!step.slug && published.has(step.slug);
  let counter = 0;
  const levels: LevelStatus[] = seriesLevels.map((level, index) => {
    const steps = level.steps.map((step) => ({ ...step, number: ++counter, live: isLive(step) }));
    return {
      number: index + 1,
      name: level.name,
      summary: level.summary,
      audience: levelAudience[index] ?? '',
      steps,
      liveCount: steps.filter((s) => s.live).length,
    };
  });
  const start: StepStatus = { ...seriesStart, number: 0, live: isLive(seriesStart) };
  // The hub ("Start here") is the map, not a step: counts cover the numbered steps only.
  const steps = levels.flatMap((l) => l.steps);
  return {
    start,
    levels,
    liveCount: steps.filter((s) => s.live).length,
    totalCount: steps.length,
  };
}
