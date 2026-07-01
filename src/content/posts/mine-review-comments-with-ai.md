---
title: "Every review comment you repeat is a bug in your guardrails"
date: 2026-07-01
tags: ["AI", "development", "process"]
description: "You and the AI bot flag the same things every week. Here is a weekly agent that mines those review comments and proposes the rule, linter, or skill that ends each one for good."
---

You are reviewing a pull request, and you leave a comment. Then you realize you have left it before. Last week, on a different PR, for a different person. Two comments down, the AI reviewer left its own version of the same note. Next week, all of it happens again.

One review comment feels free. It costs two minutes and it clears the PR. But the *same* comment, left over and over because nothing stops the mistake from recurring, is one of the more expensive things a team does, precisely because it never lands as a cost anyone can see.

<div class="stat-row">
  <div class="stat-card"><div class="stat-card__num">2 min</div><div class="stat-card__label">to leave the comment once</div></div>
  <div class="stat-card"><div class="stat-card__num">3×</div><div class="stat-card__label">a week, the same theme returns</div></div>
  <div class="stat-card"><div class="stat-card__num">150×</div><div class="stat-card__label">a year, you and the bot repeat it</div></div>
</div>

One lint rule would have erased all 150. You just never wrote it. And the reason you never wrote it is worth pulling apart, because it is the same reason your codebase drifts in the first place.

# 🔁 The rule you never write

The advice is old: when you keep correcting the same thing in review, turn it into a lint rule. Every engineer past a certain age nods at it. Almost nobody does it, and for the same reason [migrations never happen](/migrate-codebase-with-ai): the work is unowned and reactive, and it always loses to the next feature. A single comment clears the PR in two minutes, so you leave it and move on. Nothing in the week is set aside to ask, out loud, "what did we all correct five times this week, and how do we make it impossible to do a sixth?"

# 🚧 Every recurring comment is a bug in your guardrails

Plenty of layers are supposed to catch a mistake before it reaches you: the compiler, the formatter, the linter, the dead-code and CI checks, and now the skills your AI agents load before they write anything. Call them your guardrails. If a comment recurs, none of them caught it. The mistake walked through every layer and only stopped because a person happened to notice, which means it is not feedback on the pull request. It is a bug report against your guardrails.

So fix the guardrail, not the PR. Fix the PR and you spend two minutes cleaning one instance, then two more next week. Fix the guardrail and you spend an hour making that instance, and every future one, impossible. One is linear, the other compounds, and the whole game is moving your effort from the first to the second.

# 📅 The weekly run

So you schedule it. Once a week, an agent:

- pulls the week's pull requests, merged and open,
- collects every human review comment and every AI-review finding on them,
- clusters them into recurring themes and throws away the one-offs,
- ranks each theme by how often it showed up and who flagged it,
- and writes a report.

Not a pull request. A report.

Why weekly, when the [migrator](/migrate-codebase-with-ai) runs daily? Because a single comment is not a rule. You need a batch to tell a recurring pattern from a one-time reaction. A theme that appears once is noise. A theme that appears in a quarter of the week's PRs is a hole in a wall. The week is the smallest unit of time over which the signal is actually legible, and reflection wants a slower rhythm than doing.

Two streams feed the report, and they are not weighted the same.

- **Human comments are the primary signal.** A person chose to stop, read, and type. That is a strong, deliberate vote that something is wrong.
- **AI-review findings are secondary.** They are high volume and noisier, so they are held to a higher recurrence bar and labeled by where they came from. They earn their place for one specific reason: when the *same* bot finding recurs across many PRs, it usually means a skill that should have prevented it never fired. Its trigger is too narrow, so the agent never loaded it. The bot is quietly pointing at which guardrail has a bad trigger.

<div class="viz">
<svg viewBox="0 0 680 190" role="img" aria-label="A weekly loop: a week of PRs and their human and AI comments cluster into recurring themes, each theme gets the strongest enforcement lever, and enforcing it means that theme never reaches a human again." xmlns="http://www.w3.org/2000/svg">
  <defs>
    <marker id="ahR" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" style="fill: var(--color-muted)"/></marker>
    <marker id="ahRa" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" style="fill: var(--color-accent)"/></marker>
  </defs>
  <rect x="15" y="24" width="140" height="64" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="85" y="52" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px">A week of PRs</text>
  <text x="85" y="72" text-anchor="middle" style="fill: var(--color-muted); font-family: var(--font-sans); font-size:12px">human + AI comments</text>
  <rect x="185" y="24" width="140" height="64" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="255" y="52" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px">Cluster the</text>
  <text x="255" y="72" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px">recurring themes</text>
  <rect x="355" y="24" width="140" height="64" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="425" y="52" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px">Pick the</text>
  <text x="425" y="72" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px">strongest lever</text>
  <rect x="525" y="24" width="140" height="64" rx="8" style="fill: color-mix(in srgb, var(--color-accent) 12%, var(--color-bg)); stroke: var(--color-accent)"/>
  <text x="595" y="52" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px; font-weight:600">Enforce it as</text>
  <text x="595" y="72" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px; font-weight:600">a rule or skill</text>
  <line x1="157" y1="56" x2="183" y2="56" style="stroke: var(--color-muted)" marker-end="url(#ahR)"/>
  <line x1="327" y1="56" x2="353" y2="56" style="stroke: var(--color-muted)" marker-end="url(#ahR)"/>
  <line x1="497" y1="56" x2="523" y2="56" style="stroke: var(--color-muted)" marker-end="url(#ahR)"/>
  <path d="M595,88 L595,150 L85,150 L85,90" fill="none" style="stroke: var(--color-accent); stroke-dasharray:5 4" marker-end="url(#ahRa)"/>
  <text x="340" y="144" text-anchor="middle" style="fill: var(--color-accent); font-family: var(--font-sans); font-size:12px; font-weight:600">that theme never reaches a human again</text>
</svg>
<p class="viz__caption">The weekly loop closes one hole a week. Each enforced theme drops out of every future week's comments.</p>
</div>

# 🪜 The enforceability ladder

For each theme that survives, the agent's job is not to propose a fix. It is to propose the strongest fix: the highest rung on this ladder that can actually catch this class of mistake.

- **Compiler or type system.** The strongest possible, because the mistake will not compile. An exhaustive switch, a non-optional type, tighter access control. Nobody has to remember anything, since the build refuses.
- **Formatter.** Purely mechanical layout, corrected automatically before a commit ever lands: import order, spacing, a redundant `self`. The kind of thing no human should ever type into a review box.
- **Linter.** A built-in rule you switch on, or a small custom regex you add. It fires in CI, deterministically, on every PR, and it never gets tired.
- **Dead-code check.** Unused code and unreferenced symbols, where a tool can prove that removal is safe.
- **CI or Danger.** The PR-hygiene checks a per-file regex cannot express: a committed build artifact, an unresolved review thread, a red check merged anyway.
- **AI skill or rule.** When only judgment catches it ("this belongs in the interactor, not the view", "reuse the existing repository instead of adding a new one"), the lever is a skill the agent loads. No machine can prove it. The best you can do is make the agent reliably think of it.

<div class="viz">
<svg viewBox="0 0 680 352" role="img" aria-label="The enforceability ladder, strongest first: compiler or type system, formatter, linter, dead-code check, CI or Danger, and AI skill as the fallback when only judgment catches the mistake." xmlns="http://www.w3.org/2000/svg">
  <defs>
    <marker id="ahL" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" style="fill: var(--color-accent)"/></marker>
  </defs>
  <line x1="42" y1="332" x2="42" y2="16" style="stroke: var(--color-accent); stroke-width:1.5" marker-end="url(#ahL)"/>
  <text transform="translate(22,175) rotate(-90)" text-anchor="middle" style="fill: var(--color-muted); font-family: var(--font-sans); font-size:11px; letter-spacing:0.08em">STRONGER</text>
  <rect x="95" y="18" width="490" height="42" rx="6" style="fill: color-mix(in srgb, var(--color-accent) 14%, var(--color-bg)); stroke: var(--color-accent)"/>
  <text x="110" y="44" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13.5px; font-weight:600">Compiler / type system</text>
  <text x="575" y="44" text-anchor="end" style="fill: var(--color-fg-soft); font-family: var(--font-sans); font-size:12px">the mistake won't compile</text>
  <rect x="95" y="72" width="490" height="42" rx="6" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="110" y="98" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13.5px; font-weight:600">Formatter</text>
  <text x="575" y="98" text-anchor="end" style="fill: var(--color-fg-soft); font-family: var(--font-sans); font-size:12px">auto-fixed before commit</text>
  <rect x="95" y="126" width="490" height="42" rx="6" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="110" y="152" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13.5px; font-weight:600">Linter</text>
  <text x="575" y="152" text-anchor="end" style="fill: var(--color-fg-soft); font-family: var(--font-sans); font-size:12px">built-in rule or custom regex</text>
  <rect x="95" y="180" width="490" height="42" rx="6" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="110" y="206" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13.5px; font-weight:600">Dead-code check</text>
  <text x="575" y="206" text-anchor="end" style="fill: var(--color-fg-soft); font-family: var(--font-sans); font-size:12px">proves removal is safe</text>
  <rect x="95" y="234" width="490" height="42" rx="6" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="110" y="260" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13.5px; font-weight:600">CI / Danger</text>
  <text x="575" y="260" text-anchor="end" style="fill: var(--color-fg-soft); font-family: var(--font-sans); font-size:12px">PR hygiene a regex can't express</text>
  <rect x="95" y="288" width="490" height="42" rx="6" style="fill: var(--color-code-bg); stroke: var(--color-line); stroke-dasharray:5 4"/>
  <text x="110" y="314" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13.5px; font-weight:600">AI skill / rule</text>
  <text x="575" y="314" text-anchor="end" style="fill: var(--color-muted); font-family: var(--font-sans); font-size:12px">when only judgment catches it</text>
</svg>
<p class="viz__caption">Push each theme as high as it will go. The top rungs cost nobody a thought; only the dashed one depends on the agent choosing to read it.</p>
</div>

Check the top of the ladder first for something that already exists: "a rule exists but is not enabled" is the mechanical twin of "a skill exists but is not firing." More often than you would guess, the fix is a config flag you already own, not a new rule you write.

Put together, a single entry in the weekly report looks like this:

```
theme:     force-unwrapped optionals in view code   (14 PRs this week)
flagged:   6 human comments, 21 bot findings
covered:   skill "safe-optionals" exists, but its trigger only matches
           networking code, so the agent never loads it for view files
lever:     linter rule, already in the config, currently disabled
           strongest available: it fails CI, no human needed
proposal:  enable the rule; widen the skill trigger to all view files
decision:  __ staff engineer signs off
```

# 🧭 The robot proposes, you decide

The output is a report, never a pull request. The run is not the authority on good practice, and you never want it to be: it surfaces evidence (how often a theme showed up, in which PRs, flagged by whom, whether a skill already covers it, the strongest available lever) and drafts a proposal you read in a few minutes. You decide, and for what you accept, you author the rule or skill change and open the PR yourself. An agent that could promote its own taste straight into a lint rule would enshrine a bad call across the whole codebase at machine speed. It finds the pattern; you decide the pattern deserves a wall.

# 🤖 Comments are training signal now

Ten years ago a review comment taught one person, the author. Today agents write a growing share of your code and read your guardrails to decide what to write, so the comment does double duty: encode it as a rule and no human leaves it again; encode it as a skill (or fix a skill's trigger so it actually fires) and the agent stops making the mistake at all, so the bot stops flagging it and you stop reviewing it. That is the migrator's loop pointed at the rules instead of the code: cleaner guardrails produce cleaner AI code, which produces fewer comments, which frees time to tighten the next guardrail.

# 📉 Review load compounds down

This is the mirror image of the migrator's curve. The migrator makes the codebase one percent better every day, a line that points up; the weekly review makes your review load lighter every week, a line that points down. Each theme you enforce this week cannot come back next week, so the report gets shorter, you review a little less, and the freed time goes into the next batch. It is a ratchet: it only tightens, and a nit once enforced never climbs back into your reviews.

<div class="viz">
<svg viewBox="0 0 680 330" role="img" aria-label="Repeat review comments per week: doing nothing stays flat and high, while enforcing one theme a week ratchets the line down in steps toward the axis." xmlns="http://www.w3.org/2000/svg">
  <line x1="55" y1="30" x2="55" y2="290" style="stroke: var(--color-line); stroke-width:1.5"/>
  <line x1="55" y1="290" x2="655" y2="290" style="stroke: var(--color-line); stroke-width:1.5"/>
  <text x="60" y="24" style="fill: var(--color-muted); font-family: var(--font-sans); font-size:12px">repeat comments / week</text>
  <polyline points="60,58 200,56 340,55 480,54 640,52" fill="none" style="stroke: var(--color-muted); stroke-width:2; stroke-dasharray:6 5"/>
  <text x="636" y="46" text-anchor="end" style="fill: var(--color-muted); font-family: var(--font-sans); font-size:13px; font-weight:600">do nothing → same nits, forever</text>
  <polyline points="60,72 156,72 156,110 252,110 252,152 348,152 348,192 444,192 444,224 540,224 540,250 636,250" fill="none" style="stroke: var(--color-accent); stroke-width:3"/>
  <circle cx="636" cy="250" r="4" style="fill: var(--color-accent)"/>
  <text x="392" y="96" text-anchor="middle" style="fill: var(--color-accent); font-family: var(--font-sans); font-size:12px; font-weight:600">each step = one theme you enforced</text>
  <text x="632" y="272" text-anchor="end" style="fill: var(--color-accent); font-family: var(--font-sans); font-size:14px; font-weight:700">lighter every week</text>
  <text x="355" y="313" text-anchor="middle" style="fill: var(--color-muted); font-family: var(--font-sans); font-size:12px">weeks →</text>
</svg>
<p class="viz__caption">A ratchet only tightens. Every theme you enforce is a theme that cannot come back, so the line steps down and never up.</p>
</div>

# 🛠️ Set it up in two steps

No platform to buy, no pipeline to build. You already own every piece; the agent is the runtime, and everything above is the configuration.

1. **Give the agent read access to your PRs.** Install and sign in to the [GitHub CLI](https://cli.github.com), so it can pull the week's pull requests and their review threads, human and bot.
2. **Add one weekly routine and hand it the goal:** pull last week's comments, cluster the recurring themes, drop the one-offs, weight human over bot, map each survivor to its strongest rung, post the report, never open a PR.

That is the whole install. Everything that makes it yours lives in step two, so brainstorm that goal with the agent until the report it drafts is one you would actually act on. Then the schedule carries it, and your job is a short read on Monday.

# 📌 Summary

- **The problem:** you and the AI reviewer leave the same comments every week, forever, because nothing in the tooling stops those mistakes from recurring.
- **The reframe:** a recurring review comment is a bug in your guardrails, not feedback on one PR. Fix the guardrail, not the instance.
- **The fix:** a weekly agent mines the week's human and AI comments, clusters the recurring themes, and for each one proposes the strongest lever on the enforceability ladder, from the compiler down to an AI skill. It writes a report; you decide and author the change.
- **The twist:** review load compounds down while AI output compounds up, on the same codebase. Every comment you never have to leave again is a rung you only had to climb once.

<div class="banner">
  <p class="banner__big">The daily worker improves your code. The weekly worker improves the rules that judge it.</p>
  <p class="banner__sub">Migrations were the first obvious job for a background agent. Mining your own review comments is the second. Point the fleet at the code, point one weekly run at the guardrails, and the things you used to catch by hand start catching themselves, for you and for the next agent.</p>
</div>
