---
title: "Migrate your codebase automatically with AI, 1% a day"
date: 2026-06-23
tags: ["AI", "development", "process"]
description: "Big migrations never finish. Here is how to turn the AI tooling every engineer already uses into a daily agent that pays down technical debt, 1% at a time."
---

Every codebase carries debt. A deprecated component nobody replaced. An old string API that lives next to the new one. A test framework half-migrated two years ago. None of it is urgent. All of it slows you down a little, every day.

The cost is invisible because it is spread out. If drift makes each engineer 20 minutes slower per day at a $60 hourly rate, the bill quietly adds up:

<div class="stat-row">
  <div class="stat-card"><div class="stat-card__num">$20</div><div class="stat-card__label">per day</div></div>
  <div class="stat-card"><div class="stat-card__num">$400</div><div class="stat-card__label">per month</div></div>
  <div class="stat-card"><div class="stat-card__num">$4,800</div><div class="stat-card__label">per year, per engineer</div></div>
</div>

Multiply by a team. The waste is real; it just never lands on a single invoice, so it never gets prioritized.

And the reason it never gets fixed is not laziness. It is that the usual way of fixing it does not work.

# 🧱 Why migrations never happen

The classic approach is a ticket. You spot the drift, you write up a migration, you hand it to the team that owns that area, and you wait.

[I wrote a whole article about how much a badly-described ticket costs](/How-to-save-milions-in-software-development-1). But even a perfect ticket has a problem here: a migration ticket competes with features, and it loses. Every sprint. It sits in the backlog labeled "tech debt, nice to have" until the symbol it was about gets deprecated again.

The big-bang version is worse. One engineer takes "migrate everything off X" as a quarter-long project, opens a 4000-line pull request, and now nobody can review it, nothing else can merge near it, and three weeks of rebases later half of it is abandoned.

Big migrations never finish. That is the pattern.

<div class="viz">
<svg viewBox="0 0 680 430" role="img" aria-label="The ticket path loops back to the backlog every sprint and never improves." xmlns="http://www.w3.org/2000/svg">
  <defs>
    <marker id="ahT" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" style="fill: var(--color-muted)"/></marker>
  </defs>
  <!-- nodes -->
  <rect x="135" y="14" width="230" height="40" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="250" y="39" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:14px">Spot the drift</text>
  <rect x="135" y="82" width="230" height="40" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="250" y="107" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:14px">Write a migration ticket</text>
  <rect x="135" y="150" width="230" height="40" rx="8" style="fill: color-mix(in srgb, var(--color-accent) 12%, var(--color-bg)); stroke: var(--color-accent)"/>
  <text x="250" y="175" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:14px; font-weight:600">Backlog</text>
  <rect x="135" y="218" width="230" height="40" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="250" y="243" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:14px">Competes with feature work</text>
  <rect x="135" y="300" width="230" height="40" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="250" y="325" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:14px">One huge migration PR</text>
  <rect x="135" y="368" width="230" height="40" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="250" y="393" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:14px">Stuck in review and rebases</text>
  <!-- arrows -->
  <line x1="250" y1="54" x2="250" y2="80" style="stroke: var(--color-muted)" marker-end="url(#ahT)"/>
  <line x1="250" y1="122" x2="250" y2="148" style="stroke: var(--color-muted)" marker-end="url(#ahT)"/>
  <line x1="250" y1="190" x2="250" y2="216" style="stroke: var(--color-muted)" marker-end="url(#ahT)"/>
  <!-- loop back to backlog -->
  <path d="M365,238 L470,238 L470,170 L367,170" fill="none" style="stroke: var(--color-muted); stroke-dasharray:4 4" marker-end="url(#ahT)"/>
  <text x="478" y="207" style="fill: var(--color-muted); font-family: var(--font-sans); font-size:12px">loses, every sprint</text>
  <!-- branch to big PR -->
  <line x1="250" y1="258" x2="250" y2="298" style="stroke: var(--color-muted); stroke-dasharray:4 4" marker-end="url(#ahT)"/>
  <text x="262" y="283" style="fill: var(--color-muted); font-family: var(--font-sans); font-size:12px">someday</text>
  <line x1="250" y1="340" x2="250" y2="366" style="stroke: var(--color-muted)" marker-end="url(#ahT)"/>
</svg>
<p class="viz__caption">The ticket path: every arrow that loops back to the backlog is a sprint where nothing improved.</p>
</div>

# 📈 The 1% rule

There is [a well-known bit of marginal-gains math](https://jamesclear.com/marginal-gains). Improve by 1% every day and after a year you are not 365% better. You are 37× better, because the gains compound. Get 1% worse every day and you decay to almost nothing.

<div class="viz">
<svg viewBox="0 0 680 330" role="img" aria-label="Improving 1% a day compounds to about 37 times over a year; drifting 1% a day decays to near zero." xmlns="http://www.w3.org/2000/svg">
  <!-- axes -->
  <line x1="55" y1="30" x2="55" y2="290" style="stroke: var(--color-line); stroke-width:1.5"/>
  <line x1="55" y1="290" x2="655" y2="290" style="stroke: var(--color-line); stroke-width:1.5"/>
  <!-- today baseline -->
  <line x1="55" y1="273" x2="655" y2="273" style="stroke: var(--color-line); stroke-dasharray:3 4"/>
  <text x="62" y="267" style="fill: var(--color-muted); font-family: var(--font-sans); font-size:12px">1× today</text>
  <!-- drift -->
  <polyline points="60,273 176,277 292,279 408,279 524,280 640,280" fill="none" style="stroke: var(--color-muted); stroke-width:2; stroke-dasharray:6 5"/>
  <text x="636" y="296" text-anchor="end" style="fill: var(--color-muted); font-family: var(--font-sans); font-size:13px; font-weight:600">-1%/day → ~0</text>
  <!-- improve -->
  <polyline points="60,273 176,266 292,251 408,221 524,159 640,32" fill="none" style="stroke: var(--color-accent); stroke-width:3; stroke-linejoin:round; stroke-linecap:round"/>
  <circle cx="640" cy="32" r="4" style="fill: var(--color-accent)"/>
  <text x="636" y="24" text-anchor="end" style="fill: var(--color-accent); font-family: var(--font-sans); font-size:15px; font-weight:700">+1%/day → 37× better</text>
  <text x="355" y="313" text-anchor="middle" style="fill: var(--color-muted); font-family: var(--font-sans); font-size:12px">one year →</text>
</svg>
<p class="viz__caption">Same 1% a day. One direction compounds into a different codebase; the other rots it.</p>
</div>

A codebase works the same way. It drifts a little every day on its own. The question is whether you can push it the other way by the same small amount: reliably, without anyone having to care.

1% is the important part. It is small enough that:

- the change is trivial to review,
- it touches almost nothing,
- it can't break a feature,
- and nobody has to stop what they are doing.

You will not see it on any given day. But a year of compounding small, safe, mechanical changes is a genuinely different codebase.

The trick is making "1% a day" happen without a human deciding to do it each day. That is where the agents come in.

# 🪣 A bucket and a daily agent

Instead of tickets, you keep a bucket: a shared, human-curated list of mechanical migrations. Each entry is one precise change with a decision record: the exact before→after, and, just as importantly, the cases the agent must not touch.

```
campaign:  LegacyStrings → SharedStrings   (a deprecated API and its drop-in replacement)
 what:    swap every call from the old generated strings type to the new one (a pure rename)
 safe:    each accessor has an identical counterpart on the new type
 drop:    any file that fails to build after the swap; never invent a missing key
```

Then every day, on a schedule, an AI agent:

- picks the next migration from the bucket,
- makes one small batch of changes,
- builds it, runs the tests, lints it, reviews it,
- opens a draft pull request,
- and waits for the next day.

<div class="viz">
<svg viewBox="0 0 680 440" role="img" aria-label="A bucket fans out to one agent per engineer; each runs build-test-lint-review, then opens a small PR if green or does nothing if not safe." xmlns="http://www.w3.org/2000/svg">
  <defs>
    <marker id="ahI" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" style="fill: var(--color-muted)"/></marker>
  </defs>
  <!-- bucket -->
  <rect x="210" y="14" width="260" height="44" rx="8" style="fill: color-mix(in srgb, var(--color-accent) 12%, var(--color-bg)); stroke: var(--color-accent)"/>
  <text x="340" y="41" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:14px; font-weight:600">Bucket of mechanical migrations</text>
  <!-- agents -->
  <rect x="45" y="96" width="150" height="36" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="120" y="119" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px">Dev A agent</text>
  <rect x="265" y="96" width="150" height="36" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="340" y="119" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px">Dev B agent</text>
  <rect x="485" y="96" width="150" height="36" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="560" y="119" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px">Dev C agent</text>
  <line x1="300" y1="58" x2="130" y2="94" style="stroke: var(--color-muted)" marker-end="url(#ahI)"/>
  <line x1="340" y1="58" x2="340" y2="94" style="stroke: var(--color-muted)" marker-end="url(#ahI)"/>
  <line x1="380" y1="58" x2="550" y2="94" style="stroke: var(--color-muted)" marker-end="url(#ahI)"/>
  <text x="340" y="156" text-anchor="middle" style="fill: var(--color-muted); font-family: var(--font-sans); font-size:12px">split by file-path hash, so no two agents share a file</text>
  <!-- gate -->
  <line x1="340" y1="132" x2="340" y2="176" style="stroke: var(--color-muted)" marker-end="url(#ahI)"/>
  <rect x="232" y="178" width="216" height="44" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-accent)"/>
  <text x="340" y="205" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px; font-weight:600">build → test → lint → review</text>
  <!-- not safe branch -->
  <path d="M270,222 L160,258" fill="none" style="stroke: var(--color-muted)" marker-end="url(#ahI)"/>
  <text x="150" y="246" text-anchor="middle" style="fill: var(--color-muted); font-family: var(--font-sans); font-size:11px">not safe</text>
  <rect x="70" y="260" width="170" height="40" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="155" y="285" text-anchor="middle" style="fill: var(--color-muted); font-family: var(--font-sans); font-size:13px">Do nothing today</text>
  <!-- green branch -->
  <path d="M410,222 L470,258" fill="none" style="stroke: var(--color-accent)" marker-end="url(#ahI)"/>
  <text x="455" y="246" style="fill: var(--color-accent); font-family: var(--font-sans); font-size:11px; font-weight:600">all green</text>
  <rect x="410" y="260" width="200" height="40" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="510" y="285" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px">Small draft PR</text>
  <line x1="510" y1="300" x2="510" y2="324" style="stroke: var(--color-muted)" marker-end="url(#ahI)"/>
  <rect x="410" y="326" width="200" height="40" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="510" y="351" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px">Owning dev reviews ~2 min</text>
  <line x1="510" y1="366" x2="510" y2="390" style="stroke: var(--color-muted)" marker-end="url(#ahI)"/>
  <rect x="410" y="392" width="200" height="40" rx="8" style="fill: color-mix(in srgb, var(--color-accent) 14%, var(--color-bg)); stroke: var(--color-accent)"/>
  <text x="510" y="417" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px; font-weight:600">Merge: codebase 1% better</text>
</svg>
<p class="viz__caption">The improver path: the same drift, but the loop runs itself and ends in a merge instead of a backlog.</p>
</div>

In the morning you have a tidy, green, two-minute-review PR waiting. You approve it or you don't. Nobody wrote a ticket. Nobody scheduled a sprint. The codebase got 1% better, and nobody had to make time for it.

The bucket is the key idea. It turns "someone should migrate X someday", a sentence that produces nothing, into a queue an agent can drain on its own. You feed the bucket once; it gets worked forever.

# 👥 Decentralize it: every engineer's AI, not one team's

Here is the part I like most.

You do not run this as one central service. Every engineer runs the same agent on their own machine, pointed at the AI tooling they already use for work. Each engineer's agent takes a different slice of the work, split deterministically so two agents can never touch the same file, and works only that slice.

Why decentralize?

- **No bottleneck.** Ten engineers means ten agents draining the bucket in parallel, every day.
- **No collisions.** The work is partitioned by a hash of the file path, so nobody steps on anybody.
- **No new infrastructure.** There is no server to run, no central queue, no on-call. The schedule is the coordination.
- **Ownership stays human.** Each engineer wakes up to their agent's PRs and reviews them. The robot proposes; the person approves.

And it runs on time you already have. Each agent works the slack in the AI tooling you already use for work: kick it off as you wrap up the day, then review what it opened before you log off or over coffee the next morning. Keep it on tooling your company already sanctions and check your provider's terms; this is your normal work setup, not a personal plan stretched to do company work unattended.

# 🔀 Every change is a pull request (and a lesson)

The whole thing runs on GitHub. Every change the agent makes arrives as a pull request. Nothing reaches the main branch without a human clicking approve. The governance you already trust (code review, CI, branch protection) is the governance the improver runs on. There is no separate "AI pipeline" to audit. If the agent can't open a normal PR that passes your normal checks, it doesn't ship.

That also turns it into a quiet learning channel. The bucket is curated by a staff engineer, so each campaign encodes a decision: this is the pattern you want, that is the one you are leaving behind. Every morning the team reviews a stream of tiny, worked examples of the sanctioned approach. A junior dev who reads five LegacyStrings → SharedStrings PRs has absorbed the new API without a single meeting. The PRs are small enough to actually read, which is exactly why they teach.

# 🧮 The math: your best engineer is not the point

Here is the counterintuitive part, in numbers.

Picture a team today. One power user has gone deep on AI tooling and ships 20 of these tiny PRs a day. Everyone else runs the agent now and then, call it 1 a day each. With 20 other engineers:

```
20 (the power user)  +  20 × 1  =  40 PRs / day
```

Most of the output comes from one person. That feels great until that person goes on holiday, or burns out, or moves teams. Your debt burn-down has a single point of failure.

Now do the unintuitive thing. Stop optimizing the hero. Get everyone else to a modest 4 a day, and reduce the power user to 4 as well, because the fleet no longer leans on them:

```
4 (former power user)  +  20 × 4  =  84 PRs / day
```

<div class="viz">
<svg viewBox="0 0 680 196" role="img" aria-label="Leaning on one hero yields 40 PRs per day; spreading the work across the fleet yields 84 per day." xmlns="http://www.w3.org/2000/svg">
  <text x="20" y="38" style="fill: var(--color-fg-soft); font-family: var(--font-sans); font-size:13px; font-weight:600">Lean on one hero</text>
  <rect x="20" y="46" width="295" height="40" rx="6" style="fill: var(--color-muted)"/>
  <text x="327" y="72" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:16px; font-weight:700">40 PRs / day</text>
  <text x="20" y="128" style="fill: var(--color-fg-soft); font-family: var(--font-sans); font-size:13px; font-weight:600">Spread across the fleet</text>
  <rect x="20" y="136" width="620" height="40" rx="6" style="fill: var(--color-accent)"/>
  <text x="620" y="162" text-anchor="end" style="fill: var(--color-bg); font-family: var(--font-sans); font-size:16px; font-weight:700">84 PRs / day</text>
</svg>
<p class="viz__caption">Same headcount, double the throughput, and no single point of failure.</p>
</div>

You more than doubled the output while cutting your best contributor's throughput by 5×. That is the entire argument for decentralizing, in one line: throughput is the fleet, not the hero.

One person is capped by their hours and their attention; twenty agents draining their own slices are not. 4 PRs a day is nothing per person, but across a team it is the whole migration, every week.

And your best engineer is not idle. The hours they used to spend grinding out mechanical PRs now go to the work only they can do: curating the bucket, writing the decision records that keep the agents safe, and researching how to improve the codebase in the ways an agent can't. You did not lose their output, you moved it up the value chain, from doing the migrations to deciding which ones are worth doing.

# 🤖 It makes the AI better at its real job

This surprised me, but it is the strongest argument. A codebase with two string APIs, three ways to show a banner, and a half-migrated test framework forces an AI to guess which pattern you want, and that ping-pong of wrong guesses and corrections is most of the friction in working with an agent.

A more aligned codebase removes the guessing, so the agent gets it right the first time more often. The improver compounds twice: it pays down debt and makes every future AI interaction cheaper, including its own. The cleaner the codebase, the better the agent works on it, the cleaner it gets.

# 🎯 When you want to be 100% sure

You can dial the confidence as high as you like by choosing what goes in the bucket.

- **Make it provable.** Fill the bucket with changes a machine can verify: migrations covered by unit tests, pure renames the compiler proves correct, or test-file changes where a green run is the proof. The build and the test suite become a safety net the agent cannot ship past.
- **Keep judgment human.** The riskier, design-heavy migrations, the ones that need a designer's eye or an architecture call, never enter the bucket. They stay with a person, on the slice where "did it work?" has no mechanical answer.

# 🚀 Why it works

Most "let's clean up the codebase" initiatives die. This one doesn't, and the reason is the same reason it is only 1%:

- **The changes are mechanical and tiny.** A token rename, a redundant init removed, a deprecated call swapped. Each PR is capped to a few files, so there are no design decisions to argue about and a reviewer is never afraid of one.
- **They are safe by construction.** The agent runs the full build-test-lint-review chain before it opens anything and drops any case the decision record does not clearly cover. A silent day is a success: if there is nothing safe to do, it does nothing.
- **It runs itself.** A scheduled agent and a markdown bucket, with no platform to build and no service to operate. It happens every single day, whether or not anyone remembers, and consistency is the whole trick with compounding.
- **You fix your own code.** Each engineer reviews their own agent's PRs, in the areas they already know. No handing context to a stranger on another team, no waiting on someone else's backlog.
- **It costs about ten minutes a day.** Reviewing a couple of tiny, green PRs over coffee is the entire daily commitment. That is a far better deal than carrying a migration ticket for a quarter, and it compounds into a transformed codebase by the end of the year.

Simplicity is what makes it real. The moment a migration needs judgment, it stops being improver work and goes back to a human. You are not trying to automate the hard 20%. You are automating the boring 80% that nobody ever gets to.

# 📌 Summary

- **The problem:** codebases drift 1% worse every day, tickets lose to features, and big-bang migrations never finish.
- **The fix:** a bucket of small, mechanical changes, drained by a daily agent that opens one small, gated PR at a time, on every engineer's machine and the AI tooling they already use.
- **The twist:** throughput is the fleet, not the hero. Everyone doing a little beats one power user, it rides the GitHub review and CI you already trust, and a cleaner codebase makes every future AI interaction cheaper.

You will not notice a single day. That is the point. Show up every day anyway, and let it compound.

<div class="banner">
  <p class="banner__big">Background workers are the future.</p>
  <p class="banner__sub">An agent that improves the codebase beside you, while you do the work only you can do. Migrations are just the first obvious job. Once every engineer runs one, the boring, mechanical backlog drains itself.</p>
</div>
