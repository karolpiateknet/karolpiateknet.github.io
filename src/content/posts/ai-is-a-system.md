---
title: "AI is a system, not a skill: why one piece never moves the needle"
date: 2026-11-26
tags: ["AI", "development", "process"]
description: "Teams add an AI tool, write ten skills, and three months later see a small bump. The big effects come from connecting the pieces: instructions, guardrails, workflow, testing, review and background refactoring, each feeding the next."
tldr:
  - "One skill, one AI reviewer or one agent alone gives a small, flat gain."
  - "Instructions, workflow, guardrails, testing, review, review mining and background refactoring each feed the next, and the gains compound."
  - "The first weeks feel like overhead, and somebody has to own the system like CI."
---

Here is a story I keep hearing. A team buys an AI tool. A few enthusiasts write ten skills. Someone turns on an AI reviewer. Three months later the verdict is "it helps a bit, maybe ten percent", and the conversation moves on.

The tool was not the problem. The problem was treating AI as a feature you switch on, instead of a system you build. One skill, one reviewer or one agent on its own gives you a small, flat gain. Connect them, so that what one piece produces improves the next, and the gains start to compound.

# 🧩 The pieces

Every team that gets real results from AI ends up with roughly the same parts:

- **Instructions and skills.** A short CLAUDE.md that maps the repo, and skills for the judgment calls a tool cannot make.
- **An agent workflow.** Ticket, plan, build, verify, pull request. The same steps every time, not a fresh conversation every morning.
- **Guardrails.** The compiler, the formatter, the linter, Danger and hooks, the layers that catch mistakes before a human has to.
- **Verification and testing.** The agent tests its own work first, [proves its tests can fail](/prove-ai-written-tests), and leaves [test artifacts behind](/invisible-qa-ai-sdlc) for QA.
- **Code review.** An AI reviewer first, a human last, on small pull requests.
- **Review mining.** A [weekly run](/mine-review-comments-with-ai) that finds the comments you keep repeating and pushes each one down into a rule.
- **Background refactoring.** Agents that [clean the codebase 1% a day](/migrate-codebase-with-ai), one small PR at a time.

None of these is new or hard on its own. The value is in the arrows between them.

<div class="viz">
<svg viewBox="0 0 680 420" role="img" aria-label="A loop of six parts around the codebase: instructions and skills feed the agent workflow, which runs through guardrails, then verification and testing, then review, then review mining, which feeds back into instructions and skills. Background refactoring cleans the codebase in the middle." xmlns="http://www.w3.org/2000/svg">
  <defs>
    <marker id="ahS" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" style="fill: var(--color-muted)"/></marker>
  </defs>
  <rect x="250" y="20" width="180" height="46" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="340" y="40" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px; font-weight:600">Instructions + skills</text>
  <text x="340" y="57" text-anchor="middle" style="fill: var(--color-fg-soft); font-family: var(--font-sans); font-size:11px">CLAUDE.md, judgment calls</text>
  <rect x="470" y="110" width="180" height="46" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="560" y="130" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px; font-weight:600">Agent workflow</text>
  <text x="560" y="147" text-anchor="middle" style="fill: var(--color-fg-soft); font-family: var(--font-sans); font-size:11px">ticket, plan, build</text>
  <rect x="470" y="264" width="180" height="46" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="560" y="284" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px; font-weight:600">Guardrails</text>
  <text x="560" y="301" text-anchor="middle" style="fill: var(--color-fg-soft); font-family: var(--font-sans); font-size:11px">types, lint, Danger, hooks</text>
  <rect x="250" y="354" width="180" height="46" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="340" y="374" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px; font-weight:600">Verify + test</text>
  <text x="340" y="391" text-anchor="middle" style="fill: var(--color-fg-soft); font-family: var(--font-sans); font-size:11px">/verify, video, regression</text>
  <rect x="30" y="264" width="180" height="46" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="120" y="284" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px; font-weight:600">Review</text>
  <text x="120" y="301" text-anchor="middle" style="fill: var(--color-fg-soft); font-family: var(--font-sans); font-size:11px">AI first, human last</text>
  <rect x="30" y="110" width="180" height="46" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
  <text x="120" y="130" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px; font-weight:600">Review mining</text>
  <text x="120" y="147" text-anchor="middle" style="fill: var(--color-fg-soft); font-family: var(--font-sans); font-size:11px">weekly, pushes rules down</text>
  <rect x="250" y="180" width="180" height="60" rx="8" style="fill: color-mix(in srgb, var(--color-accent) 14%, var(--color-bg)); stroke: var(--color-accent)"/>
  <text x="340" y="206" text-anchor="middle" style="fill: var(--color-fg); font-family: var(--font-sans); font-size:13px; font-weight:600">The codebase</text>
  <text x="340" y="224" text-anchor="middle" style="fill: var(--color-fg-soft); font-family: var(--font-sans); font-size:11px">cleaned 1% a day</text>
  <line x1="432" y1="50" x2="520" y2="106" style="stroke: var(--color-muted)" marker-end="url(#ahS)"/>
  <line x1="560" y1="158" x2="560" y2="260" style="stroke: var(--color-muted)" marker-end="url(#ahS)"/>
  <line x1="520" y1="312" x2="434" y2="368" style="stroke: var(--color-muted)" marker-end="url(#ahS)"/>
  <line x1="248" y1="370" x2="162" y2="314" style="stroke: var(--color-muted)" marker-end="url(#ahS)"/>
  <line x1="120" y1="262" x2="120" y2="160" style="stroke: var(--color-muted)" marker-end="url(#ahS)"/>
  <line x1="160" y1="108" x2="246" y2="52" style="stroke: var(--color-muted)" marker-end="url(#ahS)"/>
</svg>
<p class="viz__caption">Each part's output is the next part's input. The loop closes when review findings come back as better instructions and rules.</p>
</div>

# 🔁 How the pieces feed each other

This is the part a single tool cannot give you. A few of the arrows, concretely:

- **Review feeds the rules.** A comment you leave three times becomes a lint rule or a skill change through review mining. Next month nobody leaves it, human or bot.
- **Rules feed the agent.** A lint error is the most precise prompt an agent ever gets. With hooks, it reads it seconds after the edit and fixes it before anyone sees the code.
- **Refactoring feeds everything.** A codebase with one string API instead of two forces the agent to guess less. Fewer wrong guesses mean fewer corrections, fewer review comments and better results from every skill.
- **Guardrails protect the refactoring.** When the migrator finishes moving the codebase off an old API, a lint rule stops new code from bringing it back. Without the rule, the migration is a treadmill.
- **Verification feeds review and QA.** A `/verify` report with "tested" and "not tested" tells the reviewer where to look, and its regression cases tell QA what changed.
- **Good tickets feed the workflow.** A ticket with acceptance criteria is a prompt with a definition of done. The agent plans better, and verification has something to check against.

Every arrow makes the next step a little cheaper. That is where the long-term effect comes from: not from one big jump, but from many small improvements that make each other bigger.

# ❌ What one piece alone gets you

Each part on its own is weaker than it looks, and some of them backfire:

- **Skills alone** rot. Nobody notices a skill that never fires, nobody tests them, and after three months there are forty of them that contradict each other.
- **An AI reviewer alone** adds noise. It leaves the same comments every week, because nothing turns its findings into rules.
- **Agents alone, without guardrails,** produce volume. The review queue grows faster than the team can read, and reviewers start approving instead of reviewing.
- **A migration alone** never ends. New code keeps adding the old pattern as fast as the agent removes it.
- **Testing alone, at the end,** becomes the bottleneck. More code from agents means more for QA to click through, unless testing is part of how the code gets built.

If your team tried AI and saw ten percent, check which of these you built in isolation. It is usually most of them.

# 📈 Why it feels slow at first

The first weeks of building the system feel like overhead. You are writing a CLAUDE.md, turning on lint rules, recording baselines, adding Danger checks, and the agents are not visibly faster yet.

Then the loop closes. The weekly report gets shorter, because last month's rules hold. The agent needs fewer corrections, because the codebase is more consistent. Review is faster, because the PRs are small and the boring comments are gone. Each of those is small. Together, a few months in, they are the difference between "it helps a bit" and a team that ships noticeably more without dropping quality.

It is the [1% rule](/migrate-codebase-with-ai) applied to the whole development process, not only the code.

# 🗺️ The order to build it

You do not need everything on day one. This is the order that has worked for me, with each step making the next one pay off:

1. **Shared instructions.** One short CLAUDE.md in the repo, so every engineer's agent starts from the same map.
2. **The bottom of the guardrails pyramid.** Compiler settings, SwiftFormat, SwiftLint, Danger, and hooks that run them inside the agent's loop.
3. **A fixed workflow.** Ticket, plan, build, verify, small PR, as a skill every agent follows.
4. **Verification.** The agent tests first and reports what it did not check. You test last.
5. **Review and review mining.** AI reviewer on every PR, and a weekly run that turns repeated comments into rules.
6. **Background refactoring.** A bucket of mechanical tasks and an agent per engineer that drains it, protected by the guardrails from step 2.
7. **Measure.** Throughput and quality together: merged PRs, time to merge, review rounds, reverts, regression time.

# 🧑‍🔧 Somebody has to own it

A system needs an owner. Skills need curating, rules need deciding, the weekly report needs reading, the bucket needs filling. If that is everyone's side job, it is nobody's, and the loop quietly stops turning.

In the teams where this works, a staff or platform engineer owns it the way they would own CI: not doing all the work, but making sure the pieces stay connected. Treat AI like platform infrastructure, not like a plugin each engineer configures alone.

# 📌 Summary

- **The problem:** teams adopt AI one piece at a time, a tool here and a few skills there, and get a small, flat gain.
- **The reframe:** AI in a team is a system: instructions, workflow, guardrails, verification, review, review mining and background refactoring.
- **The mechanism:** each part's output improves the next. Review becomes rules, rules guide agents, cleaner code means fewer corrections, and the loop compounds.
- **The cost:** the first weeks feel like overhead. The payoff comes when the loop closes.
- **The owner:** someone has to keep the pieces connected, like CI.

<div class="banner">
  <p class="banner__big">No single piece does miracles. Connected, they compound.</p>
  <p class="banner__sub">Skills, guardrails, workflow, testing, review and refactoring, built as one system. Building this in your team? <a href="https://www.linkedin.com/in/karolpiatek/">Get in touch</a>.</p>
</div>
