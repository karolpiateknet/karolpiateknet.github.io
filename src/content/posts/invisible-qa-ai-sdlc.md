---
title: "Invisible QA: an AI SDLC where testing happens as a side effect"
date: 2026-11-25
tags: ["AI", "testing", "iOS", "process"]
description: "Nobody wants more testing steps. Here is an AI development flow where every step a developer already takes with an agent leaves a test artifact behind, and about 40% of manual regression work moves to the agent."
tldr:
  - "Nobody gets a new testing duty: every step a developer already takes with an agent leaves a test artifact behind."
  - "Every PR gets `/verify` with a recording and an honest \"not tested\" list, and regression cases live in the repo next to the code."
  - "QA runs one skill that tests the release, finds gaps, reviews the code and opens fix PRs for the author."
  - "About 40% of manual regression work moved to the agent."
---

A few days before the release, QA gets a release branch with dozens of merged pull requests and one question: what actually changed? The developer says they "checked it". On which account? Which screens? Nobody knows. The regression checklist is from last quarter, half of it describes screens that no longer exist, and the UI test suite has six tests because writing a seventh means building the whole setup from scratch.

So QA clicks through everything, by hand, every release.

The usual fix is to ask people to do more: write test plans, update the checklist, write UI tests. It never sticks, because it is extra work on top of the real work.

This article is about the opposite. A development flow where nobody gets a new duty, because **every step a developer already takes with an AI agent leaves a test artifact behind**. Testing stops being a phase and becomes a side effect.

# 🔁 The idea in one picture

<div class="viz">
<svg viewBox="0 0 680 410" role="img" aria-label="Six steps of the flow. Each step on the left produces a test artifact on the right." xmlns="http://www.w3.org/2000/svg">
  <defs>
    <marker id="ahQ" markerWidth="9" markerHeight="9" refX="6" refY="3" orient="auto"><path d="M0,0 L6,3 L0,6 Z" style="fill: var(--color-muted)"/></marker>
  </defs>
  <text x="140" y="22" text-anchor="middle" style="fill: var(--color-muted); font-family: var(--font-sans); font-size:12px">what people already do</text>
  <text x="500" y="22" text-anchor="middle" style="fill: var(--color-muted); font-family: var(--font-sans); font-size:12px">what it leaves behind</text>
  <g style="font-family: var(--font-sans); font-size:14px">
    <rect x="20" y="36" width="240" height="44" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
    <text x="140" y="63" text-anchor="middle" style="fill: var(--color-fg)">Agent builds a screen</text>
    <rect x="370" y="36" width="260" height="44" rx="8" style="fill: color-mix(in srgb, var(--color-accent) 12%, var(--color-bg)); stroke: var(--color-accent)"/>
    <text x="500" y="63" text-anchor="middle" style="fill: var(--color-fg)">Robot + accessibility IDs</text>
    <rect x="20" y="98" width="240" height="44" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
    <text x="140" y="125" text-anchor="middle" style="fill: var(--color-fg)">Agent runs /verify</text>
    <rect x="370" y="98" width="260" height="44" rx="8" style="fill: color-mix(in srgb, var(--color-accent) 12%, var(--color-bg)); stroke: var(--color-accent)"/>
    <text x="500" y="125" text-anchor="middle" style="fill: var(--color-fg)">Tested / not tested + account</text>
    <rect x="20" y="160" width="240" height="44" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
    <text x="140" y="187" text-anchor="middle" style="fill: var(--color-fg)">Agent finishes the feature</text>
    <rect x="370" y="160" width="260" height="44" rx="8" style="fill: color-mix(in srgb, var(--color-accent) 12%, var(--color-bg)); stroke: var(--color-accent)"/>
    <text x="500" y="187" text-anchor="middle" style="fill: var(--color-fg)">Regression cases in the repo</text>
    <rect x="20" y="222" width="240" height="44" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
    <text x="140" y="249" text-anchor="middle" style="fill: var(--color-fg)">AI bot reviews the PR</text>
    <rect x="370" y="222" width="260" height="44" rx="8" style="fill: color-mix(in srgb, var(--color-accent) 12%, var(--color-bg)); stroke: var(--color-accent)"/>
    <text x="500" y="249" text-anchor="middle" style="fill: var(--color-fg)">"What to test" comment</text>
    <rect x="20" y="284" width="240" height="44" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line)"/>
    <text x="140" y="311" text-anchor="middle" style="fill: var(--color-fg)">QA runs the regression skill</text>
    <rect x="370" y="284" width="260" height="44" rx="8" style="fill: color-mix(in srgb, var(--color-accent) 12%, var(--color-bg)); stroke: var(--color-accent)"/>
    <text x="500" y="311" text-anchor="middle" style="fill: var(--color-fg)">Report, gaps, updated cases</text>
    <rect x="20" y="346" width="240" height="44" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-line); stroke-dasharray:4 4"/>
    <text x="140" y="373" text-anchor="middle" style="fill: var(--color-muted)">Someone needs a UI test</text>
    <rect x="370" y="346" width="260" height="44" rx="8" style="fill: var(--color-code-bg); stroke: var(--color-accent); stroke-dasharray:4 4"/>
    <text x="500" y="373" text-anchor="middle" style="fill: var(--color-muted)">Case + robots + account = test</text>
  </g>
  <line x1="262" y1="58" x2="366" y2="58" style="stroke: var(--color-muted)" marker-end="url(#ahQ)"/>
  <line x1="262" y1="120" x2="366" y2="120" style="stroke: var(--color-muted)" marker-end="url(#ahQ)"/>
  <line x1="262" y1="182" x2="366" y2="182" style="stroke: var(--color-muted)" marker-end="url(#ahQ)"/>
  <line x1="262" y1="244" x2="366" y2="244" style="stroke: var(--color-muted)" marker-end="url(#ahQ)"/>
  <line x1="262" y1="306" x2="366" y2="306" style="stroke: var(--color-muted)" marker-end="url(#ahQ)"/>
  <line x1="262" y1="368" x2="366" y2="368" style="stroke: var(--color-muted); stroke-dasharray:4 4" marker-end="url(#ahQ)"/>
</svg>
<p class="viz__caption">Nobody on the left got a new task. Everything on the right is produced by steps that were happening anyway.</p></div>

Each artifact feeds the next one. The robot makes the UI test cheap. The `/verify` comment makes the developer's testing reproducible. The regression case tells QA and the agent what "working" means. The PR comment tells the regression run where to look. Let's go through it piece by piece, starting with the part everything else depends on.

# 🧪 The foundation: clean accounts on demand

An agent cannot test a change reliably if it has to reuse whatever account happens to be logged in on the simulator. Neither can QA reproduce what the developer saw if the developer tested on "my account, the one with weird data from last month".

So the first thing to build is not a skill or a prompt. It is a set of **test-only backend endpoints that create a fresh account in a known state**:

```
POST /test/accounts
{ "state": "onboarded_cart_one_item", "flags": ["new_cart"] }

→ { "accountId": "t_8f31c2", "login": "...", "password": "..." }
```

A handful of presets covers most flows: new user, onboarded, with a subscription, with an expired card, with a full cart. The agent picks the preset the regression case asks for, creates the account, logs in, and starts from a clean, known state every time.

Three rules make this safe. The endpoints exist only in test environments and are never deployed to production. They sit behind a test-only key, so nobody outside the team can mint accounts. And every account they create is tagged as a test account, so it is easy to clean up and impossible to confuse with real data.

The account is not the only state a test depends on. Feature flags, server config, and third-party services matter too, and a shared staging environment that other teams deploy to all day is the fastest way to get failures that have nothing to do with your change. So QA and the agents get **their own environment**, separate from staging, with predictable data and config. If you want to go one step further, run part of the tests against a mocked backend. They get faster and fully deterministic, and real backend integration stays covered by the runs on the QA environment.

This is the least glamorous part of the whole setup and the most important one. Testability used to be a code style question, the kind I wrote about in [testing navigation on iOS](/testing-navigation-ios). With agents doing the testing, testability becomes infrastructure.

# 🏗️ Build: every screen comes with its robot

When the agent builds a new screen, it also builds the screen's **robot**: a small type that knows how to drive that screen in a UI test, plus the accessibility identifiers the robot relies on. It is the standard robot (or page object) pattern, nothing new. The only new thing is that nobody has to remember to write it.

```swift
struct CartRobot {
    let app: XCUIApplication

    @discardableResult
    func removeItem(at index: Int) -> Self {
        app.cells["cart.item.\(index)"].swipeLeft()
        app.buttons["cart.item.remove"].tap()
        return self
    }

    @discardableResult
    func assertEmptyState() -> Self {
        XCTAssertTrue(app.otherElements["cart.emptyState"].waitForExistence(timeout: 2))
        return self
    }
}
```

What enforces it is boring on purpose: the agent's development skill describes the flow, "a new screen ships with its robot and identifiers" is one of its steps, and `CLAUDE.md` points to the skill. The identifiers should not depend on the agent remembering either, and out of the box no linter checks them. It takes a custom rule: a SwiftLint regex rule or a small script in CI that flags a `Button`, `TextField` or tappable cell in a screen file with no `.accessibilityIdentifier`. A regex will never be perfect, so the AI reviewer checks the same thing on every PR and catches what the rule misses. That is the difference between a guideline and a guardrail ([more on that ladder here](/mine-review-comments-with-ai)).

Layout is a different job. How the screen looks on a small and a large device is covered by **snapshot tests**, which are fast and stable. UI tests and robots are for flows: tapping through screens, checking that the right thing happens. Keeping those two apart keeps the UI test suite small.

# ✅ Verify: the agent tests its own change

`/verify` is a custom skill, and it is not optional. It is built into the command the agent receives for every task, so finishing a task means verifying it.

One detail matters more than any other: **verification runs in a subagent that has none of the context from building the feature.** An agent that just wrote the code "knows" what the code is supposed to do, and it will happily confirm its own understanding, including a wrong one. A fresh subagent gets the sources of truth instead: the Jira ticket, the Figma design, the diff, and the running app. It has no reason to believe the implementation is correct, so it actually checks it against what was asked for. The same rule applies later to the regression run.

What it does:

1. Builds the app and launches it on the iOS simulator.
2. Creates a clean account through the test-account endpoints, if the change needs one.
3. Drives the simulator itself, through the flows the change touches, and records the screen. Claude Code can control the iOS simulator directly: tap, swipe, type, screenshot.
4. Reads the app logs for errors and warnings.
5. Writes down what it tested, what it could not test, and why.

If you want to see how to make sure an agent's tests actually guard something, I wrote about [the controls I put around an agent that tests my own app](/prove-ai-written-tests).

The output goes into the pull request as a comment:

````md
## ✅ Verify

**Build:** Debug, iPhone simulator
**Recording:** `verify-cart.mp4` (attached)
**Account:** `t_8f31c2` (preset `onboarded_cart_one_item`, flag `new_cart`)

### Tested by the agent
- [x] Remove the last item from the cart → empty state shown (screenshot attached)
- [x] Add an item from search → cart badge updates (screenshot attached)
- [x] Logs: no errors, 1 expected warning (image cache miss)

### Not tested, needs a human
- [ ] Apple Pay sheet: not available on the simulator
- [ ] "Cart reminder" push: needs a real device

### Regression cases
| Case     | File                                 | Change         |
|----------|--------------------------------------|----------------|
| CART-012 | `regression/cart/empty-state.md`     | new            |
| CART-007 | `regression/cart/add-from-search.md` | updated step 3 |
````

The recording is what makes the comment believable. A reviewer who doubts a checkbox watches 40 seconds of video instead of checking out the branch. The account line matters just as much. When QA or another developer wants to see what the agent saw, they do not guess. They create the same preset and get the same starting point. And the "not tested" section is the honest part: it is the list of things a human still has to look at. Those are unchecked boxes on purpose, so the reviewer ticks them after checking by hand, and an open box is visible to everyone before merge.

# 📄 Document: regression cases live in the repo

At the end of a feature, the agent writes or updates **regression cases**: short markdown files with preconditions, steps, and an expected result. If you ever wrote acceptance criteria into a ticket ([I have opinions about that](/How-to-save-milions-in-software-development-1)), this is the same idea, just kept next to the code instead of dying in a closed ticket.

```markdown
# CART-012: removing the last item shows the empty state

area: cart
executor: agent        # agent | human
tags: cart, regression

## Preconditions
- Account preset: `onboarded_cart_one_item`
- Feature flag `new_cart` enabled

## Steps
1. Open the Cart tab
2. Swipe left on the only item and tap Remove

## Expected
- The item disappears without a reload
- The empty state with the "Browse products" button is shown
- The cart badge on the tab bar is hidden
```

Why the repo and not a test management tool? Because then the cases change in the same pull request as the feature. When the agent changes the cart, it sees the cart's regression cases right there and updates them, or adds new ones. A checklist in an external tool goes stale the day after it is written. A file next to the code goes stale only if someone ignores it in review.

Cases are grouped by product area, and every case has a stable ID with the area's prefix. The PR comments, the `/verify` output, and the regression report all refer to cases by ID, so "CART-012 failed" means the same thing to the agent, the developer, and QA.

The author of the pull request owns these files. They are markdown, so they do not need a separate review ritual: if the author checked them, that is enough. The `executor` field is the important one. Most cases the agent can run. Some, like a real payment or a push notification, need a human and a device, and the file says so.

# 💬 PR: "what to test" is a comment, not a meeting

The AI bot that already reviews your pull requests (which one does not matter: Cursor, Copilot, Claude, any of them) gets one more instruction: end every review with a **"what to test"** section.

````md
## 🧪 What to test

### Agent can run
- [ ] **CART-012** Removing the last item shows the empty state (`regression/cart/empty-state.md`)
- [ ] **CART-007** Adding an item from search updates the cart badge (`regression/cart/add-from-search.md`)

### Needs a human
- [ ] Apple Pay checkout still opens from the cart (real device)

### Risk
`CartViewModel` now reloads on every appear. Leave and return to the tab twice and check items are not duplicated.
````

The bot sees the diff, the `/verify` comment, and the regression cases, so it can tell what is already covered and point at the part that is risky but not covered. The goal is for the AI to check as much as possible on its own and to be explicit about the cases that are human only.

# 🔍 Regression: QA runs one skill

This is where the artifacts pay off. Before a release, QA runs the regression skill. Its input is just the release branch:

```
Run regression for the release branch.
1. Compare the release branch with main and list every merged PR.
2. For each PR, read the "What to test" comment, the /verify comment,
   and the regression cases it added or changed.
3. Run every case with executor: agent on the iOS simulator. Create
   a clean account for each one through the test-account endpoints.
   Record pass or fail with a screenshot.
4. Look for gaps: changed screens or flows with no regression case,
   and cases whose steps no longer match the app. Propose updates.
5. Review the diff for bugs the test plan would miss, with a focus on
   UI state and navigation flows.
6. For every failed case, find the PR that caused it, open a draft fix
   PR against the release branch, and assign that PR's author.
7. Report: passed, failed (with links to the fix PRs), needs a human,
   gaps found.
```

Four things happen in one run.

**The agent tests the changes.** It knows exactly what to test, because every PR told it. It drives the simulator itself and attaches a screenshot to every result, so a "pass" is something you can check, not something you have to trust.

**It looks for what is missing.** A screen changed but no regression case mentions it. A case says "tap Remove" but the button is now in a menu. These come back as proposed updates, and QA fixes outdated cases during the run. The regression suite refreshes itself every release, as a by-product of using it.

**It reviews the code.** Not style, the bot already did that on every PR. This review reads the whole release diff looking for broken UI flows: a state that is not reset when you navigate back, a screen reachable from two places that only handles one, an error path with no UI. These are the bugs that slip through a test plan, because nobody wrote a step for them.

**It opens the fixes.** A failed case does not end as a ticket that waits for someone to read it. The agent already knows which case failed, which PR changed that area, and what the screen looked like, so it opens a draft fix PR against the release branch and assigns the author of the PR that broke it. The fix PR goes through the same flow as any other change: `/verify` with a recording, and the failed case as the first thing it checks. The author reviews a ready fix instead of starting from a bug report, the same idea as opening the PR instead of the ticket.

What is left for QA is the part humans are good at: the human-only cases, the real devices, the "this feels wrong" exploration. Not clicking through the same checklist for the fortieth time. The human-only cases show up in the report under "needs a human", and from there they are QA's call: who runs them, on which device, and whether one of them blocks the release.

The fixes do not restart the whole run. The author reviews and tests the fix, and QA retests it depending on how sensitive the area is. A copy change gets a glance; a change in checkout gets a full pass.

<div class="stat-row">
  <div class="stat-card"><div class="stat-card__num">~40%</div><div class="stat-card__label">of manual regression work now run by the agent</div></div>
  <div class="stat-card"><div class="stat-card__num">0</div><div class="stat-card__label">new duties for developers</div></div>
  <div class="stat-card"><div class="stat-card__num">every PR</div><div class="stat-card__label">verified, recorded, with cases for QA</div></div>
</div>

# 🧱 No single layer gives you quality

The regression skill only looks at what the release changed. That is its strength and its blind spot: a change in a shared component or in the backend can break a screen no pull request touched. So the agent-driven regression is one layer, not the whole thing:

- **Smoke tests of critical paths**, run by a human every release: login, onboarding, payment, whatever would hurt most if it broke. They do not depend on the diff.
- **UI tests** for the flows that are already automated.
- **`/verify` and exploratory testing** on every change, by the agent and by people.
- **The regression run** on everything the release changed.

None of these is enough on its own. Together they cover each other's blind spots, and that is where the quality comes from. It is the same reason [AI in a team is a system, not a skill](/ai-is-a-system).

# 🤖 Next: UI tests that almost write themselves

Here is the honest part: nobody writes the UI tests yet. But look at what is already in place for every flow:

- **The scenario:** the regression case, with preconditions, steps, and expected result.
- **The API to drive the screens:** the robots.
- **The starting state:** a test-account preset.
- **The identifiers:** added when the screen was built.

The hard part of writing a UI test was never the test. It was everything around it. With all of that already there, a UI test is a translation of the markdown file into code:

```swift
func test_removingLastItem_showsEmptyState() throws {
    let account = try TestAccounts.create(preset: .onboardedCartOneItem)
    let app = launch(as: account, flags: [.newCart])

    TabBarRobot(app: app).openCart()
    CartRobot(app: app)
        .removeItem(at: 0)
        .assertEmptyState()
}
```

That is a job an agent can do on its own, case by case, the same way it [migrates a codebase 1% a day](/migrate-codebase-with-ai). Pick the regression cases that the agent runs every release and that never change, turn them into UI tests, and the regression run gets shorter again.

How far to take it is a business decision, not a technical one, and the simplest rule is risk: automate the flows that would hurt most if they broke and that break most often. Checkout and login first, a settings toggle maybe never. You could turn every case into a UI test, but UI tests are the slowest and most expensive layer of the pyramid, and CI machines are not free. A team shipping a few changes a month needs far less automation than one merging dozens of pull requests a day. The point of this setup is not to automate everything. It is that when you decide a flow deserves a UI test, writing it is cheap.

# ⚠️ Where it hurts

All the usual UI testing problems are still here. The agent did not remove them, it just runs into them faster:

- **Flakiness.** Animations, timing, slow simulators. An agent that taps too early fails the same way a UI test does. And a red UI test does not always mean the app is broken: the backend may have changed under it. So a failure gets triaged before anyone fixes anything. The agent reads the logs and the network calls, says whether it was the app, the backend or plain flakiness, and assigns the right person. If the backend broke it, the backend engineer owns fixing the test and checking the app.
- **Things a simulator cannot do.** Real payments, push notifications, the camera, some biometric flows. These stay `executor: human`.
- **Trust.** An agent can report a pass it did not earn. That is why every result comes with a screenshot, every `/verify` comes with a recording, and both name the account they used.
- **Rot.** Regression cases go stale if nobody touches them. The regression run catches most of it, but only for the areas a release actually changed.

# 🛠️ Where to start

You do not need all of it on day one. In order, from cheapest to most work:

1. **Make `/verify` write the comment.** Tested, not tested, which account. Even without anything else, this makes developer testing visible and reproducible.
2. **Move regression cases into the repo** and add "update the regression cases" to the agent's development skill.
3. **Build the test-account endpoints.** This is the step that turns "the agent tested it" into "anyone can repeat it".
4. **Add robots and identifiers** to the screen-building step.
5. **Write the regression skill** and hand it to QA.

# 📌 Summary

- **The problem:** testing is a separate phase that depends on people remembering to do extra work, so the checklist rots and QA clicks through the same steps every release.
- **The reframe:** do not add testing steps. Make every step a developer already takes with an agent leave a test artifact behind.
- **The flow:** screens come with robots, `/verify` tests and documents every change, regression cases live in the repo, the PR bot writes "what to test", and QA runs one skill that tests, finds gaps, and reviews the release.
- **The foundation:** endpoints that create clean test accounts on a dedicated QA environment, so every test, human or agent, is reproducible.
- **The guardrail:** verification and regression run in fresh subagents that never saw the build, so the agent does not grade its own homework.
- **The result:** about 40% of manual regression work moved to the agent, and UI tests that are one small step away from writing themselves.

<div class="banner">
  <p class="banner__big">The best testing process is the one nobody notices.</p>
  <p class="banner__sub">Agents write more of the code every month. If testing stays a manual phase at the end, it becomes the bottleneck. Wire it into the steps that already happen, and testing scales with the agents instead of against them. Setting this up in your team? <a href="https://www.linkedin.com/in/karolpiatek/">Get in touch</a>.</p>
</div>
