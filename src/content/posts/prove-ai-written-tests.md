---
title: "Green is not proof: how I make an AI agent prove its own tests"
date: 2026-11-19
tags: ["AI", "testing", "iOS", "process"]
description: "An agent can write a hundred passing tests in an afternoon. The hard part is knowing which of them would ever fail. Here are the controls that let the agent test first and you test last: a spec the tests must point to, tests that must fail first, and reports that say what was not checked."
tldr:
  - "An agent writes tests faster than anyone can check them, and a green suite says nothing about which tests would ever fail."
  - "Four controls: a spec every test points to, tests that must fail first, a review of the suite itself, and reports that list what was not checked."
  - "Every feature ends with a video of it working, so you watch what the agent tested instead of trusting a green checkmark."
  - "The agent tests first, you test last, starting from its \"not checked\" list. Same flow solo and at work."
---

A test that cannot fail is worse than no test. It tells you a bug is covered when it is not.

My agent fixed a layout bug that only showed up when the screen was scrolled to the bottom. It wrote a UI test, and the test was green. Then, because my rules say so, it put the broken code back and ran the test again. Still green. The test never scrolled.

Without that one extra step, the test would have sat in the suite for years, green on every run, protecting nobody.

It is not a UI test problem. A unit test whose mock returns exactly what the assertion expects is just as green and just as empty.

That is the real problem with AI-written tests. Getting an agent to write tests is easy. It will write a hundred of them in an afternoon, and they will all pass. The hard part is knowing which of them would ever fail.

The examples in this post come from my side project, a small iOS app where an agent writes most of the code and most of the tests, and where I can show real numbers from four days of work on one release. But the flow is not a solo trick. It is how I would want any developer on a team to work: **the agent tests first, and you pick up the phone only after it has finished.**

This post is about the controls that make that order safe, so that "the agent tested it" actually means something.

# 🔁 The flow

Every feature goes through the same steps:

1. **The agent writes the ticket.** A local backlog of markdown tickets with what the feature should do and why.
2. **The agent implements it** and reviews its own changes in a separate pass, with fresh context.
3. **The agent tests it:** unit tests, UI tests, and exploratory testing, where it drives the iOS simulator itself and looks for anything that seems off.
4. **The agent records a video** of the feature working.
5. **I review.** I read the diff where it matters, I watch the video, and I ask what was not checked. The agent fixes what I find.
6. **I test by hand, last.** On a real phone, starting from the agent's "not checked" list.

The agent does the volume. My job is to make sure the volume can be trusted. The rest of this post is the set of controls that make that possible without me checking every test by hand.

# 🧑‍💻 You test last, not first

The order of those steps is the whole point, and it works the same at work as on a side project.

The old habit is to click through the app while you build: run it, tap around, fix, run it again. That is where most of a developer's testing time goes, and most of it is spent on the happy path the agent can check just as well.

Flip it. Let the agent finish the feature and its own testing first: the tests, the exploratory run on the simulator, the video, and the report. Only then do you open the app, and you do not start from zero. You start from the report:

- **The "not checked" list** tells you where your ten minutes on a real device go: the permission dialog, the small iPhone, the push on a locked screen.
- **The video** shows you the flow before you touch it, so you notice the jump or the flicker you would have tapped past.
- **The failures it already fixed** tell you which areas were fragile, and deserve one more look.

On a team, the same report goes into the pull request. The reviewer sees what was tested and what was not, without asking. QA gets a video and a list of gaps instead of "I checked it". Your manual testing does not disappear. It shrinks to the part only a human with a real phone can do.

# 📄 Control 1: a spec the tests must point to

The first version of testing was "the agent writes tests for the new feature". That worked until I asked a simple question: do we have UI tests for everything, so we do not break what users already rely on? Nobody knew, including the agent. There was no list of what the app is supposed to do, so there was nothing to measure coverage against.

So the agent wrote one: one file per feature in `docs/verify/`, each describing expected behavior, with a stable ID for every behavior.

```markdown
# Paywall

## Behavior
| ID    | Behavior                                                   | Check |
|-------|------------------------------------------------------------|-------|
| PAY-4 | The result card shows first and last session values        | UI test |
| PAY-5 | Price and savings badge fit on a small iPhone              | [R: check on a small device] |
| PAY-7 | Purchase and restore work in the StoreKit sandbox          | [R: sandbox account] |

## Files
PaywallView.swift, Store.swift
```

Every test says which behavior it checks:

```swift
// VERIFY: PAY-4
func testResultCardShowsFirstAndLastSession() { ... }
```

A small script, `verify_trace.py`, checks both directions: every behavior has a test or an `[R]` mark that says it is manual, and every test points to a behavior that exists. If the spec and the tests drift apart, the script fails. On top of that sits a `/verify` skill: `/verify` checks the whole app, `/verify paywall` checks one feature, and it always ends with a list of what still needs a human.

This changes what "tested" means. Not "the agent wrote some tests", but "every behavior on this list is either covered by a test or honestly marked as manual".

Four days after the first version:

<div class="stat-row">
  <div class="stat-card"><div class="stat-card__num">15 → 44</div><div class="stat-card__label">UI tests in four days</div></div>
  <div class="stat-card"><div class="stat-card__num">94</div><div class="stat-card__label">behaviors with an ID</div></div>
  <div class="stat-card"><div class="stat-card__num">27</div><div class="stat-card__label">still checked by hand</div></div>
</div>

The last number matters as much as the first two. The spec does not pretend everything is automated. It says exactly what is not.

For a solo app, a table per feature is enough. In a production codebase with a team, I would go one step further: **one file per case**, grouped in a folder per feature.

```
docs/verify/
  paywall/
    PAY-4-result-card-first-and-last-session.md
    PAY-5-price-fits-small-iphone.md
    PAY-7-purchase-and-restore.md
  reminders/
    REM-11-tap-opens-exercise.md
    REM-12-no-reminder-while-app-is-open.md
```

Each file is a full test case: preconditions, steps, and the expected result.

```markdown
# REM-11: tapping a reminder opens the exercise

executor: agent        # agent | human
covered by: ReminderUITests.testTapOpensExercise

## Preconditions
- Fresh install, onboarding finished
- Notifications allowed
- A reminder set for one minute from now

## Steps
1. Send the app to the background
2. Wait for the reminder
3. Tap it

## Expected
- The app opens on the exercise screen, not on the home screen
- The exercise is the one from the reminder
```

Small files are easier to live with than big tables. A pull request that changes one behavior touches one file, so the diff is readable. A removed feature is a removed folder. A QA person or an agent can run a single case without reading the whole feature. And a case written this way is already most of a UI test.

# 🔴 Control 2: a test has to fail first

Back to the test from the beginning. After the agent saw it pass on broken code, it fixed the test so it scrolls to the bottom, confirmed it now fails on the old code and passes on the new one, and turned that into a rule in a `/tdd` skill:

1. Write the behavior into the spec first.
2. Write the test, and watch it fail on the current code.
3. Only then write the fix.

**A new test has to fail at least once on the broken behavior, or it does not count.**

This is the single most valuable rule in the whole setup. It is cheap, the agent can follow it on its own, and it is the only way to tell a test that guards something from a test that just runs.

It also pays off in places you do not expect. One of the UI tests waited for a real notification on the simulator and tapped it, because the spec said that is how a user gets there. That test went red on its first run: the app crashed on launch from a notification. No earlier test opened the app that way, and neither did I, because I always started it from the home screen. It was fixed before the release.

# 🧪 Control 3: review the test suite, not only the app

Control 2 checks one test at a time. This one looks at the suite as a whole. Once per release, the agent gets a separate pass with fresh context and one question: which of these tests could be green for the wrong reason? It checks three things:

- **Can the test see what it checks?** Every element it taps or asserts on is actually reachable.
- **Does each test start clean?** Nothing left over from the test that ran before it.
- **Does it reach the state it claims to test?** Like the test from the beginning that never scrolled.

The most useful findings of the whole week came from this pass, not from testing the app:

**An accessibility identifier hid the buttons.** UI tests find elements by accessibility identifiers. One container view had its own identifier, and it swallowed the identifiers of the buttons inside it. The tests could not see them. This is the classic way UI tests rot: the UI changes, the accessibility tree does not keep up, and the tests either fail for the wrong reason or quietly test less than you think.

**Tests leaked state into each other.** One test turned off a feature, another changed a setting, and those values survived into the next test. The agent's own words in the report: earlier runs could have given false results. Every test now starts from default settings.

Neither of these shows up as a red test. They show up as a green suite you should not trust. That is why reviewing the tests is a step of its own, not something that happens as a side effect of reviewing the code.

# 📋 Control 4: every report says what was not checked

Before a release I asked: "Did you test everything?" The answer started with: "No." Followed by a list of what was covered, and what was not: a notification on a locked phone, the real system permission dialog, an update from the previous version on real data, any screen on a small iPhone.

Every report the agent writes now ends with a "not checked" section. That section is worth more than the list of passed tests, because it tells me exactly where to spend my ten minutes on the device. An agent that only reports successes makes you feel safe. An agent that reports its gaps lets you actually be safe.

# 🎥 Control 5: video as a review

Some bugs are invisible in a diff and in a screenshot. When I adapted the app to a phone with a folding screen, I asked the agent for a video of one screen on the unfolded display. In the video I could see the content jump the moment the first value appeared on a chart. In a screenshot it looked fine. In the code it was one missing fixed height.

A minute of video is now part of every feature review. It does not replace reading the code. It covers what reading the code cannot: how the thing behaves over time.

# 🔍 Control 6: exploratory testing is a step, not a hope

For days, the agent ran only scripted tests. Its memory had a rule not to take over the screen without an explicit request, so it never explored the app on its own. When I asked "did you do exploratory testing on the simulator?", the answer was a plain no.

The first exploratory run found a handful of small UI problems: an ambiguous line of text, truncated navigation titles, two lists showing the same items in a different order. Nothing dramatic, but exactly what a tester would catch. Now exploratory testing is an explicit step in the flow.

It is still not a replacement for a person. Ten minutes after one exploratory run, I found a date that did not show up on the home screen. The agent had looked at that exact screen and reported it as consistent. What happened next is the part I like: it found the cause (a view reading a setting without observing changes), wrote a test that failed before the fix, added the behavior to the spec, and then **searched the rest of the code for the same pattern**. A bug is rarely alone, so look for its siblings.

# 🧑‍✈️ My job: asking the control questions

Reading back through the sessions, my part of the work is mostly questions. A few of them, translated from my own messages:

- "Do we have UI tests for everything, so we do not break what users already do?"
- "Record me a video."
- "Are there unit tests and snapshots? UI tests for the whole release? Did you do exploratory testing on the simulator?"
- "Run /verify on the whole app."
- "Did you test everything?"

Each of those questions later became a rule, a skill or a step in the flow, so I do not have to ask it again. That is the pattern: a question I keep asking is a control I have not automated yet.

# ⚠️ Where it hurts

- **The simulator is not a phone.** System permission dialogs, StoreKit purchases, the share sheet, the lock screen, real update paths: these stay manual. The spec marks them `[R]` so they are not forgotten.
- **"Was it me or the app?"** In one run, a toggle did not switch after two taps. The UI test for the same toggle passed, so the agent decided it was its own missed tap. Probably right, but it is a judgment call a human would also have to make.
- **It tests what you point it at.** UI tests ran only in English until I asked for the second language.
- **It can be confidently wrong.** Once it fixed a real but unrelated problem before it noticed the bug I reported was caused by the test environment, not the app. Every finding needs a "how do you know?".
- **Usage limits.** I hit the limit of my plan twice in the middle of a session. There is no extra bill on a subscription, but there is a ceiling.

# 🏢 From one person to a team

None of the controls above need a team, and none of them stop working in one. Any developer can adopt them on Monday: a spec with IDs, the fail-first rule, a report with a "not checked" section, a video in the PR, and manual testing as the last step instead of the first.

They are also the developer's half of a bigger idea: testing as a side effect of the steps you already take with an agent. `docs/verify` with behavior IDs is a regression suite that lives next to the code. `verify_trace.py` is traceability. The next thing on my list, a `--changed main` flag that maps the diff to affected behaviors, is regression scope.

In a team, the same pieces need more: test accounts on demand, a separate QA environment, a "what to test" comment on every pull request, and a regression skill that QA runs on the release branch. I wrote about that version in [Invisible QA: an AI SDLC where testing happens as a side effect](/invisible-qa-ai-sdlc).

# 📌 Summary

- **The problem:** an agent writes tests faster than anyone can check them, and a green suite says nothing about which tests would ever go red.
- **The order:** the agent tests first, you test last, starting from its "not checked" list. Same flow on a side project and at work.
- **A spec the tests must point to:** a stable ID for every behavior, a tag in every test, a script that keeps them in sync. 94 behaviors, 27 honestly marked as manual.
- **A test has to fail first:** the rule that turned a test checking nothing into one that guards something.
- **Review the suite:** a separate pass looks for tests that are green for the wrong reason, like hidden identifiers and leaking state.
- **Reports list their gaps:** "not checked" tells me where to look on a real device.
- **Video and exploratory runs** cover what the code and the scripted tests cannot.

<div class="banner">
  <p class="banner__big">The agent writes the tests. I make it prove them.</p>
  <p class="banner__sub">Writing tests stopped being the hard part. Knowing which ones would ever fail is the job now, and it is a job you can build controls for.</p>
</div>
