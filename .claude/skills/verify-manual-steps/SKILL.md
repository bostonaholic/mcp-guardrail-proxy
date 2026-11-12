---
name: verify-manual-steps
description: Perform a pull request's manual verification yourself instead of leaving it for a person. Covers pre-merge checkboxes, "How to Verify" bullets that admit a step was not run, and any step that says to try something in the built desktop app window. Drives the app window by process id through the macOS Accessibility API in a sandbox HOME, checks files, logs, and Notification Center from the shell, and checks off a PR item only on observed evidence. Use when a PR, plan, or design has a manual or pre-merge step, or when asked to verify a PR by hand.
---

# Verify the manual steps yourself

A manual step is a check that nobody has automated yet. Run it, observe the result, and record what you saw. Hand a step back to a person only when the "Drivers" table has no row for it.

Run the scripts from the root of the checkout under test. `D` below means `.claude/skills/verify-manual-steps/scripts/desktop-app`.

## 1. List the steps

Run `.claude/skills/verify-manual-steps/scripts/list-manual-items <pr>`. It prints each checkbox item and each verification bullet that admits a gap, such as "not run", "could not", "nobody", or "mocked".

Split each item into checks. A check has one action and one observable outcome. For example, "Try a folder, a relative path, and a `~` path, and see each refused with the previous path kept" is three checks. Each of the three has two outcomes: the error in the window, and `settings.json` unchanged.

Write the checks to `$TMPDIR/manual-checks.md` as a table with these columns: id, action, expected, driver, and result. Fill in the result column as you go, so that losing your context does not lose the pass.

## 2. Pick a driver for each check

| The check needs | Driver |
| --- | --- |
| Proxy behavior, a CLI exit code, an audit line | The shell. Run the proxy, then read its output and the log. |
| A field, button, checkbox, banner, or text in the window | `D ui get`, `D ui set`, `D ui press`. See step 4. |
| How the window looks | `D shot OUT`, then read the PNG. |
| A file the app writes | `D settings`, or read the file. Read it after every save. |
| A relaunch | `D quit`, then `D launch`. |
| A launch-time variable | `D launch --env-log PATH`. |
| A blocked call reaching the app | `D block PATH`, then wait 2 seconds for one poll. |
| A macOS notification sent or held back | `D notified-since <unix-seconds>`. See "Notifications". |
| A corrupt settings file | `D quit`, `D corrupt-settings`, then `D launch`. |
| A client config that the app reads or writes | The shell. Write and read it under the sandbox `home` from `D paths`. Put the binary at `$home/.cargo/bin/mcp-guardrail-proxy`. The tab reads its `PATH` from a login shell, so put sandbox `PATH` entries in `$home/.zprofile`. On macOS, `/etc/zprofile` moves the folders of `/etc/paths` ahead of each `$home/.zshenv` entry. On the Servers tab, the row checkboxes are `#wrap-row-<index>`, and the buttons are `#servers-wrap` and `#servers-scan`. |
| A Linux build or run | No driver. Report the check as not covered. |
| A code path traced but not reproduced | Write a reproducer as a test or a shell script, run it, and report the result. |

When a step names both what the user sees and what the app did, check both: the window, then the file or log.

## 3. Build and sandbox the app

1. Check out the PR head. In a worktree, run `git switch --detach <head-sha>`.
2. Run `D build`. A first build takes about 10 minutes, so run it in the background. It also compiles `ax-driver.swift`.
3. Run `D paths` and note the sandbox `settings.json` and the default log path.

Every launch sets `HOME` to the sandbox, so the user's real `settings.json` and audit log are never touched. The harness finds the app by the pid it started, so a copy of the app that the user already runs does not get in the way.

## 4. Drive the window

`D launch` starts the app and waits until the page loads. On some launches the page never loads and the window stays blank. The harness then relaunches once by itself.

`D ui` takes these selectors:

- `#id` selects the element with that HTML id, in either window. Read `desktop/ui/index.html` (the dashboard) and `desktop/ui/settings.html` (the Settings window) for the ids.
- `AXRole:Title` selects an element that has no id, such as the update mode button `AXCheckBox:Notify`.

| Command | Does |
| --- | --- |
| `D ui get SEL` | Prints JSON with these keys: `found`, `enabled`, `value` (a field's text, or `0` or `1` for a checkbox), and `text` (the visible text). |
| `D ui set SEL TEXT` | Replaces a text field's value. It fails on a disabled field. |
| `D ui press SEL` | Clicks a button or checkbox, or opens a `<details>` summary. |
| `D ui dump` | Prints the whole element tree. Use it when a selector does not match. |

An element hidden with the HTML `hidden` attribute reports `"found": false`. So a banner that is not shown reads as `found: false`, and a banner that is shown reads as `found: true` with its message in `text`.

The Settings window does not exist at launch. Run `D ui press "#open-settings"` to open it on the General tab, then `D ui press "#tab-updates"` for the Updates tab, or `D ui press "#tab-servers"` for the Servers tab. The first `D ui get` after the window opens can print `"found": false`, so run it again before you count it as a fail. Closing the window only hides it. While the Settings window is open, `D shot` saves it, because it is the front window of the app.

The driver uses the Accessibility API and events sent to the app's pid. It does not move the mouse, take the keyboard, or bring the window to the front. The window does still appear on the user's screen. The host process needs Accessibility permission, and `D shot` also needs Screen Recording permission. If either is missing, the command exits 2 and names the setting, so tell the user.

### Notifications

macOS records each alert that it shows in Notification Center. To check the notifications switch:

1. Run `t=$(date +%s)`, then `D block <watched-log>`, then wait 3 seconds.
2. Run `D notified-since $t`. With the switch on, the count must be 1. With the switch off, it must be 0, and `#stat-blocked` must still go up by one.

`notified-since` reads only this app's rows in the Notification Center database, and it opens the database read-only. A count of 0 with the switch on means the alert was not shown. Check `D paths` for the stderr log and look for `notification failed` or `granted=false` in it.

## 5. Record and report

A check passes only when you observed its expected outcome on the PR head commit. A check you could not drive is "not covered", never "pass". Write the reason in the result column.

When every check of a checkbox item passes, run:

```sh
.claude/skills/verify-manual-steps/scripts/check-item <pr> "<text in the item>" "<date> at <short-sha>: <checks run, what you saw>"
```

It checks the box and adds an evidence line under it. If any check of the item failed or was not covered, leave the box open and list those checks for the user. For a gap bullet, report the result to the user and let them decide whether to edit the bullet.

To put PNGs in the PR, use the `attaching-pr-screenshots` skill when the user asks for it.

## 6. Clean up

1. Run `D reset`. It quits the app and deletes the sandbox.
2. Remove any worktree you added for the PR head.

## When a step fails

- `D launch` says the page did not load after 2 launches. Read the stderr log that it names. Then run `D ui dump`. A window with an `AXGroup` but no `AXWebArea` means the page never loaded.
- `D ui press` changes nothing. Run `D ui dump` and check that the selector matches the element you meant.
- `D shot` wrote nothing. The host lacks Screen Recording permission. Cite `D ui get` output instead, and tell the user.
- A check fails. Stop that item and keep its box open. Report the action, the expected outcome, and what you saw.
