---
name: release-new-version
description: Release a new version of mcp-guardrail-proxy and its desktop app. Covers the semver bump, CHANGELOG.md, the signed git tag, the GitHub release, and the downloadable desktop files for macOS and Linux. Use when asked to release, ship, cut, or publish a new version.
---

# Release a new version

A release ships the proxy source and the desktop app under one version. It holds:

- One semver version in `Cargo.toml`, `desktop/Cargo.toml`, `desktop/tauri.conf.json`, and both lockfiles.
- A dated section in `CHANGELOG.md`.
- A signed tag `vX.Y.Z` on `main`.
- A GitHub release with these 8 desktop files, built by `.github/workflows/release.yml`:

| Platform | Files |
| --- | --- |
| macOS arm64, macOS x86_64 | `.dmg` |
| Linux x86_64, Linux arm64 | `.deb`, `.rpm`, `.AppImage` |

Run the scripts from the repository root. Do the steps in order. If a script exits non-zero, stop and go to "When a step fails". A pushed tag and a published release are public, so wait for the user at both approval points.

## 1. Check the repository

Start from a clean checkout at `origin/main`. In a worktree, run `git switch --detach origin/main`.

Run `.claude/skills/release-new-version/scripts/preflight`. It prints the last tag, the current version, and each commit since the tag.

## 2. Choose the version

Read each commit, opening the diff when the subject does not settle it. The highest row that applies sets the bump.

| The release contains | From 1.0.0 | Below 1.0.0 |
| --- | --- | --- |
| A break: a policy file that loaded before fails or changes meaning, an audit field removed or renamed, a CLI flag or subcommand removed | major | minor |
| A new feature, rule, or taint source, or a stricter default policy | minor | minor |
| Only fixes | patch | patch |
| Only docs, tests, or tooling | no release: tell the user and stop | same |

The bump is a judgment on what the commits do, so the type in a commit subject is evidence and not the answer.

## 3. Write the changelog

Run `git switch -c release/vX.Y.Z`.

Edit `CHANGELOG.md` under `## Unreleased`. Group entries under `### Added`, `### Changed`, `### Deprecated`, `### Removed`, `### Fixed`, and `### Security`, and leave out empty groups. Write for someone who runs the proxy: say what changed for them, and skip docs and tooling commits. Every break gets an entry under `### Changed` or `### Removed` that says what to do about it.

## 4. Approval: version and changelog

Show the user the version, why that bump, and the changelog entries. Wait for a yes. A yes covers merging the release PR, pushing the tag, and building the files, and it does not cover publishing.

## 5. Bump and check

1. Run `.claude/skills/release-new-version/scripts/bump-version X.Y.Z`.
2. Run `.claude/skills/release-new-version/scripts/run-checks`. It takes several minutes, so give it a timeout of at least 10 minutes.
3. Run the `verify-taint-invariants` skill, because `Cargo.toml` changed.

## 6. Merge the release commit

1. Commit with the subject `chore(release): vX.Y.Z`. Run `git log -1 --show-signature` and confirm a good signature.
2. Run `git push -u origin release/vX.Y.Z`.
3. Open a PR with the same title. Put the new changelog section in the body.
4. Run `gh pr merge <number> --squash --delete-branch --repo bostonaholic/mcp-guardrail-proxy`.
5. Run `sha="$(gh pr view <number> --json mergeCommit --jq .mergeCommit.oid --repo bostonaholic/mcp-guardrail-proxy)"`, then `git fetch origin main --tags`.

## 7. Draft the release, then push the tag

The workflow attaches files to an existing draft, so the draft comes first.

```sh
.claude/skills/release-new-version/scripts/render-release-notes X.Y.Z > "$TMPDIR/release-notes.md"
gh release create vX.Y.Z --draft --target "$sha" --title vX.Y.Z --notes-file "$TMPDIR/release-notes.md"
git tag -s vX.Y.Z -m "mcp-guardrail-proxy vX.Y.Z" "$sha"
git tag -v vX.Y.Z
git push origin refs/tags/vX.Y.Z
```

`git tag -v` must report a good signature before the push. Never pass `--no-sign`.

## 8. Wait for the build

The workflow takes about 30 minutes, so run this in the background:

```sh
run_id="$(gh run list --workflow release.yml --branch vX.Y.Z --event push --limit 1 --json databaseId --jq '.[0].databaseId')"
gh run watch "$run_id" --exit-status
```

If `run_id` is empty, GitHub has not registered the run yet. Run the first line again.

## 9. Check the files

Check the file list:

```sh
gh release view vX.Y.Z --json assets | .claude/skills/release-new-version/scripts/check-release-assets X.Y.Z
```

On a Mac, check both disk images:

```sh
dir="$(mktemp -d)"
gh release download vX.Y.Z --pattern '*.dmg' --dir "$dir"
.claude/skills/release-new-version/scripts/smoke-test-dmg "$dir/mcp-guardrail-desktop-X.Y.Z-macos-arm64.dmg" X.Y.Z arm64
.claude/skills/release-new-version/scripts/smoke-test-dmg "$dir/mcp-guardrail-desktop-X.Y.Z-macos-x86_64.dmg" X.Y.Z x86_64
```

These checks do not launch the app, and nothing here tests the Linux files beyond their presence. Say so at the approval.

## 10. Approval: publish

Show the user the draft URL from `gh release view vX.Y.Z --json url --jq .url` and the results of step 9. Wait for a yes.

## 11. Publish

```sh
gh release edit vX.Y.Z --draft=false --latest
gh release view vX.Y.Z --json isDraft,isPrerelease,tagName,url,assets --jq '{isDraft, isPrerelease, tagName, url, assets: (.assets | length)}'
```

Expect `isDraft` false, `isPrerelease` false, and 8 assets. Give the user the release URL.

## When a step fails

| Failure | What to do |
| --- | --- |
| `preflight`: last tag does not match the version | A release stopped partway. If the release commit is on `main` with no tag, set `sha` to that commit and resume at step 7. Otherwise ask the user. |
| `bump-version`, `run-checks`, or `verify-taint-invariants` | Nothing is public yet. Fix it on the release branch, or on `main` first if the bug is not in the release commit. |
| A job failed in step 8 on a runner or network error | Run `gh run rerun "$run_id" --failed`, then watch it again. |
| A job failed in step 8 on a real build error, or step 9 fails | Do not move or delete the pushed tag. Run `gh release delete vX.Y.Z --yes`, which removes only the draft. Fix the bug on `main`, move the section for X.Y.Z back under `## Unreleased`, and release the next patch version from step 1. |
| A problem turns up after publishing | Do not delete the release or the tag. Fix it on `main` and release the next patch version. |

`Developer ID` signing is not set up. The macOS files carry an ad hoc signature, and the release notes tell users how to open the app.

## Change the release itself

- The list of files lives in three places, which must agree: the matrix in `.github/workflows/release.yml`, `scripts/check-release-assets`, and the table in `scripts/render-release-notes`.
- A PR that edits the workflow runs all the builds and uploads nothing, so use one to prove a workflow change.
- Run `.claude/skills/release-new-version/scripts/test-scripts` after you edit a script.
