# Releasing

## The GitHub Action tag

`apps/action` is consumed as `uses: Dhiva-Labs/dl-sentinel/apps/action@<tag>`. A `node20`
action must be able to run straight from the checked-out tag, but this repository is a
workspace monorepo whose action entry imports its sibling packages — so a release tag ships a
**self-contained bundle** built with [`ncc`](https://github.com/vercel/ncc).

The bundle is generated, so it is **not** committed on `main` (`apps/action/bundle/` is
gitignored there). It exists only on release tags. That keeps `main` free of build output and
makes it impossible for a stale bundle to sit alongside edited source.

### Cutting a release

```bash
# 1. Start from a clean, green main.
git switch main && git pull
npm ci && npm run build && npm test

# 2. Produce the self-contained bundle (tsc, then ncc).
npm run bundle:action

# 3. Verify it runs with no node_modules present.
tmp=$(mktemp -d) && cp -r apps/action/bundle "$tmp/action" \
  && cp -r tests/fixtures/vulnerable-app "$tmp/target" \
  && GITHUB_WORKSPACE="$tmp/target" INPUT_PATH=. INPUT_SARIF_FILE="$tmp/o.sarif" \
     GITHUB_STEP_SUMMARY="$tmp/s.md" GITHUB_OUTPUT="$tmp/o.txt" GITHUB_EVENT_NAME=push \
     node "$tmp/action/index.js"; echo "exit=$?  # expect 1"

# 4. Commit the bundle on a detached HEAD so it lands on the tag but not on main.
git checkout --detach
git add -f apps/action/bundle
git commit -m "build(action): bundle v0.1.0 for release"
git tag -a v0.1.0 -m "DL Sentinel v0.1.0"
git push origin v0.1.0

# 5. Return to main, which never saw the bundle.
git switch main
```

Consumers then pin `uses: Dhiva-Labs/dl-sentinel/apps/action@v0.1.0`.

### Moving a major alias (optional)

Some workflows prefer `@v0`. Point it at the same commit and force-update it on each release:

```bash
git tag -f v0 v0.1.0 && git push -f origin v0
```

Pinning to the exact tag is the safer recommendation for a tool that reads all of a
repository's source, and is what the documented examples use.

## Version numbers

`TOOL_VERSION` in `packages/core/src/version.ts` is the version the CLI, API, and reports
print. Bump it, and the `version` field of each `package.json`, in the same commit that
precedes the tag.
