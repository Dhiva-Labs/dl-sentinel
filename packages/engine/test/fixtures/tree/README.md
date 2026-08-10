# Discovery fixture tree

A small, stable directory used by the engine's discovery tests. Every file here is text,
tiny, and free of anything that looks like a real credential.

Layout notes the tests depend on:

- `.hidden.txt` — dotfiles must be discovered, never skipped.
- `config/sample.env` — env files are prime scan targets.
- `build/generated.txt` — matched by `DEFAULT_EXCLUDES`, so it must never be discovered.
- `src/nested/deep/deep.ts` — exercises nested include/exclude patterns.

Cases that cannot live in git (symlinks, binaries, oversized files, `node_modules`) are
created at test runtime in a temporary directory instead.
