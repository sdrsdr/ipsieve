# AGENTS.md — ipsieve

IPv4 CIDR allowlist check: `compileRanges()` once, `inRanges()` per request. Published to npm as
`ipsieve`, LGPL-3.0. Same conventions as `danmaru`.

## Hard Rules

- **Never add a runtime dependency.** That is the point of the package.
- **Never add `"type": "module"`.** The artifact is CommonJS and consumers `require()` it.
- Never auto-commit, auto-push or publish.
- `src/index.ts` is the only source of truth. `index.js` / `index.d.ts` at the root are build
  output, gitignored.
- **Fail closed.** Anything unparseable is `false` in `inRanges()` and a throw in
  `compileRanges()`. Never "be lenient" with input; leniency is how allowlists admit the wrong
  peer.
- Any change to the public interface means a version bump and a matching README update.

## Rules

- Tabs; compact style, as in danmaru.
- New behaviour needs a test in `src/tests/`. Check that the test fails against a broken build
  (edit `test-build/index.js`, run, restore) before trusting it.
- Keep the README API block byte-accurate against `src/index.ts`.
