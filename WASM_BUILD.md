# PoW challenge WASM — provenance & rebuild

The only WebAssembly this server ships is the proof-of-work solver the
challenge gate serves to unverified visitors:

- `static/pow_challenge.js`  — ES-module glue
- `static/pow_challenge.wasm` — compiled solver (calls `glue.solve()`)

## Source

`static/pow_challenge.{js,wasm}` are **build artifacts**, byte-for-byte copies
of `~/projects/portfolio-wasm/pow-challenge/pkg/` (verified by sha256 on
2026-09-04):

```
66beebcb…  static/pow_challenge.js        == pow-challenge/pkg/pow_challenge.js
ce8de7d3…  static/pow_challenge.wasm      == pow-challenge/pkg/pow_challenge_bg.wasm
```

`portfolio-wasm` is a `wasm-bindgen` cdylib crate (the challenge logic reads
`#challenge-data` from the challenge page and POSTs the solution to
`/pow/verify`). It is a **builder repo only**: it is never deployed directly,
and its artifacts are committed into this repo's `static/` so a release build
is self-contained.

## Rebuild

From `~/projects/portfolio-wasm/pow-challenge` (after editing `src/lib.rs`):

```sh
wasm-pack build --target web --release   # or the equivalent wasm-bindgen CLI step
cp pkg/pow_challenge.js  pkg/pow_challenge_bg.wasm \
   <this repo>/static/pow_challenge.js   <this repo>/static/pow_challenge.wasm
```

Release profile is deliberately compact (`opt-level = "z"`, `lto = true`,
`panic = "abort"`, `strip = true`).

## Security invariant — do not gate this behind a session

The challenge wasm must stay on the **public pre-session** path
(`router.rs` Step 0, alongside `/pow/verify` and `/health`). An unverified
visitor has no session cookie and cannot obtain one without solving the
challenge; the solver must therefore be fetchable *before* a session exists.
Moving `static/pow_challenge.*` behind the session gate would deadlock the
gate (the classic chicken-and-egg of a PoW challenge wall).
