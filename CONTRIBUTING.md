# Contributing to RTNP

Thanks for helping. RTNP is a small project, so the process is light.

## Before you start

* Open an issue first for anything bigger than a small fix, so we can agree on the approach.
* Security problems go through [SECURITY.md](SECURITY.md), not a public issue.
* RTNP is developed and tested on Linux. Changes that affect other platforms are welcome but cannot be
  tested by the maintainer, so say what you tried.

## Build and test

```sh
cargo build --release
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

CI runs exactly these on the latest stable Rust, whose clippy is often newer than the one on your machine.
If CI reports a lint you do not see locally, run `rustup update stable` and try again.

The test suite runs entirely on loopback, so it needs no special privileges. Checks that need real hardware
(SCTP, a real link, a SIP PBX) are described in [docs/real-link-tests.md](docs/real-link-tests.md) and are
not part of `cargo test`.

## Guidelines

* Add or update tests for behaviour you change. A bug fix should come with a test that fails without it.
* New features are **off by default** and must not change the output of existing commands.
* Be honest in the docs. If something is an estimate, an untested path or a known limit, say so in the README
  (see "Things to know" and "Not implemented").
* Presets: a preset built from a packet capture must say which capture and be labelled MEASURED. Anything
  else is labelled ESTIMATE. Please do not add presets for specific commercial products without a capture.
* Keep commits focused, with a message that explains why.
* Update `CHANGELOG.md` for anything a user would notice.

## Pull requests

Fill in the template, keep the change small enough to review, and make sure CI is green.
