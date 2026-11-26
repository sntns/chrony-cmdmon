# Publishing

Releases go to crates.io with [cargo-release](https://github.com/crate-ci/cargo-release), configured in `Cargo.toml` under `[package.metadata.release]`.

## Prerequisite

The repository secret `CARGO_REGISTRY_TOKEN`: a crates.io token (https://crates.io/settings/tokens) allowed to publish `chrony-cmdmon`.

## Cutting a release

In GitHub: **Actions → Release and Publish → Run workflow**, then pick the level:

- **patch**: bug fixes (0.1.0 → 0.1.1);
- **minor**: new features, or breaking changes before 1.0 (0.1.1 → 0.2.0);
- **major**: breaking changes (0.2.0 → 1.0.0).

The workflow (`.github/workflows/release.yml`):

1. bumps the version in `Cargo.toml`;
2. turns the changelog's `## Unreleased` into `## X.Y.Z - date`, under a new empty `## Unreleased`;
3. publishes the crate to crates.io;
4. commits (`chore: release vX.Y.Z`), tags `vX.Y.Z` and pushes both to `main`.

Before cutting a release, list its changes under `## Unreleased` in `CHANGELOG.md`.

## From a local checkout

```sh
cargo install cargo-release
cargo release patch            # dry run: shows what would happen
cargo release patch --execute  # needs `cargo login` and push rights on main
```

## Installing

```toml
[dependencies]
chrony-cmdmon = "0.1"
```

```sh
cargo install chrony-cmdmon --features cli   # the cmdmon tool
```
