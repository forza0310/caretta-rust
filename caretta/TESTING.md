# Caretta Testing Guide

This document explains the testing layout for the Rust userspace crate and the naming conventions enforced for tests.

## Scope

This guide applies to tests under:

- `caretta/src` (unit tests)
- `caretta/tests` (integration and regression tests)

## Test Layers

1. Unit tests (`#[cfg(test)]` inside source files)
- Focus on pure logic and small units.
- Must avoid external runtime dependencies when possible.
- Example areas: tuple reduction, resolver fallback behavior, state mapping.

2. Integration tests (`caretta/tests/*.rs`)
- Focus on cross-module behavior and regression protection.
- Can assert source-level invariants when behavior is difficult to execute in CI.
- Current regression suite: `review_regressions.rs`.

## Naming Convention

All test names use:

`should_<expected_behavior>_when_<condition>`

Examples:

- `should_map_src_to_client_when_role_is_client`
- `should_return_ip_string_when_dns_cache_is_disabled`
- `should_mark_and_delete_inactive_entries_in_userspace_poll_loop`

Guidelines:

- Keep names behavior-focused, not implementation-focused.
- Include the trigger condition after `when`.
- Avoid abbreviations that reduce readability.

## Comment Convention

Each test should have a short comment above it that states:

- What contract the test protects.
- Which regression it prevents (if applicable).

Keep comments brief and specific.

## Running Tests Locally

From repository root:

```bash
cargo test -p caretta --tests --config 'target."cfg(all())".runner="env"'
```

Why this command:

- The repository uses a runner in `.cargo/config.toml` for runtime commands.
- The `--config` override avoids requiring interactive sudo during CI-style test runs.

## Adding New Tests

Checklist:

1. Place the test in the correct layer (unit vs integration).
2. Use the `should_<...>_when_<...>` naming pattern.
3. Add one concise contract comment above the test.
4. Ensure assertions reflect externally visible behavior.
5. Run the full `caretta` test command before pushing.
