# Repository Guidelines

## Project Structure & Module Organization

- `__init__.py`: Binary Ninja plugin shim (registers architectures/commands when loaded by Binary Ninja).
- `src/m68k/m68k.py`: core Architecture + lifter (LLIL generation).
- `src/m68k/m68k_disasm.py` / `src/m68k/m68k_ops.py`: instruction decoding and operand helpers.
- `plugin.json`: Plugin Manager metadata.
- `src/m68k/test.py`: regression case data for unit tests (disassembly + LLIL expectations).
- `binja-esr/`: newer, more fully-tooled variant; follow `binja-esr/AGENTS.md` when contributing there.

## Build, Test, and Development Commands

Tooling: use `uv` for dependency management and running commands.

- Install dev deps: `uv sync --extra dev`
- Lint: `uv run ruff check .`
- Unit tests (uses mocks, no Binary Ninja required): `uv run pytest`
- Optional plugin init debug prints: `M68K_DEBUG=1`

- Load locally: place this folder in your Binary Ninja plugins directory and restart Binary Ninja.
- Syntax-only check (no Binary Ninja required): `python3 -m compileall .`

## Coding Style & Naming Conventions

- Python 3, 4-space indentation; keep changes small and readable.
- Prefer type hints where practical (matches the existing `m68k.py` style).
- Naming: `snake_case` for functions/variables, `CamelCase` for classes, `UPPER_SNAKE_CASE` for constants.
- Prefer plain `print(...)` for lightweight diagnostics; avoid importing `binaryninja.log` at import time so unit tests (and mocks) stay simple.

## Testing Guidelines

- Add/adjust cases in `src/m68k/test.py` when changing decode or lifting behavior.
- Tests validate both disassembly output (string) and lifted LLIL (structural `MockLLIL` trees).
- For mock-based tests, use the shared helper dependency (`binja-test-mocks` / “binja-test-helpers”) instead of duplicating Binary Ninja API stubs in this repo; if an API surface is missing, expand it upstream and bump the dependency.

## Commit & Pull Request Guidelines

- Commits use short, imperative summaries (e.g., “Fix TST flags”, “Add tests for calling functions”).
- PRs should include: what instructions/flags changed, how to reproduce, and confirmation that `uv run pytest` passes (or why it cannot).
- Open PRs against `mblsha/binaryninja-m68k` (this fork) unless explicitly coordinating with upstream; with GitHub CLI use `gh pr create --repo mblsha/binaryninja-m68k ...` to avoid targeting `galenbwill/binaryninja-m68k` by default.

## CI & Git Tips

- Watch required checks (use `--watch`; there is no `--wait`): `gh pr checks <number> --watch --interval 5 --required` (add `--fail-fast` if desired).
- Continue a rebase without an editor prompt: `GIT_EDITOR=true git rebase --continue`
- Scripted interactive rebase todo editing: `GIT_SEQUENCE_EDITOR=true git rebase -i <base>` (keep these env vars per-command; don’t export globally).
