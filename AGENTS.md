# Repository Guidelines

## Project Structure & Module Organization

- `__init__.py`: Binary Ninja plugin entrypoint (registers architectures and commands).
- `m68k.py`: core Architecture + lifter (LLIL generation).
- `m68k_disasm.py` / `m68k_ops.py`: instruction decoding and operand helpers.
- `plugin.json`: Plugin Manager metadata.
- `test.py`: LLIL regression tests (requires Binary Ninja’s Python API).
- `binja-esr/`: newer, more fully-tooled variant; follow `binja-esr/AGENTS.md` when contributing there.

## Build, Test, and Development Commands

Tooling: use `uv` for dependency management and running commands.

- Install dev deps: `uv sync --extra dev`
- Lint: `uv run ruff check .`
- Unit tests (uses mocks, no Binary Ninja required): `uv run pytest`

- Load locally: place this folder in your Binary Ninja plugins directory and restart Binary Ninja.
- Syntax-only check (no Binary Ninja required): `python3 -m compileall .`
- Run tests inside Binary Ninja’s Python environment:
  - In the Binary Ninja scripting console: `from m68k.test import test_all; assert test_all()`

## Coding Style & Naming Conventions

- Python 3, 4-space indentation; keep changes small and readable.
- Prefer type hints where practical (matches the existing `m68k.py` style).
- Naming: `snake_case` for functions/variables, `CamelCase` for classes, `UPPER_SNAKE_CASE` for constants.
- Use `logging.py` (`log_debug`, `log_info`, …) instead of `print` so output goes to the Binary Ninja log.

## Testing Guidelines

- Add/adjust cases in `test.py` when changing decode or lifting behavior.
- Tests compare LLIL string output; update expected strings only for intentional behavior changes (note the Binary Ninja version if the IL printer changed).
- For mock-based tests, use the shared helper dependency (`binja-test-mocks` / “binja-test-helpers”) instead of duplicating Binary Ninja API stubs in this repo; if an API surface is missing, expand it upstream and bump the dependency.

## Commit & Pull Request Guidelines

- Commits use short, imperative summaries (e.g., “Fix TST flags”, “Add tests for calling functions”).
- PRs should include: what instructions/flags changed, how to reproduce, and confirmation that `test_all()` passes (or why it cannot).

## CI & Git Tips

- Watch required checks (use `--watch`; there is no `--wait`): `gh pr checks <number> --watch --interval 5 --required` (add `--fail-fast` if desired).
- Continue a rebase without an editor prompt: `GIT_EDITOR=true git rebase --continue`
- Scripted interactive rebase todo editing: `GIT_SEQUENCE_EDITOR=true git rebase -i <base>` (keep these env vars per-command; don’t export globally).
