# hermit

`hermit` is a small security-focused linter for install scripts and docs. It catches remote download commands that crawl directly into a shell or scripting interpreter, like a hermit crab crawling into a shell.

The primary risk is remote code execution from patterns such as `curl ... | bash` or `wget ... | sh`. These commands execute remote content before a human or CI system has had a chance to inspect it.

## Install

From this repository:

```sh
cargo install --path .
```

For local development:

```sh
cargo run -- .
```

## Usage

Scan the current directory:

```sh
hermit .
```

Scan a specific file or directory:

```sh
hermit Dockerfile
hermit .github/workflows
hermit scripts/install.sh
```

`hermit` exits with status `0` when no findings are found and status `1` when it reports findings.

## What It Scans

`hermit` uses gitignore-aware traversal and checks common places where install commands live:

- Shell scripts: `.sh`, `.bash`, `.zsh`, `.fish`, `.ksh`, `.csh`
- Dockerfiles: `Dockerfile`, `Dockerfile.*`, `*.dockerfile`
- Makefiles: `Makefile`, `makefile`, `GNUmakefile`, `*.mk`
- GitHub Actions workflows under `.github/workflows`
- Markdown shell code blocks labeled `bash`, `sh`, `shell`, `zsh`, `console`, `terminal`, or `dockerfile`

It skips common generated or vendored directories such as `target`, `node_modules`, `.git`, `dist`, `build`, and `vendor`.

## Rules

| Rule ID | Severity | Example | Meaning |
| --- | --- | --- | --- |
| `pipe-to-shell` | Error | `curl https://example.com/install.sh | bash` | Remote content is executed by a shell. |
| `pipe-to-interpreter` | Error | `wget -qO- https://example.com/setup.py | python3` | Remote content is executed by a scripting interpreter. |
| `eval-curl` | Warning | `eval "$(curl https://example.com/setup.sh)"` | `eval` executes downloaded output in the current shell context. |

Safer alternatives generally download to a file first, inspect or verify it, then execute it explicitly.

```sh
curl -fsSLo install.sh https://example.com/install.sh
# inspect install.sh or verify its checksum/signature
bash install.sh
```

## Ignore Directives

Use ignore directives sparingly when a finding is intentional and reviewed.

Ignore the next line:

```text
# hermit: ignore
curl https://example.com/install.sh | bash
```

Ignore a specific rule on the next line:

```text
# hermit: ignore[pipe-to-shell]
curl https://example.com/install.sh | bash
```

Ignore the current line:

```text
curl https://example.com/install.sh | bash  # hermit: ignore
```

In Markdown, use HTML comments:

```md
curl https://example.com/install.sh | bash  <!-- hermit: ignore -->
```

## Why The Name?

`hermit` plays on `curl` going into a `shell`: a hermit crab curls into a shell. The tool exists to catch cases where downloaded remote content is curled straight into a shell before inspection.
