# Moodle-Scanner

**TL;DR** — a non-destructive external scanner for Moodle sites. It identifies
the exact Moodle release from public static files, lists the moodle.org
security advisories (MSA/CVE) that apply to it, and checks for common
read-only-detectable misconfigurations. Output is human-readable text or a
stable JSON report with a JSON Schema and documented exit codes, so it can run
unattended in pipelines.

Fork of [LuemmelSec/Moodle-Scanner](https://github.com/LuemmelSec/Moodle-Scanner),
rewritten as the `moodle_scanner` package. Licensed BSD-3-Clause: free for any
use, including commercial products and SaaS.

## Who it is for

Security teams and platform operators who need to know, without logging in,
which Moodle version a site runs, whether it is patched, and whether it leaks
configuration. It never exploits anything: every request is a `GET` or `HEAD`
for a public URL; no logins, form submissions, account creation or brute force.

## Capabilities

- **Version detection** — hashes web-served JS/CSS/templates as git blob ids
  and compares them with a database built from every moodle/moodle release tag
  (v1.x to the newest 5.x, including the 5.1+ `public/` layout). Adaptive: about
  10–20 requests. Falls back to the major.minor branch from public signals,
  and reports `unknown` instead of failing.
- **Advisories** — 733 moodle.org security announcements with structured
  affected/fixed ranges (including "earlier unsupported versions"); each match
  states why it applies.
- **Misconfiguration checks** — self-registration, guest login, web services
  token endpoint, debug output, reachable dataroot, exposed `.git`/`.svn`/`.hg`,
  `config.php` backups (setting names only, never values), developer/test
  files, reachable installer/upgrade pages.
- **Plugin enumeration** (opt-in) — probes plugins from the Moodle plugins
  directory list; skips components that are core in the detected branch.
- **Operational controls** — per-request timeout, total time budget, rate
  limit, concurrency, proxy, custom headers, user agent, `--insecure`.

## Install and run

Requires Python 3.10+ and [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/szybnev/Moodle-Scanner && cd Moodle-Scanner
uv sync
uv run moodle-scanner --url https://moodle.example.org/
uv run moodle-scanner --url https://moodle.example.org/ --json -o report.json
```

`python scanner.py --url ...` works from a checkout as before (Python 3.10+;
`truststore` is used when installed, otherwise the default certificate store).
Install as a tool: `uv tool install git+https://github.com/szybnev/Moodle-Scanner`.

Common options (full list: `moodle-scanner --help`):

| Option | Purpose |
|---|---|
| `--json` / `-o FILE` | JSON report to stdout / to a file (both allowed) |
| `--schema` | print the report JSON Schema |
| `--no-checks` | skip misconfiguration checks |
| `--plugins [--plugins-limit N]` | enumerate plugins, most recently released first (default 200, `0` = all) |
| `--timeout S`, `--max-time S` | per-request timeout (default 10 s), total budget |
| `--rate R`, `--concurrency N` | requests per second, parallel requests (default 4) |
| `--proxy URL`, `-H 'Name: value'`, `--user-agent UA`, `--insecure` | transport settings |
| `--scan` | accepted for compatibility with the original CLI; advisories are always matched |

Base URLs with a path (`https://host/moodle/`) are supported. Redirects are
followed only within the target origin.

## JSON report

Schema: [`moodle_scanner/schema/scan-result.schema.json`](moodle_scanner/schema/scan-result.schema.json)
(JSON Schema 2020-12, `schema_version` `1.0`; additive changes bump the minor
version). Top-level fields:

| Field | Content |
|---|---|
| `target` | `url`, `reachable`, `is_moodle`, Moodle `markers` seen |
| `version` | `status` (`exact` / `ambiguous` / `branch` / `unknown`), `version`, `candidates`, `range`, `branch`, `confidence` (`high` / `medium` / `low` / `none`), `method`, per-file `evidence` (path, HTTP status, git blob SHA-1, matched releases), `signals`, `notes` |
| `advisories[]` | `id` (MSA), `title`, `cves`, `trackers`, `severity` as published and normalised `severity_level`, `affected` ranges, `fixed`, `match` (`affected` / `possibly_affected`), `reason`, `url` |
| `misconfigurations[]` | every check with `id`, `severity`, `status` (`detected` / `not_detected` / `inconclusive`), `evidence`, `recommendation` |
| `plugins` | `null` unless `--plugins`; `found[]` with component, path, optional `version_hint` |
| `data` | bundled data versions (newest fingerprinted tag, advisory count and date) |
| `errors[]`, `limitations[]` | what failed and what the result cannot tell |
| `requests`, `duration_seconds`, `started_at`, `finished_at`, `exit_code` | run metadata |

## Exit codes

| Code | Meaning |
|---|---|
| 0 | scan completed and the target is Moodle (findings do not change the code); update succeeded |
| 1 | internal error (traceback on stderr) |
| 2 | usage error |
| 3 | target reachable but not identified as Moodle |
| 4 | scan failed (target unreachable) or data update failed |
| 5 | bundled data missing or unreadable |
| 6 | scan completed partially: `--max-time` budget exhausted |

## Updating the data

Data lives in `moodle_scanner/data/` and is committed; refresh it with:

```sh
uv run moodle-scanner --update          # fingerprints from moodle/moodle tags
uv run moodle-scanner --vuln            # advisories from moodle.org (incremental; --full re-reads all)
uv run moodle-scanner --update-plugins  # plugin list from the Moodle plugins directory
```

`--update` keeps a tree-only git mirror of all release tags in
`~/.cache/moodle-scanner/moodle.git` (about 40 MB, needs `git`). It builds the
database from scratch when it is absent, otherwise only when new tags exist
(`--force` rebuilds). Set `GITHUB_TOKEN` to authenticate the fetch. Output is
sorted and deterministic, so data diffs are reviewable. Use `--data-dir` to
write elsewhere.

Only facts are stored: tag names, URL paths and git blob ids; advisory ids,
CVEs, severities, version lists and URLs; plugin component names and versions.
No Moodle source, advisory prose or plugin code is copied.

## Limitations

- Weekly builds (`x.y.z+`) and locally modified files: matching files decide
  by majority and the report notes files with unknown hashes; the result can
  be the neighbouring release.
- A release and its last release candidate usually serve identical files; the
  final release is reported with `medium` confidence and both are candidates.
- Sites that block or rewrite all static assets yield only a branch (from
  `lib/upgrade.txt` / `UPGRADING.md`) or `unknown`.
- Advisories cover Moodle core only. 15 announcements from 2008–2016 have no
  machine-readable version list and are not matched. Advisories published
  after the last `--vuln` refresh are unknown (the report says so when the
  detected version is the newest fingerprinted release).
- Plugins: presence is detected through `version.php`; a version is reported
  only when a changelog/readme names a known release. Plugin advisories are not
  matched (no structured, redistributable source exists). "Most recently
  released first" is a proxy for popularity.
- Misconfiguration checks are heuristics over standard Moodle pages; a reverse
  proxy that rewrites error pages can hide debug output.
- Transport is the Python standard library: HTTP(S) proxies only (no SOCKS),
  one connection per request.

Lab validation against five real Moodle versions:
[docs/validation-matrix.md](docs/validation-matrix.md) (how to reproduce:
[docs/lab.md](docs/lab.md)).

## Development

```sh
uv run pytest           # offline test suite
uv run ruff check . && uv run ruff format --check .
```

Contributor and agent guide: [AGENTS.md](AGENTS.md). Changes: [CHANGELOG.md](CHANGELOG.md).

## License

BSD-3-Clause ([LICENSE](LICENSE)), © LuemmelSec and szybnev. Commercial use,
including inside proprietary products and hosted services, is permitted under
its terms. The only runtime dependency is `truststore` (MIT); all dependencies
and data sources are listed in [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
No code or data from GPL/AGPL projects (for example badmoodle or droopescan)
is included; contributions must keep it that way.
