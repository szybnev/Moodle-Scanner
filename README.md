# Moodle-Scanner

**TL;DR** — a non-destructive external scanner for Moodle sites. It matches
public files to known release fingerprints, reports version-only advisory
candidates, and checks for directly observable HTTP exposures. It does **not**
confirm exploitability, installed server-side patches, or advisory prerequisites.
Configuration observations are separate from security findings. Output is text
or a JSON report with a JSON Schema and documented exit codes.

Fork of [LuemmelSec/Moodle-Scanner](https://github.com/LuemmelSec/Moodle-Scanner),
rewritten as the `moodle_scanner` package. Licensed BSD-3-Clause: free for any
use, including commercial products and SaaS.

## Who it is for

Security teams and platform operators who need public evidence of Moodle
versions and exposed files. Every request is a `GET` or `HEAD` for a public URL;
no logins, form submissions, account creation or brute force. An advisory match
does not establish that an installation is vulnerable.

## Capabilities

- **Version detection** — hashes web-served JS/CSS/templates as git blob ids
  and compares them with a database built from every moodle/moodle release tag
  (v1.x to the newest 5.x, including the 5.1+ `public/` layout). Adaptive: about
  10–20 requests. Requires independent matching files; conflicting hashes and
  rc/final twins remain ambiguous rather than selecting a majority or final
  release. Falls back to a consistent major.minor public hint, otherwise `unknown`.
- **Advisories** — 733 moodle.org announcements, matched to release candidates.
  Exclusive bounds and explicit exclusions are preserved; unspecified old
  releases and partial qualifications remain uncertain. No match verifies
  authentication requirements, enabled features, backports or exploitability.
- **Exposure checks** — stack traces, reachable dataroot marker, VCS metadata,
  configuration copies containing secret settings (names only, never values),
  publicly served installer/upgrade forms. Positive evidence is checked against
  nonexistent sibling URLs to reject catch-all pages.
- **Configuration observations** — self-registration, guest login, web-service
  availability and public development manifests. These are not vulnerabilities
  by themselves and have informational severity.
- **Plugin enumeration** (opt-in) — requires a component-specific public artifact
  plus negative controls. Empty `version.php` responses and access-guard messages
  alone no longer establish installation.
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
| `-v` / `--verbose` | full text report: all advisory candidates, version evidence and probe details |
| `--schema` | print the report JSON Schema |
| `--no-checks` | skip misconfiguration checks |
| `--plugins [--plugins-limit N]` | enumerate plugins, most recently released first (default 200, `0` = all) |
| `--timeout S`, `--max-time S` | per-request timeout (default 10 s), total budget |
| `--rate R`, `--concurrency N` | requests per second, parallel requests (default 4) |
| `--proxy URL`, `-H 'Name: value'`, `--user-agent UA`, `--insecure` | transport settings |
| `--scan` | accepted for compatibility with the original CLI; advisories are always matched |

Pass the Moodle installation root, including its subdirectory if any
(`https://host/moodle/`). Home (`index.php`) and login (`login/index.php`) page
URLs are also accepted: `https://host/moodle/login/index.php?loginredirect=1`
becomes `https://host/moodle/`. Query strings and fragments are not part of
the scan base. For other application pages, pass the installation root instead.
Redirects are followed only within the target origin.

The default terminal report starts with a short summary, then observed exposures,
configuration observations and unresolved checks. It does not print hundreds of
version-only advisory candidates before the actual findings. `--verbose` expands
all candidates and evidence. `--json` and `-o FILE` always keep the complete report;
the text summary does not filter or change the underlying scan results.
An unresolved check is neither a finding nor proof of safety.

## JSON report

Schema: [`moodle_scanner/schema/scan-result.schema.json`](moodle_scanner/schema/scan-result.schema.json)
(JSON Schema 2020-12, `schema_version` **`2.0`**). This is a breaking correction
to prevent consumers treating observations and version guesses as vulnerabilities.
Top-level fields:

| Field | Content |
|---|---|
| `target` | `url`, `reachable`, `is_moodle`, Moodle `markers` seen |
| `version` | `status` (`exact` / `ambiguous` / `branch` / `unknown`), `version`, `candidates`, `range`, `branch`, `confidence` (`high` / `medium` / `low` / `none`), `method`, per-file `evidence` (path, HTTP status, git blob SHA-1, matched releases), `signals`, `notes` |
| `advisories[]` | MSA/CVE identifiers, advisory severity, `affected` / `excluded` / `fixed`, `match` (`version_match` / `possible_version_match`), `evidence_level: version_only`, reason and source URL |
| `misconfigurations[]` | exposure checks with `kind: finding`, severity, `status` (`detected` / `not_detected` / `inconclusive`), evidence and recommendation |
| `observations[]` | configuration/inventory checks with `kind: observation`, severity `info`, status and evidence; not vulnerabilities |
| `plugins` | `null` unless `--plugins`; `found[]` with component, path, optional `version_hint` |
| `data` | bundled data versions (newest fingerprinted tag, advisory count and date) |
| `errors[]`, `limitations[]` | what failed and what the result cannot tell |
| `requests`, `duration_seconds`, `started_at`, `finished_at`, `exit_code` | run metadata |

Migration from schema 1.0: do not import every advisory or every detected check
as a vulnerability. `affected` / `possibly_affected` were replaced with explicit
version-match states. Signup, guest login, web services and development manifests
moved out of `misconfigurations` into `observations`. `inconclusive` means evidence
was blocked, truncated, redirected, unavailable or also present at a negative-control
URL; it is not a clean bill of health. HTTP 200 alone proves nothing.

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
On loading advisory records, derived ranges are reparsed from the stored source
fields, so an older custom `--data-dir` cannot retain the previous parser's
overbroad ranges. Updating also rewrites those derived fields.

## Limitations

- Static fingerprints identify matches in the bundled database, not installed
  server-side code. Weekly builds, backports and newer releases with identical
  public assets cannot be ruled out. Conflicting or unknown asset hashes downgrade
  confidence; there is no majority-vote selection.
- A release and its last release candidate can serve identical files. Both remain
  candidates with `status: ambiguous` and `version: null`.
- Sites that block or rewrite all static assets yield only a branch (from
  `lib/upgrade.txt` / `UPGRADING.md`) or `unknown`.
- Advisories cover core only. Fifteen older announcements have no parseable
  version list; partial qualifications are not promoted to definite range matches.
  Unlisted/future releases and advisory prerequisites remain unknown.
  For example, [CVE-2025-32044](https://cveawg.mitre.org/api/cve/CVE-2025-32044)
  does not affect sites with `zend.exception_ignore_args=1`, even on an affected
  release. The scanner does not read that server setting.
- Plugins without a component-specific public Markdown artifact or a matching
  Composer manifest (package, plugin type and installer name) remain unconfirmed.
  Missing from `found` does not mean absent. Changelog release headings are only
  hints, never installed-version proof. Plugin advisories are not matched.
  The list is ordered by recent release, not measured popularity.
- A public form does not prove that account creation, guest access to private
  content, installation or upgrade can succeed. No such action is attempted.
- A readable dataroot marker does not prove that individual uploads or sessions
  are downloadable. Negative controls reduce generic-page FPs but cannot rule
  out every proxy rewrite, customized page or stale artifact.
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
