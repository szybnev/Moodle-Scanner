# Changelog

All notable changes to this fork. Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [3.0.1] - 2026-10-18

### Fixed

- Home/login page URLs were treated as directories, sending probes below
  `login/index.php/` and reporting an unknown version. Normalize these entry
  pages to their installation root while retaining subdirectory and port.
  Added end-to-end CLI regressions for root and nested installations.

## [3.0.0] - 2026-10-18

### Fixed

- False-positive developer-file detection from any HTTP 200 on an empty fixture
  path; removed the status-only probe. Exposure checks now require structured
  endpoint evidence and missing-path controls.
- Configuration options (signup, guest login, web-service availability, public
  development manifests) are observations, not vulnerabilities. Generic token
  error codes do not establish service availability.
- Empty/guarded plugin PHP responses no longer prove installation. Require
  component-specific public artifacts and differential controls.
- Contradictory fingerprints no longer select a majority release. RC/final
  twins, single-file hints and modified builds preserve uncertainty.
- Advisory parsing honors exclusive bounds and exclusions, does not widen
  a bare initial release into its entire branch, and does not fill branch gaps
  using an unspecified unsupported-version clause. Old custom data is reparsed
  from source fields when loaded.

### Changed

- **Breaking JSON schema 2.0:** `observations` is separate from `misconfigurations`;
  each check has `kind`. Advisory states are `version_match` or
  `possible_version_match`, always with `evidence_level: version_only`.
  Neither state confirms target exploitability.
- Replaced the misleading lab advisory-count oracle with seeded exposure checks,
  explicit unknowns and a manually reviewed CNA release-range control. The
  previous matrix did not prove that advisory matches were true vulnerabilities.
- Negative controls cover soft-404 HTML, empty 200 responses, redirects,
  documentation markers, unavailable responses and patched/ambiguous versions.

## [2.0.0] - 2026-10-18

First release of the szybnev fork; the single `scanner.py` became the
`moodle_scanner` package. `python scanner.py` keeps working and accepts the
original `--url`, `--update`, `--vuln` and `--scan` flags.

### Fixed

- Tag comparison was lexicographic (`"v5.10.0" < "v5.9.0"`) in the hash update
  and in the per-file skip rules; versions are now parsed numerically with
  beta/rc ordering.
- `--update` never built the hash database when `moodle_hashes.txt` was missing;
  it now builds from scratch.
- Version detection raised `IndexError` when no file hash matched and
  `ValueError` on tags such as `v5.3.0-rc2`; results are now `unknown`,
  `branch`, `ambiguous` or `exact` with confidence and evidence.
- Shipped data stopped at v4.5.0 (hashes, 2024-11-15) and 2024-11-16
  (advisories); data now covers every tag up to v5.3.0 and advisories up to
  2026-10-15.
- The update re-downloaded every file of every tag from raw.githubusercontent
  through the unauthenticated tags API; it now fetches only new tag trees.
- HTTP requests had no timeout; `compare_versions` was defined twice.
- Advisory matching ignored "earlier unsupported versions", mis-split
  "X and Y" fix lists, treated unparsable versions as equal to everything and
  could not express single-release regressions.
- Moodle 5.1+ (`public/` web root) was not fingerprinted.

### Added

- JSON report (`--json`, `-o`) with JSON Schema (`--schema`) and documented
  exit codes 0–6.
- Read-only misconfiguration checks: self-registration, guest login, web
  services, debug display, dataroot, VCS metadata, config backups, developer
  files, installer/upgrade pages.
- Opt-in plugin enumeration from the Moodle plugins directory list.
- Network controls: `--timeout`, `--max-time`, `--rate`, `--concurrency`,
  `--proxy`, `-H`, `--user-agent`, `--insecure`.
- `--update-plugins`, incremental `--vuln` (`--full` to re-read), `--data-dir`,
  `--cache-dir`, optional `GITHUB_TOKEN`.
- Docker lab harness (`lab/`) with five Moodle versions and a generated
  validation matrix; offline pytest suite; Dependabot configuration.

### Changed

- Data files: `moodle_hashes.txt` and `moodle_vulnerabilities.csv` were
  replaced by `moodle_scanner/data/{fingerprints,advisories,plugins}.json`.
  Fingerprints are git blob ids of web-served static files instead of MD5 of
  seven fixed files.
- Dependencies: `requests` and `beautifulsoup4` were replaced by the standard
  library; the only runtime dependency is `truststore` (MIT). Managed with uv.
- Advisories are always matched; `--scan` is accepted but no longer needed.
