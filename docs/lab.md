# Lab harness

Reproducible local Moodle instances for validating the scanner end to end.
Everything listens on `127.0.0.1` only; nothing external is scanned.

## Instances

Defined in [`lab/instances.json`](../lab/instances.json) (single source of truth;
`lab/lab.py` generates `lab/.work/compose.yaml` from it).

| name | Moodle tag | PHP | PostgreSQL | port | layout | seeded state |
|---|---|---|---|---|---|---|
| m311 | v3.11.8 | 7.4 | 13 | 8311 | classic | every misconfiguration + plugin `mod_customcert` |
| m401 | v4.1.2 (early 4.1 LTS) | 8.0 | 16 | 8401 | classic | self-registration, debug display, exposed `.git` |
| m405 | v4.5.1 (CVE-2025-32044 range) | 8.2 | 16 | 8405 | classic | guest login, web services + mobile, `config.php.bak`, reachable dataroot, plugins `local_staticpage`, `block_xp` |
| m500 | v5.0.2 | 8.3 | 16 | 8500 | classic | Moodle defaults + plugin `mod_attendance` |
| m503 | v5.3.0 (latest) | 8.4 | 17 | 8503 | `public/` web root | hardened negative control |

PHP and PostgreSQL versions follow each release's `admin/environment.xml`
requirements. Images: `moodlehq/moodle-php-apache:<php>` and `postgres:<major>`.
Moodle code is the exact git tag tarball from github.com/moodle/moodle; plugins
are pinned GitHub refs.

Seeds (applied with `admin/cli/cfg.php` or files in the web root):

| seed | how |
|---|---|
| selfregistration | `auth=email`, `registerauth=email` |
| guestlogin | `guestloginbutton=1` (also the Moodle default) |
| webservices | `enablewebservices=1`, `enablemobilewebservice=1` |
| debugdisplay | `debug=32767`, `debugdisplay=1` |
| git | `git init` in the web root |
| configbackup | copy of `config.php` as `config.php.bak` |
| moodledata | symlink `<webroot>/moodledata -> dataroot` plus [`exposed-dataroot.conf`](../lab/apache/exposed-dataroot.conf) so `.htaccess` is ignored (as on nginx) |

The hardened instance switches all of the above off and mounts
[`hardened.conf`](../lab/apache/hardened.conf), which denies dot files,
manifests, upgrade notes, tests and backup extensions, plus
[`50-enable-rewrite.sh`](../lab/apache/50-enable-rewrite.sh), which enables
`mod_rewrite` from the image entrypoint before Apache starts.

After seeding, `lab.py` reads the settings back and writes
`lab/results/<name>.truth.json`; the matrix compares against that, not against
what was intended.

## Running

Requires Docker, `uv`, and network access to GitHub and Docker Hub.

```sh
uv run python lab/lab.py up            # download, start, install, seed (about 8 min first run)
uv run python lab/lab.py scan          # lab/results/<name>.json, .truth.json, .exit
uv run python lab/lab.py matrix        # regenerates docs/validation-matrix.md
uv run python lab/lab.py down --purge  # remove containers, volumes, network and lab/.work
```

`--only m405 m500` limits `up` and `scan` to some instances. `scan` runs the
scanner with `--plugins --plugins-limit 0` (all ~3100 plugins) so plugin
enumeration is validated too.

## Validation

[`validation-matrix.md`](validation-matrix.md) is generated, never edited by
hand. It reports per instance: exact version, advisories reported versus an
independent oracle (`lab/matrix.py`, which reads the raw moodle.org fixed
version lists), each misconfiguration check against the read-back truth,
plugins found versus installed, JSON Schema validity and exit code.

Ports in use, a stuck install, or a failed download: `down --purge` and `up`
again. Container logs: `docker compose -p moodle-scanner-lab -f lab/.work/compose.yaml logs <name>`
(Apache logs go to stdout; reading files under `/var/log/apache2` blocks).

## Public lab

The same instances, without the scanner-specific `scan`/`matrix` steps and with
a scanner-agnostic answer key (`scenarios.json`) and `verify` command, are
published as [szybnev/moodle-vuln-lab](https://github.com/szybnev/moodle-vuln-lab).
Both use ports 8311–8503, so run one at a time.
