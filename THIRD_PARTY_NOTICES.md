# Third-party notices

moodle-scanner is licensed under BSD-3-Clause (see [LICENSE](LICENSE)). This file
lists everything it depends on or redistributes, with licenses. All entries are
permissive; none is GPL, AGPL, LGPL, SSPL, PolyForm or Commons Clause.

## Runtime dependencies (installed with the package)

| Package | Version (uv.lock) | License |
|---|---|---|
| truststore | 0.10.5 | MIT |

Everything else at runtime is the Python standard library (PSF-2.0).

### truststore — MIT

```
The MIT License (MIT)

Copyright (c) 2022 Seth Michael Larson

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

## Development and build tools (not redistributed)

| Package | Version | License |
|---|---|---|
| pytest | 9.1.1 | MIT |
| jsonschema | 4.26.0 | MIT |
| jsonschema-specifications | 2025.9.1 | MIT |
| referencing | 0.37.0 | MIT |
| rpds-py | 2026.9.1 / 0.30.0 | MIT |
| attrs | 26.1.0 | MIT |
| iniconfig | 2.3.1 | MIT |
| pluggy | 1.7.0 | MIT |
| packaging | 26.3 | Apache-2.0 OR BSD-2-Clause |
| Pygments | 2.21.0 | BSD-2-Clause |
| colorama (Windows only) | 0.4.6 | BSD-3-Clause |
| exceptiongroup (Python < 3.11) | 1.3.1 | MIT |
| tomli (Python < 3.11) | 2.5.0 | MIT |
| typing-extensions (Python < 3.13) | 4.16.0 | PSF-2.0 |
| ruff | 0.14.0 | MIT |
| uv_build (build backend) | >=0.9,<0.13 | MIT OR Apache-2.0 |

## Bundled data (`moodle_scanner/data/`)

The data files hold facts, not copyrightable source or prose:

| File | Source | What is stored |
|---|---|---|
| `fingerprints.json` | git tags of [moodle/moodle](https://github.com/moodle/moodle) (code is GPL-3.0-or-later) | tag names, URL paths and git blob ids (SHA-1 identifiers) of web-served files. No file content. |
| `advisories.json` | [moodle.org security announcements](https://moodle.org/security/) | advisory id, short title, publication date, severity word, CVE ids, tracker ids, affected/fixed version lists, derived ranges, announcement URL. No description text. |
| `plugins.json` | [Moodle plugins directory API](https://download.moodle.org/api/1.3/pluglist.php) and plugin type directories from moodle/moodle `lib/components.json` / `db/subplugins.json` | plugin component names, version numbers, release names, supported Moodle branches, plugin type directory names. No plugin code. |

## Sources deliberately not used

No code or data from other Moodle scanners is included. The GPL/AGPL scanners
badmoodle and droopescan are excluded entirely; feature ideas common to Moodle
scanners (including moodlescan and nuclei templates, both MIT) were implemented
from public Moodle sources and documentation.

## Lab harness (`lab/`, not part of the package)

The lab downloads Moodle source tarballs (GPL-3.0-or-later), third-party plugin
sources from GitHub (GPL-3.0-or-later) and runs container images
(`moodlehq/moodle-php-apache`, `postgres`) at run time on the developer's
machine. None of these are committed or redistributed.
