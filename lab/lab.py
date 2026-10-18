#!/usr/bin/env python3
"""Local Moodle lab for validating moodle-scanner.

Every instance listens on 127.0.0.1 only. Source code comes from the exact git
tag tarball on github.com/moodle/moodle; the database is the official postgres
image; the web tier is moodlehq/moodle-php-apache.

Usage (from the repository root):

    uv run python lab/lab.py up        # download sources, start, install, seed
    uv run python lab/lab.py scan      # scan every instance -> lab/results/*.json
    uv run python lab/lab.py matrix    # write docs/validation-matrix.md
    uv run python lab/lab.py down      # remove containers, volumes, network

Only the stdlib is used so the harness runs without extra dependencies.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

LAB = Path(__file__).resolve().parent
ROOT = LAB.parent
CACHE = LAB / ".cache"
WORK = LAB / ".work"
RESULTS = LAB / "results"
PROJECT = "moodle-scanner-lab"
COMPOSE = WORK / "compose.yaml"
ADMIN_PASS = "Lab-Admin-Pass-1!"

# Settings captured after setup as ground truth for the validation matrix.
TRUTH_SETTINGS = [
    "auth",
    "registerauth",
    "guestloginbutton",
    "enablewebservices",
    "enablemobilewebservice",
    "debug",
    "debugdisplay",
]

SEED_SETTINGS = {
    "selfregistration": {"auth": "email", "registerauth": "email"},
    "guestlogin": {"guestloginbutton": "1"},
    "webservices": {"enablewebservices": "1", "enablemobilewebservice": "1"},
    "debugdisplay": {"debug": "32767", "debugdisplay": "1"},
}

HARDENED_SETTINGS = {
    "registerauth": "",
    "guestloginbutton": "0",
    "enablewebservices": "0",
    "enablemobilewebservice": "0",
    "debug": "0",
    "debugdisplay": "0",
}


def load_instances(names: list[str] | None = None) -> list[dict]:
    instances = json.loads((LAB / "instances.json").read_text())["instances"]
    if names:
        instances = [i for i in instances if i["name"] in names]
    return instances


def run(cmd: list[str], check: bool = True, capture: bool = False, **kw) -> subprocess.CompletedProcess:
    print("+", " ".join(cmd), flush=True)
    return subprocess.run(cmd, check=check, text=True, capture_output=capture, **kw)


def compose(*args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return run(["docker", "compose", "-p", PROJECT, "-f", str(COMPOSE), *args], check=check, capture=capture)


def write_compose(instances: list[dict]) -> None:
    lines = ["name: " + PROJECT, "services:"]
    volumes = []
    for inst in instances:
        name = inst["name"]
        lines += [
            f"  {name}-db:",
            f"    image: postgres:{inst['postgres']}",
            "    environment:",
            "      POSTGRES_USER: moodle",
            "      POSTGRES_PASSWORD: moodle",
            "      POSTGRES_DB: moodle",
            "    volumes:",
            f"      - {name}-pg:/var/lib/postgresql/data",
            f"  {name}:",
            f"    image: moodlehq/moodle-php-apache:{inst['php']}",
            "    depends_on:",
            f"      - {name}-db",
            "    ports:",
            f'      - "127.0.0.1:{inst["port"]}:80"',
            "    environment:",
            "      APACHE_DOCUMENT_ROOT: " + ("/var/www/html/public" if inst["public_dir"] else "/var/www/html"),
            "    volumes:",
            f"      - ./{name}/moodle:/var/www/html",
            f"      - {name}-data:/var/www/moodledata",
        ]
        if inst["hardened"]:
            lines.append(f"      - {LAB / 'apache' / 'hardened.conf'}:/etc/apache2/conf-enabled/zz-hardened.conf:ro")
            lines.append(
                f"      - {LAB / 'apache' / '50-enable-rewrite.sh'}:/docker-entrypoint.d/50-enable-rewrite.sh:ro"
            )
        if "moodledata" in inst["seeds"]:
            lines.append(
                f"      - {LAB / 'apache' / 'exposed-dataroot.conf'}:/etc/apache2/conf-enabled/zz-exposed-dataroot.conf:ro"
            )
        volumes += [f"{name}-pg", f"{name}-data"]
    lines.append("volumes:")
    lines += [f"  {v}: {{}}" for v in volumes]
    COMPOSE.write_text("\n".join(lines) + "\n")


def fetch_source(inst: dict) -> None:
    tag = inst["tag"]
    CACHE.mkdir(parents=True, exist_ok=True)
    tarball = CACHE / f"moodle-{tag}.tar.gz"
    if not tarball.exists():
        url = f"https://github.com/moodle/moodle/archive/refs/tags/{tag}.tar.gz"
        print(f"downloading {url}", flush=True)
        tmp = tarball.with_suffix(".part")
        with urllib.request.urlopen(url, timeout=300) as resp, tmp.open("wb") as out:
            shutil.copyfileobj(resp, out)
        tmp.rename(tarball)
    dest = WORK / inst["name"] / "moodle"
    if dest.exists():
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    staging = WORK / inst["name"] / "staging"
    shutil.rmtree(staging, ignore_errors=True)
    with tarfile.open(tarball) as tf:
        tf.extractall(staging, filter="tar")
    (top,) = list(staging.iterdir())
    top.rename(dest)
    staging.rmdir()


def dexec(inst: dict, *cmd: str, user: str = "www-data", check: bool = True, capture: bool = False):
    return compose("exec", "-T", "-u", user, "-w", "/var/www/html", inst["name"], *cmd, check=check, capture=capture)


def wait_db(inst: dict) -> None:
    for _ in range(120):
        res = compose("exec", "-T", f"{inst['name']}-db", "pg_isready", "-U", "moodle", check=False, capture=True)
        if res.returncode == 0:
            return
        time.sleep(1)
    raise RuntimeError(f"database for {inst['name']} not ready")


def cfg_set(inst: dict, name: str, value: str) -> None:
    dexec(inst, "php", "admin/cli/cfg.php", f"--name={name}", f"--set={value}")


def cfg_get(inst: dict, name: str) -> str:
    res = dexec(inst, "php", "admin/cli/cfg.php", f"--name={name}", capture=True, check=False)
    return res.stdout.strip()


def install(inst: dict) -> None:
    name = inst["name"]
    code = WORK / name / "moodle"
    config_php = code / "config.php"
    wait_db(inst)
    dexec(inst, "chown", "www-data:www-data", "/var/www/moodledata", user="root")
    if not config_php.exists():
        dexec(
            inst,
            "php",
            "admin/cli/install.php",
            "--non-interactive",
            "--agree-license",
            "--lang=en",
            f"--wwwroot=http://127.0.0.1:{inst['port']}",
            "--dataroot=/var/www/moodledata",
            "--dbtype=pgsql",
            f"--dbhost={name}-db",
            "--dbname=moodle",
            "--dbuser=moodle",
            "--dbpass=moodle",
            f"--fullname=Lab {name}",
            f"--shortname={name}",
            "--adminuser=admin",
            f"--adminpass={ADMIN_PASS}",
            "--adminemail=admin@example.invalid",
        )
    install_plugins(inst)
    seed(inst)


def install_plugins(inst: dict) -> None:
    """Install third-party plugins from their GitHub source at a pinned ref."""
    code = WORK / inst["name"] / "moodle"
    docroot = code / "public" if inst["public_dir"] else code
    pending = False
    for plugin in inst.get("plugins", []):
        dest = docroot / plugin["dir"]
        if dest.exists():
            continue
        tarball = CACHE / f"{plugin['component']}-{plugin['ref']}.tar.gz"
        if not tarball.exists():
            url = f"https://github.com/{plugin['repo']}/archive/{plugin['ref']}.tar.gz"
            print(f"downloading {url}", flush=True)
            with urllib.request.urlopen(url, timeout=300) as resp, tarball.open("wb") as out:
                shutil.copyfileobj(resp, out)
        staging = WORK / inst["name"] / f"plugin-{plugin['component']}"
        shutil.rmtree(staging, ignore_errors=True)
        with tarfile.open(tarball) as tf:
            tf.extractall(staging, filter="tar")
        (top,) = list(staging.iterdir())
        top.rename(dest)
        staging.rmdir()
        pending = True
    if pending:
        dexec(inst, "php", "admin/cli/upgrade.php", "--non-interactive")


def seed(inst: dict) -> None:
    name = inst["name"]
    code = WORK / name / "moodle"
    docroot = code / "public" if inst["public_dir"] else code
    if inst["hardened"]:
        for key, value in HARDENED_SETTINGS.items():
            cfg_set(inst, key, value)
    for seed_name in inst["seeds"]:
        for key, value in SEED_SETTINGS.get(seed_name, {}).items():
            cfg_set(inst, key, value)
    if "git" in inst["seeds"] and not (docroot / ".git").exists():
        run(["git", "init", "-q", str(docroot)])
    if "configbackup" in inst["seeds"]:
        shutil.copyfile(code / "config.php", docroot / "config.php.bak")
    if "moodledata" in inst["seeds"] and not (docroot / "moodledata").is_symlink():
        dexec(inst, "ln", "-s", "/var/www/moodledata", "/var/www/html/moodledata", user="root")
    dexec(inst, "php", "admin/cli/purge_caches.php")
    compose("restart", name)
    truth = {key: cfg_get(inst, key) for key in TRUTH_SETTINGS}
    truth["tag"] = inst["tag"]
    truth["seeds"] = inst["seeds"]
    truth["hardened"] = inst["hardened"]
    truth["plugins"] = [p["component"] for p in inst.get("plugins", [])]
    (WORK / name / "truth.json").write_text(json.dumps(truth, indent=2, sort_keys=True) + "\n")
    print(f"{name}: ready at http://127.0.0.1:{inst['port']}/", flush=True)


def cmd_up(args) -> None:
    instances = load_instances(args.only)
    WORK.mkdir(parents=True, exist_ok=True)
    with ThreadPoolExecutor(max_workers=len(instances)) as pool:
        list(pool.map(fetch_source, instances))
    write_compose(load_instances())
    compose("up", "-d", *[s for i in instances for s in (f"{i['name']}-db", i["name"])])
    with ThreadPoolExecutor(max_workers=len(instances)) as pool:
        list(pool.map(install, instances))


def cmd_scan(args) -> None:
    RESULTS.mkdir(parents=True, exist_ok=True)
    for inst in load_instances(args.only):
        out = RESULTS / f"{inst['name']}.json"
        cmd = [
            "uv",
            "run",
            "moodle-scanner",
            "--url",
            f"http://127.0.0.1:{inst['port']}/",
            "--json",
            "-o",
            str(out),
            "--plugins",
            "--plugins-limit",
            "0",
            "--concurrency",
            "8",
        ]
        res = run(cmd, check=False, capture=True, cwd=ROOT)
        print(f"{inst['name']}: exit {res.returncode}", flush=True)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        truth = WORK / inst["name"] / "truth.json"
        if truth.exists():
            shutil.copyfile(truth, RESULTS / f"{inst['name']}.truth.json")
        (RESULTS / f"{inst['name']}.exit").write_text(f"{res.returncode}\n")


def cmd_matrix(args) -> None:
    sys.path.insert(0, str(LAB))
    from matrix import build_matrix  # noqa: PLC0415 - lab-local helper

    text = build_matrix(load_instances(), RESULTS)
    out = ROOT / "docs" / "validation-matrix.md"
    out.write_text(text)
    print(f"wrote {out}")
    if "Validation: **FAIL**" in text:
        raise SystemExit("lab validation failed; inspect docs/validation-matrix.md")


def cmd_down(args) -> None:
    if COMPOSE.exists():
        compose("down", "-v", "--remove-orphans", check=False)
    if args.purge:
        shutil.rmtree(WORK, ignore_errors=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    for name in ("up", "scan"):
        p = sub.add_parser(name)
        p.add_argument("--only", nargs="*", help="instance names (default: all)")
    sub.add_parser("matrix")
    p = sub.add_parser("down")
    p.add_argument("--purge", action="store_true", help="also delete extracted sources in lab/.work")
    args = parser.parse_args()
    os.chdir(ROOT)
    {"up": cmd_up, "scan": cmd_scan, "matrix": cmd_matrix, "down": cmd_down}[args.command](args)


if __name__ == "__main__":
    main()
