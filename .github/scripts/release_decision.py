#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Decide whether this commit on main is a release, and which version it is.

    release_decision.py decide <kind> <package> <sha> <pathspec>...
    release_decision.py stamp <kind> <version>

kind is pypi, maven, nuget, crates, tag, or swift. package is the registry's
name for the package; tag and swift have no registry, and git tags are the
record.

decide writes release, version, and tag to GITHUB_OUTPUT:

  - VERSION higher than anything published in its M.N: release VERSION. A hand
    edit still sets a version, and a new M.N starts there.
  - Otherwise, a pathspec differs from the last release's tag: release one patch
    above the highest published.
  - Otherwise nothing shipped has changed: no release.

The highest version on the registry or in tags is the counter. A version that is
on the registry with no tag means an earlier run stopped between upload and
release, so decide fails rather than choose a baseline.

stamp writes the version into the manifests in this workspace only. Nothing is
committed, so main is never rewritten and develop and main stay one commit.
"""
import json
import os
import pathlib
import re
import subprocess
import sys
import urllib.error
import urllib.request

AGENT = {"User-Agent": "release-decision (github.com/rcbj)"}
VER = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")


def fetch(url):
    req = urllib.request.Request(url, headers=AGENT)
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.read().decode()
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return None
        raise SystemExit("%s returned %d" % (url, e.code))


def published(kind, package):
    if kind == "pypi":
        body = fetch("https://pypi.org/pypi/%s/json" % package)
        return list(json.loads(body)["releases"]) if body else []
    if kind == "maven":
        group, artifact = package.split(":")
        body = fetch("https://repo1.maven.org/maven2/%s/%s/maven-metadata.xml" % (group.replace(".", "/"), artifact))
        return re.findall(r"<version>([^<]+)", body) if body else []
    if kind == "nuget":
        body = fetch("https://api.nuget.org/v3-flatcontainer/%s/index.json" % package.lower())
        return json.loads(body)["versions"] if body else []
    if kind == "crates":
        body = fetch("https://crates.io/api/v1/crates/%s" % package)
        return [v["num"] for v in json.loads(body)["versions"]] if body else []
    if kind in ("tag", "swift"):
        return []
    raise SystemExit("unknown kind %s" % kind)


def parse(version):
    m = VER.match(version)
    return tuple(int(x) for x in m.groups()) if m else None


def text(version):
    return ".".join(str(x) for x in version)


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True)


def tag_name(kind, version):
    return text(version) if kind == "swift" else "v" + text(version)


def committed():
    raw = pathlib.Path("VERSION").read_text().strip()
    parts = raw.split(".")
    if len(parts) == 2:
        parts.append("0")
    version = parse(".".join(parts))
    if version is None:
        raise SystemExit("VERSION must be M.N or M.N.P; it is %r" % raw)
    return version


def choose(kind, floor, registry, tags, changed):
    """Returns (version or None, why). changed takes a tag name and says whether shipped files differ from it."""
    tagged = {parse(t.lstrip("v")) for t in tags} - {None}
    known = ({parse(v) for v in registry} - {None}) | tagged
    same_line = [v for v in known if v[:2] == floor[:2]]
    if not same_line or floor > max(same_line):
        return floor, "VERSION is ahead of what is published"
    last = max(same_line)
    if last not in tagged:
        raise SystemExit("%s is published with no tag. An earlier run stopped before its release. "
                         "Create it: gh release create %s --target <the commit that uploaded it> --generate-notes"
                         % (text(last), tag_name(kind, last)))
    if not changed(tag_name(kind, last)):
        return None, "nothing shipped has changed since %s" % tag_name(kind, last)
    return (last[0], last[1], last[2] + 1), "shipped files changed since %s" % tag_name(kind, last)


def decide(kind, package, sha, paths):
    tags = git("tag", "--list").stdout.split()

    def changed(tag):
        r = git("diff", "--quiet", tag, sha, "--", *paths)
        if r.returncode not in (0, 1):
            raise SystemExit("git diff against %s failed: %s" % (tag, r.stderr))
        return r.returncode == 1

    version, why = choose(kind, committed(), published(kind, package), tags, changed)
    print(why)
    lines = ["release=%s" % ("true" if version else "false")]
    if version:
        lines += ["version=%s" % text(version), "tag=%s" % tag_name(kind, version)]
        print("Releasing %s." % text(version))
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def rewrite(path, pattern, repl, count=0):
    # newline="" keeps a file's own line endings.
    with open(path, encoding="utf-8", newline="") as fh:
        body = fh.read()
    out, n = re.subn(pattern, repl, body, count=count, flags=re.M)
    if n == 0:
        raise SystemExit("no version found in %s" % path)
    with open(path, "w", encoding="utf-8", newline="") as fh:
        fh.write(out)


def stamp(kind, new):
    if kind == "pypi":
        rewrite("pyproject.toml", r'^version = "[^"]+"', 'version = "%s"' % new, 1)
    elif kind == "maven":
        # The first <version> in this pom is the project's own. It inherits nothing.
        rewrite("library/pom.xml", r"<version>[^<]+</version>", "<version>%s</version>" % new, 1)
    elif kind == "crates":
        name = re.search(r'^name = "([^"]+)"', pathlib.Path("Cargo.toml").read_text(), re.M).group(1)
        rewrite("Cargo.toml", r'^version = "[^"]+"', 'version = "%s"' % new, 1)
        rewrite("Cargo.lock", r'^(name = "%s"\r?\nversion = ")[^"]+"' % re.escape(name), r'\g<1>%s"' % new)
    else:
        raise SystemExit("nothing to stamp for %s" % kind)


def main(argv):
    if len(argv) >= 5 and argv[1] == "decide":
        decide(argv[2], argv[3], argv[4], argv[5:])
    elif len(argv) == 4 and argv[1] == "stamp":
        stamp(argv[2], argv[3])
    else:
        raise SystemExit(__doc__)


if __name__ == "__main__":
    main(sys.argv)
