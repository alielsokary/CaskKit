#!/usr/bin/env python3
"""Safely extract and optionally publish cask icons; see docs/ICON_EXTRACTION.md."""
from __future__ import annotations

import argparse
import hashlib
import json
import plistlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import urlopen

from style_standards import write_json

from app_identities import MANIFEST, merge_extractions, needs_refresh, record_extraction

from icons_state import (  # noqa: F401  (re-exported for curate_icons/tests)
    ICONS_BRANCH,
    REPO_ROOT,
    REPORT_FILE,
    ExtractError,
    _git,
    load_report,
    published_tokens,
    record,
    report_json,
    run,
)

BREW_API = "https://formulae.brew.sh/api/cask.json"
ANALYTICS_API = "https://formulae.brew.sh/api/analytics/cask-install/30d.json"
ICON_SIZE = "256"
MAX_ATTEMPTS = 3
DOWNLOAD_TIMEOUT = 600  # seconds; some vendor artifacts are multi-GB
FLUSH_EVERY = 25  # icons per publish commit - bounds loss if a long CI run dies

TAR_SUFFIXES = (".tar", ".tar.gz", ".tgz", ".tar.bz2", ".tbz", ".tar.xz", ".txz")

# Some vendors 404 curl's default UA on GET (Warp) - mimic what Homebrew
# sends, since every cask URL is served to Homebrew by definition.
DEFAULT_UA = "Homebrew/4.5.0 (Macintosh; arm64 Mac OS X 15) curl/8.7.1"


def app_names_from_artifacts(cask: dict) -> list[str]:
    """`.app` names declared by the cask's `app`/`suite` artifact stanzas."""
    names: list[str] = []
    for artifact in cask.get("artifacts") or []:
        for key in ("app", "suite"):
            for entry in artifact.get(key, []) if isinstance(artifact, dict) else []:
                if isinstance(entry, str):
                    names.append(entry)
                elif isinstance(entry, dict) and isinstance(entry.get("target"), str):
                    names.append(entry["target"])
    return names


def has_pkg_artifact(cask: dict) -> bool:
    return any(
        isinstance(a, dict) and "pkg" in a for a in cask.get("artifacts") or []
    )


def eligibility(cask: dict) -> str | None:
    """None if extractable, else a `no_icon` reason string."""
    # pkg-artifact casks (Zoom, Teams, ...) count as extractable: the installer
    # payload contains the .app, which pkgutil --expand-full exposes without
    # running any scripts.
    if cask.get("deprecated") or cask.get("disabled"):
        return "deprecated/disabled"
    if not cask.get("url"):
        return "no download url"
    if not app_names_from_artifacts(cask) and not has_pkg_artifact(cask):
        return "no app/suite/pkg artifact"
    return None


def container_type(cask: dict, filename: str) -> str | None:
    """Container type - dmg | zip | pkg | tar - from the download filename or `container` hint."""
    name = filename.lower()
    nested = (cask.get("container") or {}).get("type")
    if nested in ("dmg", "zip", "pkg"):
        return nested
    if name.endswith(".dmg"):
        return "dmg"
    if name.endswith(".zip"):
        return "zip"
    if name.endswith((".pkg", ".mpkg")):
        return "pkg"
    if name.endswith(TAR_SUFFIXES):
        return "tar"
    if name.endswith(".app"):  # rare: bare .app download
        return "zip" if name.endswith(".zip") else None
    return None


def sniff_container(artifact: Path) -> str | None:
    """Magic-byte fallback when the URL has no useful extension."""
    # Modern vendors serve .../stable (VS Code), .../osx_arm64 (Postman), .../download
    # (Raycast). Runs on the already-downloaded file, so it's authoritative.
    try:
        size = artifact.stat().st_size
        with artifact.open("rb") as f:
            head = f.read(512)
            f.seek(max(0, size - 512))
            tail = f.read(512)
    except OSError:
        return None
    # Trailer first: UDIF images carry their block-compression's magic at
    # byte 0 (Warp: zlib, Comet: xz, HandBrake: bzip2) - head bytes lie.
    if tail.startswith(b"koly"):  # UDIF trailer: the last 512 bytes of a DMG
        return "dmg"
    if head.startswith(b"PK"):
        return "zip"
    if head.startswith(b"xar!"):
        return "pkg"
    if head.startswith((b"\x1f\x8b", b"BZh", b"\xfd7zXZ\x00")):
        return "tar"  # tar -xf auto-detects the compression
    if head[257:262] == b"ustar":
        return "tar"
    return None


_INSTALLERISH = re.compile(r"\b(install(er)?|uninstall(er)?|updater?|setup)\b", re.IGNORECASE)


def installerish(app_name: str) -> bool:
    """True for installer/updater stub apps - never the icon we want."""
    return bool(_INSTALLERISH.search(app_name.removesuffix(".app")))


def _norm(s: str) -> str:
    return re.sub(r"[^a-z0-9]", "", s.lower())


def token_matches_app(token: str, app_name: str) -> bool:
    """Match cask token to app name - `microsoft-word` ↔ `Microsoft Word.app`."""
    # Containment needs ≥4 chars to avoid one-letter apps (R.app) matching everything.
    nt, na = _norm(token), _norm(app_name.removesuffix(".app"))
    if not nt or not na:
        return False
    if nt == na:
        return True
    return (len(na) >= 4 and na in nt) or (len(nt) >= 4 and nt in na)


def resolve_icns_name(info: dict) -> str | None:
    """Resolve CFBundleIconFile, appending `.icns` when the extension is omitted."""
    name = info.get("CFBundleIconFile")
    if not isinstance(name, str) or not name.strip():
        return None
    name = name.strip()
    return name if name.endswith(".icns") else f"{name}.icns"


def _curl_cmd(cask: dict, dest: Path) -> list[str]:
    """Curl invocation honouring the cask's url_specs (UA, referer, headers, cookies)."""
    cmd = ["curl", "-fSL", "--retry", "2", "--max-time", str(DOWNLOAD_TIMEOUT), "-o", str(dest)]
    specs = cask.get("url_specs") or {}
    cmd += ["-A", str(specs.get("user_agent") or DEFAULT_UA)]
    if specs.get("referer"):
        cmd += ["-e", str(specs["referer"])]
    for header in specs.get("header") or []:
        cmd += ["-H", str(header)]
    if isinstance(specs.get("cookies"), dict):
        cmd += ["-b", "; ".join(f"{k}={v}" for k, v in specs["cookies"].items())]
    return cmd


def _verify_sha256(cask: dict, dest: Path) -> None:
    expected = cask.get("sha256")
    if expected and expected != "no_check":
        hasher = hashlib.sha256()
        with dest.open("rb") as artifact:
            for chunk in iter(lambda: artifact.read(1024 * 1024), b""):
                hasher.update(chunk)
        digest = hasher.hexdigest()
        if digest != expected:
            raise ExtractError(f"sha256 mismatch (got {digest[:12]}...)")


def download(cask: dict, dest_dir: Path) -> Path:
    url = cask["url"]
    filename = Path(urlparse(url).path).name or "artifact"
    dest = dest_dir / filename
    proc = run(_curl_cmd(cask, dest) + [url])
    if proc.returncode != 0 or not dest.exists():
        raise ExtractError(f"download failed: {proc.stderr.strip().splitlines()[-1] if proc.stderr else 'curl error'}")
    _verify_sha256(cask, dest)
    return dest


def _expand_dmg(artifact: Path, workdir: Path, mounts: list[Path]) -> Path:
    mnt = workdir / "mnt"
    # input "Y": auto-accept EULA prompts (24 of batch 3+4's 34 failures
    # were "attach canceled" license DMGs). Read-only mount, nothing runs.
    proc = run(["hdiutil", "attach", "-nobrowse", "-readonly", "-noverify",
                "-mountpoint", str(mnt), str(artifact)], input_text="Y\n")
    if proc.returncode != 0:
        raise ExtractError(f"hdiutil attach failed: {proc.stderr.strip()[:200]}")
    mounts.append(mnt)
    return mnt


def _expand_zip(artifact: Path, out: Path) -> Path:
    proc = run(["ditto", "-xk", str(artifact), str(out)])
    if proc.returncode != 0:
        raise ExtractError(f"ditto failed: {proc.stderr.strip()[:200]}")
    return out


def _expand_pkg(artifact: Path, workdir: Path) -> Path:
    pkg_out = workdir / "pkg"
    proc = run(["pkgutil", "--expand-full", str(artifact), str(pkg_out)])
    if proc.returncode != 0:
        raise ExtractError(f"pkgutil failed: {proc.stderr.strip()[:200]}")
    return pkg_out


def _expand_compressed_stream(artifact: Path, workdir: Path, mounts: list[Path],
                              tar_stderr: str) -> Path:
    """Decompress a bare gzip/bzip2/xz-wrapped payload, sniff the inner file, re-expand."""
    # comet ships an xz-compressed DMG.
    with artifact.open("rb") as f:
        head = f.read(8)
    tool = next((t for magic, t in ((b"\x1f\x8b", "gzip"), (b"BZh", "bzip2"),
                                    (b"\xfd7zXZ\x00", "xz")) if head.startswith(magic)), None)
    if tool is None:
        raise ExtractError(f"tar failed: {tar_stderr.strip()[:200]}")
    inner = workdir / f"{artifact.name}.inner"
    with inner.open("wb") as fh:
        dec = subprocess.run([tool, "-dc", str(artifact)], stdout=fh, check=False,
                             stderr=subprocess.PIPE, stdin=subprocess.DEVNULL)
    if dec.returncode != 0:
        raise ExtractError(f"{tool} -dc failed: {dec.stderr.decode()[:200]}")
    inner_kind = sniff_container(inner)
    if inner_kind in (None, "tar"):  # tar guard: no infinite recursion
        raise ExtractError(f"unrecognized payload inside {tool} stream")
    return expand(inner, inner_kind, workdir / "inner", mounts)


def _expand_tar(artifact: Path, out: Path, workdir: Path, mounts: list[Path]) -> Path:
    proc = run(["tar", "-xf", str(artifact), "-C", str(out)])
    if proc.returncode == 0:
        return out
    return _expand_compressed_stream(artifact, workdir, mounts, proc.stderr)


def expand(artifact: Path, kind: str, workdir: Path, mounts: list[Path]) -> Path:
    """Expand without executing anything. Returns the directory to search."""
    workdir.mkdir(parents=True, exist_ok=True)  # nested calls pass workdir/"nested"
    out = workdir / "expanded"
    out.mkdir(exist_ok=True)
    if kind == "dmg":
        return _expand_dmg(artifact, workdir, mounts)
    if kind == "zip":
        return _expand_zip(artifact, out)
    if kind == "tar":
        return _expand_tar(artifact, out, workdir, mounts)
    if kind == "pkg":
        return _expand_pkg(artifact, workdir)
    raise ExtractError(f"unknown container type for {artifact.name}")


def find_app(root: Path, wanted: list[str], cask_token: str) -> tuple[Path, str] | None:
    """Locate the .app bundle; never follows symlinks (DMGs ship an /Applications symlink)."""
    # Returns (app, selection) where selection is the audit signal:
    # - "exact":          name matches the cask's artifact stanzas - near-certain
    # - "token":          name matches the cask token - near-certain
    # - "single":         only one non-installer .app - unambiguous
    # - "shallowest":     multiple candidates, none matching - human review
    # - "installer_only": every .app is an installer/updater stub - caller
    #                     parks the cask instead of shipping a wrong icon
    exact, found = _collect_apps(root, {w.lower() for w in wanted})
    if exact is not None:
        return exact, "exact"
    if not found:
        return None

    candidates = [a for a in found if not installerish(a.name)]
    if not candidates:
        return found[0], "installer_only"
    return _pick_candidate(candidates, cask_token)


def _collect_apps(root: Path, wanted_lower: set[str]) -> tuple[Path | None, list[Path]]:
    """Walk for .app dirs (max depth 6, symlinks skipped); (exact_hit, all_found)."""
    found: list[Path] = []
    stack = [(root, 0)]
    while stack:
        current, depth = stack.pop()
        if depth > 6:
            continue
        try:
            entries = sorted(current.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.is_symlink() or not entry.is_dir():
                continue
            if entry.name.endswith(".app"):
                if entry.name.lower() in wanted_lower:
                    return entry, found
                found.append(entry)
            else:
                stack.append((entry, depth + 1))
    return None, found


def _pick_candidate(candidates: list[Path], cask_token: str) -> tuple[Path, str]:
    """Rank non-installer candidates: token match, then single, then shallowest."""
    by_token = [a for a in candidates if token_matches_app(cask_token, a.name)]
    if by_token:
        # Exact normalized equality beats containment; then prefer shorter
        # names ("Docker.app" over "Docker Helper.app").
        nt = _norm(cask_token)
        by_token.sort(key=lambda a: (_norm(a.name.removesuffix(".app")) != nt, len(a.name)))
        return by_token[0], "token"
    if len(candidates) == 1:
        return candidates[0], "single"
    return sorted(candidates, key=lambda p: len(p.parts))[0], "shallowest"


def payload_bundle(root: Path) -> Path | None:
    """Handle a pkg whose Payload IS the .app (Tailscale)."""
    # pkgutil strips the bundle's directory name, leaving Payload/Contents/...
    # directly - invisible to find_app's *.app walk. The payload root is what
    # lands in /Applications, so it wins over any helper .apps nested inside it.
    for plist in root.rglob("Payload/Contents/Info.plist"):
        return plist.parents[1]
    return None


def find_nested_archive(root: Path) -> tuple[Path, str] | None:
    """One level of dmg-in-zip style nesting (guided search, spec §Extraction 3)."""
    for pattern, kind in (("*.dmg", "dmg"), ("*.pkg", "pkg"), ("*.zip", "zip")):
        # is_file: an expanded component package is a *directory* named *.pkg
        hits = [p for p in root.rglob(pattern) if p.is_file() and not p.is_symlink()]
        if hits:
            return hits[0], kind
    return None


# argv: <mode> <appPath> <destPng> <size> - mode: bundle | workspace | generic.
# bundle reads the asset catalog directly; workspace asks Icon Services;
# generic renders the system app icon (reference for the wrong-icon guard).
# Swift renderer for asset-catalog-only icons - kept as a real .swift file
# so it gets syntax highlighting and review as code.
_CAR_ICON_SWIFT = (Path(__file__).with_name("car_icon.swift")).read_text(encoding="utf-8")


def car_icon_to_png(app: Path, dest_png: Path) -> str | None:
    """Render an asset-catalog-only icon (Assets.car, no loose .icns) via AppKit."""
    # No public CLI decodes Assets.car. Reasons start with "car" so extract_one
    # parks them under the car_only status.
    #
    # Bundle.image(forResource:) reads the catalog directly and comes first -
    # the NSWorkspace fallback goes through Icon Services, which stamps payload
    # apps it considers unrunnable with the prohibitory overlay (shipped a
    # slashed-out Acrobat icon) and answers with the generic icon when the
    # catalog has none, hence the byte-compare guard.
    with tempfile.TemporaryDirectory(prefix="car-icon-") as td:
        script = Path(td) / "icon.swift"
        script.write_text(_CAR_ICON_SWIFT, encoding="utf-8")

        def render(mode: str, out: Path) -> bool:
            proc = run(["swift", str(script), mode, str(app), str(out), ICON_SIZE])
            return proc.returncode == 0 and out.exists()

        if render("bundle", dest_png):
            return None
        generic = Path(td) / "generic.png"
        if not render("workspace", dest_png) or not render("generic", generic):
            return "car render failed"
        if dest_png.read_bytes() == generic.read_bytes():
            dest_png.unlink()
            return "car catalog has no app icon (generic render)"
    return None


def icns_to_png(app: Path, dest_png: Path) -> str | None:
    """Convert the app's icon to PNG. Returns a no-icon/car reason or None."""
    info = _load_info_plist(app)
    resources = app / "Contents" / "Resources"

    # Mirror macOS: CFBundleIconName (asset catalog) beats CFBundleIconFile.
    # Raycast ships both - the loose .icns is stale alternate branding.
    if info.get("CFBundleIconName") and (resources / "Assets.car").exists():
        if car_icon_to_png(app, dest_png) is None:
            return None
        # Catalog render failed - fall through to the .icns path.

    icns = _find_icns(info, resources)
    if icns is None:
        if (resources / "Assets.car").exists():
            # Keyed off the actual file, not CFBundleIconName - Tailscale
            # ships a car-only icon without declaring it in the plist.
            return car_icon_to_png(app, dest_png)
        return "no .icns in Resources"

    proc = run(["sips", "-s", "format", "png", "--resampleHeightWidthMax", ICON_SIZE,
                str(icns), "--out", str(dest_png)])
    if proc.returncode != 0 or not dest_png.exists():
        raise ExtractError(f"sips failed: {proc.stderr.strip()[:200]}")
    return None


def _load_info_plist(app: Path) -> dict:
    plist_path = app / "Contents" / "Info.plist"
    if not plist_path.exists():
        return {}
    try:
        return plistlib.loads(plist_path.read_bytes())
    except Exception:
        return {}


def _find_icns(info: dict, resources: Path) -> Path | None:
    """The declared CFBundleIconFile if present, else the largest loose .icns."""
    icns_name = resolve_icns_name(info)
    icns = resources / icns_name if icns_name else None
    if icns is not None and icns.exists():
        return icns
    candidates = sorted(resources.glob("*.icns")) if resources.exists() else []
    if candidates:
        return max(candidates, key=lambda p: p.stat().st_size)
    return None


def extract_one(cask: dict, output_dir: Path) -> tuple[str, str]:
    """Extract one cask's icon; returns (status, detail), raises ExtractError for `failed`."""
    # status: ok (detail = .app selection mode) | no_icon | car_only.
    token = cask["token"]
    reason = eligibility(cask)
    if reason:
        return "no_icon", reason

    workdir = Path(tempfile.mkdtemp(prefix=f"icon-{token}-"))
    mounts: list[Path] = []
    try:
        artifact = download(cask, workdir)
        kind = container_type(cask, artifact.name) or sniff_container(artifact)
        if kind is None:
            return "no_icon", f"unsupported container: {artifact.name}"

        root = expand(artifact, kind, workdir, mounts)
        hit = _locate_app(cask, root, kind, workdir, mounts)
        record_extraction(cask, workdir, artifact, output_dir)
        if hit is None:
            # Deterministic outcome (e.g. suite/pkg of CLI binaries) - park it
            # rather than burning retries. --tokens bypasses parked entries.
            return "no_icon", "no .app found in expanded artifact"
        app, selection = hit
        if selection == "installer_only":
            # An installer stub's icon is a wrong icon, not an icon. Honest gap.
            return "no_icon", "only installer/updater apps in artifact"
        return _icon_status(app, selection, output_dir / f"{token}.png")
    finally:
        for mnt in mounts:
            run(["hdiutil", "detach", str(mnt), "-force"])
        shutil.rmtree(workdir, ignore_errors=True)


def _locate_app(cask: dict, root: Path, kind: str,
                workdir: Path, mounts: list[Path]) -> tuple[Path, str] | None:
    """Find the icon-bearing .app: payload root, direct walk, then nested archive."""
    token = cask["token"]
    wanted = [n if n.endswith(".app") else f"{n}.app" for n in app_names_from_artifacts(cask)]
    hit = None
    if kind == "pkg":
        bundle = payload_bundle(root)
        if bundle is not None:
            hit = (bundle, "payload_root")  # deterministic - no review needed
    if hit is None:
        hit = find_app(root, wanted, token)
    if hit is None:
        nested = find_nested_archive(root)
        if nested:
            inner, inner_kind = nested
            inner_root = expand(inner, inner_kind, workdir / "nested", mounts)
            hit = find_app(inner_root, wanted, token)
    return hit


def _icon_status(app: Path, selection: str, dest_png: Path) -> tuple[str, str]:
    icon_reason = icns_to_png(app, dest_png)
    if icon_reason is None:
        return "ok", selection
    if icon_reason.startswith("car"):
        return "car_only", icon_reason
    return "no_icon", icon_reason


def publish_batch(pngs: dict[str, Path], report: dict[str, dict],
                  dirty: set[str], identity_file: Path | None = None) -> None:
    """Commit a batch of icons AND the report to the icons branch via a throwaway worktree."""
    # Merge only this batch's report entries so concurrent manual audits survive.
    wt = Path(tempfile.mkdtemp(prefix="icons-wt-"))
    wt_added = False
    try:
        _add_icons_worktree(wt)
        wt_added = True
        for token, png in pngs.items():
            shutil.copyfile(png, wt / f"{token}.png")
        _merge_report(wt, report, dirty)
        if identity_file is not None:
            merge_extractions(wt / MANIFEST, identity_file, dirty)
        if _git(wt, "add", "-A").returncode != 0:
            raise ExtractError("Cannot stage icons")
        write_icon_manifest(wt)
        if _git(wt, "add", "icons.json").returncode != 0:
            raise ExtractError("Cannot stage icons.json")
        if _git(wt, "diff", "--cached", "--quiet").returncode == 0:
            return  # everything already on the branch
        changed = _git(wt, "diff", "--cached", "--name-only", "--diff-filter=AM", "--", "*.png", "icons.json")
        if changed.returncode != 0:
            raise ExtractError("Cannot determine changed icons for CDN purge")
        _commit_and_push(wt, pngs)
        for filename in changed.stdout.splitlines():
            purge_file(filename)
    finally:
        if wt_added:
            _git(REPO_ROOT, "worktree", "remove", "--force", str(wt))
        shutil.rmtree(wt, ignore_errors=True)


def write_icon_manifest(wt: Path) -> None:
    """Describe the staged PNGs, so manifest and images publish in one commit."""
    index = _git(wt, "ls-files", "--stage", "-z", "--", "*.png")
    if index.returncode != 0:
        raise ExtractError("Cannot read staged icons for icons.json")
    hashes = {}
    for entry in index.stdout.split("\0"):
        if not entry:
            continue
        info, path = entry.split("\t", 1)
        mode, sha, stage = info.split()
        if stage != "0":
            raise ExtractError("Cannot publish icons with unresolved conflicts")
        if mode in ("100644", "100755") and "/" not in path:
            hashes[Path(path).stem] = sha
    write_json(wt / "icons.json", {"version": 1, "hashes": dict(sorted(hashes.items()))})


def purge_file(filename: str) -> None:
    """Refresh a mutable CDN file; failure must not undo a successful push."""
    url = f"https://purge.jsdelivr.net/gh/alielsokary/CaskFlow@{ICONS_BRANCH}/{filename}"
    try:
        with urlopen(url, timeout=15) as response:  # nosec B310 - fixed HTTPS scheme and jsDelivr host
            result = json.load(response)
        paths = result.get("paths", {})
        if result.get("status") != "finished" or not paths or any(
            entry.get("throttled") or not entry.get("providers")
            or not all(entry["providers"].values()) for entry in paths.values()
        ):
            raise ValueError(f"purge incomplete: {result}")
    except Exception as error:
        print(f"warning: CDN purge failed for {filename}: {error}; retry {url}")


def _add_icons_worktree(wt: Path) -> None:
    if _git(REPO_ROOT, "fetch", "-q", "origin", ICONS_BRANCH).returncode != 0:
        raise ExtractError(f"git fetch origin {ICONS_BRANCH} failed - branch missing?")
    add = _git(REPO_ROOT, "worktree", "add", "--detach", str(wt), "FETCH_HEAD")
    if add.returncode != 0:
        raise ExtractError(f"worktree add failed: {add.stderr.strip()[:200]}")


def _merge_report(wt: Path, report: dict[str, dict], dirty: set[str]) -> None:
    """Overlay only this run's dirty tokens on the branch's current report."""
    base_file = wt / REPORT_FILE
    merged: dict[str, dict] = (
        json.loads(base_file.read_text(encoding="utf-8")) if base_file.exists() else {}
    )
    for token in dirty:
        if token in report:
            merged[token] = report[token]
        else:
            merged.pop(token, None)  # cleared by this run (success)
    base_file.write_text(report_json(merged), encoding="utf-8")


def _commit_and_push(wt: Path, pngs: dict[str, Path]) -> None:
    # CI runners have no git identity configured; fall back to the bot's.
    name = _git(wt, "config", "user.name").stdout.strip() or "github-actions[bot]"
    email = (_git(wt, "config", "user.email").stdout.strip()
             or "41898282+github-actions[bot]@users.noreply.github.com")
    msg = f"Add {len(pngs)} icons" if pngs else "Update icon report"
    commit = _git(wt, "-c", f"user.name={name}", "-c", f"user.email={email}",
                  "commit", "-q", "-m", msg)
    if commit.returncode != 0:
        raise ExtractError(f"icon commit failed: {commit.stderr.strip()[:200]}")
    push = _git(wt, "push", "-q", "origin", f"HEAD:{ICONS_BRANCH}")
    if push.returncode != 0:
        raise ExtractError(f"icon push failed: {push.stderr.strip()[:200]}")
    if pngs:
        print(f"  ↑ published {len(pngs)} icons to {ICONS_BRANCH}")
    else:
        print(f"  ↑ updated {REPORT_FILE} on {ICONS_BRANCH} (no new icons)")


def load_install_counts() -> dict[str, int]:
    """Load 30-day install counts - backfill priority so the most-seen icons land first."""
    # The bulk cask.json has analytics=null; counts live in this endpoint.
    # Best-effort: an empty map just means unordered selection.
    try:
        with urlopen(ANALYTICS_API, timeout=60) as resp:
            data = json.loads(resp.read())
        return {
            row["cask"]: int(str(row["count"]).replace(",", ""))
            for row in data.get("items", [])
        }
    except Exception as e:
        print(f"warning: analytics fetch failed ({e}); selection unordered")
        return {}


def select_candidates(api_casks: list[dict], report: dict, limit: int) -> list[dict]:
    from classify_new_casks import is_main_cask  # shared "what the app shows" filter

    done = published_tokens()
    parked = {
        t for t, e in report.items()
        if e["status"] in ("no_icon", "car_only")
        or (e["status"] == "failed" and e.get("attempts", 0) >= MAX_ATTEMPTS)
    }
    candidates = [
        c for c in api_casks
        # is_main_cask: skip @-version variants and font-* - the app filters
        # them out, so their icons would never be requested (--tokens still
        # bypasses this for manual runs)
        if is_main_cask(c)
        and c["token"] not in done and c["token"] not in parked
        and eligibility(c) is None
    ]
    counts = load_install_counts()
    candidates.sort(key=lambda c: counts.get(c["token"], 0), reverse=True)
    return candidates[:limit]


def _load_api_casks(casks_json: Path | None) -> list[dict]:
    if casks_json:
        return json.loads(casks_json.read_text(encoding="utf-8"))
    print(f"Fetching {BREW_API} ...")
    with urlopen(BREW_API, timeout=60) as resp:
        return json.loads(resp.read())


def _build_batch(tokens: list[str] | None, by_token: dict[str, dict],
                 api_casks: list[dict], report: dict, limit: int,
                 retry_parked: bool = False) -> list[dict]:
    if retry_parked:
        # Monthly second chance for failed-parks only: sha256-mismatch parks
        # heal once brew bumps the cask's version. no_icon/car_only parks are
        # deterministic and never retried. Tokens gone from the API (removed
        # casks) are skipped.
        return [by_token[t] for t, e in sorted(report.items())
                if e["status"] == "failed" and e.get("attempts", 0) >= MAX_ATTEMPTS
                and t in by_token]
    if not tokens:
        return select_candidates(api_casks, report, limit)
    missing = [t for t in tokens if t not in by_token]
    if missing:
        raise SystemExit(f"unknown tokens: {missing}")
    return [by_token[t] for t in tokens]


def _extract_status(cask: dict, output_dir: Path) -> tuple[str, str]:
    """extract_one with failures folded into the (status, detail) result."""
    try:
        return extract_one(cask, output_dir)
    except ExtractError as e:
        return "failed", str(e)
    except Exception as e:  # never let one cask kill the batch
        return "failed", f"{type(e).__name__}: {e}"


def _record_ok(token: str, detail: str, report: dict) -> None:
    report.pop(token, None)  # clear any prior failure/review
    if detail in ("single", "shallowest"):
        # Audit queue: the .app was picked heuristically, not by
        # stanza name or token match - a human should eyeball it.
        record(report, token, "review", f"non-exact .app selection: {detail}")


def _flush_if_due(report: dict, pending: dict[str, Path], dirty: set[str],
                  identity_file: Path | None = None) -> None:
    if len(pending) >= FLUSH_EVERY or len(dirty) >= FLUSH_EVERY:
        publish_batch(pending, report, dirty, identity_file)
        pending.clear()
        dirty.clear()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tokens", nargs="*", help="Extract exactly these casks")
    parser.add_argument("--identity-backfill", action="store_true",
                        help="Reinspect existing icons whose identity metadata is missing or outdated")
    parser.add_argument("--retry-parked", action="store_true",
                        help="Retry every failed-parked token (attempts >= MAX_ATTEMPTS)")
    parser.add_argument("--limit", type=int, default=50, help="Batch cap (default 50)")
    parser.add_argument("--publish", action="store_true",
                        help="Publish cask-<token> pre-releases (requires gh auth)")
    parser.add_argument("--output-dir", type=Path, default=REPO_ROOT / "icons_out")
    parser.add_argument("--casks-json", type=Path,
                        help="Path to a pre-downloaded cask.json (skips the 30MB fetch)")
    args = parser.parse_args(argv)

    api_casks = _load_api_casks(args.casks_json)
    by_token = {c["token"]: c for c in api_casks}

    report = load_report()
    if args.identity_backfill and not args.tokens and not args.retry_parked:
        show = _git(REPO_ROOT, "show", f"FETCH_HEAD:{MANIFEST}")
        identities = json.loads(show.stdout).get("casks", {}) if show.returncode == 0 else {}
        counts = load_install_counts()
        from classify_new_casks import is_main_cask
        batch = [c for c in api_casks if is_main_cask(c) and eligibility(c) is None
                 and needs_refresh(c, identities.get(c["token"]))
                 and report.get(c["token"], {}).get("attempts", 0) < MAX_ATTEMPTS]
        batch.sort(key=lambda c: counts.get(c["token"], 0), reverse=True)
        batch = batch[:args.limit]
    else:
        batch = _build_batch(args.tokens, by_token, api_casks, report, args.limit,
                             retry_parked=args.retry_parked)

    args.output_dir.mkdir(parents=True, exist_ok=True)
    identity_file = args.output_dir / MANIFEST
    # Never republish stale local records from an earlier invocation after a failed download.
    from style_standards import write_json
    write_json(identity_file, {"schemaVersion": 1, "casks": {}}, trailing_newline=True)
    print(f"Extracting {len(batch)} casks → {args.output_dir}"
          + (" (publishing)" if args.publish else " (local only)"))

    ok = 0
    outcomes: list[tuple[str, str, str]] = []
    pending: dict[str, Path] = {}
    dirty: set[str] = set()  # tokens whose report entry this run may change
    start = time.time()
    for i, cask in enumerate(batch, 1):
        token = cask["token"]
        dirty.add(token)
        status, detail = _extract_status(cask, args.output_dir)
        if status == "ok":
            ok += 1
            _record_ok(token, detail, report)
            if args.publish:
                pending[token] = args.output_dir / f"{token}.png"
        else:
            record(report, token, status, detail)
        if args.publish:
            _flush_if_due(report, pending, dirty, identity_file)
        outcomes.append((token, status, detail))
        note = ""
        if status == "failed":
            attempts = report[token]["attempts"]
            note = (f" [attempt {attempts} - parked]" if attempts >= MAX_ATTEMPTS
                    else f" [attempt {attempts}/{MAX_ATTEMPTS}]")
        print(f"  [{i}/{len(batch)}] {token}: {status} - {detail}{note}", flush=True)

    if args.publish:
        # Always flush at the end - persists report-only outcomes (failures,
        # parks) even when no new icons were extracted.
        publish_batch(pending, report, dirty, identity_file)
    else:
        print("(local run - report changes not persisted; use --publish)")

    elapsed = time.time() - start
    failed = sum(1 for _, s, _ in outcomes if s == "failed")
    print(f"\n{ok}/{len(batch)} icons extracted in {elapsed:.0f}s; "
          f"{failed} failed, "
          f"{sum(1 for _, s, _ in outcomes if s in ('no_icon', 'car_only'))} skipped")
    if batch and failed == len(batch) and not args.retry_parked:
        # Every cask hard-failed: either the tail-end dregs day (rare, worth a
        # look) or a systemic problem (runner network, stale brew metadata).
        # Report/parking is already pushed above, so failing here loses nothing.
        # Retry-parked runs are exempt: all-fail is their expected outcome.
        print("error: every cask in the batch failed - flagging the run red")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
