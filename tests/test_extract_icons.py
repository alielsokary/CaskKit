"""Tests for extract_icons pure helpers - eligibility, container detection, icon naming."""
from __future__ import annotations

import hashlib

import pytest

from extract_icons import (
    ExtractError,
    _flush_if_due,
    _verify_sha256,
    app_names_from_artifacts,
    container_type,
    eligibility,
    resolve_icns_name,
)
import extract_icons


def _cask(**kw) -> dict:
    return {"token": "test", "url": "https://example.com/Test.dmg",
            "artifacts": [{"app": ["Test.app"]}], **kw}


# --- eligibility -----------------------------------------------------------

def test_app_cask_is_eligible():
    assert eligibility(_cask()) is None


def test_deprecated_and_disabled_are_skipped():
    assert eligibility(_cask(deprecated=True)) == "deprecated/disabled"
    assert eligibility(_cask(disabled=True)) == "deprecated/disabled"


def test_non_app_cask_is_no_icon():
    qlplugin = _cask(artifacts=[{"qlplugin": ["Foo.qlgenerator"]}, {"zap": {"trash": []}}])
    assert eligibility(qlplugin) == "no app/suite/pkg artifact"


def test_suite_counts_as_app():
    assert eligibility(_cask(artifacts=[{"suite": ["Office Suite"]}])) is None


def test_pkg_installer_cask_is_eligible():
    zoomish = _cask(artifacts=[{"uninstall": [{}]}, {"pkg": ["Zoom.pkg"]}, {"zap": {}}])
    assert eligibility(zoomish) is None


def test_app_names_handles_target_dicts_and_strings():
    cask = _cask(artifacts=[{"app": ["A.app", {"target": "B.app"}]}, {"suite": ["S"]}])
    assert app_names_from_artifacts(cask) == ["A.app", "B.app", "S"]


# --- container detection ----------------------------------------------------

def test_container_type_from_extension():
    assert container_type({}, "Foo-1.2.dmg") == "dmg"
    assert container_type({}, "Foo.ZIP") == "zip"
    assert container_type({}, "Foo.pkg") == "pkg"
    assert container_type({}, "foo-x86.tar.xz") == "tar"
    assert container_type({}, "installer.exe") is None


def test_container_hint_wins_over_extension():
    # dmg-in-zip style: the cask's `container` field names the outer type.
    assert container_type({"container": {"type": "dmg"}}, "download.php") == "dmg"


# --- icns name resolution ----------------------------------------------------

def test_resolve_icns_name_appends_extension():
    assert resolve_icns_name({"CFBundleIconFile": "AppIcon"}) == "AppIcon.icns"
    assert resolve_icns_name({"CFBundleIconFile": "AppIcon.icns"}) == "AppIcon.icns"


def test_resolve_icns_name_missing_or_blank():
    assert resolve_icns_name({}) is None
    assert resolve_icns_name({"CFBundleIconFile": "  "}) is None


# --- find_app selection paths -------------------------------------------------

from extract_icons import find_app


def _mk_app(root, *parts):
    app = root.joinpath(*parts)
    (app / "Contents").mkdir(parents=True)
    return app


def test_find_app_exact_match_wins(tmp_path):
    _mk_app(tmp_path, "Helper.app")
    target = _mk_app(tmp_path, "sub", "Real.app")
    app, sel = find_app(tmp_path, ["Real.app"], "")
    assert app == target and sel == "exact"


def test_find_app_single_is_unambiguous(tmp_path):
    target = _mk_app(tmp_path, "Only.app")
    app, sel = find_app(tmp_path, ["SomethingElse.app"], "")
    assert app == target and sel == "single"


def test_find_app_multiple_without_match_flags_shallowest(tmp_path):
    shallow = _mk_app(tmp_path, "A.app")
    _mk_app(tmp_path, "deep", "B.app")
    app, sel = find_app(tmp_path, [], "")
    assert app == shallow and sel == "shallowest"


def test_find_app_never_follows_symlinks(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    (outside / "Trap.app" / "Contents").mkdir(parents=True)
    (root / "Applications").symlink_to(outside)
    assert find_app(root, [], "") is None


# --- installer demotion & token matching (batch-1 lessons) --------------------

from extract_icons import installerish, token_matches_app


def test_installerish_names():
    assert installerish("Install TeamViewer.app")
    assert installerish("Microsoft Office Installer.app")
    assert installerish("Setup Assistant.app")
    assert installerish("Sparkle Updater.app")
    assert not installerish("Microsoft Word.app")
    assert installerish("Uninstaller Pro Cleaner.app")  # contains 'uninstaller'


def test_token_matches_app():
    assert token_matches_app("microsoft-word", "Microsoft Word.app")
    assert token_matches_app("docker-desktop", "Docker.app")
    assert token_matches_app("google-chrome", "Google Chrome.app")
    assert not token_matches_app("r-app", "R.app")  # 1-char containment guarded
    assert not token_matches_app("zoom", "Microsoft Word.app")


def test_find_app_token_match_beats_shallow_installer(tmp_path):
    _mk_app(tmp_path, "Office Installer.app")           # shallow stub
    target = _mk_app(tmp_path, "payload", "Microsoft Word.app")
    app, sel = find_app(tmp_path, [], "microsoft-word")
    assert app == target and sel == "token"


def test_find_app_installer_only_is_parked(tmp_path):
    _mk_app(tmp_path, "Install TeamViewer.app")
    _, sel = find_app(tmp_path, [], "teamviewer")
    assert sel == "installer_only"


def test_find_app_single_ignores_installer_sibling(tmp_path):
    _mk_app(tmp_path, "Updater.app")
    target = _mk_app(tmp_path, "RealThing.app")
    app, sel = find_app(tmp_path, [], "unrelated-token")
    assert app == target and sel == "single"


# --- selection skips non-main casks (shared filter with the classifier) -------

from classify_new_casks import is_main_cask


def test_is_main_cask_shared_filter():
    assert is_main_cask({"token": "obsidian"})
    assert not is_main_cask({"token": "1password@beta"})
    assert not is_main_cask({"token": "font-fira-code"})
    assert not is_main_cask({"token": "old-tool", "deprecated": True})


# --- magic-byte container sniffing (extension-less URLs: .../stable, .../osx_arm64)

import zipfile

from extract_icons import icns_to_png, sniff_container


def test_sniff_zip(tmp_path):
    f = tmp_path / "stable"  # VS Code style: no extension
    with zipfile.ZipFile(f, "w") as z:
        z.writestr("hello.txt", "hi")
    assert sniff_container(f) == "zip"


def test_sniff_xar_pkg(tmp_path):
    f = tmp_path / "download"
    f.write_bytes(b"xar!" + b"\x00" * 100)
    assert sniff_container(f) == "pkg"


def test_sniff_gzip_tar(tmp_path):
    f = tmp_path / "release"
    f.write_bytes(b"\x1f\x8b\x08" + b"\x00" * 100)
    assert sniff_container(f) == "tar"


def test_sniff_ustar_tar(tmp_path):
    f = tmp_path / "osx_arm64"
    f.write_bytes(b"\x00" * 257 + b"ustar" + b"\x00" * 250)
    assert sniff_container(f) == "tar"


def test_sniff_dmg_koly_trailer(tmp_path):
    f = tmp_path / "download.php"
    # UDIF: the last 512 bytes are the koly block.
    f.write_bytes(b"\x00" * 1024 + b"koly" + b"\x00" * 508)
    assert sniff_container(f) == "dmg"


def test_sniff_koly_trailer_beats_head_magic(tmp_path):
    # comet/handbrake: UDIF images whose first data block carries the
    # compression magic (xz/bzip2). The koly trailer is authoritative.
    f = tmp_path / "download"
    f.write_bytes(b"\xfd7zXZ\x00" + b"\x00" * 1024 + b"koly" + b"\x00" * 508)
    assert sniff_container(f) == "dmg"


def test_sniff_unknown_is_none(tmp_path):
    f = tmp_path / "file"
    f.write_bytes(b"MZ\x90\x00" + b"\x00" * 100)  # PE executable
    assert sniff_container(f) is None


def test_expand_bare_compressed_payload(tmp_path):
    # comet: an xz/gzip-wrapped DMG is not a tarball - tar fails, the
    # fallback decompresses and expands whatever is inside (here: a zip).
    import gzip

    from extract_icons import expand

    inner_zip = tmp_path / "inner.zip"
    with zipfile.ZipFile(inner_zip, "w") as z:
        z.writestr("payload.txt", "hi")
    wrapped = tmp_path / "download"  # extension-less, gzip of a zip
    wrapped.write_bytes(gzip.compress(inner_zip.read_bytes()))

    root = expand(wrapped, "tar", tmp_path / "work", mounts=[])
    assert list(root.rglob("payload.txt"))


# --- payload-root bundles (Tailscale: pkgutil strips the .app dir name) -------

from extract_icons import payload_bundle  # noqa: E402


def test_payload_root_bundle_detected(tmp_path):
    contents = tmp_path / "Distribution.pkg" / "Payload" / "Contents"
    contents.mkdir(parents=True)
    (contents / "Info.plist").write_bytes(b"<plist/>")
    assert payload_bundle(tmp_path) == tmp_path / "Distribution.pkg" / "Payload"


def test_payload_bundle_ignores_normal_pkg_layout(tmp_path):
    # Ordinary payload: Payload/Applications/Foo.app - find_app's job, not ours.
    app = tmp_path / "Foo.pkg" / "Payload" / "Applications" / "Foo.app" / "Contents"
    app.mkdir(parents=True)
    (app / "Info.plist").write_bytes(b"<plist/>")
    assert payload_bundle(tmp_path) is None


def test_sha256_verification_streams_file(tmp_path, monkeypatch):
    artifact = tmp_path / "artifact"
    payload = b"large-enough-payload" * 100
    artifact.write_bytes(payload)
    monkeypatch.setattr(type(artifact), "read_bytes", lambda self: pytest.fail("must stream"))

    _verify_sha256({"sha256": hashlib.sha256(payload).hexdigest()}, artifact)


def test_sha256_mismatch_is_rejected(tmp_path):
    artifact = tmp_path / "artifact"
    artifact.write_bytes(b"unexpected")
    with pytest.raises(ExtractError, match="sha256 mismatch"):
        _verify_sha256({"sha256": "0" * 64}, artifact)


def test_flush_clears_published_pending_and_dirty(monkeypatch, tmp_path):
    pending = {"example": tmp_path / "example.png"}
    dirty = {"example", "failed-example"}
    published = []
    monkeypatch.setattr(extract_icons, "FLUSH_EVERY", 1)
    monkeypatch.setattr(
        extract_icons,
        "publish_batch",
        lambda pngs, report, tokens, identity_file=None: published.append((dict(pngs), set(tokens))),
    )

    _flush_if_due({}, pending, dirty)

    assert published == [({"example": tmp_path / "example.png"}, {"example", "failed-example"})]
    assert pending == {}
    assert dirty == set()


# --- asset-catalog icon path (car_only apps: little-snitch, tailscale-app, ...) --

def _mk_app_with_resources(tmp_path, *files):
    app = tmp_path / "Test.app"
    res = app / "Contents" / "Resources"
    res.mkdir(parents=True)
    for name in files:
        (res / name).write_bytes(b"x")
    return app


def test_icns_to_png_routes_car_only_apps_to_renderer(tmp_path, monkeypatch):
    import extract_icons
    app = _mk_app_with_resources(tmp_path, "Assets.car")
    monkeypatch.setattr(extract_icons, "car_icon_to_png", lambda a, d: "rendered")
    assert icns_to_png(app, tmp_path / "out.png") == "rendered"


def test_icns_to_png_prefers_declared_catalog_icon_over_legacy_icns(tmp_path, monkeypatch):
    # Raycast: CFBundleIconName (Assets.car) is what macOS shows; the loose
    # .icns beside it is stale alternate branding. Mirror the OS priority.
    import plistlib

    import extract_icons
    app = _mk_app_with_resources(tmp_path, "Assets.car", "Legacy.icns")
    (app / "Contents" / "Info.plist").write_bytes(plistlib.dumps(
        {"CFBundleIconName": "AppIcon", "CFBundleIconFile": "Legacy"}))
    monkeypatch.setattr(extract_icons, "car_icon_to_png", lambda a, d: None)
    assert icns_to_png(app, tmp_path / "out.png") is None  # car path won


def test_icns_to_png_no_icns_no_car_is_parked(tmp_path):
    app = _mk_app_with_resources(tmp_path)  # empty Resources
    assert icns_to_png(app, tmp_path / "out.png") == "no .icns in Resources"


# --- main exit code --------------------------------------------------------

def _run_main(monkeypatch, tmp_path, statuses):
    import extract_icons
    casks = [{"token": f"t{i}", "url": "https://example.com/a.dmg",
              "artifacts": [{"app": ["A.app"]}]} for i in range(len(statuses))]
    results = iter(statuses)
    monkeypatch.setattr(extract_icons, "_load_api_casks", lambda p: casks)
    monkeypatch.setattr(extract_icons, "load_report", lambda: {})
    monkeypatch.setattr(extract_icons, "select_candidates", lambda a, r, lim: casks)
    monkeypatch.setattr(extract_icons, "_extract_status", lambda c, o: next(results))
    return extract_icons.main(["--output-dir", str(tmp_path)])


def test_main_all_failed_batch_exits_nonzero(monkeypatch, tmp_path):
    # A batch where every cask hard-fails must flag the CI run red - a green
    # run with "0 published, 40 failed" hides systemic breakage (2026-07-12).
    assert _run_main(monkeypatch, tmp_path,
                     [("failed", "boom"), ("failed", "boom")]) == 1


def test_main_partial_failure_stays_green(monkeypatch, tmp_path):
    # Individual failures are routine (MAX_ATTEMPTS retry design) - only a
    # clean sweep of failures is an error signal.
    assert _run_main(monkeypatch, tmp_path,
                     [("failed", "boom"), ("no_icon", "no url")]) == 0
    assert _run_main(monkeypatch, tmp_path, []) == 0  # empty batch: steady state


# --- retry-parked ----------------------------------------------------------

def test_build_batch_retry_parked_selects_failed_parked_only():
    from extract_icons import _build_batch
    by_token = {"a": {"token": "a"}, "b": {"token": "b"}, "c": {"token": "c"}}
    report = {
        "a": {"status": "failed", "attempts": 3},   # parked - retried
        "b": {"status": "failed", "attempts": 2},   # daily cron still owns it
        "c": {"status": "no_icon", "attempts": 0},  # deterministic - never retried
        "gone": {"status": "failed", "attempts": 5},  # removed from brew API
    }
    batch = _build_batch(None, by_token, [], report, 50, retry_parked=True)
    assert [c["token"] for c in batch] == ["a"]


def test_main_retry_parked_all_fail_stays_green(monkeypatch, tmp_path):
    # All-fail is the expected outcome of a speculative monthly retry -
    # only the daily cron's all-fail flags the run red.
    import extract_icons
    casks = [{"token": "t0", "url": "u", "artifacts": [{"app": ["A.app"]}]}]
    monkeypatch.setattr(extract_icons, "_load_api_casks", lambda p: casks)
    monkeypatch.setattr(extract_icons, "load_report", lambda: {
        "t0": {"status": "failed", "reason": "x", "attempts": 3, "updated": "2026-07-11"}})
    monkeypatch.setattr(extract_icons, "_extract_status", lambda c, o: ("failed", "boom"))
    assert extract_icons.main(["--output-dir", str(tmp_path), "--retry-parked"]) == 0


def test_publish_manifest_and_purge_only_changed_files_after_push(monkeypatch, tmp_path):
    import json
    import subprocess

    wt = tmp_path / "worktree"
    wt.mkdir()

    def git(*args):
        return subprocess.check_output(["git", "-C", str(wt), *args], text=True).strip()
    git("init", "-q")
    git("config", "user.name", "Test")
    git("config", "user.email", "test@example.com")
    (wt / "antinote.png").write_bytes(b"old")
    (wt / "unchanged.png").write_bytes(b"same")
    git("add", "-A")
    git("commit", "-qm", "initial")
    events = []
    monkeypatch.setattr(extract_icons.tempfile, "mkdtemp", lambda **_: str(wt))
    monkeypatch.setattr(extract_icons, "_add_icons_worktree", lambda _: None)
    monkeypatch.setattr(extract_icons, "_merge_report", lambda *_: None)
    monkeypatch.setattr(extract_icons.shutil, "rmtree", lambda *a, **k: None)

    def push(*_):
        git("commit", "-qm", "publish")
        manifest = json.loads(git("show", "HEAD:icons.json"))
        assert manifest == {"version": 1, "hashes": {
            "antinote": git("rev-parse", "HEAD:antinote.png"),
            "unchanged": git("rev-parse", "HEAD:unchanged.png"),
        }}
        events.append("push")
    monkeypatch.setattr(extract_icons, "_commit_and_push", push)
    monkeypatch.setattr(extract_icons, "purge_file", events.append)
    png = tmp_path / "antinote.png"
    png.write_bytes(b"new")
    extract_icons.publish_batch({"antinote": png}, {}, set())
    assert events == ["push", "antinote.png", "icons.json"]
    events.clear()
    extract_icons.publish_batch({"antinote": png}, {}, set())
    assert events == []  # Unchanged bytes: no commit or purge.
    png.write_bytes(b"newer")

    def failed_push(*_):
        raise ExtractError("push failed")
    monkeypatch.setattr(extract_icons, "_commit_and_push", failed_push)
    with pytest.raises(ExtractError, match="push failed"):
        extract_icons.publish_batch({"antinote": png}, {}, set())
    assert events == []


def test_purge_failure_warns_without_failing_publication(monkeypatch, capsys):
    def unavailable(*args, **kwargs):
        raise OSError("offline")
    monkeypatch.setattr(extract_icons, "urlopen", unavailable)
    extract_icons.purge_file("antinote.png")
    assert "warning: CDN purge failed for antinote" in capsys.readouterr().out
