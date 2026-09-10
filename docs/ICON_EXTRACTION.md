# Icon Extraction

Extracts original app icons from Homebrew cask artifacts and publishes them to
the orphan **`icons` branch**, served through jsDelivr's edge CDN.

## Consumption

```
https://cdn.jsdelivr.net/gh/alielsokary/CaskFlow@icons/<token>.png     (primary - edge CDN)
https://raw.githubusercontent.com/alielsokary/CaskFlow/icons/<token>.png   (fallback)
```

256×256 PNG per cask token. Scheduled runs skip existing icons; explicit
`--tokens` re-extracts them. Publishing purges changed PNGs from jsDelivr;
purge failures are reported without undoing publication. jsDelivr caches branch refs for 12h at the edge and mirrors
served files permanently to its own storage; new icons are visible within
minutes on first request, cached aggressively thereafter.

The independent `icons.json` on the `icons` branch contains
`{"version": 1, "hashes": {"<token>": "<Git blob SHA-1>"}}`. It is generated
from the staged PNGs and committed alongside them on every publication, including
selective runs. No category release is needed. Existing `iconTokens` in category
releases stays available for older consumers; hashes are not added to categories.

Manifest URL: `https://raw.githubusercontent.com/alielsokary/CaskFlow/icons/icons.json`.
The same path is also available through jsDelivr. After a successful push, CI
purges only changed PNG URLs and the manifest if it changed. A selective run for
one changed icon purges that icon, not the entire collection. Unchanged images
are not purged, and purge failures warn without undoing publication.

Consumers refresh the manifest independently, compare saved hashes, and fetch
only changed icons using the existing URLs. Verify SHA-1 of
`blob <byte-count>\0` followed by the original PNG bytes before replacing a cached
icon. On network errors or mismatches, retain the previous icon and retry later:
mutable CDN content can temporarily lag behind the manifest. A CDN purge cannot
clear a consumer's local cache. Missing or unsupported manifests should preserve
legacy loading behavior, or the last successfully loaded manifest.

CaskHub checks on startup and on foreground activation (at most once per 15
minutes). Health > Sync now bypasses that interval and retries visible stale
icons, even if their advertised hashes have not changed. Failed downloads also
retry on a subsequent image load; there is no continuous background polling.

## Protocol (per cask)

1. **Eligibility** - skip `deprecated`/`disabled`; require an `app`, `suite`,
   or `pkg` artifact (pkg payloads contain the `.app`).
2. **Download** the cask `url` via curl, honoring `url_specs` (user-agent,
   referer, cookies, headers). Verify `sha256` unless `no_check`.
3. **Expand without executing anything**:
   dmg → `hdiutil attach -nobrowse -readonly`, zip → `ditto -xk`,
   tar → `tar -xf`, pkg → `pkgutil --expand-full` (no install scripts run).
   One level of nested-container recursion (dmg-in-zip etc.).
4. **Locate the `.app`** - selection is recorded as an audit signal:
   `exact` (matches the artifact stanza), `single` (only app present), or
   `shallowest` (heuristic - lands in the review queue). Symlinks are never
   followed (DMGs ship an `/Applications` link).
5. **Icon**: `CFBundleIconFile` from `Info.plist` → `.icns` → 256px PNG via
   `sips`. No `.icns` but `CFBundleIconName` → recorded `car_only`, skipped (v1).
6. **Publish**: batch-committed to the `icons` branch (one commit per ~25
   icons via a throwaway git worktree) - no release plumbing, no rate limits.

## State

- **Everything lives on the `icons` branch, written only by the extractor**:
  the PNGs *and* `icon_report.json`, committed in the same pushes. Master
  carries no report copy - keeping report state in one place prevents
  clobber races. Manual audits edit `icon_report.json` on the icons branch
  directly.
- **Done** = the `.png` files on the branch (one `git ls-tree`, no pagination).
- `icon_report.json` records:
  - `no_icon` / `car_only` - permanently parked with a reason
  - `failed` - retried up to 3 runs, then parked (`--tokens` bypasses parking;
    a monthly cron re-runs all failed-parks via `--retry-parked`, since
    sha256-mismatch parks heal once brew bumps the cask version).
    A run where *every* cask in the batch fails exits non-zero (red CI run) -
    it's either the tail-end dregs or a systemic problem worth a look; the
    report/parking push happens before the exit, so nothing is lost.
  - `review` - icon published but the `.app` was picked heuristically
    (`single`/`shallowest`); **the human audit queue**. Eyeball these after
    each batch; a wrong-but-plausible icon is worse than a missing one.
- Backfill order: 30-day install counts from the brew analytics API, so the
  most-installed apps get icons first.

## Running

```sh
# Local, no publishing - PNGs land in icons_out/
python3 scripts/extract_icons.py --tokens obsidian rectangle

# Batch with publishing (CI does this via extract-icons.yml workflow_dispatch)
python3 scripts/extract_icons.py --publish --limit 300
```

Backfill runs on GitHub-hosted macOS runners, and per-cask cleanup keeps disk flat.
Stdlib + stock macOS tooling only - no extra dependencies.

## App identity metadata

Each successful archive inspection also writes `app_identities.json`. This is
independent of icon extraction success. Entries record the cask version, source
URL, actual archive SHA-256, installed bundle name, and `CFBundleIdentifier`.
Only uniquely matched, explicitly declared `app` artifacts qualify. Source/target
renames are honored; embedded helpers, symlinks, ambiguous duplicates, suite/pkg
name guesses, and icon-selection fallbacks cannot establish app identity.
Unsupported or ambiguous artifacts produce an empty `apps` list.

The existing batch publisher merges only inspected tokens into the icons branch.
Failed downloads leave previous evidence intact. Daily releases merge the
checked-in seed with the branch manifest (fresh records win, including empty
records), add reviewed App Store variants from `data/app_identity_variants.json`,
and publish the resulting manifest. A compact `appIdentities` projection is
embedded in `categories.json`, with `metadataUpdatedAt` allowing identity-only
updates when the classification date is unchanged. Variant records require
review evidence; neither shared names nor identifier prefixes prove a relation.

Already-published icons need an explicit identity backfill. Use the workflow's
`identity_backfill` input, or run locally without publishing:

```sh
python3 scripts/extract_icons.py --identity-backfill --limit 25 --output-dir /tmp/cask-identities
```

This reuses normal archive download and expansion, without installing apps.
Backfill revisits missing records or changed cask versions, URLs, or checked
SHA-256 values. An empty result is not retried until those inputs change. For
rolling `no_check` archives, use `--tokens` to force a fresh inspection. Add
`--publish` only when ready to update the icons branch. Package payload identities
and coverage beyond inspected artifacts remain absent until verified.

CaskHub consumes the optional projection using its release loader and bundled
fallback. Older releases without the field remain readable. Unverified apps stay
unassigned; a verified App Store variant can be recognized without becoming
adoptable while its receipt is present.
