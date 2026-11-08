# Signature loading and cache safety

`SignatureRepository` keeps a per-process cache of validated packs, keyed by filename and SHA-256 content hash. Unchanged content reuses its validation result, including invalid-pack errors. Changing a pack reparses only that pack; duplicate IDs are checked across the complete candidate repository before publishing. JSON duplicate-property checks and deserialization share the same parsed document.

Published snapshots are immutable, including nested condition arrays and values. Refreshes are serialized and the complete snapshot is published at once. A scan captures one snapshot for every enabled mailbox; later changes apply on subsequent scans. Removed files are evicted. Invalid, unreadable or unstable repositories publish errors and no scoring rules. A last-known-good snapshot is never substituted after a failed refresh.

## Dashboard versus authoritative operations

`GetSummary()` returns counts, filenames, errors and a content revision. Ordinary status requests neither parse JSON nor send rule definitions to the browser. Concurrent status requests share a refresh. Metadata checks are throttled to once per second; every 30 seconds a requesting client also causes full content verification. These are request-driven checks, not a background timer. A closed dashboard performs no polling.

`Load()` always reads and hashes current bytes, including after waiting for another refresh. Scans, preview start/end, and activation use this authoritative path. Same-size edits with preserved timestamps cannot bypass these checks. A matching content revision reuses the immutable snapshot without parsing or rule validation. Changed bytes reuse only unchanged packs.

Files are bounded to 1 MB before allocation. Read handles remain open during capture, preventing normal Windows writers from overwriting or deleting captured files. The directory manifest is checked again after capture; observed changes disable scoring for that refresh. Administrators should finish external edits before scanning and use atomic file replacement where possible. No filesystem operation can make an entire externally edited directory transactional; application-managed changes retain the existing scan/account lock.

Preview fingerprints combine the verified repository revision with the existing message, account and configuration fingerprints. Preview checks the repository again after evaluation, and activation verifies it again before saving. Stale previews are rejected. Installation/deletion explicitly invalidate the presentation cache and immediately reload. Preview and activation still perform no mailbox actions; quarantine occurs only in a scan and respects DryRun.

`/api/status` now returns `signatures.count`, `signatures.files`, `signatures.errors` and `signatures.revision`, with the existing `signatureFiles` filename alias. It no longer includes `signatures.rules`. The existing authenticated file-view endpoint still returns a selected pack's JSON. All existing authentication, CSRF and no-store response controls remain.

## Performance verification

Local Release measurements compared repeated loads before and after caching. Both runs warmed the JIT and operating-system file cache first; these timings exclude application startup, account storage and Graph requests. They are indicative measurements, not latency guarantees.

| Workload | Before | After |
| --- | ---: | ---: |
| Verify/reload 8 bundled packs (~23 KB) | ~1.9 ms, 304 KB allocated | ~0.9 ms, 72 KB allocated |
| Verify/reload 100 synthetic packs, 50 rules each | ~32 ms, 16.9 MB allocated | ~8 ms, 1.4 MB allocated |
| Bundled signature JSON portion of status | 14,363 bytes | 305 bytes |
| Synthetic signature JSON portion of status | 815,133 bytes | 1,214 bytes |

Warm summary reads between checks perform no file-content reads or parsing. The payload figures exclude the rest of the status response and the compatibility filename alias. First-load time is broadly unchanged: every new process must validate its repository, and the cache is not persisted. A scheduled `--scan` process benefits from the simpler JSON path, but cannot reuse a previous process's memory cache. No database, binary cache, watcher, or regex compilation mode is required.

`SignatureRepository.Statistics` exposes cumulative verification, content-read and pack-parse counts for diagnostics and deterministic tests. Cache tests assert work avoided rather than imposing machine-dependent timing limits. Regression tests cover partial writes, locked files, missing directories, same-size/preserved-timestamp edits, add/rename/delete, duplicate IDs, invalid-pack recovery, concurrent requests, immutable snapshots, compact API responses and stale-preview rejection. Live-scan tests verify that a warmed dashboard cache cannot cause actions from obsolete rules.
