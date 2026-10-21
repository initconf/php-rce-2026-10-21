### =======================================================================
## PHP 2026-10-21 critical RCEs — CVE-2026-109618 (OOM corruption) / CVE-2026-109619 (stale global state)
### https://www.php.net/archive/2026.php#2026-10-21-5
### https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
### https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
### =======================================================================

Fixed in PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35. Unauthenticated RCE before any application
code runs; highest risk Apache mod_php. **Plaintext HTTP only** — nothing inside TLS is
visible to Zeek; CF-fronted hosts are covered by the Cloudflare WAF rule instead.

Cluster-safe: per-connection heuristics run on the worker that owns the connection; the
two cross-connection pieces (crash sequence, version inventory) route their observations
with `Cluster::publish_hrw` to the proxy that owns the key, following
`policy/protocols/conn/known-services.zeek` and `~bro/AI.GUIDES/CLUSTERIZE-DEDUP.md`.
Standalone / `zeek -r` behaves identically (publish_hrw is a no-op there).

## Installation
------------
	cp -r php-rce-2026-10-21 /home/bro/zeek-cpp/packages/
	# then in the cluster policy (e.g. c100-mgr.lbl.gov/policies/c100-mgr.lbl.gov.zeek), next to
	# the existing `@load cups_rce/scripts` line:
	@load php-rce-2026-10-21/scripts
	zeekctl check && zeekctl deploy

	# or with zkg:
	zkg install ./php-rce-2026-10-21

Dry run on a trace:

	zeek -C -r some.pcap php-rce-2026-10-21/scripts

## Tests
	cd php-rce-2026-10-21/tests && btest -d
	#   php-rce.parse              parse-only
	#   php-rce.multipart-shapes   standalone: 12 notices + 2 signature hits on the synthetic trace
	#   php-rce.cluster-sequence   real cluster (manager-as-logger, 1 proxy, 2 workers, ZeroMQ):
	#                              both workers replay the trace; exactly ONE Crash_Sequence and
	#                              ONE Affected_PHP_Version must reach the manager
	python3 Traces/make-multipart-shapes.py      # regenerates the (benign, synthetic) trace

btest's TmpDir is on local disk (`/tmp/btest-php-rce-2026-10-21`): on NFS the node log
files linger as `.nfs*` for a few seconds after a cluster run and make back-to-back runs
collide. Workers in the cluster test hold packet processing (`suspend_processing`) until
the proxy and manager are peered, otherwise HRW events published during a millisecond-long
replay are dropped before the peering exists. Verified stable over 6 consecutive runs.

## Files
	scripts/detect-php-upload-progress.zeek   per-connection heuristics (worker-local)
	scripts/crash-sequence.zeek               producer->consumer pairing per PHP session (HRW -> proxy)
	scripts/version-inventory.zeek            affected PHP version from Server / X-Powered-By (HRW -> proxy)
	scripts/notice-policy.zeek                site actions (log only; email on the two strongest)
	scripts/php-upload-progress.sig           cheap body-literal layer
	tests/Traces/make-multipart-shapes.py     15-flow synthetic trace builder

## Heuristics
--------------------------------------------------
Per-connection notices are raised only for POSTs to responders in
`PHPUploadProgress::MONITORED_NETS` (LBL nets, unioned with `Site::local_nets`) from
non-local originators (`inbound_only = T`). Thresholds are `&redef`-able; the vendor
publishes no numbers, so the Many_* defaults sit above the measured 7-day LBL baseline
(legit max 6 parts/request) and should be tuned on day one.

| Notice | Fires on | Maps to |
|---|---|---|
| `Progress_Field` | multipart POST with a part named `PHP_SESSION_UPLOAD_PROGRESS` | 109619 session consumer (no sid) |
| `Progress_With_Sid` | same + `PHPSESSID` cookie or part — the full consumer shape | **109619 session path** (strongest) |
| `Crash_Sequence` | a request that raised any notice (producer), then a `Progress_With_Sid` request on the **same PHP session** to the same server+host within `correlation_window` (60 s), across connections / workers | **109619 producer→consumer sequence** |
| `Many_Parts` | ≥ 40 parts | 109618 shape |
| `Many_Part_Headers` | ≥ 8 headers inside one part | 109618 shape ("unrestricted number of headers") |
| `Many_Empty_Files` | ≥ 10 zero-length file parts | 109618 shape ("empty file controls") |
| `Deep_Nesting` | field name nested ≥ 12 levels (`a[b][c]…`), multipart or urlencoded | 109618 shape ("nested field names") |
| `Large_Form_Key` | urlencoded field name ≥ 64 KB | 109618 shape (huge key) |
| `Multipart_No_Length` | multipart POST sent chunked (no usable Content-Length) | 109618 shape (bypasses early post_max_size) |
| `Multipart_5xx` | multipart POST (≥2 parts) answered 5xx | outcome: FPM worker died behind a proxy |
| `Multipart_No_Reply` | multipart POST fully sent, connection ended with no HTTP reply | outcome: mod_php child segfault (reset / empty reply) |
| `Affected_PHP_Version` | monitored server's `Server:` or `X-Powered-By:` shows `PHP/x.y.z` below the fixed patch for its branch (unlisted branches = affected); one per server+version per hour | inventory hint, not proof (banners can lie / be backported) |
| `Signatures::Sensitive_Signature` (`php-upload-progress-field`) | body literal `name="PHP_SESSION_UPLOAD_PROGRESS"` | cheap layer, same signal as Progress_* |

Session key for `Crash_Sequence` = sha256(cookie value | server | port | host); the raw
cookie is never logged or published. Ideas borrowed from corelight/php2shell-detect
(PHP_Crash_Sequence, Potentially_Affected_PHP_Version, Large_Form_Key); its serialized-data
PoC fingerprints were deliberately not copied.

Notice-framework suppression: notices share `$identifier = (orig, resp, uri, type)` with a
1-hour `Notice::default_suppression_interval`, so a repeat of the same shape to the same
URI is logged once per hour per source (the trace shows this: flows 11/12 repeat flows 4/2
and are suppressed, while `Crash_Sequence` still fires because it keys on the request
state, not the notice).

## Triage
- `Crash_Sequence` or `Progress_With_Sid` from outside → attempt on the 109619 session
  path. Pull the connection(s), check the responder's PHP version/SAPI, ask the owner for
  Apache `exit signal Segmentation fault` / php-fpm `exited on signal 11` lines for that minute.
- Any `Many_*` / `Large_Form_Key` / `Multipart_No_Length` **followed by** `Multipart_No_Reply`
  or `Multipart_5xx` from the same source to the same host = the producer→crash sequence
  the advisories describe. Treat as an attempt that reached vulnerable code.
- Same source hitting many hosts with shape notices and no outcome notices = sweep.
- `Affected_PHP_Version` = patch tracker input; re-check after the owner reports patching.

## Known limits
- Plaintext only. Direct-to-origin HTTPS and non-CF HTTPS hosts are blind spots.
- `Multipart_No_Reply` also fires on client aborts and captures that lose the server side
  (guarded by history containing `D` and `R`/`F`); corroboration only. In a cluster it is
  raised at connection removal, which for a reset flow can be at shutdown.
- `Crash_Sequence` needs the session id as a **cookie**; a `PHPSESSID` form part carries
  the id in the body and is not keyed on (Progress_With_Sid still fires).
- Chunked multipart parsing: Zeek logged an extra `trans_depth=2` row for the chunked test
  flow; the notice fired, but a progress part *inside* a chunked body has not been tested.
- urlencoded scanning stops after `urlenc_scan_limit` (1 MB) per request.
