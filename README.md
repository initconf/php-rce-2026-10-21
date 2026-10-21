### =======================================================================
## PHP 2026-10-21 critical RCEs — CVE-2026-109618 (OOM corruption) / CVE-2026-109619 (stale global state)
### https://www.php.net/archive/2026.php#2026-10-21-5
### https://github.com/php/php-src/security/advisories/GHSA-w8hw-w9fx-j79w
### https://github.com/php/php-src/security/advisories/GHSA-6wmf-4rv5-p3rp
### =======================================================================

Fixed in PHP 8.5.12 / 8.4.27 / 8.3.36 / 8.2.35. Unauthenticated RCE before any application
code runs; highest risk Apache mod_php. **Plaintext HTTP only** — nothing inside TLS is
visible to Zeek; CF-fronted hosts are covered by the Cloudflare WAF rule instead.

## Installation
------------
	cp -r php-rce-2026-10-21 /home/bro/zeek-cpp/packages/
	# then in the cluster policy (e.g. c100-mgr.lbl.gov/policies/c100-mgr.lbl.gov.zeek), next to
	# the existing `@load cups_rce/scripts` line:
	@load php-rce-2026-10-21/scripts
	zeekctl check && zeekctl deploy

	# or with zkg:
	zkg install ./php-rce-2026-10-21

Standalone / dry run on a pcap or a day of logs is not possible (http.log has no field
names); dry-run on a trace:

	zeek -C -r some.pcap php-rce-2026-10-21/scripts

## Tests
	cd php-rce-2026-10-21/tests && btest -d      # 2 tests; baseline from Traces/multipart-shapes.pcap
	python3 Traces/make-multipart-shapes.py      # regenerates the (benign, synthetic) trace

## Heuristics
--------------------------------------------------
All notices are raised only for POSTs to responders in `PHPUploadProgress::MONITORED_NETS`
(LBL nets, unioned with `Site::local_nets`) from non-local originators (`inbound_only = T`).
Thresholds are `&redef`-able; the vendor publishes no numbers, so Many_* defaults sit above
the measured 7-day LBL baseline (legit max 6 parts/request) and should be tuned on day one.

| Notice | Fires on | Maps to |
|---|---|---|
| `Progress_Field` | multipart POST with a part named `PHP_SESSION_UPLOAD_PROGRESS` | 109619 session consumer (no sid) |
| `Progress_With_Sid` | same + `PHPSESSID` cookie or part — the full consumer shape | **109619 session path** (strongest) |
| `Many_Parts` | ≥ 40 parts | 109618 shape |
| `Many_Part_Headers` | ≥ 8 headers inside one part | 109618 shape ("unrestricted number of headers") |
| `Many_Empty_Files` | ≥ 10 zero-length file parts | 109618 shape ("empty file controls") |
| `Deep_Nesting` | field name nested ≥ 12 levels (`a[b][c]…`) | 109618 shape ("nested field names") |
| `Multipart_No_Length` | multipart POST sent chunked (no usable Content-Length) | 109618 shape (bypasses early post_max_size) |
| `Multipart_5xx` | multipart POST (≥2 parts) answered 5xx | outcome: FPM worker died behind a proxy |
| `Multipart_No_Reply` | multipart POST fully sent, connection ended with no HTTP reply | outcome: mod_php child segfault (reset / empty reply) |
| `Signatures::Sensitive_Signature` (`php-upload-progress-field`) | body literal `name="PHP_SESSION_UPLOAD_PROGRESS"` | cheap layer, same signal as Progress_* |

Notice policy (`scripts/notice-policy.zeek`): log everything; e-mail on `Progress_With_Sid`;
DROP actions present but commented out until production hits have been reviewed.

## Example notices (synthetic trace)
```
PHPUploadProgress::Progress_With_Sid   PHP upload-progress field in multipart POST to www.example.lbl.gov/index.php (parts=1, sid=yes)
PHPUploadProgress::Many_Parts          multipart POST with >=40 parts to www.example.lbl.gov/index.php
PHPUploadProgress::Multipart_No_Reply  multipart POST (2 parts) to www.example.lbl.gov/index.php got no HTTP reply (history ShADar)
```

## Triage
- `Progress_With_Sid` or `Progress_Field` from outside → attempt on the 109619 session path.
  Pull the connection, check the responder's PHP version/SAPI, ask the owner for Apache
  `exit signal Segmentation fault` / php-fpm `exited on signal 11` lines for that minute.
- Any `Many_*` / `Multipart_No_Length` **followed by** `Multipart_No_Reply` or `Multipart_5xx`
  from the same source to the same host = the producer→crash sequence the advisories
  describe. Treat as an attempt that reached vulnerable code.
- Same source hitting many hosts with shape notices and no outcome notices = sweep.

## Known limits
- Plaintext only. Direct-to-origin HTTPS and non-CF HTTPS hosts are blind spots.
- `Multipart_No_Reply` also fires on client aborts and captures that lose the server side
  (guarded by history containing `D` and `R`/`F`); corroboration only.
- Chunked multipart parsing: Zeek logged an extra `trans_depth=2` row for the chunked test
  flow; the notice fired, but a progress part *inside* a chunked body has not been tested.
