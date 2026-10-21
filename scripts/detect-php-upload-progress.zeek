##! Detection heuristics for the PHP 2026-10-21 security release:
##!   CVE-2026-109618 "RCE via OOM corruption"      (GHSA-w8hw-w9fx-j79w)
##!   CVE-2026-109619 "RCE via stale global state"  (GHSA-6wmf-4rv5-p3rp)
##! Fixed in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12. Highest risk: Apache mod_php
##! (validated unauthenticated RCE over HTTP before any application code runs).
##!
##! What the advisories say an attacker's requests look like (no numeric thresholds
##! are published; the ones below are tunable and were chosen above measured LBL
##! baselines, see PLAN.md):
##!   109618 - POSTs that exhaust memory_limit during automatic body parsing: no
##!            usable declared Content-Length (chunked), an unbounded number of
##!            headers per part, many empty file controls (not counted by
##!            max_file_uploads), deeply nested / very long field names, large
##!            decoded size.
##!   109619 - a request interrupted by OOM/fatal error (producer) followed by a
##!            request on the same worker that reaches session upload-progress
##!            handling before normal init (consumer). The consumer is a multipart
##!            POST carrying a part named session.upload_progress.name (default
##!            PHP_SESSION_UPLOAD_PROGRESS) plus a session id (PHPSESSID cookie or
##!            part) and a file part - verified in ext/session/session.c.
##!
##! This file holds the per-connection heuristics (they run on the worker that owns
##! the connection; nothing to deduplicate). crash-sequence.zeek correlates the
##! producer->consumer pair across connections (HRW to a proxy), and
##! version-inventory.zeek reports affected PHP versions seen in response headers.
##!
##! Notices raised here:
##!   Progress_Field        multipart POST carrying the upload-progress part.
##!   Progress_With_Sid     same + session id: the full consumer shape (strongest).
##!   Many_Parts            >= many_parts_threshold parts in one multipart POST.
##!   Many_Part_Headers     >= part_headers_threshold headers inside one part.
##!   Many_Empty_Files      >= empty_files_threshold zero-length file parts.
##!   Deep_Nesting          a field name nested >= nesting_threshold levels (a[b][c]..),
##!                         multipart or urlencoded.
##!   Large_Form_Key        a urlencoded field name >= large_form_key_bytes.
##!   Multipart_No_Length   multipart POST sent chunked / without Content-Length.
##!   Multipart_5xx         multipart POST answered 5xx (crashed FPM worker behind a
##!                         proxy; also ordinary app errors - corroboration).
##!   Multipart_No_Reply    multipart POST with no HTTP reply before the connection
##!                         ended (mod_php worker segfault typically yields a reset
##!                         or empty reply rather than a 5xx).
##!
##! Limits: plaintext HTTP only. Zeek delivers multipart part headers via http_header
##! (base/protocols/http/entities.zeek already reads Content-Disposition this way);
##! orig_mime_depth is 1 for message headers and >1 inside a part. Zeek raises
##! http_begin_entity before the message headers, so header-pair checks live in
##! http_header.
##!
##! Site nets mirror /usr/local/zeek/etc/networks.cfg so `zeek -r` without
##! networks.cfg still works; unioned with Site::local_nets in a cluster.

@load base/protocols/http
@load base/frameworks/notice
@load base/utils/site

module PHPUploadProgress;

export {
	redef enum Notice::Type += {
		Progress_Field,
		Progress_With_Sid,
		Many_Parts,
		Many_Part_Headers,
		Many_Empty_Files,
		Deep_Nesting,
		Large_Form_Key,
		Multipart_No_Length,
		Multipart_5xx,
		Multipart_No_Reply,
		## Producer (any notice above) followed by a consumer (upload-progress
		## part) on the same session within correlation_window. crash-sequence.zeek.
		Crash_Sequence,
		## A response header advertised a PHP version below the fixed release
		## for its branch (or an unsupported branch). version-inventory.zeek.
		Affected_PHP_Version,
	};

	const MONITORED_NETS: set[subnet] = {
		128.3.0.0/16, 131.243.0.0/16, 192.12.173.0/24, 192.58.231.0/24,
		204.62.155.0/24, 198.128.24.0/21, 198.128.42.0/24, 198.128.192.0/19,
		[2620:83:8000::]/44, [2620:83:8001::]/48, [2001:400:613:18::]/64,
	} &redef;

	## session.upload_progress.name / session.name defaults. Add site-specific
	## values if an app changes them.
	const progress_names: set[string] = { "PHP_SESSION_UPLOAD_PROGRESS" } &redef;
	const session_names: set[string] = { "PHPSESSID" } &redef;

	## Parts per multipart POST. Baseline (c101 http.log 2026-10-14..20): no
	## inbound request above 20 parts except one scanner; legit max seen 6.
	const many_parts_threshold = 40 &redef;
	## Headers inside a single part. Browsers send 1-2 (Content-Disposition,
	## Content-Type). Not measurable from http.log; start conservative.
	const part_headers_threshold = 8 &redef;
	## Zero-length file parts in one request. A form with a few optional file
	## controls submits a few; attacks need many.
	const empty_files_threshold = 10 &redef;
	## Bracket nesting depth of a field name (PHP max_input_nesting_level = 64).
	const nesting_threshold = 12 &redef;
	## Length of a single urlencoded field name (wire bytes, before decoding).
	const large_form_key_bytes = 65536 &redef;
	## Stop scanning a urlencoded body after this many bytes.
	const urlenc_scan_limit = 1048576 &redef;

	## Only alert on requests to internal responders by default.
	const inbound_only = T &redef;

	type State: record {
		multipart: bool &default=F;
		urlenc: bool &default=F;
		chunked: bool &default=F;
		parts: count &default=0;
		progress: bool &default=F;
		sid: bool &default=F;
		## Raw session token from the cookie; used only to build a digest in
		## crash-sequence.zeek, never logged.
		token: string &default="";
		cur_hdrs: count &default=0;      # headers seen in the current part
		cur_is_file: bool &default=F;
		cur_len: count &default=0;       # body bytes of the current part
		empty_files: count &default=0;
		max_depth: count &default=0;
		uk_len: count &default=0;        # urlencoded: current key length
		uk_depth: count &default=0;      # urlencoded: '[' count in current key
		uk_inkey: bool &default=T;
		uk_scanned: count &default=0;
		fired: set[Notice::Type];        # once-per-request suppression
		fired_kinds: set[string];        # crash-sequence.zeek: "trigger"/"followup" sent
		flagged: bool &default=F;        # any notice fired on this request
		replied: bool &default=F;
	};

	global internal: function(a: addr): bool;
}

redef record connection += {
	php_up: State &optional;
};

function internal(a: addr): bool
	{
	return a in MONITORED_NETS || Site::is_local_addr(a);
	}

function wanted(c: connection): bool
	{
	if ( ! inbound_only )
		return T;
	return internal(c$id$resp_h) && ! internal(c$id$orig_h);
	}

# Pull name="..." out of a Content-Disposition value.
function part_name(v: string): string
	{
	local m = match_pattern(v, /name=\"[^\"]*\"/);
	if ( ! m$matched )
		return "";
	return sub_bytes(m$str, 7, |m$str| - 7);
	}

function bracket_depth(name: string): count
	{
	local d = 0;
	for ( ch in name )
		if ( ch == "[" )
			++d;
	return d;
	}

function fire(c: connection, n: Notice::Type, msg: string, sub: string)
	{
	local s = c$php_up;
	s$flagged = T;
	if ( n in s$fired )
		return;
	add s$fired[n];
	NOTICE([$note=n, $conn=c, $msg=msg, $sub=sub,
	        $identifier=cat(c$id$orig_h, c$id$resp_h, c$http$uri, n)]);
	}

event http_request(c: connection, method: string, original_URI: string,
                   unescaped_URI: string, version: string) &priority=5
	{
	if ( method == "POST" && wanted(c) )
		c$php_up = State($fired=set(), $fired_kinds=set());
	}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
	{
	if ( ! is_orig || ! c?$php_up )
		return;
	local s = c$php_up;

	if ( c$http$orig_mime_depth <= 1 )
		{
		if ( name == "CONTENT-TYPE" )
			{
			if ( /^[mM][uU][lL][tT][iI][pP][aA][rR][tT]\// in value )
				s$multipart = T;
			else if ( /^[aA][pP][pP][lL][iI][cC][aA][tT][iI][oO][nN]\/[xX]-[wW][wW][wW]-[fF][oO][rR][mM]-[uU][rR][lL][eE][nN][cC][oO][dD][eE][dD]/ in value )
				s$urlenc = T;
			}
		else if ( name == "TRANSFER-ENCODING" && /[cC][hH][uU][nN][kK][eE][dD]/ in value )
			s$chunked = T;
		else if ( name == "COOKIE" )
			{
			local pieces = split_string(value, /;[ \t]*/);
			for ( pi in pieces )
				{
				local kv = split_string1(pieces[pi], /=/);
				if ( |kv| == 2 && kv[0] in session_names && |kv[1]| > 0 )
					{
					s$sid = T;
					s$token = kv[1];
					}
				}
			}
		# Header order is arbitrary; check once both are known.
		if ( s$multipart && s$chunked )
			fire(c, Multipart_No_Length,
			     fmt("chunked multipart POST to %s%s", c$http$host, c$http$uri),
			     "transfer-encoding=chunked");
		return;
		}

	if ( ! s$multipart )
		return;

	# Inside a part.
	++s$cur_hdrs;
	if ( s$cur_hdrs >= part_headers_threshold )
		fire(c, Many_Part_Headers,
		     fmt("multipart part with >=%d headers in POST to %s%s", s$cur_hdrs,
		         c$http$host, c$http$uri),
		     fmt("part=%d headers=%d", s$parts, s$cur_hdrs));

	if ( name == "CONTENT-DISPOSITION" )
		{
		++s$parts;
		local pn = part_name(value);
		if ( pn in progress_names )
			s$progress = T;
		else if ( pn in session_names )
			s$sid = T;
		if ( /filename=/ in value )
			s$cur_is_file = T;

		local d = bracket_depth(pn);
		if ( d > s$max_depth )
			s$max_depth = d;
		if ( d >= nesting_threshold )
			fire(c, Deep_Nesting,
			     fmt("multipart field nested %d levels in POST to %s%s", d,
			         c$http$host, c$http$uri),
			     fmt("name=%s", sub_bytes(pn, 1, 80)));

		if ( s$parts >= many_parts_threshold )
			fire(c, Many_Parts,
			     fmt("multipart POST with >=%d parts to %s%s", s$parts,
			         c$http$host, c$http$uri),
			     fmt("parts=%d", s$parts));
		}
	}

event http_begin_entity(c: connection, is_orig: bool) &priority=3
	{
	if ( ! is_orig || ! c?$php_up )
		return;
	local s = c$php_up;
	if ( c$http$orig_mime_depth > 1 )
		{
		s$cur_hdrs = 0;
		s$cur_is_file = F;
		s$cur_len = 0;
		}
	}

# urlencoded bodies: walk key/value tokens; a key runs until '=' and ends at '&'.
function scan_urlencoded(c: connection, s: State, data: string)
	{
	if ( s$uk_scanned >= urlenc_scan_limit )
		return;
	s$uk_scanned += |data|;

	local toks = split_string_all(data, /[&=]/);
	local i = 0;
	while ( i < |toks| )
		{
		local t = toks[i];
		if ( i % 2 == 0 )
			{
			# text between separators
			if ( s$uk_inkey && |t| > 0 )
				{
				s$uk_len += |t|;
				s$uk_depth += bracket_depth(t);
				}
			}
		else if ( t == "=" )
			{
			if ( s$uk_inkey )
				{
				if ( s$uk_len >= large_form_key_bytes )
					fire(c, Large_Form_Key,
					     fmt("urlencoded field name of %d bytes in POST to %s%s",
					         s$uk_len, c$http$host, c$http$uri),
					     fmt("key_bytes=%d", s$uk_len));
				if ( s$uk_depth >= nesting_threshold )
					fire(c, Deep_Nesting,
					     fmt("urlencoded field nested %d levels in POST to %s%s",
					         s$uk_depth, c$http$host, c$http$uri),
					     fmt("depth=%d", s$uk_depth));
				}
			s$uk_inkey = F;
			}
		else  # "&"
			{
			s$uk_inkey = T;
			s$uk_len = 0;
			s$uk_depth = 0;
			}
		++i;
		}
	# A key that never sees '=' (e.g. one giant key) still counts once it is big.
	if ( s$uk_inkey && s$uk_len >= large_form_key_bytes )
		fire(c, Large_Form_Key,
		     fmt("urlencoded field name of >=%d bytes in POST to %s%s",
		         s$uk_len, c$http$host, c$http$uri),
		     fmt("key_bytes=%d", s$uk_len));
	}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string) &priority=3
	{
	if ( ! is_orig || ! c?$php_up )
		return;
	local s = c$php_up;
	if ( c$http$orig_mime_depth > 1 )
		s$cur_len += length;
	else if ( s$urlenc )
		scan_urlencoded(c, s, data);
	}

event http_end_entity(c: connection, is_orig: bool) &priority=-3
	{
	if ( ! is_orig || ! c?$php_up )
		return;
	local s = c$php_up;

	if ( c$http$orig_mime_depth > 1 )
		{
		if ( s$cur_is_file && s$cur_len == 0 )
			{
			++s$empty_files;
			if ( s$empty_files >= empty_files_threshold )
				fire(c, Many_Empty_Files,
				     fmt("multipart POST with >=%d empty file parts to %s%s",
				         s$empty_files, c$http$host, c$http$uri),
				     fmt("empty_files=%d parts=%d", s$empty_files, s$parts));
			}
		}

	if ( s$progress )
		{
		# Fire once, when the first part carrying the progress field has been seen;
		# sid may have arrived as a cookie or an earlier part.
		local n = s$sid ? Progress_With_Sid : Progress_Field;
		fire(c, n,
		     fmt("PHP upload-progress field in multipart POST to %s%s (parts=%d, sid=%s)",
		         c$http$host, c$http$uri, s$parts, s$sid ? "yes" : "no"),
		     fmt("body_len=%d", c$http$request_body_len));
		s$progress = F;
		}
	}

event http_reply(c: connection, version: string, code: count, reason: string) &priority=-3
	{
	if ( ! c?$php_up )
		return;
	local s = c$php_up;
	s$replied = T;
	if ( s$multipart && s$parts >= 2 && code >= 500 )
		fire(c, Multipart_5xx,
		     fmt("multipart POST (%d parts) to %s%s answered %d", s$parts,
		         c$http$host, c$http$uri, code),
		     fmt("status=%d body_len=%d", code, c$http$request_body_len));
	}

# State is dropped after every lower-priority reader (crash-sequence.zeek at -4).
event http_reply(c: connection, version: string, code: count, reason: string) &priority=-5
	{
	if ( c?$php_up )
		delete c$php_up;
	}

event connection_state_remove(c: connection) &priority=-3
	{
	if ( ! c?$php_up )
		return;
	local s = c$php_up;
	# A multipart POST that was fully sent but never answered. Ignore captures
	# that never saw the server side at all (history without any resp bytes).
	if ( s$multipart && s$parts >= 1 && ! s$replied && c?$http && c$http?$uri
	     && /[Dd]/ in c$history && /[Rr]|[Ff]/ in c$history )
		fire(c, Multipart_No_Reply,
		     fmt("multipart POST (%d parts) to %s%s got no HTTP reply (history %s)",
		         s$parts, c$http$host, c$http$uri, c$history),
		     fmt("body_len=%d", c$http$request_body_len));
	}
