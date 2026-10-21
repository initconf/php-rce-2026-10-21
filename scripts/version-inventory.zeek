##! Inventory of PHP versions advertised by monitored servers, with a notice when
##! the version is below the first fixed release for CVE-2026-109618/-109619.
##!
##! Reads `Server:` and `X-Powered-By:` response headers (any method - a GET is
##! enough). Zeek's software framework only parses `Server:`, so X-Powered-By is
##! the extra coverage here. Banners can be absent, rewritten, or reflect a vendor
##! build with backported fixes: this is an inventory hint, not a vulnerability
##! confirmation (same caveat as corelight/php2shell-detect, where the idea comes
##! from).
##!
##! Dedup: one notice per (server, version) per version_notice_interval, keyed by
##! HRW to a proxy so every worker that sees the server converges on one notice.

@load base/frameworks/cluster
@load base/frameworks/notice
@load base/protocols/http
@load ./detect-php-upload-progress

module PHPUploadProgress;

export {
	## Branch -> first fixed patch level (php.net advisory 2026-10-21). Branches
	## not listed (7.x, 8.0, 8.1) are out of support and treated as affected.
	const php_fixed_patch: table[string] of count = {
		["8.2"] = 35, ["8.3"] = 36, ["8.4"] = 27, ["8.5"] = 12,
	} &redef;

	## Suppress repeat notices per (server, version) for this long.
	const version_notice_interval = 1hr &redef;

	## Report only servers in MONITORED_NETS / Site::local_nets.
	const version_internal_only = T &redef;

	type VersionSeen: record {
		server: addr;
		server_p: port;
		version: string;    # e.g. "8.3.35"
		header: string;     # SERVER | X-POWERED-BY
		banner: string;
		id: conn_id;
		uid: string;
		ts: time;
	};

	global version_seen: event(v: VersionSeen, key: string);
	global php_version_is_affected: function(version: string): bool;
}

# Authoritative on proxies in cluster mode; a pre-filter cache on workers.
global reported: set[string] &create_expire=version_notice_interval;

function php_version_is_affected(version: string): bool
	{
	local parts = split_string(version, /\./);
	if ( |parts| < 3 )
		return T;
	local branch = cat(parts[0], ".", parts[1]);
	if ( branch !in php_fixed_patch )
		return T;
	return to_count(parts[2]) < php_fixed_patch[branch];
	}

function parts_fixed(version: string): string
	{
	local parts = split_string(version, /\./);
	if ( |parts| < 2 )
		return "?";
	local branch = cat(parts[0], ".", parts[1]);
	if ( branch !in php_fixed_patch )
		return fmt("(branch %s unsupported)", branch);
	return fmt("%s.%d", branch, php_fixed_patch[branch]);
	}

event version_seen(v: VersionSeen, key: string)
	{
	if ( key in reported )
		return;
	add reported[key];
	if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::PROXY )
		return;

	NOTICE([$note=Affected_PHP_Version,
	        $id=v$id, $uid=v$uid, $src=v$id$orig_h, $dst=v$server, $p=v$server_p,
	        $msg=fmt("%s:%s advertises PHP/%s (%s), below fixed %s", v$server, v$server_p,
	                 v$version, v$header,
	                 cat(parts_fixed(v$version))),
	        $sub=v$banner,
	        $identifier=key]);
	}

event http_header(c: connection, is_orig: bool, name: string, value: string) &priority=3
	{
	if ( is_orig || ! c?$http || c$http$resp_mime_depth > 1 )
		return;
	if ( name != "SERVER" && name != "X-POWERED-BY" )
		return;
	if ( version_internal_only && ! internal(c$id$resp_h) )
		return;

	local m = match_pattern(value, /PHP\/[0-9]+\.[0-9]+\.[0-9]+/);
	if ( ! m$matched )
		return;
	local ver = sub_bytes(m$str, 5, |m$str| - 4);
	if ( ! php_version_is_affected(ver) )
		return;

	local key = cat(c$id$resp_h, "|", ver);
	if ( key in reported )
		return;    # worker-local pre-filter
	local v = VersionSeen($server=c$id$resp_h, $server_p=c$id$resp_p, $version=ver,
	                      $header=name, $banner=sub_bytes(value, 1, 120),
	                      $id=c$id, $uid=c$uid, $ts=network_time());
	Cluster::publish_hrw(Cluster::proxy_pool, key, PHPUploadProgress::version_seen, v, key);
	event PHPUploadProgress::version_seen(v, key);
	}

@if ( Cluster::is_enabled() )
event Cluster::node_up(name: string, id: string)
	{
	if ( Cluster::local_node_type() == Cluster::WORKER )
		clear_table(reported);
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( Cluster::local_node_type() == Cluster::WORKER )
		clear_table(reported);
	}
@endif
