##! Producer -> consumer correlation for CVE-2026-109619 (session upload-progress path).
##!
##! The advisory: a request that is interrupted (OOM / fatal error) leaves stale
##! session or decoder state on the worker; a later request handled by the same
##! worker that reaches session upload-progress handling consumes it. On the wire:
##!   trigger   = any request this package already flagged (shape or outcome notice)
##!   followup  = a multipart POST carrying the upload-progress part
##! on the SAME session (PHPSESSID cookie) to the SAME server+host within
##! correlation_window. The two requests are usually separate connections, so on a
##! cluster they can land on different workers: both observations are routed with
##! Cluster::publish_hrw to the proxy that owns the session key (pattern from
##! policy/protocols/conn/known-services.zeek and ~bro/AI.GUIDES/CLUSTERIZE-DEDUP.md).
##! Standalone/pcap: publish_hrw is a no-op and the local event fire does the work.
##!
##! The session key is sha256(token | server | port | host). The raw cookie value is
##! never logged or published. Idea borrowed from corelight/php2shell-detect
##! (PHP_Crash_Sequence); the trigger set here is this package's own notices.

@load base/frameworks/cluster
@load base/frameworks/notice
@load ./detect-php-upload-progress

module PHPUploadProgress;

export {
	## How long a trigger stays eligible for a followup (and vice versa).
	const correlation_window = 60sec &redef;

	type Observation: record {
		kind: string;        # "trigger" | "followup"
		key: string;         # session digest
		ts: time;
		id: conn_id;
		uid: string;
		host: string;
		uri: string;
		reason: string;      # notices fired on the trigger, or "upload-progress"
	};

	global sequence_observe: event(o: Observation);
}

# In cluster mode these tables are HRW-distributed across proxies and are the
# authority; worker copies are a non-authoritative pre-filter only and are
# cleared on membership change.
global triggers: table[string] of Observation &write_expire=correlation_window;
global followups: table[string] of Observation &write_expire=correlation_window;
global fired_pairs: set[string] &create_expire=correlation_window;

function session_key(s: State, c: connection): string
	{
	return sha256_hash(cat(s$token, "|", c$id$resp_h, "|", c$id$resp_p, "|",
	                       c$http?$host ? c$http$host : ""));
	}

function pair_notice(t: Observation, f: Observation)
	{
	local pk = cat(t$key, "|", t$uid, "|", f$uid);
	if ( pk in fired_pairs )
		return;
	add fired_pairs[pk];

	# Only the authoritative node emits: a proxy in cluster mode, or the single
	# process standalone. Workers run this handler too (to seed their pre-filter
	# caches) but must not emit, or per-worker duplication returns.
	if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::PROXY )
		return;

	NOTICE([$note=Crash_Sequence,
	        $id=f$id, $uid=f$uid, $src=f$id$orig_h, $dst=f$id$resp_h, $p=f$id$resp_p,
	        $msg=fmt("flagged request (%s) then upload-progress POST on the same PHP session to %s%s after %.1fs (trigger uid %s)",
	                 t$reason, f$host, f$uri, f$ts - t$ts, t$uid),
	        $sub=fmt("trigger=%s%s", t$host, t$uri),
	        $identifier=cat(f$id$orig_h, f$id$resp_h, t$key)]);
	}

event sequence_observe(o: Observation)
	{
	if ( o$kind == "trigger" )
		{
		# Keep the newest trigger per session.
		if ( o$key !in triggers || o$ts >= triggers[o$key]$ts )
			triggers[o$key] = o;
		# A followup already waiting (reordered delivery across workers)?
		if ( o$key in followups )
			{
			local f = followups[o$key];
			if ( f$uid != o$uid && f$ts >= o$ts && f$ts - o$ts <= correlation_window )
				pair_notice(o, f);
			}
		return;
		}

	# followup
	followups[o$key] = o;
	if ( o$key in triggers )
		{
		local t = triggers[o$key];
		if ( t$uid != o$uid && o$ts >= t$ts && o$ts - t$ts <= correlation_window )
			pair_notice(t, o);
		}
	}

function observe(c: connection, kind: string, reason: string)
	{
	local s = c$php_up;
	if ( s$token == "" || ! c?$http || ! c$http?$uri )
		return;
	local o = Observation($kind=kind, $key=session_key(s, c), $ts=network_time(),
	                      $id=c$id, $uid=c$uid, $host=c$http?$host ? c$http$host : "",
	                      $uri=c$http$uri, $reason=reason);
	# Route to the proxy that owns this session key (no-op standalone), and
	# fire locally to drive the standalone path / seed the worker cache.
	Cluster::publish_hrw(Cluster::proxy_pool, o$key, PHPUploadProgress::sequence_observe, o);
	event PHPUploadProgress::sequence_observe(o);
	}

function fired_names(s: State): string
	{
	local v: vector of string = vector();
	for ( n in s$fired )
		v += fmt("%s", n);
	return join_string_vec(sort(v, strcmp), ",");
	}

# Followup: the upload-progress part was seen (Progress_* just fired at -3).
event http_end_entity(c: connection, is_orig: bool) &priority=-4
	{
	if ( ! is_orig || ! c?$php_up )
		return;
	local s = c$php_up;
	# Progress_Field (no session id) has no token to key on; only With_Sid pairs.
	if ( Progress_With_Sid in s$fired && "followup" !in s$fired_kinds )
		{
		add s$fired_kinds["followup"];
		observe(c, "followup", "upload-progress");
		}
	}

# Trigger: the request ended (reply or connection end) with any notice fired.
event http_reply(c: connection, version: string, code: count, reason: string) &priority=-4
	{
	if ( ! c?$php_up )
		return;
	local s = c$php_up;
	if ( s$flagged && "trigger" !in s$fired_kinds )
		{
		add s$fired_kinds["trigger"];
		observe(c, "trigger", fired_names(s));
		}
	}

event connection_state_remove(c: connection) &priority=-4
	{
	if ( ! c?$php_up )
		return;
	local s = c$php_up;
	if ( s$flagged && "trigger" !in s$fired_kinds )
		{
		add s$fired_kinds["trigger"];
		observe(c, "trigger", fired_names(s));
		}
	}

@if ( Cluster::is_enabled() )
event Cluster::node_up(name: string, id: string)
	{
	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;
	clear_table(triggers);
	clear_table(followups);
	}

event Cluster::node_down(name: string, id: string)
	{
	if ( Cluster::local_node_type() != Cluster::WORKER )
		return;
	clear_table(triggers);
	clear_table(followups);
	}
@endif
