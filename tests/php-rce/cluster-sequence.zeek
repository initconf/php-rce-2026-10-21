# @TEST-DOC: Real cluster (manager-as-logger, 1 proxy, 2 workers, ZeroMQ): both workers
# replay the same trace, so every per-connection observation reaches the proxy twice;
# the HRW-owned state must still yield exactly one Crash_Sequence and one
# Affected_PHP_Version notice. Per-connection notices are intentionally not asserted
# here (each worker raises its own copy when both read the full pcap).
#
# @TEST-REQUIRES: have-zeromq
# @TEST-GROUP: cluster
#
# @TEST-PORT: XPUB_PORT
# @TEST-PORT: XSUB_PORT
# @TEST-PORT: LOG_PULL_PORT
#
# On NFS, btest's cleanup of the previous run's node dirs can fail while the old
# processes are still exiting (stale .nfs files), leaving "directory 'manager'
# already exists" on the next run. Clear them explicitly first.
# @TEST-EXEC: rm -rf ./manager ./proxy ./worker-1 ./worker-2
# @TEST-EXEC: chmod +x ./check-log.sh
# @TEST-EXEC: cp $FILES/zeromq/cluster-layout-no-logger.zeek cluster-layout.zeek
# @TEST-EXEC: cp $FILES/zeromq/test-bootstrap.zeek zeromq-test-bootstrap.zeek
#
# @TEST-EXEC: btest-bg-run manager  "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=manager  zeek -b ../manager.zeek >out"
# @TEST-EXEC: btest-bg-run proxy    "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=proxy    zeek -b ../node.zeek >out"
# @TEST-EXEC: btest-bg-run worker-1 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-1 zeek -b -C -r $TRACES/multipart-shapes.pcap ../node.zeek >out"
# @TEST-EXEC: btest-bg-run worker-2 "ZEEKPATH=$ZEEKPATH:.. && CLUSTER_NODE=worker-2 zeek -b -C -r $TRACES/multipart-shapes.pcap ../node.zeek >out"
#
# @TEST-EXEC: btest-bg-wait 90
#
# @TEST-EXEC: test -f manager/notice.log
# @TEST-EXEC: zeek-cut note src dst p sub < manager/notice.log | grep -E 'Crash_Sequence|Affected_PHP_Version' | sort > hrw-notices.out
# @TEST-EXEC: test "$(grep -c Crash_Sequence hrw-notices.out)" = "1"
# @TEST-EXEC: test "$(grep -c Affected_PHP_Version hrw-notices.out)" = "1"
# @TEST-EXEC: btest-diff hrw-notices.out

# @TEST-START-FILE common.zeek
@load ./zeromq-test-bootstrap
@load base/frameworks/cluster
@load base/protocols/http
@load base/frameworks/notice
@load base/frameworks/signatures

@load php-rce-2026-10-21/scripts

redef Log::default_rotation_interval = 0sec;
redef Log::flush_interval = 0.01sec;

global finish: event() &is_used;
# @TEST-END-FILE

# @TEST-START-FILE manager.zeek
@load ./common.zeek

global nodes_down: set[string] = { "manager" };
global done = F;

# Poll the manager-written notice.log until both HRW notices have landed, then
# broadcast `finish` until every node goes down.
event check_log()
	{
	if ( ! done && file_size("DONE") < 0 )
		system("../check-log.sh");
	if ( file_size("DONE") >= 0 )
		done = T;
	if ( done )
		{
		Cluster::publish(Cluster::worker_topic, finish);
		Cluster::publish(Cluster::proxy_topic, finish);
		}
	schedule 0.2sec { check_log() };
	}

event Cluster::node_down(name: string, id: string)
	{
	add nodes_down[name];
	if ( |nodes_down| == |Cluster::nodes| )
		terminate();
	}

event zeek_init()
	{
	schedule 0.2sec { check_log() };
	}
# @TEST-END-FILE

# @TEST-START-FILE node.zeek
@load ./common.zeek

event finish()
	{
	terminate();
	}

# Workers must not replay the trace before the proxy and manager are peered:
# an event published before peering is dropped, and a 187-frame pcap is read in
# milliseconds. Hold packet processing until both are up.
@if ( Cluster::local_node_type() == Cluster::WORKER )
global peers_up: set[string];

event zeek_init()
	{
	suspend_processing();
	}

event Cluster::node_up(name: string, id: string)
	{
	add peers_up[name];
	if ( "proxy" in peers_up && "manager" in peers_up )
		continue_processing();
	}
@endif
# @TEST-END-FILE

# @TEST-START-FILE check-log.sh
#!/bin/sh
# Touch DONE once notice.log carries both HRW-deduplicated notices.
LOG=notice.log
[ -f DONE ] && exit 0
[ -f "$LOG" ] || exit 0
if grep -q Crash_Sequence "$LOG" && grep -q Affected_PHP_Version "$LOG"; then
	# give late duplicates a moment to arrive so the count assertion is honest
	sleep 2
	echo "DONE" > DONE
fi
exit 0
# @TEST-END-FILE
