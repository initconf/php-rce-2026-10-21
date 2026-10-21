# Every notice the package defines must fire exactly once on the synthetic trace
# (10 flows built by Traces/make-multipart-shapes.py; flows 1 and 10 are controls).
# @TEST-EXEC: zeek -C -r $TRACES/multipart-shapes.pcap $PACKAGE
# @TEST-EXEC: zeek-cut id.orig_p note sub < notice.log | sort -n > notices.out
# @TEST-EXEC: btest-diff notices.out
# @TEST-EXEC: zeek-cut src_port sig_id < signatures.log > sigs.out
# @TEST-EXEC: btest-diff sigs.out
