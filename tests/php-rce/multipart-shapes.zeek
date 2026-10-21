# @TEST-DOC: Standalone: every notice the package defines fires on the synthetic trace
# (15 flows built by Traces/make-multipart-shapes.py; flows 1, 10 and 15 are controls; flow 11 Many_Parts and flow 12 Progress_With_Sid are
# suppressed by the notice framework because they share an identifier with flows 4 and 2).
#
# @TEST-EXEC: zeek -C -r $TRACES/multipart-shapes.pcap $PACKAGE
# @TEST-EXEC: zeek-cut id.orig_p note sub < notice.log | sort -n > notices.out
# @TEST-EXEC: test "$(grep -c PHPUploadProgress notices.out)" = "12"
# @TEST-EXEC: grep -q Crash_Sequence notices.out
# @TEST-EXEC: grep -q Affected_PHP_Version notices.out
# @TEST-EXEC: btest-diff notices.out
# @TEST-EXEC: zeek-cut src_port sig_id < signatures.log > sigs.out
# @TEST-EXEC: btest-diff sigs.out
