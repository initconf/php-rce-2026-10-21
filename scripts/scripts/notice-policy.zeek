##! Site policy for the PHP 2026-10-21 RCE notices. Default: log only. Uncomment the
##! actions once the first day of production hits has been reviewed.

hook Notice::policy(n: Notice::Info)
	{
	if ( n$note == PHPUploadProgress::Progress_With_Sid ||
	     n$note == PHPUploadProgress::Crash_Sequence )
		{
		# Full consumer shape / producer->consumer pair of CVE-2026-109619's
		# session path; rare in benign traffic.
		add n$actions[Notice::ACTION_EMAIL];
		#add n$actions[Notice::ACTION_DROP];
		#Notice::email_notice_to(n, "ir-reports@lbl.gov", T);
		}

	if ( n$note == PHPUploadProgress::Multipart_No_Reply ||
	     n$note == PHPUploadProgress::Multipart_5xx )
		{
		# Outcome signals: corroboration, never drop on these alone.
		#add n$actions[Notice::ACTION_EMAIL];
		}

	if ( n$note == PHPUploadProgress::Many_Parts ||
	     n$note == PHPUploadProgress::Many_Part_Headers ||
	     n$note == PHPUploadProgress::Many_Empty_Files ||
	     n$note == PHPUploadProgress::Deep_Nesting ||
	     n$note == PHPUploadProgress::Large_Form_Key ||
	     n$note == PHPUploadProgress::Multipart_No_Length )
		{
		# CVE-2026-109618 request shapes (vendor publishes no thresholds; tune &redefs first).
		#add n$actions[Notice::ACTION_DROP];
		}

	if ( n$note == PHPUploadProgress::Affected_PHP_Version )
		{
		# Inventory: one per server+version per hour. Feed to the patch tracker.
		}
	}
