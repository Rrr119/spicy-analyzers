##! Log stream for Spicy analyzer parse failures. Loading this module adds a
##! ``spicy_analyzer_failures.log`` with one row per classified failure.

@load ./main

module SpicyAnalyzerFailures;

export {
	redef enum Log::ID += { LOG };

	type Info: record {
		ts:          time   &log;
		analyzer:    string &log;
		category:    string &log;
		reason:      string &log;
		data_len:    count  &log;
		uid:         string &log;
		sample_path: string &log;
	};

	## Whether to write the failure log. Set to F in scripts to disable.
	option log_failures: bool = T &redef;
}

event zeek_init()
	{
	Log::create_stream(LOG, [$columns=Info, $path="spicy_analyzer_failures"]);
	}

event failure(info: FailureInfo)
	{
	if ( ! log_failures )
		return;

	Log::write(LOG, Info($ts=info$ts,
	                     $analyzer=info$analyzer,
	                     $category=cat(info$category),
	                     $reason=info$reason,
	                     $data_len=info$data_len,
	                     $uid=info$uid,
	                     $sample_path=info$sample_path));
	}
