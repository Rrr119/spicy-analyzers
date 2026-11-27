##! Track parse failures of Spicy analyzers without dropping them silently.
##!
##! Spicy analyzers report parse failures through Zeek's analyzer violation
##! mechanism. This module hooks those violations, classifies them into a
##! small set of failure categories, keeps per-analyzer/per-category counters,
##! and can persist the offending bytes to disk so that a failure can be
##! reproduced offline.
##!
##! The module is generic: it does not hardcode any analyzer names and works
##! with every Spicy (and non-Spicy) analyzer registered through Zeek's normal
##! analyzer registration mechanism.

module SpicyAnalyzerFailures;

export {

	## Failure categories derived from the parser's error message.
	##!
	##! TRUNCATED:
	##! 	The input ended before the parser could consume a field, e.g.
	##! 	"expected 5 bytes (2 available)".
	##!
	##! CONSTRAINT:
	##! 	A grammar constraint (``&requires``/``require``) rejected the
	##! 	parsed values, e.g. "&requires failed: ..." or a custom message.
	##!
	##! FORMAT:
	##! 	The bytes did not match the grammar, e.g. a failed literal,
	##! 	regular expression, switch case, or unit alternative.
	##!
	##! OTHER:
	##! 	An error that does not match any of the patterns above.
	type Category: enum {
		TRUNCATED,
		CONSTRAINT,
		FORMAT,
		OTHER,
	};

	## One recorded parse failure.
	type FailureInfo: record {
		ts:            time;
		analyzer:      string;  ##< Analyzer tag name, e.g. "ANALYZER_SPICY_DNS".
		category:      Category;
		reason:        string;  ##< Raw parser error message.
		data_len:      count;   ##< Number of bytes that triggered the failure.
		uid:           string  &default="";
		conn_id:       conn_id &optional;
		sample_path:   string  &default="";
	};

	## Where to write failure samples. An empty string disables persisting
	##! samples (classification and counters stay active). The directory is
	##! created on demand.
	option sample_dir: string = "spicy-failures";

	## Maximum number of samples persisted per (analyzer, category) pair.
	##! Once the cap is reached, counting continues but no more files are
	##! written. A value of 0 removes the limit.
	option max_samples_per_category: count = 100;

	## Persist a sample only when the violating data chunk is at most this
	##! many bytes long. A value of 0 removes the limit.
	option max_sample_bytes: count = 65536;

	## Analyzers whose violations should be ignored entirely.
	option ignored_analyzers: set[string] = set();

	## Number of failures recorded, keyed by analyzer tag name and category.
	global counters: table[string] of table[Category] of count &redef;

	## All failures recorded during the run (subject to memory growth on
	##! long runs; counters remain the compact aggregation).
	global failures: vector of FailureInfo &redef;

	## Raised for every classified parse failure after counters and the
	##! optional sample have been handled.
	global failure: event(info: FailureInfo);

	## Classify a raw parser error message into one of the categories.
	global classify_failure: function(reason: string): Category;

	## Return the per-category failure counters for one analyzer. An unknown
	##! analyzer yields an empty table.
	global get_counter: function(analyzer: string): table[Category] of count;
}

# Patterns are ordered from most specific to most generic. They cover the
# error strings emitted by the Spicy runtime (see its ParseError messages);
# the location suffix "(file.spicy:line:col)" is ignored on purpose. RE2 does
# not support non-capturing groups, so plain alternation is used.
const re_truncated: pattern = /.*(expected [0-9]+ bytes \([0-9]+ available\)|unexpected end of data|not enough data|ran out of data|truncated).*/;
const re_constraint: pattern = /.*(&requires failed|requirement failed|require failed|constraint violation|constraint failed|assertion failed|too large|too small|out of range|value .* not allowed).*/;
const re_format: pattern = /.*(expected .* but|expected .* got|no matching case|failed to match|could not parse|invalid |unknown |unsupported |parse error).*/;

function classify_failure(reason: string): Category
	{
	if ( reason == re_truncated )
		return TRUNCATED;

	if ( reason == re_constraint )
		return CONSTRAINT;

	if ( reason == re_format )
		return FORMAT;

	return OTHER;
	}

function analyzer_name(atype: AllAnalyzers::Tag): string
	{
	if ( is_protocol_analyzer(atype) )
		return Analyzer::name(atype);

	if ( is_file_analyzer(atype) )
		return Files::analyzer_name(atype);

	return cat(atype);
	}

function get_counter(analyzer: string): table[Category] of count
	{
	if ( analyzer in counters )
		return counters[analyzer];

	return table();
	}

# Track how many samples were written per (analyzer, category) so the cap
# works even across reconnects.
global samples_written: table[string] of table[Category] of count;

function sample_limit_reached(analyzer: string, category: Category): bool
	{
	if ( max_samples_per_category == 0 )
		return F;

	if ( analyzer !in samples_written ||
	     category !in samples_written[analyzer] )
		return F;

	return samples_written[analyzer][category] >= max_samples_per_category;
	}

function sample_too_large(data: string): bool
	{
	return max_sample_bytes != 0 && |data| > max_sample_bytes;
	}

# "SpicyAnalyzerFailures::TRUNCATED" -> "TRUNCATED", for compact file names.
function short_category(category: Category): string
	{
	return gsub(cat(category), /.*::/, "");
	}

# Persist the raw bytes that caused the failure alongside a sidecar file
# describing how to reproduce the error offline.
function persist_sample(analyzer: string, category: Category, reason: string,
                        data: string, uid: string,
                        cid: conn_id, have_cid: bool): string
	{
	if ( sample_dir == "" || sample_limit_reached(analyzer, category) ||
	     sample_too_large(data) )
		return "";

	if ( ! mkdir(sample_dir) && ! mkdir(fmt("%s/.", sample_dir)) )
		{
		Reporter::warning(fmt("SpicyAnalyzerFailures: cannot create sample directory %s",
		                      sample_dir));
		return "";
		}

	local stamp = strftime("%Y%m%d-%H%M%S", network_time());

	if ( analyzer !in samples_written )
		samples_written[analyzer] = table();

	if ( category !in samples_written[analyzer] )
		samples_written[analyzer][category] = 0;

	local seq = samples_written[analyzer][category];
	local basename = fmt("%s/%s-%s-%s-%06d", sample_dir, stamp, analyzer,
	                     short_category(category), seq);
	local data_path = fmt("%s.bin", basename);
	local meta_path = fmt("%s.meta", basename);

	local fh = open(data_path);
	if ( ! write_file(fh, data) || ! close(fh) )
		{
		Reporter::warning(fmt("SpicyAnalyzerFailures: failed to write sample %s",
		                      data_path));
		return "";
		}

	local meta = FailureInfo($ts=network_time(), $analyzer=analyzer,
	                         $category=category, $reason=reason,
	                         $data_len=|data|, $uid=uid,
	                         $sample_path=data_path);

	if ( have_cid )
		meta$conn_id = cid;

	local meta_fh = open(meta_path);
	if ( ! write_file(meta_fh, to_json(meta)) || ! close(meta_fh) )
		{
		Reporter::warning(fmt("SpicyAnalyzerFailures: failed to write metadata %s",
		                      meta_path));
		return "";
		}

	samples_written[analyzer][category] += 1;
	return data_path;
	}

function handle_violation(atype: AllAnalyzers::Tag, reason: string,
                          data: string, have_data: bool,
                          uid: string, cid: conn_id, have_cid: bool)
	{
	local analyzer = analyzer_name(atype);

	if ( analyzer in ignored_analyzers )
		return;

	local category = classify_failure(reason);

	if ( analyzer !in counters )
		counters[analyzer] = table();

	if ( category !in counters[analyzer] )
		counters[analyzer][category] = 0;

	counters[analyzer][category] += 1;

	local data_len = have_data ? |data| : 0;
	local info = FailureInfo($ts=network_time(), $analyzer=analyzer,
	                         $category=category, $reason=reason,
	                         $data_len=data_len, $uid=uid);

	if ( have_cid )
		info$conn_id = cid;

	if ( have_data )
		info$sample_path = persist_sample(analyzer, category, reason, data,
		                                  uid, cid, have_cid);

	local idx = |failures|;
	failures += info;

	event failure(info);

	if ( getenv("SPICY_ANALYZER_FAILURES_DEBUG") != "" )
		print fmt("[SpicyAnalyzerFailures] #%d %s/%s: %s (sample=%s)",
		          idx, analyzer, cat(category), reason, info$sample_path);
	}

# Zeek 5.2+ unified violation event covering protocol, file and packet
# analyzers. The violating chunk is carried in info$data when available.
@if ( Version::number >= 50200 )
event analyzer_violation_info(atype: AllAnalyzers::Tag,
                              info: AnalyzerViolationInfo)
	{
	local uid = "";
	local cid: conn_id;
	local have_cid = F;

	if ( info?$c )
		{
		uid = info$c$uid;
		cid = info$c$id;
		have_cid = T;
		}

	if ( info?$data )
		handle_violation(atype, info$reason, info$data, T, uid,
		                 cid, have_cid);
	else
		handle_violation(atype, info$reason, "", F, uid,
		                 cid, have_cid);
	}
@endif

# Pre-5.2 compatibility. In Zeek 5.0/5.1 violations arrive through
# analyzer_violation; the raw bytes are folded into the reason string (e.g.
# 'reason [hex bytes...]') rather than exposed as a separate field, so only
# classification and counters are available there.
@if ( Version::number < 50200 )
event analyzer_violation(c: connection, atype: Analyzer::Tag, aid: count,
                         reason: string)
	{
	handle_violation(atype, reason, "", F, c$uid, c$id, T);
	}
@endif

event zeek_done()
	{
	if ( |failures| == 0 )
		return;

	print fmt("SpicyAnalyzerFailures: %d parse failure(s) recorded",
	          |failures|);

	for ( analyzer in counters )
		for ( category in counters[analyzer] )
			print fmt("SpicyAnalyzerFailures: %s [%s] = %d",
			          analyzer, cat(category),
			          counters[analyzer][category]);
	}
