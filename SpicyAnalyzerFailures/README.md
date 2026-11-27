# Spicy Analyzer Failure Tracking

Spicy analyzers report parse failures through Zeek's analyzer violation
mechanism (`AnalyzerViolation`), which by default only surfaces in `dpd.log`
and is easy to lose. This package adds:

- **Classification** of every parse failure into one of four categories based
  on the parser's error message.
- **Counters** maintained per analyzer and per category.
- **Sample persistence**, writing the raw bytes that triggered the failure
  plus a JSON sidecar so the error can be reproduced offline.

The module is generic: it does not hardcode any analyzer name and works with
every analyzer registered through Zeek's normal analyzer registration
mechanism, including all Spicy analyzers bundled by this meta-package. It is
loaded automatically through the package's top-level `__load__.zeek`.

## Failure categories

| Category     | Typical Spicy error                                                        |
| ------------ | -------------------------------------------------------------------------- |
| `TRUNCATED`  | `expected 5 bytes (2 available)`, unexpected end of data                   |
| `CONSTRAINT` | `&requires failed: ...`, custom `require` messages such as `length too large` |
| `FORMAT`     | `expected bytes literal "PROBE" but input starts with "XROBE"`, no matching case, failed regex |
| `OTHER`      | Any error that does not match the built-in patterns                        |

Classification is implemented with ordered regular expressions in
`main.zeek`; extend `re_truncated`/`re_constraint`/`re_format` to recognize
additional parser messages.

## Outputs

- `spicy_analyzer_failures.log`: one row per failure (time, analyzer,
  category, raw reason, payload length, connection UID, sample path).
- `spicy-failures/` (configurable): for each failure, a `<name>.bin` file with
  the exact violating bytes and a `<name>.meta` JSON sidecar containing the
  category, reason and connection 4-tuple needed to replay it.
- `SpicyAnalyzerFailures::counters`: in-memory
  `table[analyzer] of table[Category] of count`, also summarized at shutdown.
- `SpicyAnalyzerFailures::failure`: event raised for every classified failure.

## Configuration

```zeek
redef SpicyAnalyzerFailures::sample_dir = "spicy-failures";       # "" disables samples
redef SpicyAnalyzerFailures::max_samples_per_category = 100;      # 0 = unlimited
redef SpicyAnalyzerFailures::max_sample_bytes = 65536;            # 0 = unlimited
redef SpicyAnalyzerFailures::ignored_analyzers = set("SPICY_DNS");
redef SpicyAnalyzerFailures::log_failures = F;                    # keep counters but no log
```

Set `SPICY_ANALYZER_FAILURES_DEBUG` in the environment to print each failure
as it is recorded.

## Offline reproduction

Persisted samples are self-contained. `tests/tools/replay_failures.py` wraps a
sample's bytes back into a UDP pcap (using the sidecar's destination port),
runs Zeek with the same compiled analyzer, and asserts that the replay
produces the identical category and parser message:

```sh
python3 tests/tools/replay_failures.py spicy-failures \
    --hlto tests/analyzer/faildemo.hlto \
    --scripts .
```

The location suffix of the parser message (e.g. `(faildemo.spicy:22:16-...)`)
is ignored when comparing, since line numbers can shift between builds.

## Compatibility

- Zeek 5.2 and newer use the unified `analyzer_violation_info` event, which
  carries the violating data chunk and works for protocol, file and packet
  analyzers.
- Older Zeek versions (4.x / 5.0 / 5.1) are supported through
  `analyzer_violation`; those releases fold the bytes into the reason string,
  so classification and counters work but sample persistence is unavailable
  there.
