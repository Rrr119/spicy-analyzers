#!/usr/bin/env bash
# End-to-end acceptance check for Spicy analyzer parse-failure tracking.
#
# It verifies that
#   1. the three kinds of malformed datagrams shipped in tests/traces are
#      classified into TRUNCATED, FORMAT and CONSTRAINT respectively,
#   2. per-analyzer/per-category counters are maintained,
#   3. every failure sample is persisted to disk, and
#   4. each persisted sample reproduces the same error offline.
#
# Requirements: zeek and the Spicy toolchain (spicyz) on PATH, plus a C++
# compiler for spicyz. The Spicy module search path is derived from
# `spicy-config --prefix`; set SPICY_LIBRARY_PATHS to override it.

set -euo pipefail

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
analyzer_dir="${root_dir}/tests/analyzer"
traces_dir="${root_dir}/tests/traces"
tools_dir="${root_dir}/tests/tools"
# Package root doubles as the zkg script_dir: it contains __load__.zeek and
# the SpicyAnalyzerFailures module directory.
scripts_dir="${root_dir}"

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

hlto="${analyzer_dir}/faildemo.hlto"
if [[ ! -f "${hlto}" || "${analyzer_dir}/faildemo.spicy" -nt "${hlto}" || \
      "${analyzer_dir}/faildemo.evt" -nt "${hlto}" ]]; then
    echo "==> Compiling FailDemo Spicy analyzer"
    prefix="$(spicy-config --prefix)"
    if [[ ! -d "${prefix}/share/hilti" ]]; then
        # Relocated toolchain (e.g. unpacked .deb into a home directory):
        # spicy-config reports the compile-time prefix, so derive the real
        # one from the spicyz binary instead.
        prefix="$(dirname "$(dirname "$(readlink -f "$(command -v spicyz)")")")"
    fi
    library_paths=()
    if [[ -n "${SPICY_LIBRARY_PATHS:-}" ]]; then
        IFS=':' read -ra library_paths <<< "${SPICY_LIBRARY_PATHS}"
    else
        library_paths=(
            "${prefix}/share/hilti"
            "${prefix}/share/spicy"
            "${prefix}/share/zeek/spicy"
        )
    fi

    path_args=()
    for path in "${library_paths[@]}"; do
        [[ -d "${path}" ]] && path_args+=("-L" "${path}")
    done

    (
        cd "${analyzer_dir}"
        spicyz "${path_args[@]}" -o faildemo.hlto faildemo.evt faildemo.spicy
    )
fi

echo "==> Running Zeek on malformed trace"
(
    cd "${work_dir}"
    export ZEEKPATH="${scripts_dir}${ZEEKPATH:+:${ZEEKPATH}}"
    zeek "${hlto}" SpicyAnalyzerFailures \
        -r "${traces_dir}/malformed-all.pcap"
)

failure_log="${work_dir}/spicy_analyzer_failures.log"
sample_dir="${work_dir}/spicy-failures"

echo "==> Checking classification and counters"
status=0
for category in TRUNCATED FORMAT CONSTRAINT; do
    if ! grep -qP "\tSpicyAnalyzerFailures::${category}\t" "${failure_log}"; then
        echo "FAIL: expected category ${category} not found in failure log" >&2
        status=1
    fi
done

row_count="$(grep -cvP '^#' "${failure_log}")"
if [[ "${row_count}" -ne 3 ]]; then
    echo "FAIL: expected 3 failure rows, got ${row_count}" >&2
    status=1
fi

bin_count="$(find "${sample_dir}" -name '*.bin' | wc -l | tr -d ' ')"
meta_count="$(find "${sample_dir}" -name '*.meta' | wc -l | tr -d ' ')"
if [[ "${bin_count}" -ne 3 || "${meta_count}" -ne 3 ]]; then
    echo "FAIL: expected 3 .bin and 3 .meta samples, got ${bin_count}/${meta_count}" >&2
    status=1
fi

echo "==> Replaying failure samples offline"
if ! python3 "${tools_dir}/replay_failures.py" "${sample_dir}" \
        --hlto "${hlto}" --scripts "${scripts_dir}"; then
    echo "FAIL: offline replay did not reproduce all errors" >&2
    status=1
fi

if [[ "${status}" -eq 0 ]]; then
    echo
    echo "ACCEPTANCE PASSED: 3 malformed packets classified correctly and" \
         "reproduced offline"
fi

exit "${status}"
