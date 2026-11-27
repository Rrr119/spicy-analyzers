#!/usr/bin/env python3
"""Replay persisted Spicy analyzer failure samples offline.

For every ``*.bin`` sample produced by the ``SpicyAnalyzerFailures`` module
(optionally filtered by its ``*.meta`` sidecar) the tool:

1. wraps the raw bytes in a fresh UDP/IP/Ethernet pcap addressed to the
   analyzer's registered port from the sidecar,
2. runs Zeek with the given compiled Spicy analyzer (``.hlto``) and the
   failure tracking scripts,
3. checks that a violation with the same category is reproduced,
4. compares the re-emitted reason against the original sidecar reason.

A sample reproduces "the same error" when both the failure category and the
parser message (location suffix ignored) match. The tool exits non-zero if any
sample cannot be reproduced.
"""

import argparse
import json
import os
import re
import struct
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from make_trace import ipv4_checksum, write_pcap  # noqa: E402


LOCATION_RE = re.compile(r"\s*\([^)]*\.spicy:\d+:\d+-\d+:\d+\)\s*$")


def strip_location(reason: str) -> str:
    return LOCATION_RE.sub("", reason).strip()


def default_zeek_path(zeek_bin: str, env: dict) -> str:
    """Return Zeek's effective default script search path."""
    config = zeek_bin + "-config"
    if os.path.exists(config):
        result = subprocess.run(
            [config, "--zeekpath"], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()

    # Last resort: parse the path table printed by "zeek --help".
    result = subprocess.run(
        [zeek_bin, "--help"], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
    )
    match = re.search(r"\$ZEEKPATH\s*\|\s*file search path \(([^)]+)\)",
                      result.stdout)
    if match:
        return match.group(1)
    return "."


def wrap_udp(payload: bytes, dport: int, sport: int = 53999) -> bytes:
    eth = (
        b"\x02\x00\x00\x00\x00\x03"
        + b"\x02\x00\x00\x00\x00\x04"
        + struct.pack("!H", 0x0800)
    )
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0)
    src = b"\x0a\x00\x00\x09"
    dst = b"\x0a\x00\x00\x0a"
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45, 0, 20 + len(udp) + len(payload),
        0x4321, 0, 64, 17, 0, src, dst,
    )
    ip = ip[:10] + struct.pack("!H", ipv4_checksum(ip)) + ip[12:]
    return eth + ip + udp + payload


def port_from_meta(meta: dict) -> int:
    conn_id = meta.get("conn_id")
    if conn_id and "resp_p" in conn_id:
        return int(conn_id["resp_p"]["port"])
    return 43107


def find_samples(sample_dir: str):
    samples = []
    for name in sorted(os.listdir(sample_dir)):
        if not name.endswith(".bin"):
            continue
        data_path = os.path.join(sample_dir, name)
        meta_path = data_path[:-4] + ".meta"
        with open(data_path, "rb") as handle:
            payload = handle.read()
        meta = {}
        if os.path.exists(meta_path):
            with open(meta_path, "r", encoding="utf-8") as handle:
                meta = json.load(handle)
        samples.append((data_path, meta, payload))
    return samples


def parse_failure_log(log_path: str):
    rows = []
    if not os.path.exists(log_path):
        return rows
    with open(log_path, "r", encoding="utf-8") as handle:
        header = None
        for line in handle:
            if not line.strip():
                continue
            if line.startswith("#fields\t"):
                header = line.rstrip("\n").split("\t")[1:]
                continue
            if line[0] == "#":
                continue
            fields = line.rstrip("\n").split("\t")
            if header is None:
                continue
            rows.append(dict(zip(header, fields)))
    return rows


def replay_one(sample, hlto: str, scripts_dir: str, zeek_bin: str,
               category_expect: str):
    data_path, meta, payload = sample
    dport = port_from_meta(meta)
    original_reason = strip_location(meta.get("reason", ""))

    with tempfile.TemporaryDirectory(prefix="spicy-replay-") as workdir:
        pcap = os.path.join(workdir, "replay.pcap")
        write_pcap(pcap, [wrap_udp(payload, dport)])

        env = dict(os.environ)
        existing_path = env.get("ZEEKPATH", "")
        if not existing_path:
            # Resolve Zeek's own default search path so the replay works in
            # minimal environments where ZEEKPATH is not exported.
            existing_path = default_zeek_path(zeek_bin, env)
        env["ZEEKPATH"] = scripts_dir + os.pathsep + existing_path

        cmd = [
            zeek_bin,
            os.path.abspath(hlto),
            "SpicyAnalyzerFailures",
            "-r",
            pcap,
        ]
        result = subprocess.run(
            cmd, cwd=workdir, env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )

        if result.returncode != 0:
            return False, f"zeek exited {result.returncode}: {result.stdout.strip()}"

        rows = parse_failure_log(
            os.path.join(workdir, "spicy_analyzer_failures.log")
        )
        if not rows:
            return False, "no failure reproduced"

        row = rows[0]
        reproduced_category = row["category"].split("::")[-1]
        reproduced_reason = strip_location(row["reason"])

        if reproduced_category != category_expect:
            return False, (
                f"category mismatch: expected {category_expect}, "
                f"got {reproduced_category}"
            )

        if original_reason and reproduced_reason != original_reason:
            return False, (
                f"reason mismatch:\n  original: {original_reason}\n"
                f"  replay:   {reproduced_reason}"
            )

        return True, f"{reproduced_category}: {reproduced_reason}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sample_dir",
                        help="directory containing .bin/.meta failure samples")
    parser.add_argument("--hlto", required=True,
                        help="compiled Spicy analyzer (.hlto) to replay with")
    parser.add_argument("--scripts", required=True,
                        help="directory containing the SpicyAnalyzerFailures "
                             "scripts package")
    parser.add_argument("--zeek", default="zeek", help="zeek binary to use")
    args = parser.parse_args()

    samples = find_samples(args.sample_dir)
    if not samples:
        print(f"no samples found in {args.sample_dir}", file=sys.stderr)
        return 2

    failures = 0
    for data_path, meta, _payload in samples:
        category = meta.get("category", "").split("::")[-1] or "UNKNOWN"
        ok, detail = replay_one(
            (data_path, meta, _payload),
            os.path.abspath(args.hlto),
            os.path.abspath(args.scripts),
            args.zeek,
            category,
        )
        status = "OK  " if ok else "FAIL"
        print(f"[{status}] {os.path.basename(data_path)} -> {detail}")
        if not ok:
            failures += 1

    print(f"{len(samples) - failures}/{len(samples)} samples reproduced")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
