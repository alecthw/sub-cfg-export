#!/usr/bin/env python3
"""Extract configuration URLs and optional decrypt key/iv from supported installers."""

from __future__ import annotations

import argparse
import lzma
import mmap
import os
import re
import struct
import sys
import tempfile
from collections import defaultdict
from pathlib import Path
from urllib.parse import urlsplit


URL_JSON_RE = re.compile(
    rb"https?://[A-Za-z0-9.-]+(?::[0-9]{1,5})?"
    rb"/[A-Za-z0-9._~!$&()*+,;=:@%/+-]*?\.json",
    re.IGNORECASE,
)
HEX16_RE = re.compile(rb"[0-9a-fA-F]{16}\Z")
SNAPSHOT_MAGIC = b"\xf5\xf5\xdc\xdc"
INNO_LZMA_MARKER = b"zlb\x1a"


class ExtractionError(RuntimeError):
    pass


def _unique(items):
    return list(dict.fromkeys(items))


def _read_unsigned(data, pos: int, end: int):
    value = 0
    shift = 0
    while pos < end and shift <= 63:
        byte = data[pos]
        pos += 1
        if byte > 0x7F:
            return value | ((byte - 0x80) << shift), pos
        value |= byte << shift
        shift += 7
    raise ValueError("truncated compact unsigned integer")


def _read_compact_signed(data, pos: int, end: int, bits: int):
    value = 0
    shift = 0
    while pos < end and shift < bits:
        byte = data[pos]
        pos += 1
        if byte > 0x7F:
            value |= (byte - 0xC0) << shift
            mask = (1 << bits) - 1
            value &= mask
            if value & (1 << (bits - 1)):
                value -= 1 << bits
            return value, pos
        value |= byte << shift
        shift += 7
    raise ValueError("truncated compact signed integer")


def _read_ref_id(data, pos: int, end: int):
    value = 0
    for _ in range(4):
        if pos >= end:
            raise ValueError("truncated reference id")
        byte = data[pos]
        pos += 1
        signed_byte = byte if byte < 0x80 else byte - 0x100
        value = signed_byte + (value << 7)
        if signed_byte < 0:
            return value + 0x80, pos
    raise ValueError("invalid reference id")


def _lzma2_dict_size(prop: int) -> int:
    if not 0 <= prop <= 40:
        raise ValueError(f"invalid LZMA2 property: {prop}")
    if prop == 40:
        return 0xFFFFFFFF
    return (2 | (prop & 1)) << (prop // 2 + 11)


def _decompress_inno_payload(installer: bytes):
    offsets = []
    start = 0
    while True:
        offset = installer.find(INNO_LZMA_MARKER, start)
        if offset < 0:
            break
        offsets.append(offset)
        start = offset + 1

    if not offsets:
        raise ExtractionError("未找到 Inno Setup LZMA2 数据块")

    last_error = None
    for offset in offsets:
        output = tempfile.TemporaryFile()
        try:
            prop_pos = offset + len(INNO_LZMA_MARKER)
            if prop_pos >= len(installer):
                raise ValueError("LZMA2 property missing")
            dictionary = _lzma2_dict_size(installer[prop_pos])
            decoder = lzma.LZMADecompressor(
                format=lzma.FORMAT_RAW,
                filters=[{"id": lzma.FILTER_LZMA2, "dict_size": dictionary}],
            )
            source_pos = prop_pos + 1
            while source_pos < len(installer) and not decoder.eof:
                chunk = installer[source_pos : source_pos + 1024 * 1024]
                source_pos += len(chunk)
                decoded = decoder.decompress(chunk)
                if decoded:
                    output.write(decoded)
            if not decoder.eof:
                raise lzma.LZMAError("LZMA2 stream did not reach end marker")
            if output.tell() < 1024:
                raise lzma.LZMAError("decompressed payload is unexpectedly small")
            output.seek(0)
            return output
        except (ValueError, lzma.LZMAError) as exc:
            last_error = exc
            output.close()

    raise ExtractionError(f"Inno Setup 数据块解压失败: {last_error}")


def _extract_json_urls(data):
    urls = []
    for match in URL_JSON_RE.finditer(data):
        try:
            url = match.group(0).decode("ascii")
            parsed = urlsplit(url)
        except (UnicodeDecodeError, ValueError):
            continue
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            continue
        urls.append(url)
    return _unique(urls)


def _snapshot_candidates(data):
    candidates = []
    search_pos = 0
    data_len = len(data)
    while True:
        start = data.find(SNAPSHOT_MAGIC, search_pos)
        if start < 0:
            break
        search_pos = start + 1
        try:
            if start + 52 >= data_len:
                continue
            stored_length = struct.unpack_from("<q", data, start + 4)[0]
            total_length = stored_length + 4
            if total_length < 128 or start + total_length > data_len:
                continue
            version = bytes(data[start + 20 : start + 52])
            if not re.fullmatch(rb"[0-9a-f]{32}", version):
                continue
            features_end = data.find(b"\0", start + 52, min(start + 4096, data_len))
            if features_end < 0:
                continue
            features = bytes(data[start + 52 : features_end])
            pos = features_end + 1
            values = []
            for _ in range(5):
                value, pos = _read_unsigned(data, pos, start + total_length)
                values.append(value)
            num_base, num_objects, num_clusters, _, _ = values
            if num_objects <= num_base or num_clusters <= 0:
                continue
            candidates.append(
                {
                    "start": start,
                    "end": start + total_length,
                    "cluster_pos": pos,
                    "num_base": num_base,
                    "num_objects": num_objects,
                    "num_clusters": num_clusters,
                    "features": features,
                }
            )
        except (ValueError, struct.error):
            continue
    return candidates


def _parse_small_integer_refs(data, snapshot):
    pos = snapshot["cluster_pos"]
    end = snapshot["end"]

    string_tags, pos = _read_compact_signed(data, pos, end, 32)
    string_count, pos = _read_unsigned(data, pos, end)
    if not 100 <= string_count <= snapshot["num_objects"]:
        raise ValueError("unexpected Dart string cluster")

    for _ in range(string_count):
        _, pos = _read_unsigned(data, pos, end)

    # Canonical String clusters store their hash-table layout after offsets.
    if string_tags & 0x02:
        _, pos = _read_unsigned(data, pos, end)  # table length
        first_element, pos = _read_unsigned(data, pos, end)
        if first_element > string_count:
            raise ValueError("invalid Dart canonical string layout")
        for _ in range(string_count - first_element):
            _, pos = _read_unsigned(data, pos, end)

    _, pos = _read_compact_signed(data, pos, end, 32)  # Mint cluster tags
    integer_count, pos = _read_unsigned(data, pos, end)
    if not 128 <= integer_count <= snapshot["num_objects"]:
        raise ValueError("unexpected Dart integer cluster")

    first_ref = 1 + snapshot["num_base"] + string_count
    ref_values = {}
    for index in range(integer_count):
        value, pos = _read_compact_signed(data, pos, end, 64)
        if 0 <= value <= 255:
            ref_values[first_ref + index] = value

    if len(ref_values) < 64:
        raise ValueError("Dart integer cluster does not contain a byte alphabet")
    return ref_values, pos


def _decode_smi_arrays(data, snapshot):
    try:
        ref_values, scan_start = _parse_small_integer_refs(data, snapshot)
    except ValueError:
        return [], []

    end = snapshot["end"]
    max_ref = snapshot["num_objects"]
    urls = []
    hex_values = []
    seen_arrays = set()

    for candidate_pos in range(scan_start, max(scan_start, end - 12)):
        try:
            length, pos = _read_unsigned(data, candidate_pos, end)
        except ValueError:
            continue
        if not 8 <= length <= 512:
            continue

        try:
            type_ref, pos = _read_ref_id(data, pos, end)
        except ValueError:
            continue
        if not 0 < type_ref <= max_ref:
            continue

        values = bytearray()
        valid = True
        for _ in range(length):
            try:
                ref_id, pos = _read_ref_id(data, pos, end)
            except ValueError:
                valid = False
                break
            value = ref_values.get(ref_id)
            if value is None:
                valid = False
                break
            values.append(value)
        if not valid:
            continue

        raw = bytes(values)
        marker = (candidate_pos, raw)
        if marker in seen_arrays:
            continue
        seen_arrays.add(marker)

        # URL arrays used by these clients are either plain ASCII or protected
        # with a one-byte XOR. Derive likely masks from the expected "h" prefix.
        masks = {0, raw[0] ^ ord("h"), raw[0] ^ ord("H")}
        for mask in masks:
            decoded = bytes(byte ^ mask for byte in raw)
            match = URL_JSON_RE.fullmatch(decoded)
            if match:
                urls.append((candidate_pos, match.group(0).decode("ascii")))

        if length == 16 and HEX16_RE.fullmatch(raw):
            text = raw.decode("ascii").lower()
            if text not in {
                "0123456789abcdef",
                "0123456789abcdeF".lower(),
            }:
                hex_values.append((candidate_pos, text))

    return urls, hex_values


def _select_snapshot_info(data):
    snapshots = _snapshot_candidates(data)
    snapshots.sort(
        key=lambda item: (item["num_clusters"], item["num_objects"]),
        reverse=True,
    )
    for snapshot in snapshots:
        if snapshot["num_clusters"] < 100:
            continue
        urls, hex_values = _decode_smi_arrays(data, snapshot)
        if urls:
            return urls, hex_values
    return [], []


def _basename(url: str) -> str:
    return urlsplit(url).path.rsplit("/", 1)[-1].lower()


def _select_config_urls(all_urls, dart_urls):
    preferred = [url for _, url in dart_urls]
    source = preferred or all_urls
    if not source:
        raise ExtractionError("未找到配置 JSON URL")

    groups = defaultdict(list)
    for url in source:
        groups[_basename(url)].append(url)

    def score(item):
        name, urls = item
        hosts = {urlsplit(url).hostname for url in urls}
        hint = int(any(word in name for word in ("config", "news", "oss")))
        return len(hosts), len(_unique(urls)), hint, len(name)

    _, selected = max(groups.items(), key=score)
    selected = _unique(selected)

    # Keep URLs of the same host together while preserving the host's first
    # appearance. This also keeps an HTTP/HTTPS pair in the natural order.
    host_rank = {}
    original_rank = {url: index for index, url in enumerate(selected)}
    for url in selected:
        host = urlsplit(url).hostname or ""
        host_rank.setdefault(host, len(host_rank))
    selected.sort(
        key=lambda url: (
            host_rank[urlsplit(url).hostname or ""],
            0 if urlsplit(url).scheme.lower() == "http" else 1,
            original_rank[url],
        )
    )

    # This family uses a recognizable primary/fallback host convention.
    hosts = [urlsplit(url).hostname or "" for url in selected]
    if (
        len(selected) == 4
        and any(host.startswith("tcdn.") for host in hosts)
        and any(host.startswith("api") for host in hosts)
        and any(host.startswith("cdno") for host in hosts)
        and any(host.startswith("ocdn") for host in hosts)
    ):
        def host_order(url):
            host = urlsplit(url).hostname or ""
            if host.startswith("tcdn."):
                return 0
            if host.startswith("api"):
                return 1
            if host.startswith("cdno"):
                return 2
            if host.startswith("ocdn"):
                return 3
            return 4

        selected.sort(key=host_order)

    return selected


def _select_decrypt_values(selected_urls, dart_urls, hex_values):
    if not selected_urls or not dart_urls:
        return None

    selected_set = set(selected_urls)
    positions = [pos for pos, url in dart_urls if url in selected_set]
    if not positions:
        return None

    first_url_pos = min(positions)
    nearby = [
        (pos, value)
        for pos, value in hex_values
        if 0 < first_url_pos - pos <= 4096
    ]
    nearby.sort()
    if len(nearby) < 2:
        return None

    # In this client's initializer layout the IV text is serialized first,
    # followed by the AES key text, then the URL arrays.
    iv = nearby[-2][1]
    key = nearby[-1][1]
    if key == iv:
        return None
    return {"key": key, "iv": iv}


def extract_info(input_path: Path):
    installer = input_path.read_bytes()
    raw_urls = _extract_json_urls(installer)

    with _decompress_inno_payload(installer) as payload_file:
        payload_file.seek(0, os.SEEK_END)
        payload_size = payload_file.tell()
        payload_file.seek(0)
        with mmap.mmap(payload_file.fileno(), payload_size, access=mmap.ACCESS_READ) as payload:
            payload_urls = _extract_json_urls(payload)
            dart_urls, hex_values = _select_snapshot_info(payload)

    cfg_urls = _select_config_urls(_unique(raw_urls + payload_urls), dart_urls)
    decrypt = _select_decrypt_values(cfg_urls, dart_urls, hex_values)
    return {"cfgUrls": cfg_urls, "decrypt": decrypt}


def _yaml_scalar(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9:/?&=._~%+\-]+", value):
        return value
    return "'" + value.replace("'", "''") + "'"


def render_yaml(info) -> str:
    lines = ["cfgUrls:"]
    for url in info["cfgUrls"]:
        lines.append(f"  - {_yaml_scalar(url)}")
    lines.append("")
    lines.append("username:")
    lines.append("password:")
    lines.append("headers:")
    lines.append("  User-Agent: NetFlow/v3.0.6 clash-verge Platform/linux")
    if info.get("decrypt"):
        lines.append("decrypt:")
        lines.append(f"  key: {_yaml_scalar(info['decrypt']['key'])}")
        lines.append(f"  iv: {_yaml_scalar(info['decrypt']['iv'])}")
    else:
        lines.append("decrypt: null")
    return "\n".join(lines) + "\n"


def _write_atomic(output_path: Path, content: str):
    output_path.parent.mkdir(parents=True, exist_ok=True)
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="\n",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(content)
        os.replace(temporary, output_path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def build_parser():
    parser = argparse.ArgumentParser(
        description="从 mihomo/Flutter Inno Setup 客户端安装包导出配置 URL 和可选 key/iv"
    )
    parser.add_argument(
        "-f", "-file", "--file", dest="input_file", required=True, help="输入 EXE"
    )
    parser.add_argument(
        "-o", "-out", "--out", dest="output_file", required=True, help="输出 YAML"
    )
    return parser


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    input_path = Path(args.input_file).expanduser()
    output_path = Path(args.output_file).expanduser()

    try:
        if not input_path.is_file():
            raise ExtractionError(f"输入文件不存在: {input_path}")
        if input_path.resolve() == output_path.resolve():
            raise ExtractionError("输出文件不能覆盖输入安装包")

        info = extract_info(input_path)
        _write_atomic(output_path, render_yaml(info))
        return 0
    except (ExtractionError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
