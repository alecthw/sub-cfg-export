#!/usr/bin/env python3
"""Extract configuration URLs and optional decrypt key/iv from supported installers."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
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
    rb"https?://(?:[A-Za-z0-9.-]+|\[[0-9a-fA-F:]+\])(?::[0-9]{1,5})?"
    rb"/[A-Za-z0-9._~!$&()*+,;=:@%/+-]*?\.json",
    re.IGNORECASE,
)
HEX16_RE = re.compile(rb"[0-9a-fA-F]{16}\Z")
SNAPSHOT_MAGIC = b"\xf5\xf5\xdc\xdc"
INNO_LZMA_MARKER = b"zlb\x1a"
DEFAULT_USER_AGENT = "NetFlow/v2.2.4 clash-verge Platform/windows"


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
    app_entry = None
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
            if app_entry:
                digest = hashlib.sha256()
                while chunk := output.read(1024 * 1024):
                    digest.update(chunk)
                if output.tell() != app_entry['size'] or digest.hexdigest() != app_entry['sha256']:
                    output.close()
                    continue
                output.seek(0)
                return output
            if output.tell() == 0:
                prefix = output.read(1)
                output.seek(0)
                if prefix == b'{':
                    try:
                        manifest = json.load(output)
                        app_entry = next((f for f in manifest.get('files', []) if f.get('path') == 'data/app.so'), None)
                    except (ValueError, AttributeError):
                        pass
                    output.seek(0)
                    if app_entry:
                        output.close()
                        continue
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
    modern_tags = string_tags >= 0x1000
    first_ref = 1 + snapshot["num_base"]
    ref_values = {}
    if modern_tags:
        # Dart 3.13 uses object-header tags and may emit singleton clusters
        # before String. Count their references and retain Mint(0), which
        # also occurs in XOR-obfuscated URL arrays.
        sized_clusters = {23, 24, 25, 26, 27, 28, 30, 90, 91}
        cluster_count = 0
        while string_tags >> 12 != 93:
            cluster_count += 1
            if cluster_count >= snapshot["num_clusters"]:
                raise ValueError("Dart String cluster missing")
            cid = string_tags >> 12
            if cid != 61 and cid not in sized_clusters:
                raise ValueError("unsupported Dart prefix cluster")
            count, pos = _read_unsigned(data, pos, end)
            if count > snapshot["num_objects"] - first_ref + 1:
                raise ValueError("invalid Dart cluster object count")
            for index in range(count):
                if cid == 61:
                    value, pos = _read_compact_signed(data, pos, end, 64)
                    if 0 <= value <= 255:
                        ref_values[first_ref + index] = value
                else:
                    _, pos = _read_unsigned(data, pos, end)
            first_ref += count
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

    integer_tags, pos = _read_compact_signed(data, pos, end, 32)
    if modern_tags and integer_tags >> 12 != 61:
        raise ValueError("unexpected Dart Mint cluster")
    integer_count, pos = _read_unsigned(data, pos, end)
    if not 128 <= integer_count <= snapshot["num_objects"]:
        raise ValueError("unexpected Dart integer cluster")

    first_ref += string_count
    for index in range(integer_count):
        value, pos = _read_compact_signed(data, pos, end, 64)
        if 0 <= value <= 255:
            ref_values[first_ref + index] = value

    if len(ref_values) < 64:
        raise ValueError("Dart integer cluster does not contain a byte alphabet")
    return ref_values, pos


def _decode_smi_arrays(data, snapshot, subscription_passwords=None):
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

        if subscription_passwords is not None and length == 12:
            try:
                parts = [raw]
                next_pos = pos
                for _ in range(2):
                    next_length, next_pos = _read_unsigned(data, next_pos, end)
                    if next_length != 10:
                        raise ValueError("unexpected seed part")
                    next_type, next_pos = _read_ref_id(data, next_pos, end)
                    if not 0 < next_type <= max_ref:
                        raise ValueError("invalid seed type")
                    part = []
                    for _ in range(10):
                        ref, next_pos = _read_ref_id(data, next_pos, end)
                        part.append(ref_values[ref])
                    parts.append(bytes(part))
                first = bytes(v ^ 0x5a ^ ((i + 0xc3) & 0xff) for i, v in enumerate(parts[2]))
                second = bytes((v - 0x3c - i) & 0xff for i, v in enumerate(parts[1]))
                third = []
                for i, v in enumerate(parts[0]):
                    byte, shift = v ^ 0xa7, i % 5 + 1
                    third.append(((byte >> shift) | (byte << (8 - shift))) & 0xff)
                seed = first + second + bytes(third)
                if re.fullmatch(b"[0-9a-f]{32}", seed):
                    subscription_passwords.append(seed.decode("ascii"))
            except (ValueError, KeyError):
                pass

        if subscription_passwords is not None and length == 16:
            candidates = {bytes(v ^ mask for v in raw) for mask in range(1, 256)}
            candidates = {v.decode("ascii").lower() for v in candidates if HEX16_RE.fullmatch(v)}
            if len(candidates) == 1:
                subscription_passwords.extend(candidates)

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


def _select_snapshot_info(data, subscription_passwords=None):
    snapshots = _snapshot_candidates(data)
    snapshots.sort(
        key=lambda item: (item["num_clusters"], item["num_objects"]),
        reverse=True,
    )
    for snapshot in snapshots:
        if snapshot["num_clusters"] < 100:
            continue
        passwords = [] if subscription_passwords is not None else None
        urls, hex_values = _decode_smi_arrays(data, snapshot, passwords)
        if urls:
            if subscription_passwords is not None:
                subscription_passwords.extend(passwords)
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
    lite_family = len(selected_urls) == 4 and all(
        re.search(r"/saos/(?:xjkp|xmtz)_news\.json$", urlsplit(url).path, re.IGNORECASE)
        for url in selected_urls
    )
    if not selected_urls or not dart_urls:
        return None

    selected_set = set(selected_urls)
    positions = [pos for pos, url in dart_urls if url in selected_set]
    if not positions:
        return None

    if lite_family:
        last_url_pos = max(positions)
        following = sorted(
            (pos, value)
            for pos, value in hex_values
            if 0 < pos - last_url_pos <= 64 * 1024
        )[:2]
        if len(following) == 2 and following[0][1] != following[1][1]:
            return {"key": following[1][1], "iv": following[0][1]}

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


def _extract_product_version(installer: bytes):
    marker = "ProductVersion".encode("utf-16le")
    search_pos = 0
    while True:
        marker_pos = installer.find(marker, search_pos)
        if marker_pos < 0:
            return None
        text = installer[marker_pos : marker_pos + 512].decode(
            "utf-16le", errors="ignore"
        )
        match = re.search(r"\d+\.\d+\.\d+", text)
        if match:
            return match.group(0)
        search_pos = marker_pos + len(marker)


def _extract_user_agent(installer: bytes, payload):
    brand = next(
        (value.decode("ascii") for value in (b"NetFlow", b"SecurityNet", b"securitynet") if payload.find(value) >= 0),
        None,
    )
    version = _extract_product_version(installer)
    has_clash_verge = payload.find(b"clash-verge") >= 0
    if payload.find(b"Platform/windows") >= 0:
        platform = "windows"
    elif payload.find(b"Platform/linux") >= 0:
        platform = "linux"
    else:
        platform = None
    if not brand or not version or not has_clash_verge or not platform:
        return DEFAULT_USER_AGENT
    return f"{brand}/v{version} clash-verge Platform/{platform}"


def _extract_apex(data, installer):
    if data.find(b'apex-config-v1') < 0:
        return None
    snapshots = sorted(_snapshot_candidates(data), key=lambda v: v['num_clusters'], reverse=True)
    for snap in snapshots:
        if snap['num_clusters'] < 100:
            continue
        end = snap['end']
        pos = snap['cluster_pos']
        tags, pos = _read_compact_signed(data, pos, end, 32)
        if tags >> 12 != 93:
            continue
        count, pos = _read_unsigned(data, pos, end)
        if count > snap['num_objects']:
            continue
        image = (end + 63) // 64 * 64
        strings = {}
        offset = 0
        for i in range(count):
            delta, pos = _read_unsigned(data, pos, end)
            offset += delta * 16
            address = image + offset
            if address + 16 > len(data):
                raise ExtractionError('Apex Dart 字符串地址越界')
            cid = struct.unpack_from('<I', data, address)[0] >> 12
            length = struct.unpack_from('<Q', data, address + 8)[0] // 2
            width = 1 if cid == 94 else 2
            if cid not in (94, 95) or length > 100000 or address + 16 + length * width > len(data):
                raise ExtractionError('Apex Dart 字符串对象无效')
            strings[snap['num_base'] + 1 + i] = data[address+16:address+16+length*width].decode('latin1' if width == 1 else 'utf-16le')
        best = []
        pos = snap['cluster_pos']
        while pos < end:
            start = pos
            refs = []
            try:
                while pos < end:
                    bits = data[pos]
                    pos += 1
                    typ, behavior = bits & 15, bits >> 5
                    ref = None
                    if typ not in (0, 1, 2):
                        raise ValueError()
                    if not behavior:
                        if typ == 1:
                            ref, pos = _read_ref_id(data, pos, end)
                            if not 0 < ref <= snap['num_objects']:
                                raise ValueError()
                        elif typ == 0:
                            _, pos = _read_compact_signed(data, pos, end, 64)
                    refs.append(strings.get(ref))
            except ValueError:
                pass
            if len(refs) > len(best):
                best = refs
            pos = max(start + 1, pos)
        try:
            ci = best.index('apex-config-v1')
            si = best.index('apex-sub-sign-v2\0')
        except ValueError:
            continue
        keys = _unique(v for v in best if isinstance(v, str) and re.fullmatch('[A-Za-z0-9]{32}', v) and len(re.findall('[0-9]', v)) >= 2 and re.search('[A-Z]', v) and re.search('[a-z]', v))
        if len(keys) != 1:
            raise ExtractionError('Apex XOR 密钥不唯一，无法可靠提取')
        tls = {}
        for value in strings.values():
            if not value.startswith('eyJ') or len(value) < 500:
                continue
            try:
                bundle = json.loads(base64.b64decode(value, validate=True))
                if bundle.get('version') == 1 and bundle.get('purpose') in ('oss', 'api', 'subscription'):
                    tls[bundle['purpose']] = bundle
            except (ValueError, AttributeError):
                pass
        if set(tls) != {'oss', 'api', 'subscription'} or len({b['profile_id'] for b in tls.values()}) != 1:
            raise ExtractionError('Apex 客户端证书不完整或品牌不一致')
        apex = dict(xorKey=keys[0], configPublicKey=best[ci+1], subscriptionPublicKey=best[si-2], subscriptionKey=best[si-3], flag='apex', profileId=1, keyId=1, mtls=tls)
        for field in ('configPublicKey', 'subscriptionPublicKey', 'subscriptionKey'):
            if not isinstance(apex[field], str) or len(base64.b64decode(apex[field], validate=True)) != 32:
                raise ExtractionError('Apex 密钥长度无效')
        urls = _unique(v for v in best if isinstance(v, str) and re.fullmatch(URL_JSON_RE, v.encode('ascii', errors='replace')) and '_apex' in v)
        if not urls:
            raise ExtractionError('Apex 配置 URL 缺失')
        packages = _unique(v for v in strings.values() if re.fullmatch(r'ua\.net\.[a-z0-9]+\.app\.apex', v))
        version = _extract_product_version(installer)
        if len(packages) != 1 or not version:
            raise ExtractionError('Apex 应用标识或版本缺失')
        return {'cfgUrls': urls, 'userAgent': f'{packages[0]}/v{version}', 'decrypt': None, 'subscriptionDecrypt': None, 'apex': apex}
    raise ExtractionError('未找到有效的 Apex Dart 常量池')


def extract_info(input_path: Path):
    installer = input_path.read_bytes()
    raw_urls = _extract_json_urls(installer)

    with _decompress_inno_payload(installer) as payload_file:
        payload_file.seek(0, os.SEEK_END)
        payload_size = payload_file.tell()
        payload_file.seek(0)
        with mmap.mmap(payload_file.fileno(), payload_size, access=mmap.ACCESS_READ) as payload:
            apex = _extract_apex(payload, installer)
            if apex:
                return apex
            payload_urls = _extract_json_urls(payload)
            subscription_passwords = []
            dart_urls, hex_values = _select_snapshot_info(payload, subscription_passwords)
            user_agent = _extract_user_agent(installer, payload)

    cfg_urls = _select_config_urls(_unique(raw_urls + payload_urls), dart_urls)
    decrypt = _select_decrypt_values(cfg_urls, dart_urls, hex_values)
    passwords = _unique(subscription_passwords)
    subscription_decrypt = {"type": "aes-256-gcm", "password": passwords[0]} if len(passwords) == 1 else None
    return {"cfgUrls": cfg_urls, "userAgent": user_agent, "decrypt": decrypt,
            "subscriptionDecrypt": subscription_decrypt}


def _yaml_scalar(value: str) -> str:
    if re.fullmatch(r"[A-Za-z0-9:/?&=._~%+\-]+", value):
        return value
    return "'" + value.replace("'", "''") + "'"


def render_yaml(info) -> str:
    lines = ["cfgUrls:"]
    for url in info["cfgUrls"]:
        lines.append(f"  - {_yaml_scalar(url)}")
    lines.append("username:")
    lines.append("password:")
    lines.append("headers:")
    lines.append(f"  User-Agent: {info['userAgent']}")
    if info.get("decrypt"):
        lines.append("decrypt:")
        lines.append(f"  key: {_yaml_scalar(info['decrypt']['key'])}")
        lines.append(f"  iv: {_yaml_scalar(info['decrypt']['iv'])}")
    else:
        lines.append("decrypt: null")
    if info.get("subscriptionDecrypt"):
        lines.append("subscriptionDecrypt:")
        lines.append("  type: aes-256-gcm")
        lines.append(f"  password: {_yaml_scalar(info['subscriptionDecrypt']['password'])}")
    if info.get('apex'):
        lines.append('apex: ' + json.dumps(info['apex'], ensure_ascii=True, separators=(',', ':')))
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
