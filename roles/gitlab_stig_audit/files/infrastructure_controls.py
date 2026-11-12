"""Bounded read-only infrastructure collector; no raw log text or key material output."""
import datetime
import glob
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

_deadline = None


def command(argv, payload=None):
    try:
        remaining = 8 if _deadline is None else min(8, _deadline - time.monotonic())
        if remaining <= 0:
            return -1, ""
        result = subprocess.run(argv, input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=remaining)
        return result.returncode, result.stdout[:65536].decode("utf-8", "replace")
    except (OSError, subprocess.TimeoutExpired):
        return -1, ""


def absolute_path(value):
    return isinstance(value, str) and os.path.isabs(value) and "\x00" not in value


def bounded_read(path, limit, tail=False):
    if not absolute_path(path):
        raise ValueError("absolute path required")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(descriptor, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise ValueError("regular file required")
        if tail:
            stream.seek(0, 2)
            size = stream.tell()
            stream.seek(max(0, size - limit))
            if size > limit:
                stream.readline()
            return stream.read(limit)
        content = stream.read(limit + 1)
        if len(content) > limit:
            raise ValueError("read limit exceeded")
        return content


def entries(config, key, maximum, out):
    values = config.get(key, {})
    if not isinstance(values, dict):
        out["errors"].append(key + ": expected a name-to-path mapping")
        return []
    if len(values) > maximum:
        out["errors"].append(key + ": collection truncated")
    return list(values.items())[:maximum]


def collect(config):
    global _deadline
    _deadline = time.monotonic() + 45
    out = {"errors": [], "clock": {}, "timestamp_logs": {}, "trust_bundles": {}, "retired_paths": {}, "cipher_scans": {}, "public_certificates": {}, "key_storage": {}}
    rc, tracking = command(["chronyc", "-n", "tracking"])
    # Tracking output contains reference/offset metadata only; retain selected numeric facts.
    clock = out["clock"]
    clock["tracking_available"] = rc == 0 and "Reference ID" in tracking
    for key, pattern in (("update_interval_seconds", r"Update interval\s*:\s*([0-9.]+)"),
                         ("system_offset_seconds", r"System time\s*:\s*([0-9.]+)")):
        match = re.search(pattern, tracking)
        if match:
            clock[key] = float(match.group(1))
    rc, sources = command(["chronyc", "-n", "sources"])
    clock["sources_available"] = rc == 0
    clock["selected_sources"] = [parts[1] for line in sources.splitlines() for parts in [line.split()] if len(parts) > 1 and parts[0] in ("^*", "=*", "#*")]
    clock["configured_sources"] = []
    paths = ["/etc/chrony.conf"] + list(glob.iglob("/etc/chrony.d/*.conf"))[:32]
    clock["configuration_complete"] = True
    for path in paths:
        try:
            for line in bounded_read(path, 65536).decode("utf-8", "replace").splitlines():
                parts = shlex.split(line, comments=True)
                if parts and parts[0] in ("include", "confdir", "sourcedir"):
                    clock["configuration_complete"] = False  # reference review must expand dynamic/include scope
                if len(parts) >= 2 and parts[0] in ("server", "pool", "peer"):
                    row = {"type": parts[0], "source": parts[1]}
                    for option in ("minpoll", "maxpoll"):
                        if option in parts:
                            index = parts.index(option) + 1
                            if index < len(parts) and re.fullmatch(r"-?\d+", parts[index]):
                                row[option] = int(parts[index])
                    clock["configured_sources"].append(row)
        except (OSError, ValueError):
            clock["configuration_complete"] = False

    seconds = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
    minutes = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?")
    for name, path in entries(config, "timestamp_logs", 16, out):
        item = {"seconds_count": 0, "coarse_count": 0, "unknown_count": 0}
        out["timestamp_logs"][name] = item
        try:
            for line in bounded_read(path, 65536, True).decode("utf-8", "replace").splitlines()[-200:]:
                try:
                    row = json.loads(line)
                    value = row.get("time") or row.get("created_at") or row.get("timestamp") if isinstance(row, dict) else None
                    if not isinstance(value, str):
                        raise ValueError("unknown timestamp")
                    # Validate calendar/time components as well as declared resolution.
                    length = 19 if seconds.fullmatch(value) else 16 if minutes.fullmatch(value) else 0
                    if not length:
                        raise ValueError("unrecognized timestamp format")
                    datetime.datetime.strptime(value[:length].replace(" ", "T"), "%Y-%m-%dT%H:%M:%S" if length == 19 else "%Y-%m-%dT%H:%M")
                    if seconds.fullmatch(value):
                        item["seconds_count"] += 1
                    elif minutes.fullmatch(value):
                        item["coarse_count"] += 1
                    else:
                        item["unknown_count"] += 1
                except (ValueError, TypeError, AttributeError):
                    item["unknown_count"] += 1
        except (OSError, ValueError):
            item["unavailable"] = True

    for name, path in entries(config, "trust_bundles", 8, out):
        item = {"complete": False, "fingerprints": []}
        out["trust_bundles"][name] = item
        try:
            content = bounded_read(path, 1048576)
            certificates = re.findall(b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", content, re.S)
            if not certificates or len(certificates) > 256:
                raise ValueError("empty or oversized certificate inventory")
            for certificate in certificates:
                rc, output = command(["openssl", "x509", "-noout", "-fingerprint", "-sha256"], certificate)
                match = re.search(r"=([0-9A-Fa-f:]+)", output)
                digest = match.group(1).replace(":", "").lower() if match else ""
                if rc != 0 or not re.fullmatch(r"[a-f0-9]{64}", digest):
                    raise ValueError("certificate fingerprint unavailable")
                item["fingerprints"].append(digest)
            # Alternate certificate encodings/objects must be inventoried separately.
            remainder = re.sub(b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", b"", content, flags=re.S)
            if b"-----BEGIN" in remainder:
                raise ValueError("unprocessed PEM objects present")
            item["complete"] = True
        except (OSError, ValueError):
            item["error"] = "Incomplete PEM certificate inventory"

    for name, paths in entries(config, "retired_paths", 64, out):
        item = {"complete": True, "paths": {}}
        out["retired_paths"][name] = item
        if not isinstance(paths, list) or not paths or len(paths) > 64:
            item["complete"] = False
            continue
        for path in paths:
            if not absolute_path(path):
                item["complete"] = False
                continue
            # lstat distinguishes genuinely absent paths from permission/access errors.
            try:
                os.lstat(path)
                item["paths"][path] = True
            except FileNotFoundError:
                item["paths"][path] = False
            except OSError:
                item["complete"] = False
    for name, path in entries(config, "public_certificates", 8, out):
        item = {"complete": False, "policy_oids": []}
        out["public_certificates"][name] = item
        try:
            content = bounded_read(path, 65536)
            cert = re.search(b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", content, re.S)
            if not cert:
                raise ValueError("public leaf certificate unavailable")
            rc, text = command(["openssl", "x509", "-noout", "-text", "-fingerprint", "-sha256", "-dates"], cert.group(0))
            match = re.search(r"Fingerprint=([0-9A-Fa-f:]+)", text)
            digest = match.group(1).replace(":", "").lower() if match else ""
            if rc != 0 or not re.fullmatch(r"[a-f0-9]{64}", digest):
                raise ValueError("certificate metadata unavailable")
            item["fingerprint"] = digest
            item["policy_oids"] = sorted(set(re.findall(r"Policy:\s*([0-9]+(?:\.[0-9]+)+)", text)))
            for key, openssl_key in (("not_before", "notBefore"), ("not_after", "notAfter")):
                value = re.search(r"^" + openssl_key + r"=(.+)$", text, re.M)
                if not value:
                    raise ValueError("certificate validity unavailable")
                parsed = datetime.datetime.strptime(value.group(1).strip(), "%b %d %H:%M:%S %Y GMT")
                item[key] = parsed.replace(tzinfo=datetime.timezone.utc).isoformat()
            item["complete"] = True
        except (OSError, ValueError):
            item["error"] = "Incomplete public-certificate metadata"

    for name, path in entries(config, "key_storage", 32, out):
        item = {"complete": False}
        out["key_storage"][name] = item
        if not absolute_path(path):
            continue
        try:
            info = os.stat(path)
            item.update(exists=True, owner_uid=info.st_uid, group_gid=info.st_gid,
                        mode=format(stat.S_IMODE(info.st_mode), "04o"), resolved_path=os.path.realpath(path),
                        world_readable=bool(info.st_mode & 0o004), world_writable=bool(info.st_mode & 0o002))
            rc, acl = command(["getfacl", "-p", "--absolute-names", "--", path])
            item["acl_available"] = rc == 0
            if rc == 0:
                item["acl_metadata"] = acl
            item["complete"] = True
        except FileNotFoundError:
            item["exists"] = False
        except OSError:
            pass
        # Deliberately never open/read the key path, even to hash it.

    # Optional, explicitly configured single-port TLS enumeration. Missing Nmap
    # and local crypto limitations remain inconclusive; they never prove absence.
    for name, endpoint in entries(config, "cipher_endpoints", 4, out):
        item = {"complete": False, "accepted_ciphers": [], "protocols": []}
        out["cipher_scans"][name] = item
        if not isinstance(endpoint, dict):
            continue
        host, port = endpoint.get("host"), endpoint.get("port", 443)
        if not isinstance(host, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.:-]*", host) or type(port) is not int or not 1 <= port <= 65535:
            continue
        rc, xml = command(["nmap", "-Pn", "-sT", "-p", str(port), "--script", "ssl-enum-ciphers", "--script-timeout", "5s", "--host-timeout", "7s", "-oX", "-", "--", host])
        if rc != 0:
            continue
        try:
            tree = ET.fromstring(xml)
            for script in tree.findall(".//script[@id='ssl-enum-ciphers']"):
                for protocol in script.findall("table"):
                    key = protocol.get("key", "")
                    if key.startswith(("TLS", "SSL")):
                        item["protocols"].append(key)
                    for cipher in protocol.findall("table[@key='ciphers']/table/elem[@key='name']"):
                        if cipher.text:
                            item["accepted_ciphers"].append(cipher.text)
            item["complete"] = bool(item["accepted_ciphers"])
        except ET.ParseError:
            pass
    return out


if __name__ == "__main__":
    try:
        config = json.loads(sys.argv[1])
        if not isinstance(config, dict):
            raise ValueError("configuration must be a mapping")
        print(json.dumps(collect(config)))
    except (ValueError, IndexError):
        print(json.dumps({"errors": ["Invalid infrastructure collector configuration"]}))
