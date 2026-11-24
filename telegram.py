import asyncio
import base64
import hashlib
import hmac as hmac_mod
import ipaddress
import json
import os
import random
import socket
import struct
import time
from datetime import datetime, timezone
from urllib.parse import quote as _url_quote

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

DC_SEEDS = {
    1: ["149.154.175.50", "149.154.175.51", "149.154.175.52"],
    2: ["149.154.167.51", "149.154.167.50", "149.154.167.41"],
    3: ["149.154.175.100"],
    4: ["149.154.167.91", "149.154.167.92"],
    5: ["149.154.171.5", "91.108.56.130", "91.108.56.156"],
}

TG_NETWORKS = [
    ipaddress.ip_network("91.108.4.0/22"),
    ipaddress.ip_network("91.108.56.0/22"),
    ipaddress.ip_network("149.154.160.0/20"),
    ipaddress.ip_network("149.154.164.0/22"),
    ipaddress.ip_network("149.154.168.0/22"),
    ipaddress.ip_network("149.154.172.0/22"),
    ipaddress.ip_network("91.105.192.0/18"),
]

TLS_START_BYTES = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03"
TLS_HELLO_LEN = 517
TAG_ABRIDGED = b"\xef\xef\xef\xef"
TAG_INTERMEDIATE = b"\xee\xee\xee\xee"
TAG_PADDED = b"\xdd\xdd\xdd\xdd"
VALID_TAGS = (TAG_ABRIDGED, TAG_INTERMEDIATE, TAG_PADDED)

_SECRET = b""
_DOMAIN = "www.google.com"
_AUTH_LOOKUP = None
_COUNT_TRAFFIC = None
_MTPROXY_QUOTA_OK = None
_SESSION_ALLOWED = None
ACTIVE_PROXY = {}
_SERVERS = []
_STATS = {"socks_connections": 0, "socks_bytes": 0, "mtproxy_connections": 0, "mtproxy_bytes": 0, "http_connections": 0, "http_bytes": 0}
_REPLAY = {}
_FAKE_TLS_REPLAY = {}


def configure(secret, domain="www.google.com"):
    global _SECRET, _DOMAIN
    if not isinstance(secret, (bytes, bytearray)) or len(secret) != 16:
        raise ValueError("mtproxy secret must be 16 bytes")
    _SECRET = bytes(secret)
    _DOMAIN = domain or "www.google.com"


def secret_hex():
    return _SECRET.hex()


def mtproxy_link(host, port):
    return "tg://proxy?server=" + str(host) + "&port=" + str(port) + "&secret=" + _SECRET.hex()


def mtproxy_faketls_link(host, port):
    return "tg://proxy?server=" + str(host) + "&port=" + str(port) + "&secret=ee" + _SECRET.hex() + _DOMAIN.encode().hex()


def mtproxy_dd_link(host, port):
    return "tg://proxy?server=" + str(host) + "&port=" + str(port) + "&secret=dd" + _SECRET.hex()



_MTPROXY_LINK_SECRETS = {}


def mtproxy_secret_for_uid(uid):
    return hashlib.sha256(_SECRET + b"mtproxy-link-v1\x00" + str(uid).encode("utf-8")).digest()[:16]


def mtproxy_register_link(uid):
    secret = mtproxy_secret_for_uid(uid)
    _MTPROXY_LINK_SECRETS[str(uid)] = secret
    return secret


def mtproxy_unregister_link(uid):
    _MTPROXY_LINK_SECRETS.pop(str(uid), None)


def mtproxy_link_for_uid(host, port, uid, variant="dd", domain="www.google.com"):
    secret = mtproxy_secret_for_uid(uid)
    if variant == "faketls":
        dom = (domain or "www.google.com").strip() or "www.google.com"
        return "tg://proxy?server=" + str(host) + "&port=" + str(port) + "&secret=" + "dd" + secret.hex() + dom.encode("utf-8").hex()
    if variant == "plain":
        return "tg://proxy?server=" + str(host) + "&port=" + str(port) + "&secret=" + secret.hex()
    return "tg://proxy?server=" + str(host) + "&port=" + str(port) + "&secret=" + "dd" + secret.hex()


def mtproxy_links_for_uid(host, port, uid, domain="www.google.com"):
    return {
        "plain": mtproxy_link_for_uid(host, port, uid, "plain", domain),
        "dd": mtproxy_link_for_uid(host, port, uid, "dd", domain),
        "faketls": mtproxy_link_for_uid(host, port, uid, "faketls", domain),
    }


def socks5_link(host, port, username, password):
    return "socks5://" + _url_quote(str(username), safe="") + ":" + _url_quote(str(password), safe="") + "@" + str(host) + ":" + str(port)


def http_proxy_link(host, port, username, password):
    return "http://" + _url_quote(str(username), safe="") + ":" + _url_quote(str(password), safe="") + "@" + str(host) + ":" + str(port)


def _mtproxy_candidates():
    out = []
    for uid, secret in list(_MTPROXY_LINK_SECRETS.items()):
        out.append((uid, secret))
    return out


def _mtproxy_match_plain(init):
    if init[0] == 0xEF:
        return None, None
    for uid, secret in _mtproxy_candidates():
        try:
            enc_key, enc_iv, dec_key, dec_iv = _derive_obfs_keys(init, secret)
            decryptor = _aes_ctr(enc_key, enc_iv).decryptor()
            plain = decryptor.update(init)
        except (ValueError, TypeError):
            continue
        tag = plain[56:60]
        if tag not in VALID_TAGS:
            continue
        dc_id = struct.unpack("<h", plain[60:62])[0]
        dc = abs(dc_id)
        if dc >= 10000:
            dc -= 10000
        if dc < 1 or dc > 5:
            continue
        return secret, uid
    return None, None


def _mtproxy_match_faketls(hello):
    zeroed = hello[:11] + b"\x00" * 32 + hello[43:]
    received = hello[11:43]
    for uid, secret in _mtproxy_candidates():
        digest = hmac_mod.new(secret, zeroed, hashlib.sha256).digest()
        xored = bytes(a ^ b for a, b in zip(received, digest))
        if xored[:28] == b"\x00" * 28:
            return secret, uid, xored
    return None, None, None

def stats():
    return dict(_STATS)


def is_telegram_ip(ip_str):
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    for net in TG_NETWORKS:
        if ip in net:
            return True
    return False


def _aes_ctr(key, iv):
    return Cipher(algorithms.AES(key), modes.CTR(iv))


def _derive_obfs_keys(init, secret):
    enc_key_raw = init[8:40]
    enc_iv = init[40:56]
    rev = init[::-1]
    dec_key_raw = rev[8:40]
    dec_iv = rev[40:56]
    if secret:
        enc_key = hashlib.sha256(enc_key_raw + secret).digest()
        dec_key = hashlib.sha256(dec_key_raw + secret).digest()
    else:
        enc_key = enc_key_raw
        dec_key = dec_key_raw
    return enc_key, enc_iv, dec_key, dec_iv


def _build_obfs_init(tag, dc_id):
    init = bytearray(os.urandom(64))
    while init[0] == 0xEF:
        init[0] = os.urandom(1)[0]
    init[56:60] = tag
    init[60:62] = struct.pack("<h", dc_id)
    enc_key, enc_iv, _dk, _di = _derive_obfs_keys(bytes(init), b"")
    cipher = _aes_ctr(enc_key, enc_iv).encryptor()
    encrypted = cipher.update(bytes(init))
    return bytes(init[:56]) + encrypted[56:64], cipher, bytes(init)


async def _read_exact(reader, n):
    data = b""
    while len(data) < n:
        chunk = await reader.read(n - len(data))
        if not chunk:
            raise ConnectionError("connection closed while reading")
        data += chunk
    return data


async def _tls_read_record(reader):
    header = await _read_exact(reader, 5)
    rtype = header[0]
    length = struct.unpack(">H", header[3:5])[0]
    if length > 18432:
        raise ConnectionError("tls record too large")
    payload = await _read_exact(reader, length) if length else b""
    return rtype, payload


async def _tls_read_data(reader, need):
    data = b""
    while len(data) < need:
        rtype, payload = await _tls_read_record(reader)
        if rtype == 0x14:
            continue
        if rtype != 0x17:
            raise ConnectionError("unexpected tls record")
        data += payload
    return data[:need], data[need:]


async def _tls_write(writer, data):
    offset = 0
    while offset < len(data):
        chunk = data[offset:offset + 16384]
        writer.write(b"\x17\x03\x03" + struct.pack(">H", len(chunk)) + chunk)
        await writer.drain()
        offset += len(chunk)


def _fake_tls_server_hello(hello, secret):
    client_random = hello[11:43]
    digest = hmac_mod.new(secret, client_random + hello, hashlib.sha256).digest()
    session_len = hello[43]
    session_id = hello[44:44 + session_len]
    body = b"\x03\x03" + digest + bytes([session_len]) + session_id + b"\x13\x01\x00"
    extensions = b"\x00\x2b\x00\x03\x02\x03\x04" + b"\x00\x33\x00\x26\x00\x1d\x00\x20" + os.urandom(32)
    body += struct.pack(">H", len(extensions)) + extensions
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    record = b"\x16\x03\x03" + struct.pack(">H", len(handshake)) + handshake
    record += b"\x14\x03\x03\x00\x01\x01"
    cert = os.urandom(2048)
    record += b"\x17\x03\x03" + struct.pack(">H", len(cert)) + cert
    return record


def active_proxy_sessions():
    out = []
    for s in list(ACTIVE_PROXY.values()):
        out.append({k: v for k, v in s.items() if k != "writer"})
    return out


def disconnect_proxy_session(sid):
    entry = ACTIVE_PROXY.get(sid)
    if entry is None:
        return False
    writer = entry.get("writer")
    if writer is not None:
        try:
            writer.close()
        except OSError:
            pass
    ACTIVE_PROXY.pop(sid, None)
    return True


async def _handle_mtproxy(reader, writer):
    _STATS["mtproxy_connections"] += 1
    upstream_reader = None
    upstream_writer = None
    client_enc = None
    client_dec = None
    up_enc = None
    up_dec = None
    tls_mode = False
    mt_sid = None
    mt_entry = None
    mt_uid = ""
    mt_secret = _SECRET
    mt_totals = {"up": 0, "down": 0, "up_flushed": 0, "down_flushed": 0}
    async def _mt_flush(direction, force=False):
        if not mt_uid or _COUNT_TRAFFIC is None:
            return True
        delta = mt_totals[direction] - mt_totals[direction + "_flushed"]
        if delta <= 0:
            return True
        if not force and delta < 1048576:
            return True
        ok = await _COUNT_TRAFFIC(mt_uid, delta)
        if ok:
            mt_totals[direction + "_flushed"] = mt_totals[direction]
            if mt_entry is not None:
                mt_entry["bytes_flushed"] = mt_totals["up_flushed"] + mt_totals["down_flushed"]
        return ok
    try:
        if _MTPROXY_QUOTA_OK is not None:
            if not await _MTPROXY_QUOTA_OK():
                writer.close()
                return
        first = await _read_exact(reader, 11)
        if first == TLS_START_BYTES:
            rest = await _read_exact(reader, TLS_HELLO_LEN - 11)
            hello = first + rest
            matched_secret, matched_uid, xored = _mtproxy_match_faketls(hello)
            if matched_secret is None:
                writer.close()
                return
            stamp = struct.unpack("<I", xored[28:32])[0]
            now = int(time.time())
            if stamp < now - 1200 or stamp > now + 600:
                writer.close()
                return
            replay_key = hmac_mod.new(matched_secret, hello[:11] + b"\x00" * 32 + hello[43:], hashlib.sha256).digest()[:16]
            if replay_key in _FAKE_TLS_REPLAY:
                writer.close()
                return
            _FAKE_TLS_REPLAY[replay_key] = now
            if len(_FAKE_TLS_REPLAY) > 65536:
                oldest = min(_FAKE_TLS_REPLAY, key=_FAKE_TLS_REPLAY.get)
                del _FAKE_TLS_REPLAY[oldest]
            mt_secret = matched_secret
            mt_uid = matched_uid
            writer.write(_fake_tls_server_hello(hello, mt_secret))
            await writer.drain()
            tls_mode = True
            init, leftover = await _tls_read_data(reader, 64)
            pending = leftover
        else:
            rest = await _read_exact(reader, 53)
            init = first + rest
            pending = b""
            matched_secret, matched_uid = _mtproxy_match_plain(init)
            if matched_secret is None:
                writer.close()
                return
            mt_secret = matched_secret
            mt_uid = matched_uid
        if not mt_uid:
            writer.close()
            return
        replay_key = hashlib.sha256(init).digest()[:16]
        if replay_key in _REPLAY:
            writer.close()
            return
        _REPLAY[replay_key] = time.time()
        if len(_REPLAY) > 65536:
            oldest = min(_REPLAY, key=_REPLAY.get)
            del _REPLAY[oldest]
        enc_key, enc_iv, dec_key, dec_iv = _derive_obfs_keys(init, mt_secret)
        decryptor = _aes_ctr(enc_key, enc_iv).decryptor()
        plain_init = decryptor.update(init)
        tag = plain_init[56:60]
        if tag not in VALID_TAGS:
            writer.close()
            return
        dc_id = struct.unpack("<h", plain_init[60:62])[0]
        dc = abs(dc_id)
        if dc >= 10000:
            dc -= 10000
        if dc < 1 or dc > 5:
            writer.close()
            return
        if mt_uid:
            peer = writer.get_extra_info("peername")
            cip = peer[0] if peer else ""
            if _SESSION_ALLOWED is not None and not _SESSION_ALLOWED(mt_uid, cip):
                writer.close()
                return
            if _COUNT_TRAFFIC is not None and not await _COUNT_TRAFFIC(mt_uid, 0):
                writer.close()
                return
        client_enc = _aes_ctr(dec_key, dec_iv).encryptor()
        client_dec = decryptor
        seeds = DC_SEEDS.get(dc, [])
        upstream_reader = None
        upstream_writer = None
        last_error = None
        for seed in seeds:
            try:
                upstream_reader, upstream_writer = await asyncio.wait_for(
                    asyncio.open_connection(seed, 443), timeout=10
                )
                break
            except (OSError, asyncio.TimeoutError) as exc:
                last_error = exc
        if upstream_writer is None:
            writer.close()
            return
        up_init, up_enc, up_orig = _build_obfs_init(tag, dc)
        upstream_writer.write(up_init)
        await upstream_writer.drain()
        _uk, _ui, up_dec_key, up_dec_iv = _derive_obfs_keys(up_orig, b"")
        up_dec = _aes_ctr(up_dec_key, up_dec_iv).decryptor()
        async def _client_write(data):
            if tls_mode:
                await _tls_write(writer, data)
            else:
                writer.write(data)
                await writer.drain()
        if pending:
            chunk = client_dec.update(pending)
            chunk = up_enc.update(chunk)
            upstream_writer.write(chunk)
            await upstream_writer.drain()
        async def _up_to_client():
            total = 0
            try:
                while True:
                    chunk = await upstream_reader.read(65536)
                    if not chunk:
                        break
                    chunk = up_dec.update(chunk)
                    chunk = client_enc.update(chunk)
                    await _client_write(chunk)
                    total += len(chunk)
                    mt_totals["down"] += len(chunk)
                    _STATS["mtproxy_bytes"] += len(chunk)
                    if mt_entry is not None:
                        mt_entry["bytes_down"] += len(chunk)
                    if mt_uid and not await _mt_flush("down"):
                        break
            except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
                pass
            finally:
                try:
                    writer.close()
                except OSError:
                    pass
            return total
        async def _client_to_up():
            total = 0
            try:
                while True:
                    if tls_mode:
                        rtype, payload = await _tls_read_record(reader)
                        if rtype == 0x14:
                            continue
                        if rtype != 0x17:
                            break
                        chunk = payload
                    else:
                        chunk = await reader.read(65536)
                    if not chunk:
                        break
                    chunk = client_dec.update(chunk)
                    chunk = up_enc.update(chunk)
                    upstream_writer.write(chunk)
                    await upstream_writer.drain()
                    total += len(chunk)
                    mt_totals["up"] += len(chunk)
                    _STATS["mtproxy_bytes"] += len(chunk)
                    if mt_entry is not None:
                        mt_entry["bytes_up"] += len(chunk)
                    if mt_uid and not await _mt_flush("up"):
                        break
            except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
                pass
            finally:
                try:
                    upstream_writer.close()
                except OSError:
                    pass
            return total
        peer = writer.get_extra_info("peername")
        mt_sid = "mtproxy-" + os.urandom(6).hex()
        mt_entry = {"id": mt_sid, "username": mt_uid, "protocol": "mtproto", "client_ip": peer[0] if peer else "", "started_at": datetime.now(timezone.utc).isoformat(), "bytes_up": 0, "bytes_down": 0, "bytes_flushed": 0, "writer": writer}
        ACTIVE_PROXY[mt_sid] = mt_entry
        await asyncio.gather(_client_to_up(), _up_to_client())
        if mt_uid:
            await _mt_flush("up", force=True)
            await _mt_flush("down", force=True)
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
        pass
    finally:
        try:
            writer.close()
        except OSError:
            pass
        if upstream_writer is not None:
            try:
                upstream_writer.close()
            except OSError:
                pass
        if mt_sid is not None:
            ACTIVE_PROXY.pop(mt_sid, None)

async def _handle_socks5(reader, writer):
    _STATS["socks_connections"] += 1
    link = None
    total_bytes = 0
    up_flushed = 0
    down_flushed = 0
    sid = None
    entry = None
    try:
        greeting = await _read_exact(reader, 2)
        if greeting[0] != 0x05:
            writer.close()
            return
        nmethods = greeting[1]
        methods = await _read_exact(reader, nmethods)
        if 0x02 in methods:
            writer.write(b"\x05\x02")
        else:
            writer.write(b"\x05\xff")
            await writer.drain()
            writer.close()
            return
        await writer.drain()
        auth_head = await _read_exact(reader, 2)
        if auth_head[0] != 0x01:
            writer.close()
            return
        ulen = auth_head[1]
        username = (await _read_exact(reader, ulen)).decode("utf-8", "ignore")
        plen = (await _read_exact(reader, 1))[0]
        password = (await _read_exact(reader, plen)).decode("utf-8", "ignore")
        if _AUTH_LOOKUP is not None:
            link = _AUTH_LOOKUP(username, password)
        if link is None:
            writer.write(b"\x01\x01")
            await writer.drain()
            writer.close()
            return
        if _SESSION_ALLOWED is not None:
            peer = writer.get_extra_info("peername")
            cip = peer[0] if peer else ""
            if not _SESSION_ALLOWED(username, cip):
                writer.write(b"\x01\x01")
                await writer.drain()
                writer.close()
                return
        writer.write(b"\x01\x00")
        await writer.drain()
        req = await _read_exact(reader, 4)
        if req[0] != 0x05:
            writer.close()
            return
        cmd = req[1]
        atyp = req[3]
        if cmd != 0x01:
            writer.write(b"\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return
        if atyp == 0x01:
            addr_bytes = await _read_exact(reader, 4)
            host = socket.inet_ntoa(addr_bytes)
            ips = [host]
        elif atyp == 0x03:
            dlen = (await _read_exact(reader, 1))[0]
            host = (await _read_exact(reader, dlen)).decode("utf-8", "ignore")
            loop = asyncio.get_running_loop()
            infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            ips = list({info[4][0] for info in infos})
        elif atyp == 0x04:
            addr_bytes = await _read_exact(reader, 16)
            host = socket.inet_ntop(socket.AF_INET6, addr_bytes)
            ips = [host]
        else:
            writer.write(b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return
        port = struct.unpack(">H", await _read_exact(reader, 2))[0]
        target_ip = None
        for ip in ips:
            if is_telegram_ip(ip):
                target_ip = ip
                break
        if target_ip is None:
            writer.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return
        uid = link.get("uid", "")
        if _COUNT_TRAFFIC is not None:
            if not await _COUNT_TRAFFIC(uid, 0):
                writer.write(b"\x05\x02\x00\x01\x00\x00\x00\x00\x00\x00")
                await writer.drain()
                writer.close()
                return
        try:
            target_reader, target_writer = await asyncio.wait_for(
                asyncio.open_connection(target_ip, port), timeout=10
            )
        except (OSError, asyncio.TimeoutError):
            writer.write(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")
            await writer.drain()
            writer.close()
            return
        bound = target_writer.get_extra_info("sockname")
        if bound and ":" in str(bound[0]):
            reply = b"\x05\x00\x00\x04" + socket.inet_pton(socket.AF_INET6, bound[0]) + struct.pack(">H", bound[1])
        elif bound:
            reply = b"\x05\x00\x00\x01" + socket.inet_aton(bound[0]) + struct.pack(">H", bound[1])
        else:
            reply = b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        writer.write(reply)
        await writer.drain()

        peer = writer.get_extra_info("peername")
        sid = "socks5-" + os.urandom(6).hex()
        entry = {"id": sid, "username": username, "protocol": "socks5", "client_ip": peer[0] if peer else "", "started_at": datetime.now(timezone.utc).isoformat(), "bytes_up": 0, "bytes_down": 0, "bytes_flushed": 0, "writer": writer}
        ACTIVE_PROXY[sid] = entry

        async def _count(n, direction):
            nonlocal total_bytes, up_flushed, down_flushed
            total_bytes += n
            _STATS["socks_bytes"] += n
            pending = 0
            if entry is not None:
                if direction == "up":
                    entry["bytes_up"] += n
                    pending = entry["bytes_up"] - up_flushed
                else:
                    entry["bytes_down"] += n
                    pending = entry["bytes_down"] - down_flushed
            if _COUNT_TRAFFIC is not None and pending >= 1048576:
                if await _COUNT_TRAFFIC(uid, pending):
                    if direction == "up":
                        up_flushed += pending
                    else:
                        down_flushed += pending
                    if entry is not None:
                        entry["bytes_flushed"] = up_flushed + down_flushed
                else:
                    try:
                        writer.close()
                    except OSError:
                        pass
                    try:
                        target_writer.close()
                    except OSError:
                        pass

        async def _relay(src, dst, direction):
            try:
                while True:
                    chunk = await src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
                    await _count(len(chunk), direction)
            except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
                pass
            finally:
                try:
                    dst.write_eof()
                except (AttributeError, OSError, RuntimeError):
                    try:
                        dst.close()
                    except OSError:
                        pass

        await asyncio.gather(_relay(reader, target_writer, "up"), _relay(target_reader, writer, "down"))
        try:
            target_writer.close()
        except OSError:
            pass
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
        pass
    finally:
        if link is not None and _COUNT_TRAFFIC is not None and total_bytes - (up_flushed + down_flushed) > 0:
            try:
                await _COUNT_TRAFFIC(link.get("uid", ""), total_bytes - (up_flushed + down_flushed))
            except (ConnectionError, asyncio.TimeoutError, OSError):
                pass
        if sid is not None:
            ACTIVE_PROXY.pop(sid, None)
        try:
            writer.close()
        except OSError:
            pass


async def _handle_http_proxy(reader, writer):
    _STATS["http_connections"] += 1
    link = None
    total_bytes = 0
    up_flushed = 0
    down_flushed = 0
    sid = None
    entry = None
    target_writer = None
    try:
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10.0)
        except (asyncio.IncompleteReadError, asyncio.TimeoutError, ConnectionError, OSError):
            writer.close()
            return
        text = head.decode("iso-8859-1", "ignore")
        lines = text.split("\r\n")
        parts = lines[0].split(" ")
        if len(parts) < 2 or parts[0].upper() != "CONNECT":
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        target = parts[1].strip()
        if ":" not in target:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        host, port_text = target.rsplit(":", 1)
        try:
            port = int(port_text)
        except ValueError:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        if port < 1 or port > 65535:
            writer.write(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                key, val = line.split(":", 1)
                headers[key.strip().lower()] = val.strip()
        username = ""
        password = ""
        auth = headers.get("proxy-authorization", "") or headers.get("authorization", "")
        if auth.lower().startswith("basic "):
            try:
                decoded = base64.b64decode(auth[6:].strip()).decode("utf-8", "ignore")
                if ":" in decoded:
                    username, password = decoded.split(":", 1)
            except (ValueError, TypeError):
                username = ""
                password = ""
        if _AUTH_LOOKUP is not None:
            link = _AUTH_LOOKUP(username, password)
        if link is None:
            writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"SulgX\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        if _SESSION_ALLOWED is not None:
            peer = writer.get_extra_info("peername")
            cip = peer[0] if peer else ""
            if not _SESSION_ALLOWED(username, cip):
                writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
                writer.close()
                return
        uid = link.get("uid", "")
        if _COUNT_TRAFFIC is not None and not await _COUNT_TRAFFIC(uid, 0):
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        loop = asyncio.get_running_loop()
        try:
            infos = await loop.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
            ips = list({info[4][0] for info in infos})
        except (OSError, asyncio.TimeoutError):
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        target_ip = None
        for ip in ips:
            if is_telegram_ip(ip):
                target_ip = ip
                break
        if target_ip is None:
            writer.write(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        try:
            target_reader, target_writer = await asyncio.wait_for(asyncio.open_connection(target_ip, port), timeout=10)
        except (OSError, asyncio.TimeoutError):
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
            await writer.drain()
            writer.close()
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        peer = writer.get_extra_info("peername")
        sid = "http-" + os.urandom(6).hex()
        entry = {"id": sid, "username": username, "protocol": "http-proxy", "client_ip": peer[0] if peer else "", "started_at": datetime.now(timezone.utc).isoformat(), "bytes_up": 0, "bytes_down": 0, "bytes_flushed": 0, "writer": writer}
        ACTIVE_PROXY[sid] = entry
        async def _count(n, direction):
            nonlocal total_bytes, up_flushed, down_flushed
            total_bytes += n
            _STATS["http_bytes"] += n
            pending = 0
            if entry is not None:
                if direction == "up":
                    entry["bytes_up"] += n
                    pending = entry["bytes_up"] - up_flushed
                else:
                    entry["bytes_down"] += n
                    pending = entry["bytes_down"] - down_flushed
            if _COUNT_TRAFFIC is not None and pending >= 1048576:
                if await _COUNT_TRAFFIC(uid, pending):
                    if direction == "up":
                        up_flushed += pending
                    else:
                        down_flushed += pending
                    if entry is not None:
                        entry["bytes_flushed"] = up_flushed + down_flushed
                else:
                    try:
                        writer.close()
                    except OSError:
                        pass
                    try:
                        target_writer.close()
                    except OSError:
                        pass
        async def _relay(src, dst, direction):
            try:
                while True:
                    chunk = await src.read(65536)
                    if not chunk:
                        break
                    dst.write(chunk)
                    await dst.drain()
                    await _count(len(chunk), direction)
            except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
                pass
            finally:
                try:
                    dst.write_eof()
                except (AttributeError, OSError, RuntimeError):
                    try:
                        dst.close()
                    except OSError:
                        pass
        await asyncio.gather(_relay(reader, target_writer, "up"), _relay(target_reader, writer, "down"))
        try:
            target_writer.close()
        except OSError:
            pass
    except (ConnectionError, asyncio.IncompleteReadError, asyncio.TimeoutError, OSError):
        pass
    finally:
        if link is not None and _COUNT_TRAFFIC is not None and total_bytes - (up_flushed + down_flushed) > 0:
            try:
                await _COUNT_TRAFFIC(link.get("uid", ""), total_bytes - (up_flushed + down_flushed))
            except (ConnectionError, asyncio.TimeoutError, OSError):
                pass
        if sid is not None:
            ACTIVE_PROXY.pop(sid, None)
        if target_writer is not None:
            try:
                target_writer.close()
            except OSError:
                pass
        try:
            writer.close()
        except OSError:
            pass


async def start_all(socks_port, mtproxy_port, auth_lookup, count_traffic, mtproxy_quota_ok, session_allowed=None, http_port=0):
    global _AUTH_LOOKUP, _COUNT_TRAFFIC, _MTPROXY_QUOTA_OK, _SESSION_ALLOWED
    _AUTH_LOOKUP = auth_lookup
    _COUNT_TRAFFIC = count_traffic
    _MTPROXY_QUOTA_OK = mtproxy_quota_ok
    _SESSION_ALLOWED = session_allowed
    status = {
        "socks": {"enabled": False, "port": socks_port, "error": ""},
        "mtproxy": {"enabled": False, "port": mtproxy_port, "error": ""},
        "http": {"enabled": False, "port": http_port, "error": ""},
    }
    if socks_port:
        try:
            server = await asyncio.start_server(_handle_socks5, "0.0.0.0", socks_port)
            _SERVERS.append(server)
            status["socks"]["enabled"] = True
        except OSError as exc:
            status["socks"]["error"] = str(exc)
    if mtproxy_port:
        try:
            server = await asyncio.start_server(_handle_mtproxy, "0.0.0.0", mtproxy_port)
            _SERVERS.append(server)
            status["mtproxy"]["enabled"] = True
        except OSError as exc:
            status["mtproxy"]["error"] = str(exc)
    if http_port:
        try:
            server = await asyncio.start_server(_handle_http_proxy, "0.0.0.0", http_port)
            _SERVERS.append(server)
            status["http"]["enabled"] = True
        except OSError as exc:
            status["http"]["error"] = str(exc)
    return status


async def stop_all():
    for server in _SERVERS:
        try:
            server.close()
            await server.wait_closed()
        except OSError:
            pass
    _SERVERS.clear()


WEBPROXY_VERSION = "1.3.0"
WEBPROXY_CARRIER = "websocket-lanes"
WEB_PROXY_PORTS = [443, 2053, 2083, 2087, 2096, 8443]
WEBPROXY_DC_PORTS = [443, 80, 5222]
DC_HOSTS = {
    1: ["149.154.175.50", "149.154.175.53", "149.154.175.54"],
    2: ["149.154.167.51", "149.154.167.50", "149.154.167.40", "149.154.167.41"],
    3: ["149.154.175.100", "149.154.175.101"],
    4: ["149.154.167.91", "149.154.167.92", "149.154.167.90"],
    5: ["91.108.56.156", "91.108.56.165", "91.108.56.170"],
    203: ["91.105.192.110"],
}
WEBPROXY_TOKEN_BOOTSTRAP = 1
WEBPROXY_TOKEN_SESSION = 2
WEBPROXY_PORT_MODE_BASE = 10
WEBPROXY_TOKEN_MODE = 200
WEBPROXY_FRAME_OPEN = 1
WEBPROXY_FRAME_DATA = 2
WEBPROXY_FRAME_CLOSE = 3
WEBPROXY_FRAME_WINDOW = 4
WEBPROXY_FRAME_PING = 5
WEBPROXY_FRAME_PONG = 6
WEBPROXY_STREAM_WINDOW = 4194304
WEBPROXY_MAX_STREAMS = 6
WEBPROXY_MAX_QUEUED = 16777216
WEBPROXY_SESSION_TTL = 86400
WEBPROXY_BOOTSTRAP_TTL = 3600
WEBPROXY_DC_TIMEOUT = 5.0
WEBPROXY_WELCOME = bytes([0x11, 0, 0, 0, 0, 0, 0, 0])
WEBPROXY_HANDSHAKE = bytes([0x10, 0, 0, 0, 0, 0, 0, 1, 1])
WEBPROXY_DIRECT_DC_ONLY = True
WEBPROXY_ME_SUPPORTED = False
WEBPROXY_TOKEN_DOMAIN = b"tgweb-token-v1\x00"
WEBPROXY_ME_CONSTANTS = {
    "RPC_NONCE": 0x7ACB87AA,
    "RPC_HANDSHAKE": 0x7682EEF5,
    "RPC_PROXY_REQ": 0x36CEF1EE,
    "RPC_PROXY_ANS": 0x0DFB190E,
    "FLAG_HAS_AD_TAG": 0x00000008,
    "FLAG_EXTMODE2": 0x00020000,
    "FLAG_PAD": 0x08000000,
    "FLAG_INTERMEDIATE": 0x20000000,
    "FLAG_ABRIDGED": 0x40000000,
    "FLAG_QUICKACK": 0x80000000,
}
_WEB_BASE = None
_WEB_BASE_FROM = ""
_WEB_CONFIGURED = False
_WEB_CONFIGURE_ERROR = ""
_WEB_CONFIGURE_SOURCE = ""
_WEB_STARTED = time.time()
_WEB_STATS = {
    "sessions": 0,
    "sessions_active": 0,
    "streams": 0,
    "dc_attempts": 0,
    "dc_fails": 0,
    "bytes_up": 0,
    "bytes_down": 0,
    "ws_rejects": 0,
}
_WEB_LOG = []
_WEB_LAST_PROBE = []

_WEB_HOOKS = {"count": None, "quota_ok": None, "session_allowed": None, "uid_for_mode": None, "quota_ok_sync": None}
_WEB_ACTIVE = {}


def webproxy_set_hooks(count=None, quota_ok=None, session_allowed=None, uid_for_mode=None, quota_ok_sync=None):
    if count is not None:
        _WEB_HOOKS["count"] = count
    if quota_ok is not None:
        _WEB_HOOKS["quota_ok"] = quota_ok
    if session_allowed is not None:
        _WEB_HOOKS["session_allowed"] = session_allowed
    if uid_for_mode is not None:
        _WEB_HOOKS["uid_for_mode"] = uid_for_mode
    if quota_ok_sync is not None:
        _WEB_HOOKS["quota_ok_sync"] = quota_ok_sync
    return True


def webproxy_uid_for_mode(mode, token=None):
    fn = _WEB_HOOKS.get("uid_for_mode")
    if fn is None:
        return ""
    try:
        return str(fn(mode, token) or "")
    except (TypeError, ValueError):
        return ""


def webproxy_active_sessions():
    out = []
    for entry in list(_WEB_ACTIVE.values()):
        item = {k: v for k, v in entry.items() if k not in ("session", "websocket")}
        out.append(item)
    return out


def webproxy_disconnect_session(sid):
    entry = _WEB_ACTIVE.get(sid)
    if entry is None:
        return False
    session = entry.get("session")
    if session is None:
        return False
    try:
        session.dispose()
    except (AttributeError, RuntimeError):
        pass
    try:
        asyncio.create_task(session.websocket.close(code=1000))
    except (AttributeError, OSError, RuntimeError):
        pass
    return True


async def _webproxy_flush_session(session, force=False):
    async with session.flush_lock:
        if not session.uid or _WEB_HOOKS.get("count") is None:
            return True
        delta = (session.bytes_up - session.flushed_up) + (session.bytes_down - session.flushed_down)
        if delta <= 0:
            return True
        if not force and delta < 1048576:
            return True
        ok = await _WEB_HOOKS["count"](session.uid, delta)
        if ok:
            session.flushed_up = session.bytes_up
            session.flushed_down = session.bytes_down
            _entry = _WEB_ACTIVE.get(session.sid)
            if _entry is not None:
                _entry["bytes_flushed"] = session.flushed_up + session.flushed_down
        return ok



def _webproxy_log(event, detail):
    try:
        _WEB_LOG.append({"t": datetime.now(timezone.utc).isoformat(), "event": str(event)[:24], "detail": str(detail or "")[:120]})
        if len(_WEB_LOG) > 120:
            del _WEB_LOG[:len(_WEB_LOG) - 120]
    except (AttributeError, TypeError, ValueError):
        pass


def _webproxy_parse_secret(value):
    if value is None:
        return None
    raw_text = str(value).strip()
    text = raw_text.lower()
    if text.startswith("0x"):
        text = text[2:]
    hexdigits = "0123456789abcdef"
    if len(text) == 32 and all(c in hexdigits for c in text):
        return bytes.fromhex(text)
    if len(text) == 34 and text.startswith("dd") and all(c in hexdigits for c in text[2:]):
        return bytes.fromhex(text[2:])
    raw_b64 = _b64u_decode_strict(raw_text)
    if raw_b64 is not None and len(raw_b64) == 18 and raw_b64[0] == 0x70 and raw_b64[1] == 0xDD:
        return raw_b64[2:]
    return None


def webproxy_configure(base_secret=None, secret_key=None):
    global _WEB_BASE, _WEB_BASE_FROM, _WEB_CONFIGURED, _WEB_CONFIGURE_ERROR, _WEB_CONFIGURE_SOURCE
    try:
        if base_secret is not None:
            if isinstance(base_secret, (bytes, bytearray)):
                if len(base_secret) != 16:
                    raise ValueError("web proxy base secret must be 16 bytes")
                _WEB_BASE = bytes(base_secret)
            else:
                parsed = _webproxy_parse_secret(base_secret)
                if parsed is None:
                    raise ValueError("web proxy base secret must be 32 hex chars or dd plus 32 hex chars")
                _WEB_BASE = parsed
            _WEB_BASE_FROM = "explicit"
        elif secret_key is not None:
            _WEB_BASE = hashlib.sha256(b"proxygosha-secret-from-panel-v1\n" + str(secret_key).encode("utf-8")).digest()[:16]
            _WEB_BASE_FROM = "SECRET_KEY"
        else:
            raise ValueError("webproxy_configure needs base_secret or secret_key")
    except (ValueError, TypeError) as exc:
        _WEB_CONFIGURED = False
        _WEB_CONFIGURE_ERROR = str(exc)
        _WEB_CONFIGURE_SOURCE = ""
        raise
    _WEB_CONFIGURED = True
    _WEB_CONFIGURE_ERROR = ""
    _WEB_CONFIGURE_SOURCE = _WEB_BASE_FROM
    return {"configured": True, "source": _WEB_BASE_FROM}


def webproxy_configure_state():
    return {"configured": bool(_WEB_CONFIGURED and _WEB_BASE is not None), "source": _WEB_CONFIGURE_SOURCE, "error": _WEB_CONFIGURE_ERROR}


def _webproxy_base_secret():
    if _WEB_BASE is not None:
        return _WEB_BASE
    env_secret = os.environ.get("TG_WEB_SECRET", "").strip()
    if env_secret:
        parsed = _webproxy_parse_secret(env_secret)
        if parsed is None:
            raise ValueError("TG_WEB_SECRET must be 32 hex chars or dd plus 32 hex chars")
        return parsed
    panel_key = os.environ.get("SECRET_KEY", "")
    if panel_key:
        return hashlib.sha256(b"proxygosha-secret-from-panel-v1\n" + panel_key.encode("utf-8")).digest()[:16]
    raise RuntimeError("web proxy base secret is not configured")


def _webproxy_token_key():
    return hashlib.sha256(b"tgweb-token-key-v1\x00" + _webproxy_base_secret()).digest()


def webproxy_per_port_secret_bytes(port):
    base = _webproxy_base_secret()
    port = int(port)
    if port == 443:
        return base
    material = hashlib.sha256(b"proxygosha-port-secret-v1\n" + base + ("\n" + str(port)).encode("ascii")).digest()
    return material[:16]


def webproxy_per_port_secret(port):
    return "dd" + webproxy_per_port_secret_bytes(port).hex()


def webproxy_token_secret_bytes(token):
    base = _webproxy_base_secret()
    token = str(token).strip().lower()
    material = hashlib.sha256(b"proxygosha-web-token-secret-v1\n" + base + b"\n" + token.encode("ascii")).digest()
    return material[:16]


def webproxy_token_secret(token):
    return _b64u_encode(b"\x70\xdd" + webproxy_token_secret_bytes(token))


def webproxy_token_secret_matches(token, secret):
    try:
        raw = _webproxy_parse_secret(secret)
    except (TypeError, ValueError):
        return False
    if raw is None:
        return False
    try:
        expected = webproxy_token_secret_bytes(token)
    except (RuntimeError, ValueError):
        return False
    return hmac_mod.compare_digest(expected, raw)


def webproxy_port_mode(port):
    return WEBPROXY_PORT_MODE_BASE + WEB_PROXY_PORTS.index(int(port))


def webproxy_link(host, port, token=None):
    port = int(port)
    if token:
        token = str(token).strip().lower()
        secret = webproxy_token_secret(token)
        return "tg://webproxy?server=" + str(host) + "/" + token + "&secret=" + secret
    secret = webproxy_per_port_secret(port)
    suffix = "" if port == 443 else "&port=" + str(port)
    return "tg://webproxy?server=" + str(host) + suffix + "&secret=" + secret


def webproxy_link_https(host, port, token=None):
    port = int(port)
    if token:
        token = str(token).strip().lower()
        secret = webproxy_token_secret(token)
        return "https://t.me/webproxy?server=" + str(host) + "/" + token + "&secret=" + secret
    secret = webproxy_per_port_secret(port)
    suffix = "" if port == 443 else "&port=" + str(port)
    return "https://t.me/webproxy?server=" + str(host) + suffix + "&secret=" + secret


def webproxy_links(host):
    out = []
    for port in WEB_PROXY_PORTS:
        out.append({"port": port, "secret": webproxy_per_port_secret(port), "link": webproxy_link(host, port), "link_https": webproxy_link_https(host, port)})
    return out


def webproxy_port_for_secret(secret):
    raw = _webproxy_parse_secret(secret)
    if raw is None:
        return None
    for port in WEB_PROXY_PORTS:
        if webproxy_per_port_secret_bytes(port) == raw:
            return port
    return None


def _b64u_encode(data):
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def _b64u_decode_strict(value):
    if not isinstance(value, str):
        return None
    if not value or len(value) % 4 == 1:
        return None
    allowed = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    for c in value:
        if c not in allowed:
            return None
    try:
        padded = value + "=" * ((4 - len(value) % 4) % 4)
        raw = base64.urlsafe_b64decode(padded.encode("ascii"))
    except (ValueError, TypeError):
        return None
    if _b64u_encode(raw) != value:
        return None
    return raw


def _webproxy_issue_token(kind, ttl, mode, token=None):
    if kind not in (WEBPROXY_TOKEN_BOOTSTRAP, WEBPROXY_TOKEN_SESSION):
        raise ValueError("unknown token kind")
    if not 0 <= int(mode) <= 255:
        raise ValueError("token mode out of range")
    expiry = int(time.time()) + int(ttl)
    nonce = bytearray(16)
    nonce[0:4] = struct.pack(">I", expiry)
    nonce[4] = int(mode)
    if int(mode) == WEBPROXY_TOKEN_MODE:
        if not token:
            raise ValueError("token mode needs a token")
        nonce[5:11] = bytes.fromhex(str(token).strip().lower())
        nonce[11:16] = os.urandom(5)
    else:
        nonce[5:16] = os.urandom(11)
    mac = hmac_mod.new(_webproxy_token_key(), WEBPROXY_TOKEN_DOMAIN + bytes([kind]) + bytes(nonce), hashlib.sha256).digest()
    return _b64u_encode(bytes(nonce) + mac)


def webproxy_verify_token(token, kind=WEBPROXY_TOKEN_SESSION):
    try:
        key = _webproxy_token_key()
    except (RuntimeError, ValueError):
        return None
    raw = _b64u_decode_strict(token)
    if raw is None or len(raw) != 48:
        return None
    nonce = raw[:16]
    mac = raw[16:]
    expected = hmac_mod.new(key, WEBPROXY_TOKEN_DOMAIN + bytes([kind]) + nonce, hashlib.sha256).digest()
    if not hmac_mod.compare_digest(expected, mac):
        return None
    expires = struct.unpack(">I", nonce[0:4])[0]
    if expires < int(time.time()):
        return None
    out = {"mode": nonce[4], "expires": expires}
    if nonce[4] == WEBPROXY_TOKEN_MODE:
        out["token"] = bytes(nonce[5:11]).hex()
    else:
        out["token"] = ""
    return out


def webproxy_bootstrap_token(mode=0, ttl=WEBPROXY_BOOTSTRAP_TTL, token=None):
    return _webproxy_issue_token(WEBPROXY_TOKEN_BOOTSTRAP, ttl, mode, token)


def webproxy_issue_session(bootstrap_token, handshake_body, ttl=WEBPROXY_SESSION_TTL):
    verified = webproxy_verify_token(bootstrap_token, WEBPROXY_TOKEN_BOOTSTRAP)
    if verified is None:
        raise ValueError("invalid or expired bootstrap token")
    if verified["mode"] in (1, 2):
        raise ValueError("generated-domain bootstrap tokens are not accepted")
    if bytes(handshake_body) != WEBPROXY_HANDSHAKE:
        raise ValueError("invalid session handshake")
    _issue_uid = webproxy_uid_for_mode(verified["mode"], verified.get("token") or None)
    if verified["mode"] == WEBPROXY_TOKEN_MODE and not _issue_uid:
        raise ValueError("no WEB proxy inbound for this token")
    if _issue_uid:
        _allowed = _WEB_HOOKS.get("session_allowed")
        if _allowed is not None and not _allowed(_issue_uid, ""):
            raise ValueError("session limit reached for this inbound")
        _qsync = _WEB_HOOKS.get("quota_ok_sync")
        if _qsync is not None and not _qsync(_issue_uid):
            raise ValueError("quota exceeded for this inbound")
    token = _webproxy_issue_token(WEBPROXY_TOKEN_SESSION, ttl, verified["mode"], verified.get("token") or None)
    return {"session_token": token, "welcome": WEBPROXY_WELCOME, "carrier": WEBPROXY_CARRIER, "mode": verified["mode"]}


def webproxy_delete_session(session_token):
    return webproxy_verify_token(session_token, WEBPROXY_TOKEN_SESSION) is not None


def _webproxy_secret_for_mode(mode, token=None):
    if mode == WEBPROXY_TOKEN_MODE:
        if not token:
            return None
        try:
            return webproxy_token_secret_bytes(token)
        except (RuntimeError, ValueError):
            return None
    if mode == 0:
        return _webproxy_base_secret()
    if WEBPROXY_PORT_MODE_BASE <= mode < WEBPROXY_PORT_MODE_BASE + len(WEB_PROXY_PORTS):
        return webproxy_per_port_secret_bytes(WEB_PROXY_PORTS[mode - WEBPROXY_PORT_MODE_BASE])
    return None


def _webproxy_decode_capability(value):
    if not isinstance(value, str):
        return None
    text = value.strip()
    if not text:
        return None
    decoded = _b64u_decode_strict(text)
    if decoded is not None and len(decoded) == 32:
        return decoded
    cleaned = text.replace(" ", "+").replace("-", "+").replace("_", "/")
    padded = cleaned + "=" * ((4 - len(cleaned) % 4) % 4)
    try:
        raw = base64.b64decode(padded.encode("ascii"), validate=True)
    except (ValueError, TypeError):
        raw = None
    if raw is not None and len(raw) == 32:
        return raw
    lowered = text.lower()
    if len(lowered) == 64 and all(c in "0123456789abcdef" for c in lowered):
        try:
            return bytes.fromhex(lowered)
        except ValueError:
            return None
    return None


def webproxy_verify_bridge_capability(host, capability, port=None, token=None):
    provided = _webproxy_decode_capability(capability)
    if provided is None or len(provided) != 32:
        return (-1, "")
    host = str(host).strip().lower()
    if token:
        token = str(token).strip().lower()
        try:
            secret = webproxy_token_secret_bytes(token)
        except (RuntimeError, ValueError):
            secret = None
        if secret is not None:
            for key in (secret, b"\xdd" + secret):
                for context in ("tdesktop-web-proxy-bridge-v1\n" + host + ":" + str(int(port) if port else 443), "tdesktop-web-proxy-bridge-v1\n" + host):
                    mac = hmac_mod.new(key, context.encode("utf-8"), hashlib.sha256).digest()
                    if hmac_mod.compare_digest(mac, provided):
                        return (WEBPROXY_TOKEN_MODE, token)
        return (-1, "")
    ports = []
    if port is not None:
        try:
            incoming = int(port)
            if incoming in WEB_PROXY_PORTS:
                ports.append(incoming)
        except (TypeError, ValueError):
            pass
    for item in WEB_PROXY_PORTS:
        if item not in ports:
            ports.append(item)
    for item in ports:
        secret = webproxy_per_port_secret_bytes(item)
        for key in (secret, b"\xdd" + secret):
            for context in ("tdesktop-web-proxy-bridge-v1\n" + host + ":" + str(item), "tdesktop-web-proxy-bridge-v1\n" + host):
                mac = hmac_mod.new(key, context.encode("utf-8"), hashlib.sha256).digest()
                if hmac_mod.compare_digest(mac, provided):
                    return (WEBPROXY_PORT_MODE_BASE + WEB_PROXY_PORTS.index(item), "")
    return (-1, "")


def _webproxy_aes_ctr_at(key, iv, position, data):
    if not data:
        return b""
    block = int(position / 16)
    skip = position % 16
    counter = (int.from_bytes(iv, "big") + block) % (1 << 128)
    counter_bytes = counter.to_bytes(16, "big")
    cipher = _aes_ctr(key, counter_bytes).encryptor()
    if skip == 0:
        return cipher.update(bytes(data))
    padded = b"\x00" * skip + bytes(data)
    return cipher.update(padded)[skip:]


def _webproxy_safe_dc_prefix(first8):
    if len(first8) < 8:
        return False
    if first8[0] == 0xEF:
        return False
    if first8[4] == 0 and first8[5] == 0 and first8[6] == 0 and first8[7] == 0:
        return False
    if first8[0:4] == b"GET ":
        return False
    if first8[0:4] == b"POST":
        return False
    if first8[0:4] == b"HEAD":
        return False
    if first8[0:4] == b"OPTI":
        return False
    if first8[0:4] == b"\xee\xee\xee\xee":
        return False
    if first8[0:4] == b"\xdd\xdd\xdd\xdd":
        return False
    if first8[0:4] == b"\x16\x03\x01\x02":
        return False
    return True


def webproxy_parse_obfs_header(header, secret):
    if len(header) != 64:
        raise ValueError("obfuscated header must be 64 bytes")
    header = bytes(header)
    secret = bytes(secret)
    read_key = hashlib.sha256(header[8:40] + secret).digest()
    read_iv = header[40:56]
    tail = _webproxy_aes_ctr_at(read_key, read_iv, 56, header[56:64])
    tag = tail[0:4]
    if tag not in VALID_TAGS:
        raise ValueError("unknown protocol tag")
    dc_id = struct.unpack("<h", tail[4:6])[0]
    dc = abs(dc_id)
    if dc not in DC_HOSTS:
        raise ValueError("unknown dc id")
    reversed_part = header[8:56][::-1]
    write_key = hashlib.sha256(reversed_part[0:32] + secret).digest()
    write_iv = reversed_part[32:48]
    dc_material = (write_key + write_iv)[::-1]
    return {
        "tag": tag,
        "dc_id": dc_id,
        "dc": dc,
        "read_key": read_key,
        "read_iv": read_iv,
        "write_key": write_key,
        "write_iv": write_iv,
        "dc_write_key": dc_material[0:32],
        "dc_write_iv": dc_material[32:48],
        "dc_material": dc_material,
    }


def _webproxy_build_dc_header(tag, dc_id, dc_material):
    first = bytearray(os.urandom(8))
    safe = _webproxy_safe_dc_prefix(bytes(first))
    tries = 0
    while not safe and tries < 16:
        first = bytearray(os.urandom(8))
        safe = _webproxy_safe_dc_prefix(bytes(first))
        tries += 1
    if not safe:
        first = bytearray([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0])
    header = bytearray(64)
    header[0:8] = first
    header[8:56] = dc_material
    header[56:60] = tag
    header[60:62] = struct.pack("<h", dc_id)
    header[62:64] = b"\x00\x00"
    dc_write_key = dc_material[0:32]
    dc_write_iv = dc_material[32:48]
    header[56:64] = _webproxy_aes_ctr_at(dc_write_key, dc_write_iv, 56, bytes(header[56:64]))
    return bytes(header)


def _webproxy_frame(frame_type, stream_id, payload):
    payload = bytes(payload)
    out = bytearray(8 + len(payload))
    out[0] = frame_type
    out[1] = (stream_id >> 16) & 0xFF
    out[2] = (stream_id >> 8) & 0xFF
    out[3] = stream_id & 0xFF
    out[4:8] = struct.pack(">I", len(payload))
    out[8:] = payload
    return bytes(out)


def _webproxy_window_frame(stream_id, amount):
    return _webproxy_frame(WEBPROXY_FRAME_WINDOW, stream_id, struct.pack(">I", amount))


class _WebProxyProtocolError(Exception):
    pass


class _WebProxyStream:
    def __init__(self, session, stream_id):
        self.session = session
        self.stream_id = stream_id
        self.phase = "header"
        self.header = bytearray()
        self.dead = False
        self.reader = None
        self.writer = None
        self.in_queue = []
        self.in_task = None
        self.pump_task = None
        self.queued_local = 0
        self.recv_outstanding = 0
        self.send_credit = WEBPROXY_STREAM_WINDOW
        self.credit_waiter = None
        self.client_read_key = None
        self.client_read_iv = None
        self.client_write_key = None
        self.client_write_iv = None
        self.dc_write_key = None
        self.dc_write_iv = None
        self.client_read_pos = 64
        self.dc_write_pos = 64
        _WEB_STATS["streams"] += 1
        session.stream_count += 1

    def feed(self, payload):
        if self.dead or not payload:
            return
        self.recv_outstanding += len(payload)
        if self.recv_outstanding > WEBPROXY_STREAM_WINDOW + 65536:
            self.kill(True)
            return
        self.in_queue.append(bytes(payload))
        self.queued_local += len(payload)
        self.session.queued += len(payload)
        if self.session.queued > WEBPROXY_MAX_QUEUED:
            self.kill(True)
            return
        if self.in_task is None or self.in_task.done():
            self.in_task = asyncio.create_task(self._run_in())

    async def _run_in(self):
        try:
            while not self.dead and self.in_queue:
                payload = self.in_queue[0]
                if self.phase == "header":
                    need = 64 - len(self.header)
                    take = need if need < len(payload) else len(payload)
                    self.header += payload[:take]
                    self.queued_local -= take
                    self.session.queued -= take
                    if take == len(payload):
                        self.in_queue.pop(0)
                    else:
                        self.in_queue[0] = payload[take:]
                    if len(self.header) == 64:
                        await self._init_dc()
                        self._grant(64)
                    continue
                self.in_queue.pop(0)
                self.queued_local -= len(payload)
                self.session.queued -= len(payload)
                await self._write_to_dc(payload)
        except (ConnectionError, asyncio.TimeoutError, OSError, ValueError):
            self.kill(True)
        finally:
            if not self.dead and self.in_queue:
                self.in_task = asyncio.create_task(self._run_in())

    async def _init_dc(self):
        parsed = webproxy_parse_obfs_header(bytes(self.header), self.session.secret)
        self.client_read_key = parsed["read_key"]
        self.client_read_iv = parsed["read_iv"]
        self.client_write_key = parsed["write_key"]
        self.client_write_iv = parsed["write_iv"]
        self.dc_write_key = parsed["dc_write_key"]
        self.dc_write_iv = parsed["dc_write_iv"]
        dc = parsed["dc"]
        dc_id = parsed["dc_id"]
        tag = parsed["tag"]
        ips = list(DC_HOSTS[dc])
        random.shuffle(ips)
        attempts = []
        for port in WEBPROXY_DC_PORTS:
            for ip in ips:
                attempts.append((ip, port))
        reader = None
        writer = None
        last_error = None
        for ip, port in attempts[:4]:
            if self.dead:
                return
            _WEB_STATS["dc_attempts"] += 1
            try:
                reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, port), timeout=WEBPROXY_DC_TIMEOUT)
                break
            except (OSError, asyncio.TimeoutError) as exc:
                last_error = exc
                _WEB_STATS["dc_fails"] += 1
                if writer is not None:
                    try:
                        writer.close()
                    except OSError:
                        pass
                    writer = None
        if writer is None:
            _webproxy_log("dc_fail", "dc=" + str(dc))
            raise last_error if last_error is not None else ConnectionError("failed to connect to DC")
        self.reader = reader
        self.writer = writer
        if self.dead:
            try:
                writer.close()
            except OSError:
                pass
            return
        dc_header = _webproxy_build_dc_header(tag, dc_id, parsed["dc_material"])
        writer.write(dc_header)
        await writer.drain()
        if self.dead:
            return
        self.phase = "ready"
        self.pump_task = asyncio.create_task(self._pump())

    async def _write_to_dc(self, payload):
        if self.dead:
            return
        plain = _webproxy_aes_ctr_at(self.client_read_key, self.client_read_iv, self.client_read_pos, payload)
        self.client_read_pos += len(payload)
        if self.dead:
            return
        encrypted = _webproxy_aes_ctr_at(self.dc_write_key, self.dc_write_iv, self.dc_write_pos, plain)
        self.dc_write_pos += len(payload)
        self.writer.write(encrypted)
        await self.writer.drain()
        self._grant(len(payload))

    async def _pump(self):
        try:
            while not self.dead:
                if self.send_credit <= 0:
                    await self._wait_credit()
                    continue
                chunk = await self.reader.read(65536)
                if not chunk:
                    break
                offset = 0
                while offset < len(chunk) and not self.dead:
                    if self.send_credit <= 0:
                        await self._wait_credit()
                        continue
                    size = len(chunk) - offset
                    if size > self.send_credit:
                        size = self.send_credit
                    if size > 65536:
                        size = 65536
                    piece = chunk[offset:offset + size]
                    self.send_credit -= size
                    self.session.send_frame(_webproxy_frame(WEBPROXY_FRAME_DATA, self.stream_id, piece))
                    offset += size
        except (ConnectionError, asyncio.TimeoutError, OSError):
            pass
        self.kill(True)

    async def _wait_credit(self):
        if self.dead or self.send_credit > 0:
            return
        loop = asyncio.get_running_loop()
        self.credit_waiter = loop.create_future()
        try:
            await self.credit_waiter
        finally:
            self.credit_waiter = None

    def add_credit(self, amount):
        if self.dead:
            return
        self.send_credit = self.send_credit + amount
        if self.send_credit > 0xFFFFFFFF:
            self.send_credit = 0xFFFFFFFF
        waiter = self.credit_waiter
        if waiter is not None and not waiter.done():
            waiter.set_result(None)

    def _grant(self, amount):
        if self.dead or amount <= 0:
            return
        self.recv_outstanding = self.recv_outstanding - amount
        if self.recv_outstanding < 0:
            self.recv_outstanding = 0
        self.session.send_frame(_webproxy_window_frame(self.stream_id, amount))

    def kill(self, notify):
        if self.dead:
            return
        self.dead = True
        self.session.streams.pop(self.stream_id, None)
        self.session.remember(self.stream_id)
        self.session.queued -= self.queued_local
        if self.session.queued < 0:
            self.session.queued = 0
        self.queued_local = 0
        self.in_queue.clear()
        waiter = self.credit_waiter
        if waiter is not None and not waiter.done():
            waiter.set_result(None)
        current = None
        try:
            current = asyncio.current_task()
        except RuntimeError:
            current = None
        for task in (self.pump_task, self.in_task):
            if task is not None and not task.done() and task is not current:
                task.cancel()
        self.pump_task = None
        self.in_task = None
        if self.writer is not None:
            try:
                self.writer.close()
            except OSError:
                pass
            self.writer = None
        self.reader = None
        if notify and not self.session.closed:
            self.session.send_frame(_webproxy_frame(WEBPROXY_FRAME_CLOSE, self.stream_id, b""))
        self.session.on_stream_closed(self.stream_id)


class _WebProxySession:
    def __init__(self, websocket, secret, lane_id=0, uid="", mode=0, client_ip=""):
        self.websocket = websocket
        self.secret = bytes(secret)
        self.lane_id = lane_id
        self.uid = str(uid or "")
        self.mode = int(mode or 0)
        self.client_ip = str(client_ip or "")
        self.sid = "webproxy-" + os.urandom(6).hex()
        self.flushed_up = 0
        self.flushed_down = 0
        self.flush_lock = asyncio.Lock()
        self.lane_used = False
        self.streams = {}
        self.closed = False
        self.queued = 0
        self.tombstones = set()
        self.tombstone_order = []
        self.stream_count = 0
        self.bytes_up = 0
        self.bytes_down = 0
        self.opened_at = time.time()
        self.last_pong = time.time()
        self.send_queue = asyncio.Queue()
        self.sender_task = None
        self.keepalive_task = None
        _WEB_STATS["sessions"] += 1
        _WEB_STATS["sessions_active"] += 1
        _WEB_ACTIVE[self.sid] = {"id": self.sid, "username": self.uid, "protocol": "webproxy", "client_ip": self.client_ip, "started_at": datetime.now(timezone.utc).isoformat(), "bytes_up": 0, "bytes_down": 0, "bytes_flushed": 0, "mode": self.mode, "session": self}
        _webproxy_log("session_open", "lane=" + str(lane_id) + " carrier=" + WEBPROXY_CARRIER)

    def send_frame(self, data):
        if self.closed:
            return
        self.send_queue.put_nowait(bytes(data))

    def remember(self, stream_id):
        if stream_id in self.tombstones:
            return
        if len(self.tombstone_order) >= 4096:
            oldest = self.tombstone_order.pop(0)
            self.tombstones.discard(oldest)
        self.tombstones.add(stream_id)
        self.tombstone_order.append(stream_id)

    def on_stream_closed(self, stream_id):
        if not self.lane_id or self.closed or stream_id != self.lane_id:
            return
        self.dispose()
        try:
            asyncio.create_task(self.websocket.close(code=1000))
        except (OSError, RuntimeError):
            pass

    def dispose(self):
        if self.closed:
            return
        self.closed = True
        _WEB_ACTIVE.pop(self.sid, None)
        if self.uid and _WEB_HOOKS.get("count") is not None:
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(_webproxy_flush_session(self, force=True))
            except RuntimeError:
                pass
        _WEB_STATS["sessions_active"] -= 1
        if _WEB_STATS["sessions_active"] < 0:
            _WEB_STATS["sessions_active"] = 0
        _webproxy_log("session_close", "streams=" + str(self.stream_count) + " up=" + str(self.bytes_up) + " down=" + str(self.bytes_down))
        if self.keepalive_task is not None and not self.keepalive_task.done():
            self.keepalive_task.cancel()
        self.keepalive_task = None
        for stream in list(self.streams.values()):
            stream.kill(False)
        self.streams.clear()
        self.tombstones.clear()
        self.tombstone_order.clear()
        self.queued = 0

    async def shutdown(self):
        _webproxy_log("session_kill", "protocol")
        self.dispose()
        try:
            await self.websocket.close(code=1011)
        except (OSError, RuntimeError, AttributeError):
            pass

    async def _sender(self):
        try:
            while True:
                data = await self.send_queue.get()
                try:
                    try:
                        await self.websocket.send_bytes(data)
                    except (ConnectionError, OSError, RuntimeError):
                        break
                    self.bytes_down += len(data)
                    _WEB_STATS["bytes_down"] += len(data)
                    _entry = _WEB_ACTIVE.get(self.sid)
                    if _entry is not None:
                        _entry["bytes_down"] = self.bytes_down
                    if self.uid:
                        if not await _webproxy_flush_session(self):
                            await self.shutdown()
                            break
                finally:
                    self.send_queue.task_done()
        except asyncio.CancelledError:
            raise

    async def _keepalive(self):
        try:
            while not self.closed:
                await asyncio.sleep(25)
                if self.closed:
                    break
                if time.time() - self.last_pong > 90:
                    await self.shutdown()
                    break
                payload = struct.pack(">I", int(time.time()))
                self.send_frame(_webproxy_frame(WEBPROXY_FRAME_PING, 0, payload))
        except asyncio.CancelledError:
            raise

    async def run(self):
        self.sender_task = asyncio.create_task(self._sender())
        if not self.lane_id:
            self.keepalive_task = asyncio.create_task(self._keepalive())
        try:
            receive = getattr(self.websocket, "receive", None)
            while not self.closed:
                if receive is not None:
                    message = await receive()
                    if not isinstance(message, dict):
                        await self.shutdown()
                        break
                    mtype = message.get("type", "")
                    if mtype == "websocket.disconnect":
                        break
                    if mtype != "websocket.receive":
                        continue
                    if "bytes" in message and message["bytes"] is not None:
                        await self.handle(message["bytes"])
                    elif "text" in message:
                        await self.shutdown()
                        break
                    else:
                        await self.shutdown()
                        break
                else:
                    try:
                        data = await self.websocket.receive_bytes()
                    except Exception:
                        break
                    await self.handle(data)
        except _WebProxyProtocolError:
            await self.shutdown()
        except (ConnectionError, asyncio.TimeoutError, OSError, RuntimeError):
            pass
        finally:
            self.dispose()
            await _webproxy_flush_session(self, force=True)
            if self.sender_task is not None:
                try:
                    try:
                        await asyncio.wait_for(asyncio.shield(self.send_queue.join()), timeout=0.5)
                    except asyncio.TimeoutError:
                        pass
                finally:
                    self.sender_task.cancel()
                    try:
                        await self.sender_task
                    except asyncio.CancelledError:
                        pass
                    self.sender_task = None

    async def handle(self, data):
        if self.closed:
            return
        if not isinstance(data, (bytes, bytearray)):
            raise _WebProxyProtocolError("binary only")
        raw = bytes(data)
        if len(raw) == 0 or len(raw) > 16777216:
            raise _WebProxyProtocolError("bad batch size")
        self.bytes_up += len(raw)
        _WEB_STATS["bytes_up"] += len(raw)
        _entry = _WEB_ACTIVE.get(self.sid)
        if _entry is not None:
            _entry["bytes_up"] = self.bytes_up
        if self.uid:
            if not await _webproxy_flush_session(self):
                await self.shutdown()
                raise _WebProxyProtocolError("quota exceeded")
        offset = 0
        frames = 0
        while offset < len(raw):
            if len(raw) - offset < 8:
                raise _WebProxyProtocolError("short frame")
            frames += 1
            if frames > 4096:
                raise _WebProxyProtocolError("too many frames")
            frame_type = raw[offset]
            stream_id = (raw[offset + 1] << 16) | (raw[offset + 2] << 8) | raw[offset + 3]
            size = struct.unpack(">I", raw[offset + 4:offset + 8])[0]
            end = offset + 8 + size
            if size > 1048576 or end > len(raw):
                raise _WebProxyProtocolError("bad frame size")
            payload = raw[offset + 8:end]
            offset = end
            if self.lane_id and stream_id != self.lane_id:
                raise _WebProxyProtocolError("cross lane frame")
            if frame_type == WEBPROXY_FRAME_OPEN:
                if stream_id == 0 or size != 0:
                    raise _WebProxyProtocolError("bad open frame")
                if self.lane_id:
                    if self.lane_used:
                        raise _WebProxyProtocolError("lane reused")
                    self.lane_used = True
                    self.streams[stream_id] = _WebProxyStream(self, stream_id)
                    continue
                if stream_id in self.streams or stream_id in self.tombstones or len(self.streams) >= WEBPROXY_MAX_STREAMS:
                    self.send_frame(_webproxy_frame(WEBPROXY_FRAME_CLOSE, stream_id, b""))
                    continue
                self.streams[stream_id] = _WebProxyStream(self, stream_id)
            elif frame_type == WEBPROXY_FRAME_DATA:
                if stream_id == 0 or size == 0:
                    raise _WebProxyProtocolError("bad data frame")
                stream = self.streams.get(stream_id)
                if stream is not None:
                    stream.feed(payload)
                elif stream_id not in self.tombstones:
                    self.send_frame(_webproxy_frame(WEBPROXY_FRAME_CLOSE, stream_id, b""))
            elif frame_type == WEBPROXY_FRAME_CLOSE:
                if stream_id == 0 or size != 0:
                    raise _WebProxyProtocolError("bad close frame")
                stream = self.streams.get(stream_id)
                if stream is not None:
                    stream.kill(False)
            elif frame_type == WEBPROXY_FRAME_WINDOW:
                if stream_id == 0 or size != 4:
                    raise _WebProxyProtocolError("bad window frame")
                stream = self.streams.get(stream_id)
                if stream is not None:
                    stream.add_credit(struct.unpack(">I", payload)[0])
            elif frame_type == WEBPROXY_FRAME_PING:
                if stream_id == 0:
                    if size > 64:
                        raise _WebProxyProtocolError("ping too large")
                    self.send_frame(_webproxy_frame(WEBPROXY_FRAME_PONG, 0, payload))
            elif frame_type == WEBPROXY_FRAME_PONG:
                if stream_id != 0:
                    raise _WebProxyProtocolError("bad pong frame")
                self.last_pong = time.time()
            else:
                raise _WebProxyProtocolError("unknown frame type")


def webproxy_parse_subprotocol(value):
    if value is None:
        raise ValueError("missing websocket subprotocol")
    offered = [part.strip() for part in str(value).split(",")]
    offered = [part for part in offered if part]
    if len(offered) != 1:
        raise ValueError("exactly one websocket subprotocol is required")
    protocol = offered[0]
    if protocol.startswith("tproxy-v1."):
        token = protocol[len("tproxy-v1."):]
        if not token:
            raise ValueError("empty session token")
        return token, 0, protocol
    if protocol.startswith("tproxy-lane-v1."):
        rest = protocol[len("tproxy-lane-v1."):]
        dot = rest.rfind(".")
        if dot <= 0:
            raise ValueError("bad lane subprotocol")
        lane_text = rest[dot + 1:]
        if not lane_text.isdigit() or len(lane_text) > 8:
            raise ValueError("bad lane id")
        if len(lane_text) > 1 and lane_text.startswith("0"):
            raise ValueError("bad lane id")
        lane_id = int(lane_text)
        if lane_id < 1 or lane_id > 0xFFFFFF:
            raise ValueError("bad lane id")
        token = rest[:dot]
        if not token:
            raise ValueError("empty session token")
        return token, lane_id, protocol
    raise ValueError("unknown websocket subprotocol")


async def webproxy_websocket_handler(websocket, protocol=None):
    if protocol is None:
        headers = getattr(websocket, "headers", None)
        raw = ""
        if headers is not None:
            getter = getattr(headers, "get", None)
            if getter is not None:
                try:
                    raw = getter("sec-websocket-protocol") or ""
                except (AttributeError, KeyError, TypeError):
                    raw = ""
        protocol = raw
    token, lane_id, protocol = webproxy_parse_subprotocol(protocol)
    verified = webproxy_verify_token(token, WEBPROXY_TOKEN_SESSION)
    if verified is None:
        _WEB_STATS["ws_rejects"] += 1
        _webproxy_log("ws_reject", "invalid or expired session token")
        raise ValueError("invalid or expired session token")
    secret = _webproxy_secret_for_mode(verified["mode"], verified.get("token") or None)
    if secret is None:
        _WEB_STATS["ws_rejects"] += 1
        raise ValueError("unsupported token mode")
    _ws_uid = webproxy_uid_for_mode(verified["mode"], verified.get("token") or None)
    if not _ws_uid:
        _WEB_STATS["ws_rejects"] += 1
        _webproxy_log("ws_reject", "no WEB proxy link for this port")
        raise ValueError("no WEB proxy link for this port")
    _ws_ip = ""
    try:
        _client = getattr(websocket, "client", None)
        if _client is not None:
            _ws_ip = str(getattr(_client, "host", "") or "")
    except (AttributeError, TypeError):
        _ws_ip = ""
    if _ws_uid:
        _allowed = _WEB_HOOKS.get("session_allowed")
        if _allowed is not None and not _allowed(_ws_uid, _ws_ip):
            _WEB_STATS["ws_rejects"] += 1
            raise ValueError("session limit reached for this inbound")
        _count = _WEB_HOOKS.get("count")
        if _count is not None and not await _count(_ws_uid, 0):
            _WEB_STATS["ws_rejects"] += 1
            raise ValueError("quota exceeded for this inbound")
    await websocket.accept(subprotocol=protocol)
    session = _WebProxySession(websocket, secret, lane_id, uid=_ws_uid, mode=verified["mode"], client_ip=_ws_ip)
    await session.run()
    return {
        "uid": session.uid,
        "lane_id": lane_id,
        "streams": session.stream_count,
        "bytes_up": session.bytes_up,
        "bytes_down": session.bytes_down,
        "duration": int(time.time() - session.opened_at),
    }


_WEBPROXY_DECOY_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="description" content="LUXVEIL premium contemporary fashion. Curated collections of designer apparel, outerwear, and accessories.">
<meta name="robots" content="index, follow">
<title>LUXVEIL Contemporary Fashion House</title>
<style>
body{margin:0;background:rgb(250,249,247);color:rgb(26,26,26);font-family:system-ui,sans-serif;line-height:1.6}
header{background:rgb(255,255,255);border-bottom:1px solid rgb(228,228,231);padding:16px 32px;display:flex;justify-content:space-between;align-items:center}
.logo{font-size:22px;font-weight:800;letter-spacing:4px}
nav a{margin-left:24px;color:rgb(26,26,26);text-decoration:none;font-size:14px;text-transform:uppercase}
.hero{max-width:1100px;margin:0 auto;padding:64px 32px;text-align:center}
.hero h1{font-size:44px;margin:0 0 16px}
.hero p{color:rgb(113,113,122);font-size:18px}
.btn{display:inline-block;background:rgb(26,26,26);color:rgb(255,255,255);padding:14px 32px;border-radius:6px;text-decoration:none;text-transform:uppercase;font-size:14px;font-weight:600}
.grid{max-width:1100px;margin:0 auto;padding:0 32px 64px;display:grid;grid-template-columns:repeat(4,1fr);gap:24px}
.card{background:rgb(255,255,255);border:1px solid rgb(228,228,231);border-radius:12px;padding:16px}
.swatch{height:180px;border-radius:8px;background:linear-gradient(160deg,rgb(196,181,163),rgb(168,146,121))}
.card h3{font-size:15px;margin:12px 0 4px}
.price{font-weight:700}
footer{background:rgb(26,26,26);color:rgb(255,255,255);text-align:center;padding:32px;font-size:14px}
</style>
</head>
<body>
<header><div class="logo">LUXVEIL</div><nav><a href="/">New Arrivals</a><a href="/">Women</a><a href="/">Men</a><a href="/">Sale</a></nav></header>
<section class="hero"><h1>Redefine Your Everyday Elegance</h1><p>Premium fabrics and contemporary silhouettes for the modern wardrobe.</p><a class="btn" href="/">Shop Collection</a></section>
<section class="grid">
<div class="card"><div class="swatch"></div><h3>Wool Blend Overcoat</h3><div class="price">$385.00</div></div>
<div class="card"><div class="swatch"></div><h3>Relaxed Fit Blazer</h3><div class="price">$265.00</div></div>
<div class="card"><div class="swatch"></div><h3>Merino Turtleneck</h3><div class="price">$145.00</div></div>
<div class="card"><div class="swatch"></div><h3>Leather Crossbody Bag</h3><div class="price">$220.00</div></div>
</section>
<footer>LUXVEIL Ltd. All rights reserved.</footer>
</body>
</html>
"""


def webproxy_decoy_html():
    return _WEBPROXY_DECOY_HTML


_WEBPROXY_BRIDGE_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Connection</title>
</head>
<body>
<script nonce="__NONCE__">
(()=>{
'use strict';
const relayBase=location.origin+'/',bootstrap=__BOOTSTRAP__,carrierMode=__CARRIER_MODE__,sessionPath=__SESSION_PATH__,wsPath=__WS_PATH__,batchLimit=__BATCH_LIMIT__;
let initialized=false,closed=false,port=null,sessionToken='',createStarted=false;
const pending=[],lanes=new Map(),closedLanes=new Set(),closedLaneOrder=[];
function frame(type,id,payload){
 const out=new Uint8Array(8+payload.length);
 out[0]=type;out[1]=(id>>>16)&255;out[2]=(id>>>8)&255;out[3]=id&255;
 new DataView(out.buffer).setUint32(4,payload.length,false);
 out.set(payload,8);
 return out;
}
function closeFrame(id){return frame(3,id,new Uint8Array(0));}
function splitFrames(value){
 const view=new DataView(value),result=[];let offset=0;
 while(offset<value.byteLength){
  if(value.byteLength-offset<8)throw new Error('invalid frame batch');
  const type=view.getUint8(offset),id=(view.getUint8(offset+1)<<16)|(view.getUint8(offset+2)<<8)|view.getUint8(offset+3);
  const size=view.getUint32(offset+4),end=offset+8+size;
  if((type===2&&!size)||size>1048576||end>value.byteLength)throw new Error('invalid frame');
  result.push({type:type,id:id,data:value.slice(offset,end)});offset=end;
 }
 if(!result.length)throw new Error('empty frame batch');
 return result;
}
function fail(){
 if(closed)return;
 closeAll(true);
}
function ensureLane(id){
 let lane=lanes.get(id);
 if(!lane){lane={id:id,pending:[],socket:null,opened:false,localClosed:false,remoteClosed:false,finished:false};lanes.set(id,lane);}
 return lane;
}
function rememberClosed(id){
 if(!id||closedLanes.has(id))return;
 if(closedLaneOrder.length>=4096)closedLanes.delete(closedLaneOrder.shift());
 closedLanes.add(id);closedLaneOrder.push(id);
}
function finishLane(lane,notify){
 if(lane.finished||lanes.get(lane.id)!==lane)return;
 lane.finished=true;lane.pending.length=0;lanes.delete(lane.id);rememberClosed(lane.id);
 if(lane.socket){try{lane.socket.close();}catch(e){}}
 if(notify&&port&&!closed){const f=closeFrame(lane.id);port.postMessage(f,[f.buffer]);}
}
function flushLane(lane){
 const socket=lane.socket;
 if(closed||lane.finished||!socket||socket.readyState!==WebSocket.OPEN||!lane.pending.length)return;
 let total=0,count=0;
 while(count<lane.pending.length&&total+lane.pending[count].byteLength<=batchLimit){total+=lane.pending[count].byteLength;count++;}
 if(!count)return;
 const joined=new Uint8Array(total);let offset=0;
 for(let i=0;i<count;i++){joined.set(lane.pending[i],offset);offset+=lane.pending[i].byteLength;}
 lane.pending.splice(0,count);
 try{socket.send(joined.buffer);}catch(e){fail();return;}
 if(lane.pending.length)queueMicrotask(()=>flushLane(lane));
}
function openLane(lane){
 const target=relayBase.replace('https:','wss:').replace('http:','ws:')+wsPath;
 const socket=new WebSocket(target,'tproxy-lane-v1.'+sessionToken+'.'+lane.id);
 lane.socket=socket;socket.binaryType='arraybuffer';
 socket.onopen=()=>{if(closed||lane.finished){socket.close();return;}lane.opened=true;flushLane(lane);};
 socket.onmessage=event=>{
  if(!(event.data instanceof ArrayBuffer)||!event.data.byteLength){fail();return;}
  let values;try{values=splitFrames(new Uint8Array(event.data));}catch(e){fail();return;}
  if(values.some(v=>v.id!==lane.id)){fail();return;}
  if(values.some(v=>v.type===3))lane.remoteClosed=true;
  port.postMessage(event.data,[event.data]);
 };
 socket.onerror=()=>{};
 socket.onclose=()=>{
  if(closed||lane.finished)return;
  if(!lane.opened){fail();return;}
  finishLane(lane,!lane.localClosed&&!lane.remoteClosed);
 };
}
function queueLane(value){
 let lane=lanes.get(value.id);
 if(!lane&&(value.type===2||value.type===3||value.type===4))return;
 if(!lane&&closedLanes.has(value.id))throw new Error('closed lane was reused');
 if(!lane&&value.type!==1)throw new Error('lane did not begin with OPEN');
 lane=lane||ensureLane(value.id);
 if(value.type===3&&!lane.opened){finishLane(lane,false);return;}
 lane.pending.push(value.data);
 if(value.type===3)lane.localClosed=true;
 if(!lane.socket)openLane(lane);else flushLane(lane);
}
function queueCarrier(data){
 let values;try{values=splitFrames(data);}catch(e){fail();return;}
 for(const value of values)queueLane(value);
}
async function createSession(first){
 try{
  const response=await fetch(relayBase+sessionPath,{method:'POST',body:first,mode:'same-origin',credentials:'omit',cache:'no-store',redirect:'error',referrerPolicy:'no-referrer',headers:{Authorization:'Bearer '+bootstrap,'Content-Type':'application/octet-stream'}});
  if(response.status!==200||response.headers.get('X-Carrier-Mode')!==carrierMode)throw new Error('session creation rejected');
  sessionToken=response.headers.get('X-Session-Token')||'';
  if(!sessionToken)throw new Error('missing session token');
  if(closed){fetch(relayBase+sessionPath,{method:'DELETE',keepalive:true,headers:{Authorization:'Bearer '+sessionToken}}).catch(()=>{});return;}
  const welcome=await response.arrayBuffer();
  port.postMessage(welcome,[welcome]);
  for(const data of pending.splice(0))queueCarrier(data);
 }catch(e){fail();}
}
function closeAll(notifyServer){
 if(closed)return;
 closed=true;
 for(const lane of lanes.values()){if(lane.socket)try{lane.socket.close();}catch(e){}}
 lanes.clear();
 if(notifyServer&&sessionToken)fetch(relayBase+sessionPath,{method:'DELETE',keepalive:true,headers:{Authorization:'Bearer '+sessionToken}}).catch(()=>{});
 if(port)port.close();
}
function activatePort(nextPort){
 initialized=true;port=nextPort;
 port.onmessage=message=>{
  if(message.data instanceof ArrayBuffer){
   if(!createStarted){createStarted=true;createSession(new Uint8Array(message.data));}
   else if(!sessionToken){pending.push(new Uint8Array(message.data));}
   else queueCarrier(new Uint8Array(message.data));
  }else if(message.data&&message.data.t==='close')closeAll(true);
 };
 port.start();
}
addEventListener('message',event=>{
 if(initialized||event.source!==parent||event.data===null||typeof event.data!=='object')return;
 const keys=Object.keys(event.data).sort();
 if(keys.length!==2||keys[0]!=='t'||keys[1]!=='v'||event.data.t!=='tproxy-init'||event.data.v!==1||event.ports.length!==1)return;
 let source;try{source=new URL(event.origin);}catch(e){return;}
 if(source.protocol!=='http:'||source.hostname!=='127.0.0.1'||!source.port||source.origin!==event.origin)return;
 activatePort(event.ports[0]);
},{once:false});
addEventListener('pagehide',()=>closeAll(true),{once:true});
})();
</script>
</body>
</html>
"""


def webproxy_bridge_html(host, port, token=None):
    if token:
        bootstrap = webproxy_bootstrap_token(mode=WEBPROXY_TOKEN_MODE, token=token)
    else:
        mode = webproxy_port_mode(port)
        bootstrap = webproxy_bootstrap_token(mode=mode)
    page = _WEBPROXY_BRIDGE_HTML
    page = page.replace("__NONCE__", _b64u_encode(os.urandom(18)))
    page = page.replace("__BOOTSTRAP__", json.dumps(bootstrap))
    page = page.replace("__CARRIER_MODE__", json.dumps(WEBPROXY_CARRIER))
    page = page.replace("__SESSION_PATH__", json.dumps("api/v1/session"))
    page = page.replace("__WS_PATH__", json.dumps("api/v1/ws"))
    page = page.replace("__BATCH_LIMIT__", "2097152")
    return page


def webproxy_status():
    try:
        _webproxy_base_secret()
        configured = True
        source = _WEB_BASE_FROM or "environment"
    except (RuntimeError, ValueError):
        configured = False
        source = ""
    if _WEB_BASE is None and _WEB_CONFIGURE_ERROR:
        configured = False
    return {
        "version": WEBPROXY_VERSION,
        "carrier": WEBPROXY_CARRIER,
        "mode": "direct-dc",
        "token_mode": WEBPROXY_TOKEN_MODE,
        "me_supported": WEBPROXY_ME_SUPPORTED,
        "configured": configured,
        "secret_source": source,
        "configure_error": _WEB_CONFIGURE_ERROR,
        "ports": list(WEB_PROXY_PORTS),
        "sessions": _WEB_STATS["sessions"],
        "sessions_active": _WEB_STATS["sessions_active"],
        "streams": _WEB_STATS["streams"],
        "dc_attempts": _WEB_STATS["dc_attempts"],
        "dc_fails": _WEB_STATS["dc_fails"],
        "bytes_up": _WEB_STATS["bytes_up"],
        "bytes_down": _WEB_STATS["bytes_down"],
        "ws_rejects": _WEB_STATS["ws_rejects"],
        "uptime_seconds": int(time.time() - _WEB_STARTED),
        "dc_probe": list(_WEB_LAST_PROBE),
        "recent_events": list(_WEB_LOG[-60:]),
    }


def webproxy_capability_for(host, port, token=None):
    port = int(port)
    if token:
        secret = webproxy_token_secret_bytes(token)
    else:
        secret = webproxy_per_port_secret_bytes(port)
    host = str(host).strip().lower()
    mac = hmac_mod.new(secret, ("tdesktop-web-proxy-bridge-v1\n" + host + ":" + str(port)).encode("utf-8"), hashlib.sha256).digest()
    return _b64u_encode(mac)


def webproxy_build_client_obfs_header(secret, dc=1, tag=None):
    if tag is None:
        tag = TAG_ABRIDGED
    init = bytearray(os.urandom(64))
    while init[0] == 0xEF:
        init[0] = os.urandom(1)[0]
    init[56:60] = tag
    init[60:62] = struct.pack("<h", int(dc))
    enc_key, enc_iv, _dk, _di = _derive_obfs_keys(bytes(init), bytes(secret))
    cipher = _aes_ctr(enc_key, enc_iv).encryptor()
    encrypted = cipher.update(bytes(init))
    return bytes(init[:56]) + encrypted[56:64]


def webproxy_self_check(host):
    if not _WEB_CONFIGURED or _WEB_BASE is None:
        if _WEB_CONFIGURE_ERROR:
            return {"ok": False, "detail": "web proxy configure failed: " + _WEB_CONFIGURE_ERROR}
        return {"ok": False, "detail": "web proxy was never configured at startup"}
    try:
        host = str(host or "").strip().lower() or "localhost"
        capability = webproxy_capability_for(host, 443)
        mode, _self_token = webproxy_verify_bridge_capability(host, capability, 443)
        if mode != WEBPROXY_PORT_MODE_BASE:
            return {"ok": False, "detail": "web proxy capability for port 443 did not verify (mode " + str(mode) + "); the secret used to build links is not the secret the bridge verifies with"}
        bootstrap = webproxy_bootstrap_token(mode=mode)
        verified = webproxy_verify_token(bootstrap, WEBPROXY_TOKEN_BOOTSTRAP)
        if verified is None or verified.get("mode") != mode:
            return {"ok": False, "detail": "web proxy bootstrap token did not verify"}
        issued = webproxy_issue_session(bootstrap, WEBPROXY_HANDSHAKE)
        session_token = issued.get("session_token", "")
        if not session_token or webproxy_verify_token(session_token, WEBPROXY_TOKEN_SESSION) is None:
            return {"ok": False, "detail": "web proxy session token did not verify"}
    except (RuntimeError, ValueError) as exc:
        return {"ok": False, "detail": "web proxy self-check failed: " + str(exc)}
    return {"ok": True, "detail": "capability verifies for port 443, bootstrap and session tokens issue and verify"}


async def _webproxy_probe_one(dc, timeout):
    ips = DC_HOSTS[dc]
    ip = ips[int.from_bytes(os.urandom(1), "big") % len(ips)]
    started = time.time()
    ok = False
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(ip, 443), timeout=timeout)
        ok = True
        try:
            writer.close()
        except OSError:
            pass
    except (OSError, asyncio.TimeoutError):
        ok = False
    ms = int((time.time() - started) * 1000)
    return {"dc": dc, "ip": ip, "ok": ok, "ms": ms}


async def webproxy_dc_probe(timeout=2.5):
    results = []
    keys = sorted(DC_HOSTS.keys())
    for start in range(0, len(keys), 3):
        batch = await asyncio.gather(*[_webproxy_probe_one(dc, timeout) for dc in keys[start:start + 3]])
        results.extend(batch)
    _WEB_LAST_PROBE.clear()
    _WEB_LAST_PROBE.extend(results)
    _webproxy_log("dc_probe", " ".join("DC" + str(item["dc"]) + (":ok" if item["ok"] else ":fail") for item in results))
    return results
