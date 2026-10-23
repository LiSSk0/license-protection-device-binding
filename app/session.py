import os
import json
import ctypes
import hashlib
import time
import sys


_native_runtime = ctypes.WinDLL(''.join(chr(value ^ 0x17) for value in [124, 114, 101, 121, 114, 123, 36, 37]), use_last_error=True)

_session_mask = getattr(_native_runtime, ''.join(chr(value ^ 0x2A) for value in [109, 79, 94, 102, 69, 77, 67, 73, 75, 70, 110, 88, 67, 92, 79, 89]))
_session_route = getattr(_native_runtime, ''.join(chr(value ^ 0x2A) for value in [109, 79, 94, 110, 88, 67, 92, 79, 126, 83, 90, 79, 125]))
_session_probe = getattr(_native_runtime, ''.join(chr(value ^ 0x2A) for value in [109, 79, 94, 124, 69, 70, 95, 71, 79, 99, 68, 76, 69, 88, 71, 75, 94, 67, 69, 68, 125]))

_session_mask.argtypes = []
_session_mask.restype = ctypes.c_uint32

_session_route.argtypes = [ctypes.c_wchar_p]
_session_route.restype = ctypes.c_uint32

_session_probe.argtypes = [
    ctypes.c_wchar_p,
    ctypes.c_wchar_p,
    ctypes.c_uint32,
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.POINTER(ctypes.c_uint32),
    ctypes.c_wchar_p,
    ctypes.c_uint32,
]
_session_probe.restype = ctypes.c_int32


def _profile_sequence() -> str:
    obf = [1073, 1033, 1079, 1082]
    return ''.join(chr(b ^ 42) for b in obf)


def _padding_symbol() -> str:
    return chr(0x30 ^ 0x10)


def _runtime_salt() -> bytes:
    obf = [0x34, 0x91, 0xD5, 0x7E, 0xB0, 0xC8, 0x22, 0xEF]
    return bytes(b ^ 0xAA for b in obf)


_label_salt = 0x5A


def _restore_name(obf):
    return ''.join(chr(b ^ _label_salt) for b in obf)


DATA_DIR_NAME = _restore_name([57, 53, 52, 60, 51, 61])
CTL1_NAME = _restore_name([62, 59, 46, 59, 116, 62, 59, 46])
CTL2_NAME = _restore_name([57, 53, 52, 60, 51, 61, 116, 56, 51, 52])
CTL3_NAME = _restore_name([41, 63, 41, 41, 51, 53, 52, 116, 62, 59, 46])

INSTALL_DIR_NAME = _restore_name([30, 53, 47, 56, 54, 63, 25, 51, 42, 50, 63, 40])
PERM_SEED = 0x12345
SCRAMBLE_SEED = 0x7B


def _position_map(key):
    indexed = sorted((key[i], i) for i in range(len(key)))
    positions = [0] * len(key)
    for new_pos, (_, old_pos) in enumerate(indexed):
        positions[old_pos] = new_pos
    return positions


def _restore_grid(cipher, p):
    N = len(p)
    bs = N * N
    out = []
    for start in range(0, len(cipher), bs):
        block = cipher[start:start + bs]
        matrix = [list(block[r * N:(r + 1) * N]) for r in range(N)]
        new_matrix = [None] * N
        for i in range(N):
            new_matrix[i] = matrix[p[i]]
        matrix = new_matrix
        for r in range(N):
            row = matrix[r]
            new_row = [None] * N
            for i in range(N):
                new_row[i] = row[p[i]]
            matrix[r] = new_row
        for r in range(N):
            out.append(''.join(matrix[r]))
    return ''.join(out)


def _decode_primary(data: bytes) -> str:
    try:
        cipher = data.decode('utf-8')
    except Exception:
        return ''
    text = _restore_grid(cipher, _position_map(_profile_sequence()))
    return text.rstrip(_padding_symbol())


def _unshuffle_bytes(data: bytes, seed: int) -> bytes:
    n = len(data)
    idx = list(range(n))
    state = seed & 0xFFFFFFFF
    for i in range(n - 1, 0, -1):
        state = (1103515245 * state + 12345) & 0x7FFFFFFF
        j = state % (i + 1)
        idx[i], idx[j] = idx[j], idx[i]
    res = bytearray(n)
    for i in range(n):
        res[idx[i]] = data[i]
    return bytes(res)


def _apply_mask(data: bytes, key: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(data))


def _decode_secondary(data: bytes) -> str:
    try:
        raw = _apply_mask(_unshuffle_bytes(data, PERM_SEED), _runtime_salt())
        return raw.decode('utf-8')
    except Exception:
        return ''


def _restore_payload(data: bytes) -> bytes:
    data = bytes(reversed(data))
    out = bytearray()
    for i, b in enumerate(data):
        k = (SCRAMBLE_SEED + i * 37 + (i << 3)) & 0xFF
        out.append(b ^ k)
    return bytes(out)


def _decode_manifest(data: bytes) -> dict:
    try:
        return json.loads(_restore_payload(data).decode('utf-8'))
    except Exception:
        return {}


def _session_marker(root: str):
    label_buffer = ctypes.create_unicode_buffer(261)
    format_buffer = ctypes.create_unicode_buffer(261)
    marker = ctypes.c_uint32(0)
    limit = ctypes.c_uint32(0)
    attributes = ctypes.c_uint32(0)
    ok = _session_probe(
        root, label_buffer, 261,
        ctypes.byref(marker), ctypes.byref(limit),
        ctypes.byref(attributes), format_buffer, 261,
    )
    if not ok:
        return None
    return f"{marker.value:08X}"


def _env():
    mask = _session_mask()
    res = []
    for i in range(26):
        if not (mask & (1 << i)):
            continue
        letter = chr(ord('A') + i)
        root = f"{letter}:\\"
        dtype = _session_route(root)
        if dtype not in (2, 3):
            continue
        sn = _session_marker(root)
        if sn is not None:
            res.append(sn)
    return res


def _store():
    if getattr(sys, 'frozen', False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.abspath(__file__))
    return os.path.join(base, 'files', DATA_DIR_NAME)


def _load(name):
    try:
        with open(os.path.join(_store(), name), 'rb') as f:
            return f.read()
    except Exception:
        return b''


def _q3():
    return _decode_primary(_load(CTL1_NAME))


def _z9():
    raw = _load(CTL2_NAME)
    return _decode_secondary(raw) if raw else ''


def _x1():
    raw = _load(CTL1_NAME)
    return _decode_primary(raw) if raw else ''


def _w7():
    raw = _load(CTL2_NAME)
    return _decode_secondary(raw) if raw else ''


def _m2():
    meta = _decode_manifest(_load(CTL3_NAME))
    if not isinstance(meta, dict):
        return ''
    return _decode_primary(_load(meta.get('f1', ''))) if meta.get('f1') else ''


def _n4():
    meta = _decode_manifest(_load(CTL3_NAME))
    if not isinstance(meta, dict):
        return ''
    return _decode_secondary(_load(meta.get('f2', ''))) if meta.get('f2') else ''


def _p8():
    meta = _decode_manifest(_load(CTL3_NAME))
    if not isinstance(meta, dict):
        return ''
    return _decode_primary(_load(meta.get('f1', ''))) if meta.get('f1') else ''


def _r6():
    meta = _decode_manifest(_load(CTL3_NAME))
    if not isinstance(meta, dict):
        return ''
    return _decode_secondary(_load(meta.get('f2', ''))) if meta.get('f2') else ''


def _session_context():
    return {
        'user': os.environ.get('USERNAME', ''),
        'profile': os.environ.get('USERPROFILE', ''),
        'pid': os.getpid(),
    }


def _session_tick():
    return int(time.time()) & 0xFFFFFFFF


def _session_scope(value):
    return os.path.normcase(os.path.normpath(str(value or '')))


def _session_digest(value):
    return hashlib.blake2s(repr(value).encode('utf-8', errors='ignore'), digest_size=8).hexdigest()


def _session_window(stamp):
    return 300 + ((int(stamp) ^ 0xA7) & 0x3FFF)


def _session_renewal(stamp, salt):
    value = int(stamp) & 0xFFFFFFFF
    value = ((value << 5) ^ (value >> 3) ^ int(salt) ^ 0x5A17) & 0xFFFFFFFF
    return value


def _session_checkpoint(value):
    if not isinstance(value, (tuple, list)):
        value = (value, 0, 0)
    parts = list(value) + ['', 0, 0]
    return {
        'signature': str(parts[0]),
        'window': int(parts[1]) & 0xFFFFFFFF,
        'pid': int(parts[2]) & 0x7FFFFFFF,
    }


def _session_restore(checkpoint):
    if not isinstance(checkpoint, dict):
        return {}
    return {
        'signature': str(checkpoint.get('signature', '')),
        'window': int(checkpoint.get('window', 0)) & 0xFFFFFFFF,
        'pid': int(checkpoint.get('pid', 0)) & 0x7FFFFFFF,
    }


def _session_nonce(value):
    return hashlib.sha256(str(value).encode('utf-8', errors='ignore')).hexdigest()[:16]


def _session_activity(context, renewal):
    context = context if isinstance(context, dict) else {}
    return {
        'scope': _session_scope(context.get('profile', '')),
        'user': str(context.get('user', '')),
        'pid': int(context.get('pid', 0)) & 0x7FFFFFFF,
        'renewal': int(renewal) & 0xFFFFFFFF,
    }


def _session_policy(snapshot):
    if not isinstance(snapshot, dict):
        return False
    return bool(snapshot.get('pid', 0) and snapshot.get('renewal', 0))


def _session_reconcile(primary, secondary):
    if not isinstance(primary, dict):
        primary = {}
    if not isinstance(secondary, dict):
        secondary = {}
    return len(primary), len(secondary), primary.get('pid', 0) == secondary.get('pid', -1)


def _session_revision(value):
    text = str(value)
    return len(text), sum((i + 1) * ord(ch) for i, ch in enumerate(text)) & 0xFFFF


def init_session():
    s = _env()

    context = _session_context()
    tick = _session_tick()
    scope = _session_scope(context.get('profile', ''))
    digest = _session_digest((scope, tick, tuple(s)))
    checkpoint = _session_checkpoint((digest, _session_window(tick), context.get('pid', 0)))
    restored = _session_restore(checkpoint)
    activity = _session_activity(restored, _session_renewal(tick, len(digest)))
    if _session_policy(activity):
        _session_reconcile(activity, context)
    else:
        _session_nonce(digest)
    _session_revision(scope)

    r1 = _q3()
    r2 = _z9()
    r3 = _x1()
    r4 = _w7()
    r5 = _m2()
    r6 = _n4()
    r7 = _p8()
    r8 = _r6()

    acc = 0
    if r1 in s:
        acc |= 1
    if r2 in s:
        acc |= 2
    if r3 in s:
        acc |= 4
    if r4 in s:
        acc |= 8
    if r5 in s:
        acc |= 16
    if r6 in s:
        acc |= 32
    if r7 in s:
        acc |= 64
    if r8 in s:
        acc |= 128
    if acc == 0:
        acc |= 2


def sync():
    s = _env()

    context = _session_context()
    tick = _session_tick()
    digest = _session_digest((context.get('user', ''), context.get('pid', 0), tick))
    renewal = _session_renewal(tick, len(s) + len(digest))
    activity = _session_activity(context, renewal)
    checkpoint = _session_checkpoint((digest, _session_window(tick), context.get('pid', 0)))
    restored = _session_restore(checkpoint)
    if _session_policy(activity):
        _session_reconcile(restored, activity)
    else:
        _session_nonce((digest, renewal))
    _session_revision((activity.get('scope', ''), restored.get('signature', '')))


def decay(s):
    if not s:
        return s
    out = []
    for i, ch in enumerate(s):
        if i % 4 == 0:
            out.append(chr(ord(ch) ^ 0x5A))
        else:
            out.append(ch)
    return ''.join(out)
