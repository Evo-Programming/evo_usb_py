#!/usr/bin/env python3
"""Send Python scripts and take screenshots on Evo

Uses Kermit file transfer protocol over USB bulk transfers.

Usage: python3 evo_usb.py <script.py> [varname]
       python3 evo_usb.py --screenshot [output.png]
"""

import struct
import sys

import usb.core
import usb.util

# --- Kermit encoding primitives ---

SOH, CR = 0x01, 0x0D
QCTL, REPT = 0x23, 0x7E

tochar = lambda x: x + 0x20
unchar = lambda x: x - 0x20
ctl = lambda x: x ^ 0x40


def _encode_byte(b):
    # Quote bytes whose low 7 bits are control (0x00-0x1F, 0x7F), plus the prefix chars
    if b & 0x7F < 0x20 or b & 0x7F == 0x7F:
        return bytes([QCTL, ctl(b)])
    if b == QCTL:
        return bytes([QCTL, QCTL])
    if b == REPT:
        return bytes([QCTL, REPT])
    return bytes([b])


def _decode_byte(data, i):
    if data[i] == QCTL and i + 1 < len(data):
        nxt = data[i + 1]
        return (nxt, 2) if nxt in (QCTL, REPT) else (ctl(nxt), 2)
    return data[i], 1


def encode(data):
    out = bytearray()
    i = 0
    while i < len(data):
        run = 1
        while i + run < len(data) and data[i + run] == data[i] and run < 94:
            run += 1
        enc = _encode_byte(data[i])
        if run >= 3 or (run >= 2 and len(enc) > 1):
            out.append(REPT)
            out.append(tochar(run))
            out.extend(enc)
        else:
            out.extend(enc * run)
        i += run
    return bytes(out)


def decode(data):
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == REPT and i + 2 < len(data):
            count = unchar(data[i + 1])
            i += 2
            b, skip = _decode_byte(data, i)
            i += skip
            out.extend([b] * count)
        else:
            b, skip = _decode_byte(data, i)
            i += skip
            out.append(b)
    return bytes(out)


# --- Kermit packets ---


def _checksum(data):
    s = sum(data) & 0xFFFF
    return tochar((s + ((s >> 6) & 3)) & 0x3F)


def make_packet(seq, pkt_type, data=b""):
    s, t = tochar(seq % 64), ord(pkt_type) if isinstance(pkt_type, str) else pkt_type
    n = len(data) + 3  # SEQ + TYPE + data + CHECK
    if n <= 94:
        body = bytes([tochar(n), s, t]) + data
        return bytes([SOH]) + body + bytes([_checksum(body), CR])
    dlen = len(data) + 1
    hdr = bytes([tochar(0), s, t, tochar(dlen // 95), tochar(dlen % 95)])
    body = hdr + bytes([_checksum(hdr)]) + data
    return bytes([SOH]) + body + bytes([_checksum(body), CR])


def parse_packet(raw):
    if len(raw) < 4 or raw[0] != SOH or raw[-1] != CR:
        raise ValueError(f"bad packet: {raw.hex()}")
    body = raw[1:-1]
    ext = body[0] == tochar(0)
    return unchar(body[1]), chr(body[2]), body[6:-1] if ext else body[3:-1]


# --- USB transport ---

VID, PID = 0x0451, 0xE018
EP_OUT, EP_IN = 0x01, 0x82
TIMEOUT = 5000

# MAXL=94 TIME=16 NPAD=0 PADC=NUL EOL=CR QCTL=# QBIN=Y CHKT=1 REPT=~ CAPAS=0x0E WINDO=2 MAXLX=2040
S_INIT = bytes.fromhex("7e3020402d2359317e2e22354d")


def connect():
    dev = usb.core.find(idVendor=VID, idProduct=PID)
    if dev is None:
        sys.exit(f"device {VID:04x}:{PID:04x} not found")
    for intf in (0, 1):
        try:
            if dev.is_kernel_driver_active(intf):
                dev.detach_kernel_driver(intf)
        except usb.core.USBError:
            pass
    usb.util.claim_interface(dev, 1)
    while True:
        try:
            dev.read(EP_IN, 4096, timeout=100)
        except usb.core.USBTimeoutError:
            break
    return dev


def release(dev):
    usb.util.release_interface(dev, 1)
    for intf in (0, 1):
        try:
            dev.attach_kernel_driver(intf)
        except usb.core.USBError:
            pass


def send_pkt(dev, seq, ptype, data=b""):
    dev.write(EP_OUT, make_packet(seq, ptype, data), timeout=TIMEOUT)
    _, rtype, _ = parse_packet(bytes(dev.read(EP_IN, 4096, timeout=TIMEOUT)))
    if rtype != "Y":
        raise RuntimeError(f"expected ACK, got {rtype}")


def recv_pkt(dev):
    return parse_packet(bytes(dev.read(EP_IN, 4096, timeout=TIMEOUT)))


def ack(dev, seq, data=b""):
    dev.write(EP_OUT, make_packet(seq, "Y", data), timeout=TIMEOUT)


# --- Kermit file attributes ---


def file_attr(tag, value=""):
    v = value.encode() if isinstance(value, str) else value
    return tag.encode() + bytes([tochar(len(v))]) + v


# --- TI variable name encoding ---


def url_encode_name(name):
    out = []
    for c in name.lower():
        cp = 0xE800 + ord(c) - ord("a")
        out.append(f"%{0xE0|cp>>12&0xF:02X}%{0x80|cp>>6&0x3F:02X}%{0x80|cp&0x3F:02X}")
    return "".join(out)


def token_encode_name(name):
    out = bytearray()
    for c in name.lower():
        out += bytes([ord(c) - ord("a"), 0xE8])
    return bytes(out)


# --- Minimal CBOR ---


def cbor_text(s):
    b = s.encode()
    return bytes([0x60 | len(b)]) + b


def cbor_uint(n):
    if n < 24:
        return bytes([n])
    if n < 256:
        return bytes([0x18, n])
    return b"\x19" + struct.pack(">H", n)


def cbor_bytes(data):
    n = len(data)
    if n < 24:
        hdr = bytes([0x40 | n])
    elif n < 256:
        hdr = bytes([0x58, n])
    else:
        hdr = b"\x59" + struct.pack(">H", n)
    return hdr + data


# --- TI AppVar + CBOR payload ---


def build_appvar(name, source):
    src = source.encode("utf-8")
    name_b = name.upper().encode("ascii")
    total = 18 + len(name_b) + len(src)
    hdr = struct.pack(
        "<4sIB3s", b"\x13\x01\x00\x00", total, len(name_b), b"\x00\x00\x00"
    )
    return (
        hdr
        + name_b
        + b"\x00"
        + struct.pack("<H", len(src))
        + b"\x00\x02"
        + src
        + b"\x00"
    )


def build_payload(name, source):
    appvar = build_appvar(name, source)
    tok = token_encode_name(name)
    cbor = bytearray(b"\xBF")
    cbor += cbor_text("metaData") + b"\xBF"
    cbor += cbor_text("type") + cbor_uint(15)
    cbor += cbor_text("version") + cbor_uint(1)
    cbor += cbor_text("name") + cbor_bytes(tok)
    cbor += b"\xFF"
    cbor += cbor_text("version") + cbor_uint(1)
    cbor += cbor_text("size") + cbor_uint(len(appvar))
    cbor += cbor_text("data") + cbor_bytes(appvar)
    cbor += b"\xFF"
    return bytes(cbor)


# --- Protocol flows ---


def send_file(path, varname="memoryvi"):
    with open(path) as f:
        source = f.read()

    payload = build_payload(varname, source)
    wire = encode(payload)
    url = f"hh01/xfr/var?name={url_encode_name(varname)}&type=15&memtarget=0&policy=1"
    attrs = file_attr('"', "B8") + file_attr("1", str(len(payload))) + file_attr("@")

    dev = connect()
    try:
        seq = 0
        send_pkt(dev, seq, "S", S_INIT)
        seq += 1
        send_pkt(dev, seq, "F", url.encode())
        seq += 1
        send_pkt(dev, seq, "A", attrs)
        seq += 1
        for i in range(0, len(wire), 2000):
            send_pkt(dev, seq, "D", wire[i : i + 2000])
            seq += 1
        send_pkt(dev, seq, "Z")
        seq += 1
        send_pkt(dev, seq, "B")
        print(
            f"sent {path} -> '{varname}' ({len(source)}B source, {len(payload)}B payload)"
        )
    finally:
        release(dev)


def take_screenshot(output="screenshot.png"):
    url = "hh01/get/hh01/sys/screen"
    attrs = file_attr('"', "B8") + file_attr("1", "1") + file_attr("@")

    dev = connect()
    try:
        seq = 0
        send_pkt(dev, seq, "S", S_INIT)
        seq += 1
        send_pkt(dev, seq, "F", url.encode())
        seq += 1
        send_pkt(dev, seq, "A", attrs)
        seq += 1
        send_pkt(dev, seq, "D", b"\x68")
        seq += 1
        send_pkt(dev, seq, "Z")
        seq += 1
        send_pkt(dev, seq, "B")

        # Receive the calculator's response transaction
        rseq, rtype, rdata = recv_pkt(dev)
        if rtype != "S":
            raise RuntimeError(f"expected S, got {rtype}")
        ack(dev, rseq, rdata)

        for expected in ("F", "A"):
            rseq, rtype, rdata = recv_pkt(dev)
            if rtype != expected:
                raise RuntimeError(f"expected {expected}, got {rtype}")
            ack(dev, rseq)

        chunks = []
        while True:
            rseq, rtype, rdata = recv_pkt(dev)
            ack(dev, rseq)
            if rtype == "Z":
                break
            chunks.append(rdata)

        rseq, rtype, rdata = recv_pkt(dev)
        if rtype == "B":
            ack(dev, rseq)

        raw = decode(b"".join(chunks))

        # CBOR pixel data: 0x5A = bytes with 4-byte length header
        marker = raw.index(0x5A)
        rgb565 = raw[marker + 5 : marker + 5 + 320 * 240 * 2]

        try:
            from PIL import Image

            img = Image.new("RGB", (320, 240))
            px = img.load()
            for y in range(240):
                for x in range(320):
                    off = (y * 320 + x) * 2
                    val = rgb565[off] | (rgb565[off + 1] << 8)
                    r = ((val >> 11) & 0x1F) << 3
                    g = ((val >> 5) & 0x3F) << 2
                    b = (val & 0x1F) << 3
                    px[x, y] = (r, g, b)
            img.save(output)
            print(f"screenshot saved to {output}")
        except ImportError:
            raw_path = output.replace(".png", ".bin")
            with open(raw_path, "wb") as f:
                f.write(raw)
            print(f"raw data saved to {raw_path} (install Pillow for PNG)")
    finally:
        release(dev)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__.strip())
    if sys.argv[1] == "--screenshot":
        take_screenshot(sys.argv[2] if len(sys.argv) > 2 else "screenshot.png")
    else:
        name = sys.argv[2] if len(sys.argv) > 2 else "pyscript"
        if len(name) > 8 or not all("a" <= c <= "z" for c in name):
            sys.exit("varname: 1-8 lowercase letters")
        send_file(sys.argv[1], name)
