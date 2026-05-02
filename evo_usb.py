#!/usr/bin/env python3
"""Send Python scripts, OS images, and take screenshots on Evo

Uses Kermit file transfer protocol over USB bulk transfers.

Usage: python3 evo_usb.py <script.py> [varname]
       python3 evo_usb.py --screenshot [output.png]
       python3 evo_usb.py --send-os <os_bundle.bin>
       python3 evo_usb.py --extract-os <capture.pcapng> [output.bin]
       python3 evo_usb.py --get-info
       python3 evo_usb.py --reboot
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
    if b & 0x7F < 0x20 or b & 0x7F == 0x7F:
        return bytes([QCTL, ctl(b)])
    if b == QCTL:
        return bytes([QCTL, QCTL])
    if b == REPT:
        return bytes([QCTL, REPT])
    return bytes([b])


def _unctl(b):
    if (b & 0x7F) == 0x3F or (b & 0x60) == 0x40:
        return b ^ 0x40
    return b


def _decode_byte(data, i):
    if data[i] == QCTL and i + 1 < len(data):
        nxt = data[i + 1]
        return (_unctl(nxt), 2)
    return data[i], 1


def encode(data):
    out = bytearray()
    i = 0
    while i < len(data):
        run = 1
        while i + run < len(data) and data[i + run] == data[i] and run < 94:
            run += 1
        enc = _encode_byte(data[i])
        if run >= 3:
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


def send_pkt(dev, seq, ptype, data=b"", timeout=TIMEOUT):
    pkt = make_packet(seq, ptype, data)
    for attempt in range(3):
        dev.write(EP_OUT, pkt, timeout=timeout)
        _, rtype, rdata = parse_packet(bytes(dev.read(EP_IN, 4096, timeout=timeout)))
        if rtype == "Y":
            return rdata
        # NAK — flush stale data and retry
        try:
            while True:
                dev.read(EP_IN, 4096, timeout=100)
        except Exception:
            pass
    raise RuntimeError(f"packet {ptype} seq {seq} NAK'd after 3 retries")


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


def get_device_info():
    url = "hh01/get/hh01/sys/attributes"
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
        return parse_cbor_info(raw)
    finally:
        release(dev)


def parse_cbor_info(data):
    info = {}
    i = 0
    if i >= len(data):
        return info
    count = data[i] & 0x1F
    i += 1
    for _ in range(count if count < 0x1F else 256):
        if i >= len(data):
            break
        klen = data[i] & 0x1F
        i += 1
        key = data[i : i + klen].decode("ascii", errors="replace")
        i += klen
        if i >= len(data):
            break
        vtype = data[i] >> 5
        vinfo = data[i] & 0x1F
        if vtype == 3:  # text
            i += 1
            val = data[i : i + vinfo].decode("ascii", errors="replace")
            i += vinfo
        elif vtype == 0:  # uint
            if vinfo < 24:
                val = vinfo
                i += 1
            elif vinfo == 24:
                val = data[i + 1]
                i += 2
            elif vinfo == 25:
                val = struct.unpack(">H", data[i + 1 : i + 3])[0]
                i += 3
            elif vinfo == 26:
                val = struct.unpack(">I", data[i + 1 : i + 5])[0]
                i += 5
            else:
                break
        elif vtype == 1:  # negative int
            if vinfo < 24:
                val = -(vinfo + 1)
                i += 1
            else:
                break
        else:
            break
        info[key] = val
    return info


OS_MAGIC = 0x96F3B83D


def parse_os_header(data):
    if len(data) < 32:
        return None
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic != OS_MAGIC:
        return None
    data_offset = struct.unpack_from("<H", data, 8)[0]
    section_type = struct.unpack_from("<H", data, 10)[0]
    data_size = struct.unpack_from("<I", data, 12)[0]
    ver_major = struct.unpack_from("<I", data, 20)[0]
    ver_build = struct.unpack_from("<I", data, 24)[0]
    return {
        "data_offset": data_offset,
        "section_type": section_type,
        "data_size": data_size,
        "version": f"{ver_major}.0.0.{ver_build}",
    }


def parse_os_bundle(path):
    with open(path, "rb") as f:
        data = f.read()
    return parse_os_bundle_data(data)


def extract_os_from_pcapng(pcapng_path, output_path=None):
    import subprocess

    result = subprocess.run(
        [
            "tshark",
            "-r",
            pcapng_path,
            "-Y",
            "usb.endpoint_address == 0x01",
            "-T",
            "fields",
            "-e",
            "usb.capdata",
        ],
        stdout=subprocess.PIPE,
        text=True,
        stderr=subprocess.DEVNULL,
    )
    buf = bytearray()
    s_count = 0
    d_payloads = []
    url = None
    for line in result.stdout.strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        raw = bytes.fromhex(line.replace(":", ""))
        buf.extend(raw)
        while True:
            if SOH not in buf:
                break
            soh_idx = buf.index(SOH)
            cr_idx = -1
            for i in range(soh_idx + 3, len(buf)):
                if buf[i] == CR:
                    cr_idx = i
                    break
            if cr_idx == -1:
                break
            pkt_raw = bytes(buf[soh_idx : cr_idx + 1])
            buf = bytearray(buf[cr_idx + 1 :])
            body = pkt_raw[1:-1]
            ext = body[0] == tochar(0)
            ptype = chr(body[2])
            pdata = body[6:-1] if ext else body[3:-1]
            if ptype == "S":
                s_count += 1
            if s_count >= 2:
                if ptype == "F" and url is None:
                    url = pdata.decode("ascii", errors="replace")
                if ptype == "D":
                    d_payloads.append(pdata)

    if not d_payloads:
        sys.exit("no OS data found in pcapng")

    wire = b"".join(d_payloads)
    data = decode(wire)

    if output_path is None:
        _, sections, version = parse_os_bundle_data(data)
        output_path = f"os-{version}.bin"

    with open(output_path, "wb") as f:
        f.write(data)

    _, sections, version = parse_os_bundle_data(data)
    type_names = {0x6B: "secure", 0x41: "os", 0x0C: "app"}
    print(f"extracted {output_path} ({len(data)} bytes, v{version})")
    for i, s in enumerate(sections):
        tname = type_names.get(s["section_type"], f"0x{s['section_type']:02x}")
        print(f"  [{i}] {tname}: {s['data_size']} bytes @ {s['offset']:#x}")
    if url:
        print(f"  url: {url}")


def parse_os_bundle_data(data):
    sections = []
    magic_bytes = struct.pack("<I", OS_MAGIC)
    off = 0
    while off < len(data):
        idx = data.find(magic_bytes, off)
        if idx == -1:
            break
        hdr = parse_os_header(data[idx:])
        if hdr:
            hdr["offset"] = idx
            sections.append(hdr)
        off = idx + 32

    version = sections[0]["version"] if sections else "0.0.0.0"
    for s in sections:
        if s["version"] > version:
            version = s["version"]

    return data, sections, version


def send_os(path, prodnum=23):
    data, sections, version = parse_os_bundle(path)

    print(f"OS bundle: {path}")
    print(f"  size: {len(data)} bytes")
    print(f"  version: {version}")
    print(f"  sections: {len(sections)}")
    type_names = {0x6B: "secure", 0x41: "os", 0x0C: "app"}
    for i, s in enumerate(sections):
        tname = type_names.get(s["section_type"], f"0x{s['section_type']:02x}")
        print(
            f"    [{i}] {tname}: {s['data_size']} bytes @ {s['offset']:#x}, v{s['version']}"
        )

    print("  encoding...", end="", flush=True)
    wire = encode(data)

    wire_chunks = _split_element_aligned(wire)
    total_encoded = sum(len(c) for c in wire_chunks)
    print(f" {total_encoded} bytes, {len(wire_chunks)} chunks")

    os_timeout = 30000
    url = f"hh01/upd/pkg?bundle=1&prodnum={prodnum}&version={version}"
    attrs = file_attr('"', "B8") + file_attr("1", str(len(data))) + file_attr("@")

    dev = connect()
    try:
        seq = 0
        send_pkt(dev, seq, "S", S_INIT, timeout=os_timeout)
        seq += 1
        send_pkt(dev, seq, "F", url.encode(), timeout=os_timeout)
        seq += 1
        send_pkt(dev, seq, "A", attrs, timeout=os_timeout)
        seq += 1

        total_chunks = len(wire_chunks)
        for chunk_num, chunk in enumerate(wire_chunks, 1):
            if chunk_num % 200 == 0 or chunk_num == total_chunks:
                pct = chunk_num * 100 // total_chunks
                print(
                    f"\r  sending: {pct}% ({chunk_num}/{total_chunks})",
                    end="",
                    flush=True,
                )
            send_pkt(dev, seq, "D", chunk, timeout=os_timeout)
            seq += 1

        print()
        send_pkt(dev, seq, "Z", timeout=os_timeout)
        seq += 1
        try:
            send_pkt(dev, seq, "B", timeout=os_timeout)
        except (RuntimeError, usb.core.USBError):
            pass
        print(f"sent OS bundle ({len(data)} bytes, {total_chunks} packets)")
    finally:
        release(dev)


def _split_element_aligned(wire, chunk_size=2000):
    chunks = []
    pos = 0
    chunk_start = 0
    while pos < len(wire):
        if wire[pos] == REPT and pos + 2 < len(wire):
            pos += 2
            if wire[pos] == QCTL and pos + 1 < len(wire):
                pos += 2
            else:
                pos += 1
        elif wire[pos] == QCTL and pos + 1 < len(wire):
            pos += 2
        else:
            pos += 1
        if pos - chunk_start >= chunk_size:
            chunks.append(wire[chunk_start:pos])
            chunk_start = pos
    if chunk_start < len(wire):
        chunks.append(wire[chunk_start : len(wire)])
    return chunks


def reboot():
    url = "hh01/sys/reboot"
    payload = b"\xf5"
    wire = encode(payload)
    attrs = file_attr('"', "B8") + file_attr("1", str(len(payload))) + file_attr("@")

    dev = connect()
    try:
        seq = 0
        for ptype, data in [
            ("S", S_INIT),
            ("F", url.encode()),
            ("A", attrs),
            ("D", wire),
            ("Z", b""),
            ("B", b""),
        ]:
            pkt = make_packet(seq, ptype, data)
            dev.write(EP_OUT, pkt, timeout=TIMEOUT)
            try:
                _, rtype, _ = parse_packet(
                    bytes(dev.read(EP_IN, 4096, timeout=TIMEOUT))
                )
                if rtype == "E":
                    sys.exit(f"error response at {ptype} packet")
            except (usb.core.USBTimeoutError, usb.core.USBError):
                break
            seq += 1
    except usb.core.USBError:
        pass
    finally:
        try:
            release(dev)
        except Exception:
            pass
    print("reboot command sent")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__.strip())
    if sys.argv[1] == "--screenshot":
        take_screenshot(sys.argv[2] if len(sys.argv) > 2 else "screenshot.png")
    elif sys.argv[1] == "--send-os":
        if len(sys.argv) < 3:
            sys.exit("usage: evo_usb.py --send-os <os_bundle.bin>")
        send_os(sys.argv[2])
    elif sys.argv[1] == "--extract-os":
        if len(sys.argv) < 3:
            sys.exit("usage: evo_usb.py --extract-os <capture.pcapng> [output.bin]")
        output = sys.argv[3] if len(sys.argv) > 3 else None
        extract_os_from_pcapng(sys.argv[2], output)
    elif sys.argv[1] == "--get-info":
        info = get_device_info()
        for k, v in sorted(info.items()):
            print(f"  {k}: {v}")
    elif sys.argv[1] == "--reboot":
        reboot()
    else:
        name = sys.argv[2] if len(sys.argv) > 2 else "pyscript"
        if len(name) > 8 or not all("a" <= c <= "z" for c in name):
            sys.exit("varname: 1-8 lowercase letters")
        send_file(sys.argv[1], name)
