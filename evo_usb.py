#!/usr/bin/env python3
"""Send Python scripts, OS images, and take screenshots on Evo

https://github.com/Evo-Programming/evo_usb_py

Uses Kermit file transfer protocol over USB bulk transfers (serial device directly when appropriate)

Usage: python3 evo_usb.py <script.py> [varname]
       python3 evo_usb.py --screenshot [output.png] [mode]
       python3 evo_usb.py --send-file <file> [auto|ram|archive]
       python3 evo_usb.py --get-file <name> [type] [output]
       python3 evo_usb.py --delete-file <name> [type]
       python3 evo_usb.py --send-os <os_bundle.bin>
       python3 evo_usb.py --extract-os <capture.pcapng> [output.bin]
       python3 evo_usb.py --get-info
       python3 evo_usb.py --reboot
       python3 evo_usb.py --break
       python3 evo_usb.py --list-files
       python3 evo_usb.py --dynamic-info
       python3 evo_usb.py --get-logs [output_dir]
       python3 evo_usb.py --exit-ptt
       python3 evo_usb.py --key <scancode>
"""

import glob
import os
import platform
import select
import struct
import sys
import time
import zlib

usb = None


class TransportTimeout(TimeoutError):
    pass


class TransportError(OSError):
    pass


USB_ERROR_EXCEPTIONS = (TransportError, OSError)
USB_TIMEOUT_EXCEPTIONS = (TransportTimeout, TimeoutError)
TRANSFER_ERROR_EXCEPTIONS = (RuntimeError, TransportError, OSError)

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


def xfr_result_message(code):
    return XFR_RESULT_MESSAGES.get(code, f"Error: {code}")


RAW_TRANSFER_ERROR_HINTS = {
    "PM": "maybe invalid memory destination",
    "DP": "maybe rejected data or invalid memory destination",
    "ER": "unknown calculator error, maybe rejected data",
}


def raw_transfer_error_hint(text):
    return RAW_TRANSFER_ERROR_HINTS.get(text, "unknown calculator error")


def is_raw_transfer_error(text, codes):
    return any(f": {code} (" in text or text.endswith(f": {code}") for code in codes)


def transfer_error_text(data):
    text = data.decode("utf-8", errors="replace").strip()
    if text and all(c.isprintable() for c in text):
        for candidate in (text, text.split()[-1]):
            try:
                code = int(candidate, 0)
            except ValueError:
                continue
            message = xfr_result_message(code)
            return f"{text} ({message})" if message not in text else text
        if len(text) == 2 and text.isalpha():
            return f"{text} ({raw_transfer_error_hint(text)})"
        return text

    if len(data) == 1:
        return xfr_result_message(data[0])
    if len(data) == 2:
        return xfr_result_message(int.from_bytes(data, "big"))
    if len(data) == 4:
        return xfr_result_message(int.from_bytes(data, "big"))
    return data.hex()


# --- USB transport ---

VID, PID = 0x0451, 0xE018
USB_INTERFACE = 1
USB_ALT_SETTING = 0
EP_OUT, EP_IN = 0x01, 0x82
TIMEOUT = 5000

# MAXL=94 TIME=16 NPAD=0 PADC=NUL EOL=CR QCTL=# QBIN=Y CHKT=1 REPT=~ CAPAS=0x0E WINDO=2 MAXLX=2040
S_INIT = bytes.fromhex("7e3020402d2359317e2e22354d")

XFR_RESULT_MESSAGES = {
    -1: "Skipped",
    0: "Successful Transfer",
    1: "Unknown Error",
    2: "Error: PARAM",
    3: "Error: NOPORT",
    4: "Error: NOMEM",
    5: "Error: FLASH",
    6: "Error: INVALID",
    7: "Error: NOTFOUND_CLI",
    8: "Error: NOTFOUND_SRV",
    9: "Error: CANCEL",
    10: "Error: TIMEOUT",
    11: "Error: DISCONNECT",
    12: "Error: UNSUPPORTED_REQUEST",
    13: "Error: VERSION_TOO_NEW",
    14: "Error: VAR_EXISTS",
    15: "Error: INVALID_DATA_PAYLOAD",
    16: "Error: CALCULATOR_BUSY",
    17: "Error: LOW_BATT",
    18: "Error: WAIT_USER",
    19: "Error: USER_OVERWRITE",
    20: "Error: USER_OVERWRITE_ALL",
    21: "Error: USER_OMIT",
    22: "Error: USER_QUIT",
    23: "Error: USER_NOT_IN_RECEIVE",
    24: "Error: DEFRAG_INITIATED",
}


class USBConnection:
    def __init__(self, dev, interface_number, ep_out, ep_in, detached_interfaces):
        self.dev = dev
        self.interface_number = interface_number
        self.ep_out = ep_out
        self.ep_in = ep_in
        self.detached_interfaces = detached_interfaces

    def write(self, endpoint, data, timeout=None):
        if endpoint == EP_OUT:
            endpoint = self.ep_out
        return self.dev.write(endpoint, data, timeout=timeout)

    def read(self, endpoint, size_or_buffer, timeout=None):
        if endpoint == EP_IN:
            endpoint = self.ep_in
        return self.dev.read(endpoint, size_or_buffer, timeout=timeout)


class SerialConnection:
    def __init__(self, path, fd):
        self.path = path
        self.fd = fd
        self._rx = bytearray()

    def write(self, endpoint, data, timeout=None):
        deadline = _deadline(timeout)
        view = memoryview(data)
        total = 0
        while total < len(data):
            remaining = _remaining(deadline)
            if remaining <= 0:
                raise TransportTimeout(f"serial write timed out on {self.path}")
            _, writable, _ = select.select([], [self.fd], [], remaining)
            if not writable:
                raise TransportTimeout(f"serial write timed out on {self.path}")
            try:
                total += os.write(self.fd, view[total:])
            except BlockingIOError:
                continue
            except OSError as e:
                raise TransportError(e.errno, f"{self.path}: {e.strerror}") from e
        return total

    def read(self, endpoint, size_or_buffer, timeout=None):
        deadline = _deadline(timeout)
        while True:
            if CR in self._rx:
                idx = self._rx.index(CR) + 1
                pkt = bytes(self._rx[:idx])
                del self._rx[:idx]
                return pkt

            remaining = _remaining(deadline)
            if remaining <= 0:
                raise TransportTimeout(f"serial read timed out on {self.path}")
            readable, _, _ = select.select([self.fd], [], [], remaining)
            if not readable:
                raise TransportTimeout(f"serial read timed out on {self.path}")
            try:
                chunk = os.read(self.fd, 4096)
            except BlockingIOError:
                continue
            except OSError as e:
                raise TransportError(e.errno, f"{self.path}: {e.strerror}") from e
            if not chunk:
                continue
            self._rx.extend(chunk)


def _deadline(timeout):
    return time.monotonic() + ((timeout if timeout is not None else TIMEOUT) / 1000)


def _remaining(deadline):
    return max(0, deadline - time.monotonic())


def _require_pyusb():
    global usb, USB_ERROR_EXCEPTIONS, USB_TIMEOUT_EXCEPTIONS, TRANSFER_ERROR_EXCEPTIONS
    if usb is not None:
        return
    try:
        import usb as usb_pkg
        import usb.core
        import usb.util
    except ModuleNotFoundError as e:
        if e.name == "usb":
            sys.exit(
                "PyUSB is required for USB operations.\n"
                "Install it with: python3 -m pip install pyusb\n"
                "With Homebrew Python, use a virtualenv instead:\n"
                "  python3 -m venv .venv && .venv/bin/python -m pip install pyusb"
            )
        raise
    usb = usb_pkg
    USB_ERROR_EXCEPTIONS = (TransportError, OSError, usb.core.USBError)
    USB_TIMEOUT_EXCEPTIONS = (TransportTimeout, TimeoutError, usb.core.USBTimeoutError)
    TRANSFER_ERROR_EXCEPTIONS = (RuntimeError,) + USB_ERROR_EXCEPTIONS


def _serial_paths():
    configured = os.environ.get("EVO_USB_SERIAL")
    if configured:
        return [configured]
    if platform.system() == "Darwin":
        return sorted(glob.glob("/dev/cu.usbmodem*"))
    return sorted(
        glob.glob("/dev/serial/by-id/*Texas_Instruments*")
        + glob.glob("/dev/serial/by-id/*TI-84*")
        + glob.glob("/dev/ttyACM*")
        + glob.glob("/dev/ttyUSB*")
    )


def _connect_serial():
    import termios

    paths = _serial_paths()
    if not paths:
        raise RuntimeError("no Evo CDC serial device found")

    last_error = None
    for path in paths:
        try:
            fd = os.open(path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
            try:
                attrs = termios.tcgetattr(fd)
                attrs[0] = 0
                attrs[1] = 0
                attrs[2] = attrs[2] | termios.CLOCAL | termios.CREAD
                attrs[3] = 0
                attrs[6][termios.VMIN] = 0
                attrs[6][termios.VTIME] = 0
                attrs[4] = termios.B115200
                attrs[5] = termios.B115200
                termios.tcsetattr(fd, termios.TCSANOW, attrs)
                termios.tcflush(fd, termios.TCIOFLUSH)
            except Exception:
                os.close(fd)
                raise
            return SerialConnection(path, fd)
        except OSError as e:
            last_error = e

    detail = f": {last_error}" if last_error is not None else ""
    raise RuntimeError(f"could not open any Evo serial device{detail}")


def _detach_kernel_driver(dev, interface_number):
    try:
        if dev.is_kernel_driver_active(interface_number):
            dev.detach_kernel_driver(interface_number)
            return True
    except (AttributeError, NotImplementedError) + USB_ERROR_EXCEPTIONS:
        pass
    return False


def _set_configuration(dev):
    try:
        return dev.get_active_configuration()
    except (NotImplementedError,) + USB_ERROR_EXCEPTIONS:
        pass

    try:
        dev.set_configuration()
        return dev.get_active_configuration()
    except USB_ERROR_EXCEPTIONS as e:
        sys.exit(f"could not configure USB device: {e}")


def _bulk_pair(interface):
    out_ep = usb.util.find_descriptor(
        interface,
        custom_match=lambda e: (
            usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT
            and usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK
        ),
    )
    in_ep = usb.util.find_descriptor(
        interface,
        custom_match=lambda e: (
            usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN
            and usb.util.endpoint_type(e.bmAttributes) == usb.util.ENDPOINT_TYPE_BULK
        ),
    )
    if out_ep is None or in_ep is None:
        return None
    return out_ep.bEndpointAddress, in_ep.bEndpointAddress


def _transfer_interface(dev):
    cfg = _set_configuration(dev)
    candidates = []
    seen = set()

    try:
        candidates.append(cfg[(USB_INTERFACE, USB_ALT_SETTING)])
    except (IndexError, KeyError, TypeError):
        pass

    for interface in cfg:
        key = (
            interface.bInterfaceNumber,
            getattr(interface, "bAlternateSetting", USB_ALT_SETTING),
        )
        if key not in seen:
            candidates.append(interface)
            seen.add(key)

    for interface in candidates:
        pair = _bulk_pair(interface)
        if pair is not None:
            return interface.bInterfaceNumber, pair[0], pair[1]

    raise RuntimeError("could not find Evo USB bulk transfer interface")


def connect():
    if platform.system() != "Windows":
        try:
            return _connect_serial()
        except RuntimeError as e:
            sys.exit(str(e))

    _require_pyusb()
    find_args = {"idVendor": VID, "idProduct": PID}
    dev = usb.core.find(**find_args)
    if dev is None:
        sys.exit(f"device {VID:04x}:{PID:04x} not found")

    detached_interfaces = {
        intf for intf in (0, 1) if _detach_kernel_driver(dev, intf)
    }
    interface_number, ep_out, ep_in = _transfer_interface(dev)

    try:
        usb.util.claim_interface(dev, interface_number)
    except USB_ERROR_EXCEPTIONS as e:
        sys.exit(f"could not claim USB interface {interface_number}: {e}")

    conn = USBConnection(dev, interface_number, ep_out, ep_in, detached_interfaces)
    while True:
        try:
            conn.read(EP_IN, 4096, timeout=100)
        except USB_TIMEOUT_EXCEPTIONS:
            break
    return conn


def release(conn):
    if isinstance(conn, SerialConnection):
        try:
            os.close(conn.fd)
        except OSError:
            pass
        return

    dev = conn.dev if isinstance(conn, USBConnection) else conn
    interface_number = (
        conn.interface_number if isinstance(conn, USBConnection) else USB_INTERFACE
    )
    detached_interfaces = (
        conn.detached_interfaces if isinstance(conn, USBConnection) else {0, 1}
    )

    try:
        usb.util.release_interface(dev, interface_number)
    except USB_ERROR_EXCEPTIONS:
        pass

    for intf in detached_interfaces:
        try:
            dev.attach_kernel_driver(intf)
        except (AttributeError, NotImplementedError) + USB_ERROR_EXCEPTIONS:
            pass


def send_pkt(dev, seq, ptype, data=b"", timeout=TIMEOUT):
    pkt = make_packet(seq, ptype, data)
    for attempt in range(3):
        dev.write(EP_OUT, pkt, timeout=timeout)
        _, rtype, rdata = parse_packet(bytes(dev.read(EP_IN, 4096, timeout=timeout)))
        if rtype == "Y":
            return rdata
        if rtype == "E":
            raise RuntimeError(f"calculator error on packet {ptype} seq {seq}: {transfer_error_text(rdata)}")
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


def _png_chunk(kind, data):
    return (
        struct.pack(">I", len(data))
        + kind
        + data
        + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
    )


def save_rgb565_png(path, rgb565, width=320, height=240):
    rows = bytearray()
    for y in range(height):
        rows.append(0)
        for x in range(width):
            off = (y * width + x) * 2
            val = rgb565[off] | (rgb565[off + 1] << 8)
            rows.extend(
                (
                    ((val >> 11) & 0x1F) << 3,
                    ((val >> 5) & 0x3F) << 2,
                    (val & 0x1F) << 3,
                )
            )

    png = (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0))
        + _png_chunk(b"IDAT", zlib.compress(bytes(rows)))
        + _png_chunk(b"IEND", b"")
    )
    with open(path, "wb") as f:
        f.write(png)


# --- TI variable name encoding ---


def url_encode_name(name):
    out = []
    for c in name.lower():
        cp = 0xE800 + ord(c) - ord("a")
        out.append(f"%{0xE0|cp>>12&0xF:02X}%{0x80|cp>>6&0x3F:02X}%{0x80|cp&0x3F:02X}")
    return "".join(out)


def url_encode_name_bytes(name_bytes):
    out = []
    for i in range(0, len(name_bytes), 2):
        if i + 1 >= len(name_bytes):
            break
        word = name_bytes[i] | (name_bytes[i + 1] << 8)
        if word == 0:
            break
        out.extend(f"%{b:02X}" for b in chr(word).encode("utf-8"))
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


def _cbor_read_len(data, offset, addl):
    if addl < 24:
        return addl, offset
    if addl == 24:
        return data[offset], offset + 1
    if addl == 25:
        return struct.unpack(">H", data[offset : offset + 2])[0], offset + 2
    if addl == 26:
        return struct.unpack(">I", data[offset : offset + 4])[0], offset + 4
    if addl == 27:
        return struct.unpack(">Q", data[offset : offset + 8])[0], offset + 8
    if addl == 31:
        return None, offset
    raise ValueError(f"unsupported CBOR additional info {addl}")


def _cbor_decode(data, offset=0):
    if offset >= len(data):
        raise ValueError("unexpected end of CBOR data")
    initial = data[offset]
    offset += 1
    major, addl = initial >> 5, initial & 0x1F

    if major == 0:
        return _cbor_read_len(data, offset, addl)
    if major == 1:
        value, offset = _cbor_read_len(data, offset, addl)
        return -1 - value, offset
    if major in (2, 3):
        length, offset = _cbor_read_len(data, offset, addl)
        chunks = []
        if length is None:
            while offset < len(data) and data[offset] != 0xFF:
                chunk, offset = _cbor_decode(data, offset)
                chunks.append(chunk)
            offset += 1
            value = b"".join(chunks) if major == 2 else "".join(chunks)
            return value, offset
        value = data[offset : offset + length]
        offset += length
        if major == 3:
            value = value.decode("utf-8", errors="replace")
        return value, offset
    if major == 4:
        length, offset = _cbor_read_len(data, offset, addl)
        out = []
        if length is None:
            while offset < len(data) and data[offset] != 0xFF:
                value, offset = _cbor_decode(data, offset)
                out.append(value)
            return out, offset + 1
        for _ in range(length):
            value, offset = _cbor_decode(data, offset)
            out.append(value)
        return out, offset
    if major == 5:
        length, offset = _cbor_read_len(data, offset, addl)
        out = {}
        if length is None:
            while offset < len(data) and data[offset] != 0xFF:
                key, offset = _cbor_decode(data, offset)
                value, offset = _cbor_decode(data, offset)
                out[key] = value
            return out, offset + 1
        for _ in range(length):
            key, offset = _cbor_decode(data, offset)
            value, offset = _cbor_decode(data, offset)
            out[key] = value
        return out, offset
    if major == 7:
        if addl == 20:
            return False, offset
        if addl == 21:
            return True, offset
        if addl in (22, 23):
            return None, offset
        if addl == 31:
            return None, offset
    raise ValueError(f"unsupported CBOR item 0x{initial:02x}")


def cbor_loads(data):
    value, offset = _cbor_decode(data)
    if offset != len(data):
        raise ValueError("trailing CBOR data")
    return value


def evo_checksum(body):
    if len(body) < 3:
        return 0
    adjusted = len(body) - 3
    word_count = adjusted >> 1
    if adjusted & 1 and word_count > 0:
        word_count -= 1
    checksum = 0
    for i in range(word_count):
        checksum ^= body[i * 2] | (body[i * 2 + 1] << 8)
    return checksum & 0xFFFF


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


def _screen_url(mode):
    if mode == 0:
        return "hh01/get/hh01/sys/screen"
    if mode == 1:
        return "hh01/get/hh01/inf/res?name=screencapture"
    if mode == 2:
        return "hh01/get/hh01/inf/res?name=screencapture&withcursor=1"
    raise ValueError("screen mode must be 0, 1, or 2")


def take_screenshot(output="screenshot.png", mode=0):
    raw = _get_request(_screen_url(mode))

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
        save_rgb565_png(output, rgb565)
        print(f"screenshot saved to {output}")


def _get_request(url):
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

        return decode(b"".join(chunks))
    finally:
        release(dev)


def _put_request(url, payload, timeout=TIMEOUT, chunk_size=2000):
    wire = encode(payload)
    wire_chunks = _split_element_aligned(wire, chunk_size)
    attrs = file_attr('"', "B8") + file_attr("1", str(len(payload))) + file_attr("@")

    dev = connect()
    try:
        seq = 0
        send_pkt(dev, seq, "S", S_INIT, timeout=timeout)
        seq += 1
        send_pkt(dev, seq, "F", url.encode(), timeout=timeout)
        seq += 1
        send_pkt(dev, seq, "A", attrs, timeout=timeout)
        seq += 1
        for chunk in wire_chunks:
            send_pkt(dev, seq, "D", chunk, timeout=timeout)
            seq += 1
        send_pkt(dev, seq, "Z", timeout=timeout)
        seq += 1
        send_pkt(dev, seq, "B", timeout=timeout)
    finally:
        release(dev)


def get_device_info():
    raw = _get_request("hh01/get/hh01/sys/attributes")
    return parse_cbor_info(raw)


def get_dynamic_info():
    raw = _get_request("hh01/get/hh01/inf/res?name=dynamicinfo")
    parsed = cbor_loads(raw)
    parsed.pop("metaData", None)
    return parsed


def list_files():
    raw = _get_request("hh01/get/hh01/inf/res?name=directory&gotohome=1")
    parsed = cbor_loads(raw)
    entries = []
    for item in parsed.get("data", []):
        name = directory_display_name(item)
        entries.append(
            {
                "name": name,
                "type": item.get("type", 0),
                "size": item.get("size", 0),
                "mem": item.get("mem", False),
            }
        )
    return entries


def directory_display_name(item):
    tok_name = item.get("tokName", b"")
    if item.get("type") == 1 and isinstance(tok_name, bytes) and len(tok_name) == 2:
        if tok_name[1] == 0xE8 and 0x30 <= tok_name[0] <= 0x35:
            return f"L{tok_name[0] - 0x2F}"
    if item.get("type") == 7 and isinstance(tok_name, bytes) and len(tok_name) == 2:
        word = tok_name[0] | (tok_name[1] << 8)
        if 0xE840 <= word <= 0xE849:
            return f"Y{0 if word == 0xE849 else word - 0xE840 + 1}"
        if 0xE850 <= word <= 0xE85B:
            idx = (word - 0xE850) // 2 + 1
            return f"{'X' if (word - 0xE850) % 2 == 0 else 'Y'}{idx}T"
        if 0xE860 <= word <= 0xE865:
            return f"r{word - 0xE860 + 1}"
        if 0xE870 <= word <= 0xE872:
            return chr(ord("u") + word - 0xE870)

    name = item.get("dispName", tok_name)
    if isinstance(name, bytes):
        return name.decode("utf-8", errors="replace")
    return str(name)


EVO_TYPE_EXTENSIONS = {
    0: "8xn2",
    1: "8xl2",
    2: "8xp2",
    3: "8xd2",
    4: "8ci2",
    5: "8ca2",
    6: "8xm2",
    7: "8xy2",
    8: "8xv2",
    10: "8xs2",
    12: "8xw2",
    13: "8xz2",
    14: "8xt2",
    15: "8xpy2",
}


def _safe_filename(name):
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
    return safe or "var"


def find_directory_entry(name, type_id=None):
    raw = _get_request("hh01/get/hh01/inf/res?name=directory&gotohome=1")
    entries = cbor_loads(raw).get("data", [])
    matches = []
    for item in entries:
        display = directory_display_name(item)
        requested = name.lower()
        candidates = {display.lower()}
        if item.get("type") == 6 and display.startswith("[") and display.endswith("]"):
            candidates.add(display[1:-1].lower())
        if item.get("type") == 14 and display.lower() == "tblsetup":
            candidates.add("tblset")
        if requested not in candidates:
            continue
        if type_id is not None and item.get("type") != type_id:
            continue
        matches.append(item)

    if not matches:
        suffix = "" if type_id is None else f" type={type_id}"
        raise RuntimeError(f"variable '{name}'{suffix} not found")
    if len(matches) > 1:
        choices = ", ".join(f"type={item.get('type')}" for item in matches)
        raise RuntimeError(f"variable '{name}' is ambiguous; specify one of: {choices}")
    return matches[0]


def variable_resource_name(item):
    name = url_encode_name_bytes(item.get("tokName", b""))
    return f"var?name={name}&type={item.get('type', 0)}"


def get_variable(name, type_id=None, output=None):
    item = find_directory_entry(name, type_id)
    data = _get_request(f"hh01/get/hh01/xfr/{variable_resource_name(item)}")
    checksum = evo_checksum(data)
    data += bytes([checksum >> 8, checksum & 0xFF])
    display = directory_display_name(item)
    if output is None:
        ext = EVO_TYPE_EXTENSIONS.get(item.get("type"), "bin")
        output = f"{_safe_filename(display)}.{ext}"
    with open(output, "wb") as f:
        f.write(data)
    print(f"saved {display} type={item.get('type')} to {output} ({len(data)} bytes)")


def delete_variable(name, type_id=None):
    item = find_directory_entry(name, type_id)
    display = directory_display_name(item)
    _put_request(f"hh01/del/{variable_resource_name(item)}", b"\x00")
    print(f"deleted {display} type={item.get('type')}")


def evo_file_type(data):
    try:
        parsed = cbor_loads(data[:-2])
        return parsed.get("metaData", {}).get("type")
    except Exception:
        return None


def _put_var_file_to_target(path, data, archive):
    memtarget = 1 if archive else 0
    _put_request(f"hh01/xfr/var?memtarget={memtarget}&policy=1", data)
    loc = "Archive" if archive else "RAM"
    print(f"sent {path} ({len(data)} bytes) to {loc}")


def send_var_file(path, target="auto"):
    with open(path, "rb") as f:
        data = f.read()

    if isinstance(target, bool):
        target = "archive" if target else "ram"
    target = target.lower()
    if target not in ("auto", "ram", "archive"):
        raise ValueError("target must be auto, ram, or archive")

    if target == "ram":
        _put_var_file_to_target(path, data, archive=False)
        return
    if target == "archive":
        _put_var_file_to_target(path, data, archive=True)
        return

    var_type = evo_file_type(data)
    if var_type in (4, 5):
        _put_var_file_to_target(path, data, archive=True)
        return

    try:
        _put_var_file_to_target(path, data, archive=False)
    except RuntimeError as e:
        # Some AppVar-like samples reject the RAM target with raw calculator
        # payloads like DP, but accept the same file through Archive.
        if not is_raw_transfer_error(str(e), ("PM", "DP")):
            raise
        try:
            get_device_info()
        except Exception:
            pass
        _put_var_file_to_target(path, data, archive=True)


def get_logs(output_dir="evo-logs"):
    os.makedirs(output_dir, exist_ok=True)
    outputs = [
        ("info.bin", "hh01/get/hh01/dbg/Get Event Info"),
        ("events.bin", "hh01/get/hh01/dbg/Get Events"),
    ]
    for filename, url in outputs:
        data = _get_request(url)
        path = os.path.join(output_dir, filename)
        with open(path, "wb") as f:
            f.write(data)
        print(f"saved {path} ({len(data)} bytes)")


def exit_ptt():
    _put_request("hh01/xfr/var?policy=4", b"x")
    print("exit PTT command sent")


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
        except TRANSFER_ERROR_EXCEPTIONS:
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


def _sys_command(url):
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
                _, rtype, rdata = parse_packet(
                    bytes(dev.read(EP_IN, 4096, timeout=TIMEOUT))
                )
                if rtype == "E":
                    sys.exit(f"error response at {ptype} packet: {transfer_error_text(rdata)}")
            except USB_TIMEOUT_EXCEPTIONS + USB_ERROR_EXCEPTIONS:
                break
            seq += 1
    except USB_ERROR_EXCEPTIONS:
        pass
    finally:
        try:
            release(dev)
        except Exception:
            pass


def reboot():
    _sys_command("hh01/sys/reboot")
    print("reboot command sent")


def send_break():
    _sys_command("hh01/sys/break")
    print("break sent")


def send_scancode(sc):
    if sc < 24:
        payload = bytes([0x9F, sc, 0xFF])
    else:
        payload = bytes([0x9F, 0x18, sc, 0xFF])
    wire = encode(payload)
    attrs = file_attr('"', "B8") + file_attr("1", str(len(payload))) + file_attr("@")

    dev = connect()
    try:
        seq = 0
        for ptype, data in [
            ("S", S_INIT),
            ("F", b"hh01/sys/scancode"),
            ("A", attrs),
            ("D", wire),
            ("Z", b""),
            ("B", b""),
        ]:
            pkt = make_packet(seq, ptype, data)
            dev.write(EP_OUT, pkt, timeout=TIMEOUT)
            _, rtype, rdata = parse_packet(bytes(dev.read(EP_IN, 4096, timeout=TIMEOUT)))
            if rtype == "E":
                raise RuntimeError(f"scancode {sc}: error at {ptype} packet: {transfer_error_text(rdata)}")
            seq += 1
    finally:
        try:
            release(dev)
        except Exception:
            pass


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__.strip())
    if sys.argv[1] == "--screenshot":
        output = sys.argv[2] if len(sys.argv) > 2 else "screenshot.png"
        mode = int(sys.argv[3], 0) if len(sys.argv) > 3 else 0
        if len(sys.argv) == 3 and sys.argv[2].isdigit():
            output, mode = "screenshot.png", int(sys.argv[2], 0)
        take_screenshot(output, mode)
    elif sys.argv[1] == "--send-file":
        if len(sys.argv) < 3:
            sys.exit("usage: evo_usb.py --send-file <file> [auto|ram|archive]")
        target = sys.argv[3].lower() if len(sys.argv) > 3 else "auto"
        if target not in ("auto", "ram", "archive"):
            sys.exit("usage: evo_usb.py --send-file <file> [auto|ram|archive]")
        send_var_file(sys.argv[2], target)
    elif sys.argv[1] == "--get-file":
        if len(sys.argv) < 3:
            sys.exit("usage: evo_usb.py --get-file <name> [type] [output]")
        type_id = int(sys.argv[3], 0) if len(sys.argv) > 3 else None
        output = sys.argv[4] if len(sys.argv) > 4 else None
        get_variable(sys.argv[2], type_id, output)
    elif sys.argv[1] == "--delete-file":
        if len(sys.argv) < 3:
            sys.exit("usage: evo_usb.py --delete-file <name> [type]")
        type_id = int(sys.argv[3], 0) if len(sys.argv) > 3 else None
        delete_variable(sys.argv[2], type_id)
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
    elif sys.argv[1] == "--break":
        send_break()
    elif sys.argv[1] == "--list-files":
        for f in list_files():
            loc = "RAM" if f.get("mem") else "ARC"
            print(
                f"  {f['name']:20s} type={f.get('type',0):2d}  size={f.get('size',0):8d}  {loc}"
            )
    elif sys.argv[1] == "--dynamic-info":
        info = get_dynamic_info()
        for k, v in sorted(info.items()):
            print(f"  {k}: {v}")
    elif sys.argv[1] == "--get-logs":
        get_logs(sys.argv[2] if len(sys.argv) > 2 else "evo-logs")
    elif sys.argv[1] == "--exit-ptt":
        exit_ptt()
    elif sys.argv[1] == "--key":
        if len(sys.argv) < 3:
            sys.exit("usage: evo_usb.py --key <scancode>")
        send_scancode(int(sys.argv[2], 0))
    else:
        name = sys.argv[2] if len(sys.argv) > 2 else "pyscript"
        if len(name) > 8 or not all("a" <= c <= "z" for c in name):
            sys.exit("varname: 1-8 lowercase letters")
        send_file(sys.argv[1], name)
