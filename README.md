## Quick local linking/screenshot/info/control for your TI-84 Evo!

Official repo: https://github.com/Evo-Programming/evo_usb_py

Uses Kermit file transfer protocol over the serial device exposed by the calculator.

You may have to adjust your permissions for serial access:  
- On Linux, that generally means `usermod -a -G dialout $USER` and re-login for changes to take effect.  
- On macOS (`/dev/cu.usbmodem*`) it should be usable right away.
- On Windows, install pyserial with `py -m pip install pyserial`; the calculator should appear as a `COM` port.

If auto-detection does not pick the right serial device, set `EVO_USB_SERIAL` to the path or port name, for example `/dev/cu.usbmodemRTX_DUMMY1` or `/dev/ttyACM0` or `COM3`.

To connect to a remotely-exposed USB link over TCP, set `EVO_USB_SERIAL` to `tcp:<port>` for localhost or `tcp:<host>:<port>`, for example `tcp:8000` or `tcp:192.0.2.10:8000`.

```bash
Usage: python3 evo_usb.py ...

  <script.py> [varname]                       # to send a python script
  --screenshot [output.png] [mode]            # 0=system screen, 1=no-cursor, 2=with-cursor
  --list-files                                # to get names/type/size/memory
  --send-file <file> [auto|ram|archive]
  --get-file <name> [type] [output]
  --delete-file <name> [type]
  --send-csv-list <csv> <name> [ram|archive] [overwrite|no-overwrite]
  --send-csv-matrix <csv> <name> [ram|archive] [overwrite|no-overwrite]
  --send-os <os_bundle.83b2|84b2|84tb2>
  --extract-os <capture.pcapng> [output.bin]
  --get-info
  --dynamic-info
  --reboot
  --break
  --get-logs [output_dir]
  --exit-ptt
  --key <scancode> [scancode ...]
  --keys <scancode>[,<scancode>...]
```

CSV imports default to RAM and overwrite existing variables. List names may be `L1`-`L6` or a 1-5 character calculator list name; matrix names may be `A`-`J`.

Python bytecode modules are supported in both the OS 7.0 `.8xpy2` (type 15)
and OS 7.1+ `.8mp2` (type 18) containers. `--send-file` always sends bytecode
to Archive, including when `ram` was requested. It queries the connected OS
and, if needed, repackages in memory before sending: 7.0.x selects type 15;
7.1 or later, including future major versions, selects type 18. When the version
is unavailable/unrecognized, the original wrapper is tried first. A calculator
`DP` (invalid data payload) response triggers at most one repackaging/retry in
the other format, also if a version-selected transfer fails. Files on disk are not changed.
Unknown metadata and malformed objects are not automatically converted;
other transfer errors and a failed second attempt are reported normally.

The known 7.1 wrapper changes type 15 to 18, adds `flags=1`, and terminates the
tokenized name with `00 00`. Outer CBOR lengths and checksum are updated.
Conversion back to 7.0 reverses those metadata changes. The entire CBOR `data`
byte string stays byte-identical, including MPY v5 code, optional menus, and
any bytes beyond the Python object's declared length. `A5` is not a required
trailer, and no alignment padding is added or removed. The OS 7.1 importer
accepts the supplied byte-string length; exports copy the stored bytes.

Verified on OS 7.1.0.4421: freshly packed, unpadded modules covering all four
object-size residues modulo four, legacy-wrapper conversion with menus, and
arbitrary one- and five-byte tails all transferred and read back byte-exactly.
An explicit RAM request still sent these modules to Archive. This validates
transfer/storage, not calculator-side Python execution or a fresh OS 7.0 run.

Ordinary type-15 Python **source programs** retain their existing RAM/Archive
behavior and are never converted to bytecode containers.

```bash
python3 evo_usb.py --send-file TI_DRAW.8mp2
python3 evo_usb.py --get-file TI_DRAW 18
```

The second command saves `TI_DRAW.8mp2` when the module appears in the
calculator's directory. Transfers use the name embedded in the file and
overwrite existing variables.
