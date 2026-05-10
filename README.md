## Quick local linking/screenshot/info/control for your TI-84 Evo!

Official repo: https://github.com/Evo-Programming/evo_usb_py

Uses Kermit file transfer protocol over the serial device exposed by the calculator.

You may have to adjust your permissions for serial access:  
- On Linux, that generally means `usermod -a -G dialout $USER` and re-login for changes to take effect.  
- On macOS (`/dev/cu.usbmodem*`) it should be usable right away.
- On Windows, install pyserial with `py -m pip install pyserial`; the calculator should appear as a `COM` port.

If auto-detection does not pick the right serial device, set `EVO_USB_SERIAL` to the path or port name, for example `/dev/cu.usbmodemRTX_DUMMY1` or `/dev/ttyACM0` or `COM3`.

```bash
Usage: python3 evo_usb.py ...

  <script.py> [varname]                       # to send a python script
  --screenshot [output.png] [mode]            # 0=auto?, 1=no-cursor, 2=with-cursor
  --list-files                                # to get names/type/size/memory
  --send-file <file> [auto|ram|archive]
  --get-file <name> [type] [output]
  --delete-file <name> [type]
  --send-os <os_bundle.83b2|84b2|84tb2>
  --extract-os <capture.pcapng> [output.bin]
  --get-info
  --dynamic-info
  --reboot
  --break
  --get-logs [output_dir]
  --exit-ptt
  --key <scancode>
```
