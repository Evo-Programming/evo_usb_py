## Quick local linking/screenshot/info/control for your TI-84 Evo!

Official repo: https://github.com/Evo-Programming/evo_usb_py

Uses Kermit file transfer protocol over the serial device exposed by the calculator.

You may have to adjust your permissions for serial access:  
- On Linux, that generally means `usermod -a -G dialout $USER` and re-login for changes to take effect.  
- On macOS (`/dev/cu.usbmodem*`) it should be usable right away.
- On Windows (some `COM` port), it should also be fine by default.

```bash
Usage: python3 evo_usb.py ...

  <script.py> [varname]                       # to send a python script
  --screenshot [output.png] [mode]            # 0=auto?, 1=no-cursor, 2=with-cursor
  --list-files                                # to get names/type/size/memory
  --send-file <file> [auto|ram|archive]
  --get-file <name> [type] [output]
  --delete-file <name> [type]
  --send-os <os_bundle.bin>
  --extract-os <capture.pcapng> [output.bin]
  --get-info
  --dynamic-info
  --reboot
  --break
  --get-logs [output_dir]
  --exit-ptt
  --key <scancode>
```
