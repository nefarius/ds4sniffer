# DS4Sniffer

DLL performing API-hooking to find which process is talking to the DS4.

## Motivation

Created to aid in analysis [of this issue](https://github.com/libretro/retroarch-joypad-autoconfig/issues/852).

## How to use

- Download [DebugViewPP](https://github.com/CobaltFusion/DebugViewPP/releases)
- Place the 64-Bit DLL in `C:\Windows\System32` and the 32-Bit DLL in `C:\Windows\SysWOW64`
- Execute `set_appinit_dll.reg` to get the DLLs loaded into every process
- Reboot the machine
- Start DebugView++ **as Administrator**
- Connect the DS4 and observe the debug outputs
- Save the collected data with File / Save Log

## To undo/uninstall

- Execute `reset_appinit_dll.reg`
- Reboot the machine
- Delete `ds4sniffer.dll` from `C:\Windows\System32` and `C:\Windows\SysWOW64`
- Done!
