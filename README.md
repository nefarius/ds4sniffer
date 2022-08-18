# DS4Sniffer

DLL performing API-hooking to find which process is talking to the DS4.

## How to use

- Download [DebugViewPP](https://github.com/CobaltFusion/DebugViewPP/releases)
- Place the 64-Bit DLL in `C:\Windows\System32` and the 32-Bit DLL in `C:\Windows\SysWOW64`
- Execute `set_appinit_dll.reg` to get the DLLs loaded into every process
- Reboot the machine
- Start DebugView++ **as Administrator**
- Connect the DS4 and observe the debug outputs
