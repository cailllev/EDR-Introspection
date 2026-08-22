# Misc Tools

These tools can help debug or investigate various things. The most important are described, else just look at the source code.

## ETWDump
Used to attach to and print events from my custom ETW traces; EDRi, Attack or EDR Hooker.

### Usage
```
ETWDump.exe [trace] [minimal-print]
```
### Example Output
```
2026-08-22 11:25:27.485195800Z: TargetPID=9384  - NtOpenProcess with 0x101000:PROCESS_QUERY_LIMITED_INFORMATION|SYNCHRONIZE
2026-08-22 11:25:27.485224800Z: TargetPID=9384  - NtQueryInformationProcess with InfoClass=ProcessSessionInformation
2026-08-22 11:25:27.485259400Z: TargetPID=9384  - NtClose process
2026-08-22 11:25:27.485243000Z: TargetPID=9384  - NtQueryInformationProcess with InfoClass=ProcessImageFileName
2026-08-22 11:25:27.598717900Z: TargetPID=3472  - NtQueryInformationProcess with InfoClass=ProcessDeviceMap
2026-08-22 11:25:27.598741800Z: TargetPID=3472  - NtCreateFile \??\C:\Windows\System32\taskhostw.exe with DesiredAccess=0x100080:FILE_READ_ATTRI
2026-08-22 11:25:27.598932500Z: TargetPID=5576  - NtOpenProcess with 0x600:PROCESS_SET_INFORMATION|PROCESS_QUERY_INFORMATION
2026-08-22 11:25:27.598947300Z: TargetPID=5576  - NtClose process
```

## FileCopier
Copies a file from src to dst, as a DLL, so inherits the permissions from the executing (injected) process.

### Usage
- `LoadLibrary("FileCopier")` with fixed src and dst, or
- `GetProcAddr("DoCopyFile"); DoCopyFile(src, dst)`

## Handler
Traverses the open handles in the current process (Handler.exe) and prints relevant information about process, thread and file handles.

### Usage 
```
Handler.exe

# or with many inherited handles via KDU
kdu.exe -pho (Get-Process MsMpEng).Id -pht -phc Handler.exe -prv 64
```

### Example Output
```
[*] Handle Inspector started
[*] Got 89 handles of all types owned by Process Handle Inspector...
[+] Checking for process handles...
[+] Proc handle found: ID=0x00000000000001B4, PID=3472, Access=0x001FFFFF
[*] Traversing PEB for loaded DLLs...
Base Address        DLL Name                                                                                            
------------------------------------------------
0x00007FF6D11F0000 C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\MsMpEng.exe
0x00007FFD59000000 C:\WINDOWS\SYSTEM32\ntdll.dll
0x00007FFD58820000 C:\WINDOWS\SYSTEM32\KERNEL32.DLL
0x00007FFD56210000 C:\WINDOWS\SYSTEM32\KERNELBASE.dll
0x00007FFD56870000 C:\WINDOWS\SYSTEM32\CRYPT32.dll
...
0x00007FFD54850000 C:\WINDOWS\system32\SAMCLI.DLL
[+] Checking for thread handles...
Handle ID  Access     Thread ID
------------------------------------------------
0x000001A0 0x001FFFFF 3928
...
0x0000025C 0x001FFFFF 9340
```

## ReadPEB
Gets a local or remote PEB and dumps the loaded DLLs.

### Usage
```
ReadPEB.exe

# or via KDU to also read PPLs
kdu.exe -pse "ReadPEB.exe $((Get-Process MsMpEng).Id)" -prv 64
```

### Example Output
```
[*] Reading PEB from process pid=3472
[*] Got PBI.PebBaseAddress = 0x000000560D24A000
[*] Got remote PEB.LDR     = 0x00007FFD591D18A0
[*] Got remote remoteHead  = 0x00007FFD591D18C0
[+] Found entry: base=0x00007FF6D11F0000, size=0x0000000000045000, ldr=0x00000182391056E0, name=C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26070.9-0\MsMpEng.exe
[+] Found entry: base=0x00007FFD59000000, size=0x0000000000266000, ldr=0x0000018239105530, name=C:\WINDOWS\SYSTEM32\ntdll.dll
[+] Found entry: base=0x00007FFD58820000, size=0x00000000000C9000, ldr=0x0000018239105D10, name=C:\WINDOWS\SYSTEM32\KERNEL32.DLL
[+] Found entry: base=0x00007FFD56210000, size=0x00000000003FF000, ldr=0x0000018239106490, name=C:\WINDOWS\SYSTEM32\KERNELBASE.dll
[+] Found entry: base=0x00007FFD56870000, size=0x000000000017E000, ldr=0x00000182391225A0, name=C:\WINDOWS\SYSTEM32\CRYPT32.dll
...
[+] Found entry: base=0x00007FFD54850000, size=0x000000000001B000, ldr=0x000001825EEDB970, name=C:\WINDOWS\system32\SAMCLI.DLL
```