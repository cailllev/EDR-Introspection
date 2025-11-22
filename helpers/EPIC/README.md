# Setup
1. Install MSYS2, https://github.com/msys2/msys2-installer/releases/download/2025-08-30/msys2-x86_64-20250830.exe
2. run MSYS2 UCRT64
```bash
cd /ucrt64/bin
ln -s ld.exe x86_64-w64-mingw32-ld.exe
ln -s objcopy.exe x86_64-w64-mingw32-objcopy.exe
cd EDR-Introspection/helpers/EPIC/
./EPIC.exe init PIC/
```
3. using EPIC
```bash
./EPIC.exe pic-compile PIC/ -o Out/
./EPIC.exe pic-link Out/ -o Out/ -a
../shellcode/runshc64.exe Out/payload.bin
```