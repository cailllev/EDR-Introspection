# InjectLoader

InjectLoader is a modular Windows process injection utility designed for security research and EDR introspection. 
It supports multiple DLL payload injection strategies (standard disk-based, host-mapped memory, reflective) combined with various remote execution techniques.

## DLL Loader Techniques

| DLL Loader Technique | Limitations                                                        | Usage                                                                                                                                                                                                                                           |
|----------------------|--------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| LoadLibrary          | denied by CodeIntegrity (default for PPLs spawned by ELAM drivers) | 1. write DLL path to remote proc 2. execute LoadLibrary(pRemotePath) in remote proc                                                                                                                                                             |
| HostMapped + Loader  | cannot actually load DLLs in remote proc (bug)                     | 1. write DLL to local proc 2. get local offsets for relocations and do relocs 3. write adjusted local image to remote proc 4. get address of setup functions 5. write DLL loader with the func offsets to the remote proc 6. execute the loader |
| Reflective Injection | DLL must implement and export a self-reflective loader             | 1. write dll to remote proc 2. resolve and execute self-reflective loader                                                                                                                                                                       |

## Execution Techniques

