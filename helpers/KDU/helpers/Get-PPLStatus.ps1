param([int]$targetPID)

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class NativeMethods {
    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_PROTECTION_LEVEL_INFORMATION {
        public byte ProtectionLevel;
    }

    [DllImport("ntdll.dll")]
    public static extern int NtQueryInformationProcess(
        IntPtr ProcessHandle,
        int ProcessInformationClass,
        out PROCESS_PROTECTION_LEVEL_INFORMATION ProcessInformation,
        int ProcessInformationLength,
        out int ReturnLength
    );
}
"@


Write-Host "Getting the PPL status of PID: $targetPID"

$process = Get-Process -Id $targetPID -ErrorAction Stop
$handle = $process.Handle

$info = New-Object NativeMethods+PROCESS_PROTECTION_LEVEL_INFORMATION
$retLen = 0

try {
	$status = [NativeMethods]::NtQueryInformationProcess(
		$handle,
		61, # ProcessProtectionInformation
		[ref]$info,
		[System.Runtime.InteropServices.Marshal]::SizeOf($info),
		[ref]$retLen
	)

	if ($status -eq 0) {
		$level = $info.ProtectionLevel
		if ($level -eq 0) {
			Write-Host "PID $($targetPID): Not Protected (No PPL)"
		} else {
			Write-Host "PID $($targetPID): Protected Process Light (PPL) - ProtectionLevel: $level"
		}
	} else {
		Write-Host "NtQueryInformationProcess failed with NTSTATUS: 0x{0:X}" -f $status
	}
} catch {
	Write-Host "NtQueryInformationProcess failed, insufficient rights"
}