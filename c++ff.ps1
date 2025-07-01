# Este script inyecta un DLL en el proceso de Spotify.
# Requiere ejecutar como Administrador.

$IsAdmin = [Security.Principal.WindowsIdentity]::GetCurrent()
If ((New-Object Security.Principal.WindowsPrincipal $IsAdmin).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -eq $FALSE)
{
    Write-Host "Abra o powershell como administrador!!"
    return
}

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
"@

function Inject-Dll {
    param(
        [string]$ProcessName,
        [string]$DllPath
    )

    # Buscar el proceso de Spotify
    $process = Get-Process -Name $ProcessName -ErrorAction SilentlyContinue
    if (-not $process) {
        Write-Host "No se encontró el proceso $ProcessName."
        return
    }
    $pid = $process.Id

    $PROCESS_ALL_ACCESS = 0x1F0FFF
    $MEM_COMMIT = 0x1000
    $PAGE_READWRITE = 0x04

    # Abrir el proceso
    $hProcess = [Kernel32]::OpenProcess($PROCESS_ALL_ACCESS, $false, [uint32]$pid)
    if ($hProcess -eq [IntPtr]::Zero) {
        Write-Host "No se pudo abrir el proceso."
        return
    }

    # Escribir el path del DLL en la memoria del proceso
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($DllPath + [char]0)
    $alloc = [Kernel32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $bytes.Length, $MEM_COMMIT, $PAGE_READWRITE)
    if ($alloc -eq [IntPtr]::Zero) {
        Write-Host "No se pudo reservar memoria en el proceso remoto."
        [Kernel32]::CloseHandle($hProcess) | Out-Null
        return
    }
    $written = [UIntPtr]::Zero
    $r = [Kernel32]::WriteProcessMemory($hProcess, $alloc, $bytes, $bytes.Length, [ref]$written)
    if (-not $r) {
        Write-Host "No se pudo escribir en memoria remota."
        [Kernel32]::CloseHandle($hProcess) | Out-Null
        return
    }

    # Obtener la dirección de LoadLibraryA
    $hKernel32 = [Kernel32]::GetModuleHandle("kernel32.dll")
    $loadLibraryAddr = [Kernel32]::GetProcAddress($hKernel32, "LoadLibraryA")
    if ($loadLibraryAddr -eq [IntPtr]::Zero) {
        Write-Host "No se pudo obtener la dirección de LoadLibraryA."
        [Kernel32]::CloseHandle($hProcess) | Out-Null
        return
    }

    # Crear hilo remoto en el proceso de Spotify que llama LoadLibraryA(DllPath)
    $hThread = [Kernel32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $loadLibraryAddr, $alloc, 0, [IntPtr]::Zero)
    if ($hThread -eq [IntPtr]::Zero) {
        Write-Host "No se pudo crear el hilo remoto."
        [Kernel32]::CloseHandle($hProcess) | Out-Null
        return
    }

    Write-Host "DLL inyectado correctamente en $ProcessName (PID: $pid)."
    [Kernel32]::CloseHandle($hThread) | Out-Null
    [Kernel32]::CloseHandle($hProcess) | Out-Null
}

# --- CONFIGURACIÓN ---

# Ruta absoluta al DLL que se quiere inyectar
$dll = "C:\Windows\Fonts\dafont.ttf"
# Nombre del proceso de Spotify (sin extensión)
$proc = "Spotify"
# Ruta completa al ejecutable de Spotify (ajusta si es diferente en tu sistema)
$spotifyPath = "$env:APPDATA\Spotify\Spotify.exe"

# Si Spotify NO está abierto, lo inicia como proceso independiente
if (-not (Get-Process -Name $proc -ErrorAction SilentlyContinue)) {
    Write-Host "Spotify no está abierto. Iniciando..."
    Start-Process -FilePath $spotifyPath
    # Espera a que el proceso Spotify abra realmente
    Start-Sleep -Seconds 3
}

# Inyectar el DLL (la consola puede cerrarse después, Spotify sigue funcionando)
Inject-Dll -ProcessName $proc -DllPath $dll

Write-Host "Puedes cerrar esta ventana, Spotify seguirá funcionando normalmente."
