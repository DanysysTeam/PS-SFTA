<#
.SYNOPSIS
    Set File Type Association Windows 8/10

.DESCRIPTION
    Set File/Protocol Type Association Default Application Windows 8/10

.NOTES
    Version    : 1.0.0
    Author(s)  : Danyfirex & Dany3j
    Credits    : https://bbs.pediy.com/thread-213954.htm
                 Matthew Graeber - Get-DelegateType/Get-ProcAddress Functions
    License    : MIT License
    Copyright  : 2020 Danysys. <danysys.com>
  
.EXAMPLE
    Get-FTA
    Show All Application Program Id

.EXAMPLE
    Get-FTA .pdf
    Show Default Application Program Id for an Extension
    
.EXAMPLE
    Set-FTA AcroExch.Document.DC .pdf
    Set Acrobat Reader DC as Default .pdf reader
 
.EXAMPLE
    Set-FTA Applications\SumatraPDF.exe .pdf
    Set Sumatra PDF as Default .pdf reader

.EXAMPLE
    Set-PTA ChromeHTML http
    Set Google Chrome as Default for http Protocol

.EXAMPLE
    Register-FTA "C:\SumatraPDF.exe" .pdf -Icon "shell32.dll,100"
    Register Application and Set as Default for .pdf reader

.LINK
    https://github.com/DanysysTeam/PS-SFTA
    
#>


function Get-FTA {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $false)]
    [String]
    $Extension
  )

  
  if ($Extension) {
    Write-Verbose "Get File Type Association for $Extension"
    
    $assocFile = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"-ErrorAction SilentlyContinue).ProgId
    Write-Output $assocFile
  }
  else {
    Write-Verbose "Get File Type Association List"

    $assocList = Get-ChildItem HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\* |
    ForEach-Object {
      $progId = (Get-ItemProperty "$($_.PSParentPath)\$($_.PSChildName)\UserChoice" -ErrorAction SilentlyContinue).ProgId
      if ($progId) {
        "$($_.PSChildName), $progId"
      }
    }
    Write-Output $assocList
  }
  
}


function Register-FTA {
  [CmdletBinding()]
  param (
    [Parameter( Position = 0, Mandatory = $true)]
    [ValidateScript( { Test-Path $_ })]
    [String]
    $ProgramPath,

    [Parameter( Position = 1, Mandatory = $true)]
    [Alias("Protocol")]
    [String]
    $Extension,
    
    [Parameter( Position = 2, Mandatory = $false)]
    [String]
    $ProgId,
    
    [Parameter( Position = 3, Mandatory = $false)]
    [String]
    $Icon
  )

  Write-Verbose "Register Application + Set Association"
  Write-Verbose "Application Path: $ProgramPath"
  if ($Extension.Contains(".")) {
    Write-Verbose "Extension: $Extension"
  }
  else {
    Write-Verbose "Protocol: $Extension"
  }
  
  if (!$ProgId) {
    $ProgId = "SFTA." + [System.IO.Path]::GetFileNameWithoutExtension($ProgramPath).replace(" ", "") + $Extension
  }
  
  $progCommand = """$ProgramPath"" ""%1"""
  Write-Verbose "ApplicationId: $ProgId" 
  Write-Verbose "ApplicationCommand: $progCommand"
  
  try {
    $keyPath = "HKEY_CURRENT_USER\SOFTWARE\Classes\$Extension\OpenWithProgids"
    [Microsoft.Win32.Registry]::SetValue( $keyPath, $ProgId, ([byte[]]@()), [Microsoft.Win32.RegistryValueKind]::None)
    $keyPath = "HKEY_CURRENT_USER\SOFTWARE\Classes\$ProgId\shell\open\command"
    [Microsoft.Win32.Registry]::SetValue($keyPath, "", $progCommand)
    Write-Verbose "Register ProgId and ProgId Command OK"
  }
  catch {
    throw "Register ProgId and ProgId Command FAIL"
  }
  
  Set-FTA -ProgId $ProgId -Extension $Extension -Icon $Icon
}


function Remove-FTA {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [Alias("ProgId")]
    [String]
    $ProgramPath,

    [Parameter(Mandatory = $true)]
    [String]
    $Extension
  )
  
  function local:Remove-UserChoiceKey {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $Key
    )

    $code = @'
    using System;
    using System.Runtime.InteropServices;
    using Microsoft.Win32;
    
    namespace Registry {
      public class Utils {
        [DllImport("advapi32.dll", SetLastError = true)]
        private static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, int ulOptions, int samDesired, out UIntPtr hkResult);
    
        [DllImport("advapi32.dll", SetLastError=true, CharSet = CharSet.Unicode)]
        private static extern uint RegDeleteKey(UIntPtr hKey, string subKey);

        public static void DeleteKey(string key) {
          UIntPtr hKey = UIntPtr.Zero;
          RegOpenKeyEx((UIntPtr)0x80000001u, key, 0, 0x20019, out hKey);
          RegDeleteKey((UIntPtr)0x80000001u, key);
        }
      }
    }
'@

    try {
      Add-Type -TypeDefinition $code
    }
    catch {}

    try {
      [Registry.Utils]::DeleteKey($Key)
    }
    catch {} 
  } 

  function local:Update-Registry {
    $code = @'
    [System.Runtime.InteropServices.DllImport("Shell32.dll")] 
    private static extern int SHChangeNotify(int eventId, int flags, IntPtr item1, IntPtr item2);
    public static void Refresh() {
        SHChangeNotify(0x8000000, 0, IntPtr.Zero, IntPtr.Zero);    
    }
'@ 

    try {
      Add-Type -MemberDefinition $code -Namespace SHChange -Name Notify
    }
    catch {}

    try {
      [SHChange.Notify]::Refresh()
    }
    catch {} 
  }

  if (Test-Path -Path $ProgramPath) {
    $ProgId = "SFTA." + [System.IO.Path]::GetFileNameWithoutExtension($ProgramPath).replace(" ", "") + $Extension
  }
  else {
    $ProgId = $ProgramPath
  }

  try {
    $keyPath = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
    Write-Verbose "Remove User UserChoice Key If Exist: $keyPath"
    Remove-UserChoiceKey $keyPath

    $keyPath = "HKCU:\SOFTWARE\Classes\$ProgId"
    Write-Verbose "Remove Key If Exist: $keyPath"
    Remove-Item -Path $keyPath -Recurse -ErrorAction Stop | Out-Null
    
  }
  catch {
    Write-Verbose "Key No Exist: $keyPath"
  }

  try {
    $keyPath = "HKCU:\SOFTWARE\Classes\$Extension\OpenWithProgids"
    Write-Verbose "Remove Property If Exist: $keyPath Property $ProgId"
    Remove-ItemProperty -Path $keyPath -Name $ProgId  -ErrorAction Stop | Out-Null
    
  }
  catch {
    Write-Verbose "Property No Exist: $keyPath Property: $ProgId"
  } 

  Update-Registry
  Write-Output "Removed: $ProgId" 
}


function Set-FTA {

  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [String]
    $ProgId,

    [Parameter(Mandatory = $true)]
    [Alias("Protocol")]
    [String]
    $Extension,
      
    [String]
    $Icon
  )
  
  if (Test-Path -Path $ProgId) {
    $ProgId = "SFTA." + [System.IO.Path]::GetFileNameWithoutExtension($ProgId).replace(" ", "") + $Extension
  }

  Write-Verbose "ProgId: $ProgId"
  Write-Verbose "Extension/Protocol: $Extension"

  function local:Get-DelegateType {
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


  function local:Get-ProcAddress {
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
    # $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress')
    $GetProcAddress = $UnsafeNativeMethods.GetMethod('GetProcAddress', [reflection.bindingflags] "Public,Static", $null, [System.Reflection.CallingConventions]::Any, @((New-Object System.Runtime.InteropServices.HandleRef).GetType(), [string]), $null);

    # Get a handle to the module specified
    $Kern32Handle = $GetModuleHandle.Invoke($null, @($Module))
    $tmpPtr = New-Object IntPtr
    $HandleRef = New-Object System.Runtime.InteropServices.HandleRef($tmpPtr, $Kern32Handle)

    # Return the address of the function
    Write-Output $GetProcAddress.Invoke($null, @([System.Runtime.InteropServices.HandleRef]$HandleRef, $Procedure))
  }
   

  function local:Update-RegistryChanges {
    $SHChangeNotifyAddr = Get-ProcAddress Shell32.dll SHChangeNotify
    $SHChangeNotifyDelegate = Get-DelegateType @([UInt32], [UInt32], [IntPtr], [IntPtr]) ([Int])
    $SHChangeNotify = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($SHChangeNotifyAddr, $SHChangeNotifyDelegate)
    $SHChangeNotify.Invoke(0x8000000, 0, [IntPtr]::Zero, [IntPtr]::Zero) | Out-Null
  }

  
  function local:Set-Icon {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $ProgId,

      [Parameter( Position = 1, Mandatory = $True )]
      [String]
      $Icon
    )

    try {
      $keyPath = "HKEY_CURRENT_USER\SOFTWARE\Classes\$ProgId\DefaultIcon"
      [Microsoft.Win32.Registry]::SetValue($keyPath, "", $Icon) 
      Write-Verbose "Write Reg Icon OK"
      Write-Verbose "Reg Icon: $keyPath"
    }
    catch {
      Write-Verbose "Write Reg Icon Fail"
    }
  }


  function local:Write-ExtensionKeys {
    param (
      [Parameter( Position = 0, Mandatory = $True )]
      [String]
      $ProgId,

      [Parameter( Position = 1, Mandatory = $True )]
      [String]
      $Extension,

      [Parameter( Position = 2, Mandatory = $True )]
      [String]
      $ProgHash
    )
    

    function local:Remove-UserChoiceKey {
      param (
        [Parameter( Position = 0, Mandatory = $True )]
        [String]
        $Key
      )

      $code = @'
      using System;
      using System.Runtime.InteropServices;
      using Microsoft.Win32;
      
      namespace Registry {
        public class Utils {
          [DllImport("advapi32.dll", SetLastError = true)]
          private static extern int RegOpenKeyEx(UIntPtr hKey, string subKey, int ulOptions, int samDesired, out UIntPtr hkResult);
      
          [DllImport("advapi32.dll", SetLastError=true, CharSet = CharSet.Unicode)]
          private static extern uint RegDeleteKey(UIntPtr hKey, string subKey);
  
          public static void DeleteKey(string key) {
            UIntPtr hKey = UIntPtr.Zero;
            RegOpenKeyEx((UIntPtr)0x80000001u, key, 0, 0x20019, out hKey);
            RegDeleteKey((UIntPtr)0x80000001u, key);
          }
        }
      }
'@
  
      try {
        Add-Type -TypeDefinition $code
      }
      catch {}

      try {
        [Registry.Utils]::DeleteKey($Key)
      }
      catch {} 
    } 

    
  try {
    $keyPath = "Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
    Write-Verbose "Remove Extension UserChoice Key If Exist: $keyPath"
    Remove-UserChoiceKey $keyPath
  }
  catch {
    Write-Verbose "Extension UserChoice Key No Exist: $keyPath"
  }
  

  try {
    $keyPath = "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\FileExts\$Extension\UserChoice"
    [Microsoft.Win32.Registry]::SetValue($keyPath, "Hash", $ProgHash)
    [Microsoft.Win32.Registry]::SetValue($keyPath, "ProgId", $ProgId)
    Write-Verbose "Write Reg Extension UserChoice OK"
  }
  catch {
    throw "Write Reg Extension UserChoice FAIL"
  }
}


function local:Write-ProtocolKeys {
  param (
    [Parameter( Position = 0, Mandatory = $True )]
    [String]
    $ProgId,

    [Parameter( Position = 1, Mandatory = $True )]
    [String]
    $Protocol,

    [Parameter( Position = 2, Mandatory = $True )]
    [String]
    $ProgHash
  )
      

  try {
    $keyPath = "HKCU:\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice"
    Write-Verbose "Remove Protocol UserChoice Key If Exist: $keyPath"
    Remove-Item -Path $keyPath -Recurse -ErrorAction Stop | Out-Null
    
  }
  catch {
    Write-Verbose "Protocol UserChoice Key No Exist: $keyPath"
  }
  

  try {
    $keyPath = "HKEY_CURRENT_USER\Software\Microsoft\Windows\Shell\Associations\UrlAssociations\$Protocol\UserChoice"
    [Microsoft.Win32.Registry]::SetValue( $keyPath, "Hash", $ProgHash)
    [Microsoft.Win32.Registry]::SetValue($keyPath, "ProgId", $ProgId)
    Write-Verbose "Write Reg Protocol UserChoice OK"
  }
  catch {
    throw "Write Reg Protocol UserChoice FAIL"
  }
    
}

  
function local:Get-UserExperience {
  [OutputType([string])]
      
  $userExperienceSearch = "User Choice set via Windows User Experience"
  $user32Path = [Environment]::GetFolderPath([Environment+SpecialFolder]::SystemX86) + "\Shell32.dll"
  $fileStream = [System.IO.File]::Open($user32Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
  $binaryReader = New-Object System.IO.BinaryReader($fileStream)
  [Byte[]] $bytesData = $binaryReader.ReadBytes(5mb)
  $fileStream.Close()
  $dataString = [Text.Encoding]::Unicode.GetString($bytesData)
  $position1 = $dataString.IndexOf($userExperienceSearch)
  $position2 = $dataString.IndexOf("}", $position1)

  Write-Output $dataString.Substring($position1, $position2 - $position1 + 1)
}
  

function local:Get-UserSid {
  [OutputType([string])]
  $userSid = ((New-Object System.Security.Principal.NTAccount([Environment]::UserName)).Translate([System.Security.Principal.SecurityIdentifier]).value).ToLower()
  Write-Output $userSid
}


function local:Get-HexDateTime {
  [OutputType([string])]

  $now = [DateTime]::Now
  $dateTime = [DateTime]::New($now.Year, $now.Month, $now.Day, $now.Hour, $now.Minute, 0)
  $fileTime = $dateTime.ToFileTime()
  $hi = ($fileTime -shr 32)
  $low = ($fileTime -band 0xFFFFFFFFL)
  $dateTimeHex = ($hi.ToString("X8") + $low.ToString("X8")).ToLower()
  Write-Output $dateTimeHex
}


function local:Get-Hash {
  param (
    [OutputType([string])]

    [Parameter( Position = 0, Mandatory = $True )]
    [String]
    $ProgId,

    [Parameter( Position = 1, Mandatory = $True )]
    [String]
    $Extension
  )
    
  $userSid = Get-UserSid
  $userExperience = Get-UserExperience
  $userDateTime = Get-HexDateTime
  Write-Debug "UserDateTime: $userDateTime"
  Write-Debug "UserSid: $userSid"
  Write-Debug "UserExperience: $userExperience"

  $baseInfo = "$Extension$userSid$ProgId$userDateTime$userExperience".ToLower()
  Write-Debug "baseInfo: $baseInfo"

   
  $VirtualAllocAddr = Get-ProcAddress kernel32.dll VirtualAlloc
  $VirtualAllocDelegate = Get-DelegateType @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr])
  $VirtualAlloc = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualAllocAddr, $VirtualAllocDelegate)
    
  $VirtualFreeAddr = Get-ProcAddress kernel32.dll VirtualFree
  $VirtualFreeDelegate = Get-DelegateType @([IntPtr], [Uint32], [UInt32]) ([Bool])
  $VirtualFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($VirtualFreeAddr, $VirtualFreeDelegate)
    
  $RtlMoveMemoryAddr = Get-ProcAddress kernel32.dll RtlMoveMemory
  $RtlMoveMemoryDelegate = Get-DelegateType @([IntPtr], [Byte[]], [UInt32] ) ([void])
  $RtlMoveMemory = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($RtlMoveMemoryAddr, $RtlMoveMemoryDelegate)
    

  #Select Hash Algorithm
  if ($env:Processor_Architecture -eq "x86") {
    Write-Verbose "Using X86 Algorithm"
    [Byte[]] $bytesAlgorithm = [Convert]::FromBase64String(
      @("VYnlU4HswAAAAItFDMHoAolF+ItFDIPgBIXAdASDbfgBi0UIiUXMi0X4iUXEi0UQiUXAjYVE////iUW8i0XEiUX0g33EAXYKi0XE"
        "g+ABhcB0CrgAAAAA6fIGAADHRfAAAAAAx0XsAAAAAItFwIsAg8gBBQAA+2mJReiLRcCDwASLAIPIAQUAANsTiUW4i0XEg+gC0eiD"
        "wAGJReSDbfQCi0XMixCLRewB0IlFtItFzIPABIlFsItF6A+vRbSJwotFtMHoEGnABZb6ECnCidBp0JWj+HmLRegPr0W0icGLRbTB"
        "6BBpwAWW+hApwYnIwegQacCfa5toAdCJRayLRaxp0AEAl+qLRazB6BBpwGkVEDwpwonQiUWoi1Woi0XwAdCJRaSLRbCLEItFqAHQ"
        "iUWgi0Wwg8AEiUXMi0XAiwCDyAEFAAD7aYlF6ItFuA+vRaCJwotFoMHoEGnAJezoPCnCidBp0C2vGCqLRbgPr0WgicGLRaDB6BBp"
        "wCXs6DwpwYnIwegQacDx4Gv9idMpw4tFuA+vRaCJwotFoMHoEGnAJezoPCnCidBp0C2vw1mLRbgPr0WgicGLRaDB6BBpwCXs6Dwp"
        "wYnIwegQacDx4DIiKcKJ0MHoEGnAyR69NQHYiUXsi1Wki0XsAdCJRfCDbeQBg33kAA+Fov7//4N99AEPhToBAACLRcyLEItF7AHC"
        "i0XAiwCDyAFpwJWj+HktAADpfw+v0ItFzIsIi0XsAcjB6BBpwOl/NiGJ0ynDi0XMixCLRewBwotFwIsAg8gBBQAA+2kPr9CLRcyL"
        "CItF7AHIwegQacAFlvoQKcKJ0MHoEGnAn2ubaAHYiUWci0WcadABAJfqi0WcwegQacBpFRA8KcKJ0IlFmItFuA+vRZiJwotFmMHo"
        "EGnAJezoPCnCidBp0C2vGCqLRbgPr0WYicGLRZjB6BBpwCXs6DwpwYnIwegQacDx4Gv9idMpw4tFuA+vRZiJwotFmMHoEGnAJezo"
        "PCnCidBp0C2vw1mLRbgPr0WYicGLRZjB6BBpwCXs6DwpwYnIwegQacDx4DIiKcKJ0MHoEGnAyR69NQHYiUXsi1Xsi0WYAcKLRfAB"
        "0IlF8MZFlwGLRbyNUASLRfCJAotFvItV7IkQi0UIiUXIi0X4iUWQi0UQiUWMjYU8////iUWIi0WQiUXgg32QAXYKi0WQg+ABhcB0"
        "CrgAAAAA6b8DAADHRdwAAAAAi0WMiwCDyAGJRdjHRdQAAAAAi0WMg8AEiwCDyAGJRYSLRZCD6ALR6IPAAYlF0INt4AKLRciLEItF"
        "1AHQiUWAi0XIg8AEiYV8////i0XYacAAABGxD69FgInCi0XYD69FgMHoEGnA705nMCnCidCJhXj///+LhXj///9p0AAAn1uLhXj/"
        "///B6BBpwGGk93gpwonQwegQadAAAMc7i4V4////acgAAJ9bi4V4////wegQacBhpPd4KcGJyMHoEGnIbbnOEouFeP///8HoEGnA"
        "AACz6QHIwegQacCDHX4lAdCJhXT///+LVdyLhXT///8B0ImFcP///4uFfP///4sQi4V0////AcKLRYQPr8KJhWz///+LhXz///+D"
        "wASJRciLhWz////B6BBpwAAA9ZP32InBi4Vs////adAAAPUWi4Vs////wegQacAL6YtdKcKJ0MHoEGnAAWl8LCnBiciJhWj///+L"
        "hWj////B6BBpwIkrk3yJhWT///+LhWj///9pwAAAiSuJhWD///+LRYyLAIPIAYlF2IuVYP///4uFZP///wHQacAAAGmficGLlWD/"
        "//+LhWT///8B0MHoEGnAl2BbQCnBiciJRdSLlXD///+LRdQB0IlF3INt0AGDfdAAD4VI/v//g33gAQ+FeAEAAItFjIsAg8gBicGL"
        "RciLEItF1AHQD6/BadAAABGxi0WMiwCDyAGJw4tFyIsIi0XUAcgPr8PB6BBpwO9OZzApwonQiYVc////i4Vc////adAAAJ9bi4Vc"
        "////wegQacBhpPd4KcKJ0MHoEGnQAADHO4uFXP///2nIAACfW4uFXP///8HoEGnAYaT3eCnBicjB6BBpyG25zhKLhVz////B6BBp"
        "wAAAs+kByMHoEGnAgx1+JQHQiYVY////i1Xci4VY////AdCJhVT///+LRYQPr4VY////adAAAPUWi0WED6+FWP///8HoEGnAC+mL"
        "XSnCidCJhVD///+LhVD///9p0AAA/5aLhVD////B6BBpwAFpfCwpwonQwegQadAAADHyi4VQ////acgAAP+Wi4VQ////wegQacAB"
        "aXwsKcGJyMHoEGnIiSuTfIuFUP///8HoEGnAAACJXCnBicjB6BBpwJdgW0ApwonQiUXUi5VU////i0XUAdCJRdzGRZcBi0WIjVAE"
        "i0XciQKLRYiLVdSJEMeFTP///wAAAACLlUT///+LhTz///8xwotFFIkQi0UUg8AEi41I////i5VA////McqJEIuFTP///4HEwAAA"
        "AFtdwhAA") -join '')
  }
  else {
    Write-Verbose "Using X64 Algorithm"
    [Byte[]] $bytesAlgorithm = [Convert]::FromBase64String( 
      @("VUiJ5UiB7PAAAABIiU0QiVUYTIlFIEyJTSiLRRjB6AKJRfyLRRiD4ASFwHQEg238AUiLRRBIiUXIi0X8iUW8SItFIEiJRbBIjYUg"
        "////SIlFqItFvIlF+IN9vAF2CotFvIPgAYXAdAq4AAAAAOlwBwAAx0X0AAAAAMdF8AAAAABIi0WwiwCDyAEFAAD7aYlF7EiLRbBI"
        "g8AEiwCDyAEFAADbE4lFpItFvIPoAtHog8ABiUXog234AkiLRciLEItF8AHQiUWgSItFyEiDwARIiUWYi0XsD69FoInCi0WgwegQ"
        "acAFlvoQKcKJ0GnQlaP4eYtF7A+vRaCJwYtFoMHoEGnABZb6ECnBicjB6BBpwJ9rm2gB0IlFlItFlGnQAQCX6otFlMHoEGnAaRUQ"
        "PCnCidCJRZCLVZCLRfQB0IlFjEiLRZiLEItFkAHQiUWISItFmEiDwARIiUXISItFsIsAg8gBBQAA+2mJReyLRaQPr0WIicKLRYjB"
        "6BBpwCXs6DwpwonQadAtrxgqi0WkD69FiInBi0WIwegQacAl7Og8KcGJyMHoEGnA8eBr/SnCQYnQi0WkD69FiInCi0WIwegQacAl"
        "7Og8KcKJ0GnQLa/DWYtFpA+vRYiJwYtFiMHoEGnAJezoPCnBicjB6BBpwPHgMiIpwonQwegQacDJHr01RAHAiUXwi1WMi0XwAdCJ"
        "RfSDbegBg33oAA+Fl/7//4N9+AEPhUQBAABIi0XIixCLRfABwkiLRbCLAIPIAWnAlaP4eS0AAOl/D6/QSItFyIsIi0XwAcjB6BBp"
        "wOl/NiEpwkGJ0EiLRciLEItF8AHCSItFsIsAg8gBBQAA+2kPr9BIi0XIiwiLRfAByMHoEGnABZb6ECnCidDB6BBpwJ9rm2hEAcCJ"
        "RYSLRYRp0AEAl+qLRYTB6BBpwGkVEDwpwonQiUWAi0WkD69FgInCi0WAwegQacAl7Og8KcKJ0GnQLa8YKotFpA+vRYCJwYtFgMHo"
        "EGnAJezoPCnBicjB6BBpwPHga/0pwkGJ0ItFpA+vRYCJwotFgMHoEGnAJezoPCnCidBp0C2vw1mLRaQPr0WAicGLRYDB6BBpwCXs"
        "6DwpwYnIwegQacDx4DIiKcKJ0MHoEGnAyR69NUQBwIlF8ItV8ItFgAHCi0X0AdCJRfTGhX////8BSItFqEiNUASLRfSJAkiLRaiL"
        "VfCJEEiLRRBIiUXAi0X8iYV4////SItFIEiJhXD///9IjYUQ////SImFaP///4uFeP///4lF5IO9eP///wF2DYuFeP///4PgAYXA"
        "dAq4AAAAAOkHBAAAx0XgAAAAAEiLhXD///+LAIPIAYlF3MdF2AAAAABIi4Vw////SIPABIsAg8gBiYVk////i4V4////g+gC0eiD"
        "wAGJRdSDbeQCSItFwIsQi0XYAdCJhWD///9Ii0XASIPABEiJhVj///+LRdxpwAAAEbEPr4Vg////icKLRdwPr4Vg////wegQacDv"
        "TmcwKcKJ0ImFVP///4uFVP///2nQAACfW4uFVP///8HoEGnAYaT3eCnCidDB6BBp0AAAxzuLhVT///9pyAAAn1uLhVT////B6BBp"
        "wGGk93gpwYnIwegQachtuc4Si4VU////wegQacAAALPpAcjB6BBpwIMdfiUB0ImFUP///4tV4IuFUP///wHQiYVM////SIuFWP//"
        "/4sQi4VQ////AcKLhWT///8Pr8KJhUj///9Ii4VY////SIPABEiJRcCLhUj////B6BBpwAAA9ZP32InBi4VI////adAAAPUWi4VI"
        "////wegQacAL6YtdKcKJ0MHoEGnAAWl8LCnBiciJhUT///+LhUT////B6BBpwIkrk3yJhUD///+LhUT///9pwAAAiSuJhTz///9I"
        "i4Vw////iwCDyAGJRdyLlTz///+LhUD///8B0GnAAABpn4nBi5U8////i4VA////AdDB6BBpwJdgW0ApwYnIiUXYi5VM////i0XY"
        "AdCJReCDbdQBg33UAA+FMP7//4N95AEPhYoBAABIi4Vw////iwCDyAGJwUiLRcCLEItF2AHQD6/BadAAABGxSIuFcP///4sAg8gB"
        "QYnASItFwIsIi0XYAchBD6/AwegQacDvTmcwKcKJ0ImFOP///4uFOP///2nQAACfW4uFOP///8HoEGnAYaT3eCnCidDB6BBp0AAA"
        "xzuLhTj///9pyAAAn1uLhTj////B6BBpwGGk93gpwYnIwegQachtuc4Si4U4////wegQacAAALPpAcjB6BBpwIMdfiUB0ImFNP//"
        "/4tV4IuFNP///wHQiYUw////i4Vk////D6+FNP///2nQAAD1FouFZP///w+vhTT////B6BBpwAvpi10pwonQiYUs////i4Us////"
        "adAAAP+Wi4Us////wegQacABaXwsKcKJ0MHoEGnQAAAx8ouFLP///2nIAAD/louFLP///8HoEGnAAWl8LCnBicjB6BBpyIkrk3yL"
        "hSz////B6BBpwAAAiVwpwYnIwegQacCXYFtAKcKJ0IlF2IuVMP///4tF2AHQiUXgxoV/////AUiLhWj///9IjVAEi0XgiQJIi4Vo"
        "////i1XYiRDHhSj///8AAAAAi5Ug////i4UQ////McJIi0UoiRBIi0UoSIPABIuNJP///4uVFP///zHKiRCLhSj///9IgcTwAAAA"
        "XcOQkJCQkA==") -join '')
  }

  $BaseAddress = $VirtualAlloc.Invoke([IntPtr]::Zero, $bytesAlgorithm.Length + 1, 0x3000, 0x40) # (Reserve|Commit, RWX)
  $codeAlgorithm = $BaseAddress
  $codeAlgorithmDelegate = Get-DelegateType @([Byte[]], [UInt32], [Byte[]], [IntPtr]) ([UInt32])
  $codeAlgorithm = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($codeAlgorithm, $codeAlgorithmDelegate)
  $RtlMoveMemory.Invoke($BaseAddress, $bytesAlgorithm, $bytesAlgorithm.Length + 1) #Copy Algorithm 

  [Byte[]] $bytesBaseInfo = [System.Text.Encoding]::Unicode.GetBytes($baseInfo) 
  $bytesBaseInfo += 0x00, 0x00  

  $MD5 = New-Object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
  [Byte[]] $bytesMD5 = $MD5.ComputeHash($bytesBaseInfo)
  Write-Debug "MD5: $bytesMD5"

  $length = ($baseInfo.Length * 2) + 2 
  [Byte[]] $outHash = @(0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
    
  [IntPtr]$alloc = [System.Runtime.InteropServices.Marshal]::AllocHGlobal(8)
  $codeAlgorithm.Invoke($bytesBaseInfo, $length, $bytesMD5, $alloc) | Out-Null
  [System.Runtime.InteropServices.Marshal]::Copy($alloc, $outHash, 0 , 8) 
  [System.Runtime.InteropServices.Marshal]::FreeHGlobal($alloc) 
    
  $hexOutHash = [System.BitConverter]::ToString($outHash) 
  Write-Debug "Hex Hash: $hexOutHash"
  $base64Hash = [Convert]::ToBase64String($outHash) 
  $VirtualFree.Invoke($BaseAddress, $bytesAlgorithm.Length + 1, 0x8000) | Out-Null # MEM_RELEASE (0x8000)

  Write-Output $base64Hash
}
  
Write-Verbose "Getting Hash For $ProgId   $Extension"
$progHash = Get-Hash $ProgId $Extension
Write-Verbose "Hash: $progHash"
  

#Handle Extension Or Protocol
if ($Extension.Contains(".")) {
  Write-Verbose "Write Registry Extension: $Extension"
  Write-ExtensionKeys $ProgId $Extension $progHash

}
else {
  Write-Verbose "Write Registry Protocol: $Extension"
  Write-ProtocolKeys $ProgId $Extension $progHash
}

   
if ($Icon) {
  Write-Verbose  "Set Icon: $Icon"
  Set-Icon $ProgId $Icon
}

Update-RegistryChanges 

}

function Set-PTA {
  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [String]
    $ProgId,

    [Parameter(Mandatory = $true)]
    [String]
    $Protocol,
      
    [String]
    $Icon
  )

  Set-FTA -ProgId $ProgId -Protocol $Protocol -Icon $Icon
}
