# Copyright (C) 1994-2016 Altair Engineering, Inc.
# For more information, contact Altair at www.altair.com.
#
# This file is part of the PBS Professional ("PBS Pro") software.
#
# Open Source License Information:
#
# PBS Pro is free software. You can redistribute it and/or modify it under the
# terms of the GNU Affero General Public License as published by the Free
# Software Foundation, either version 3 of the License, or (at your option) any
# later version.
#
# PBS Pro is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
# PARTICULAR PURPOSE.  See the GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License along
# with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Commercial License Information:
#
# The PBS Pro software is licensed under the terms of the GNU Affero General
# Public License agreement ("AGPL"), except where a separate commercial license
# agreement for PBS Pro version 14 or later has been executed in writing with Altair.
#
# Altair’s dual-license business model allows companies, individuals, and
# organizations to create proprietary derivative works of PBS Pro and distribute
# them - whether embedded or bundled with other software - under a commercial
# license agreement.
#
# Use of Altair’s trademarks, including but not limited to "PBS™",
# "PBS Professional®", and "PBS Pro™" and Altair’s logos is subject to Altair's
# trademark licensing policies.


#requires -version 2

Add-Type @"
using System;
using System.Text;
using System.Runtime.InteropServices;

public class Win32Api
{
    [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredFree")]
    private static extern void CredFree([In] IntPtr cred);

    [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredReadW", CharSet = CharSet.Unicode)]
    private static extern bool CredReadW([In] String target, [In] UInt32 type, [In] int reservedFlag, out IntPtr CredentialPtr);

    [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredWriteW", CharSet = CharSet.Unicode)]
    private static extern bool CredWriteW([In] ref Credential userCredential, [In] UInt32 flags);

    [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "CredDeleteW", CharSet = CharSet.Unicode)]
    private static extern bool CredDeleteW([In] String target, [In] UInt32 type, [In] UInt32 reservedFlag);

    [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "OpenProcessToken")]
    private static extern bool OpenProcessToken(IntPtr hProc, UInt32 access, ref IntPtr hToken);

    [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "LookupPrivilegeValue")]
    private static extern bool LookupPrivilegeValue(String hostname, String privname, ref LUID luid);

    [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "LogonUser")]
    private static extern bool LogonUser
    (
        String name,
        String domain,
        String password,
        UInt32 ltype,
        UInt32 lprovide,
        ref IntPtr hToken
    );

    [DllImport("Advapi32.dll", SetLastError = true, EntryPoint = "AdjustTokenPrivileges")]
    private static extern bool AdjustTokenPrivileges
    (
        IntPtr hToken,
        bool diablepriv,
        ref TOKEN_PRIV newpriv,
        UInt32 privlen,
        IntPtr prevpriv,
        IntPtr retlen
    );

    [DllImport("Kernel32.dll", SetLastError = true, EntryPoint = "GetCurrentProcess")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "CloseHandle")]
    private static extern bool CloseHandle(IntPtr hToken);

    [DllImport("Userenv.dll", SetLastError = true, EntryPoint = "LoadUserProfile")]
    private static extern bool LoadUserProfile(IntPtr hToken, ref PROFILEINFO hProf);

    [DllImport("Userenv.dll", SetLastError = true, EntryPoint = "UnloadUserProfile")]
    private static extern bool UnloadUserProfile(IntPtr hToken, IntPtr hProfile);

    [StructLayout(LayoutKind.Sequential)]
    private struct PROFILEINFO
    {
        public UInt32 Size;
        public UInt32 Flags;
        public String UserName;
        public String ProfilePath;
        public String DefaultPath;
        public String ServerName;
        public String PolicyPath;
        public IntPtr hProfile;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID
    {
        public Int32 LowPart;
        public UInt32 HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct LUID_AND_ATTR
    {
        public LUID Luid;
        public UInt32 Attr;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TOKEN_PRIV
    {
        public UInt32 Count;
        public LUID_AND_ATTR LuidAttr;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct Credential
    {
        public UInt32 Flags;
        public UInt32 Type;
        public IntPtr TargetName;
        public IntPtr Comment;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWritten;
        public UInt32 CredentialBlobSize;
        public IntPtr CredentialBlob;
        public UInt32 Persist;
        public UInt32 AttributeCount;
        public IntPtr Attributes;
        public IntPtr TargetAlias;
        public IntPtr UserName;
    }

    public static String ReadCred(String username)
    {
        IntPtr pCredential = IntPtr.Zero;
        if (!CredReadW(username, 1, 0, out pCredential))
        {
            return null;
        }
        Credential pcred = (Credential)Marshal.PtrToStructure(pCredential, typeof(Credential));
        String cred = null;
        if (pcred.CredentialBlobSize > 0)
        {
            cred = Marshal.PtrToStringUni(pcred.CredentialBlob, (int)pcred.CredentialBlobSize / 2);
        }
        CredFree(pCredential);
        return cred;
    }

    public static int WriteCred(String username, String cred)
    {
        Credential pcred = new Credential();
        int ret = 0;
        pcred.Flags = (UInt32) 0;
        pcred.Type = (UInt32) 1;
        pcred.Persist = (UInt32) 3;
        pcred.AttributeCount = (UInt32) 0;
        pcred.TargetName = Marshal.StringToHGlobalUni(username);
        pcred.UserName = Marshal.StringToHGlobalUni(username);
        pcred.CredentialBlobSize = (UInt32) Encoding.Unicode.GetBytes(cred).Length;
        pcred.CredentialBlob = Marshal.StringToHGlobalUni(cred);
        if (!CredWriteW(ref pcred, 0))
        {
            ret = Marshal.GetHRForLastWin32Error();
        }
        Marshal.FreeHGlobal(pcred.TargetName);
        Marshal.FreeHGlobal(pcred.UserName);
        Marshal.FreeHGlobal(pcred.CredentialBlob);
        return ret;
    }

    public static int DelCred(String username)
    {
        if (!CredDeleteW(username, 1, 0))
        {
            return Marshal.GetHRForLastWin32Error();
        }
        return 0;
    }

    public static int AddPrivilege(String privilege)
    {
        TOKEN_PRIV priv = new TOKEN_PRIV();
        IntPtr hProc = GetCurrentProcess();
        IntPtr hToken = IntPtr.Zero;
        if (!OpenProcessToken(hProc, 40, ref hToken))
        {
            CloseHandle(hProc);
            return 1;
        }
        priv.Count = 1;
        priv.LuidAttr.Attr = 2;
        if(!LookupPrivilegeValue(null, privilege, ref priv.LuidAttr.Luid))
        {
            CloseHandle(hProc);
            CloseHandle(hToken);
            return 2;
        }
        if (!AdjustTokenPrivileges(hToken, false, ref priv, 0, IntPtr.Zero, IntPtr.Zero))
        {
            CloseHandle(hProc);
            CloseHandle(hToken);
            return 3;
        }
        CloseHandle(hProc);
        CloseHandle(hToken);
        return 0;
    }

    public static int LoadProfile(String domain, String name)
    {
        String password = ReadCred(domain + "\\" + name);
        if (password == null)
        {
            return 1;
        }
        IntPtr hToken = IntPtr.Zero;
        if (!LogonUser(name, domain, password, 4, 0, ref hToken))
        {
            return 2;
        }
        int ret = 0;
        PROFILEINFO hProf = new PROFILEINFO();
        hProf.Size = (UInt32)Marshal.SizeOf(hProf.GetType());
        hProf.Flags = 1;
        hProf.UserName = name;
        hProf.ProfilePath = null;
        hProf.DefaultPath = null;
        hProf.ServerName = domain;
        hProf.PolicyPath = null;
        hProf.hProfile = IntPtr.Zero;
        if (!LoadUserProfile(hToken, ref hProf))
        {
            CloseHandle(hToken);
            ret = 3;
        }
        UnloadUserProfile(hToken, hProf.hProfile);
        CloseHandle(hToken);
        return ret;
    }
}
"@

$__MDOMAIN = $env:USERDOMAIN

function __exit
{
    Param
    (
        [Parameter(Mandatory=$true)][String]$text
    )
    throw ("<PTLPSERROR>{0}<PTLPSERROR>" -f $text)
}

function Get-CurrentUserId
{
    $uid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    return $uid.Substring($uid.LastIndexOf("-") + 1)
}

function Get-CurrentGroupId
{
    $gid = [Security.Principal.WindowsIdentity]::GetCurrent().Groups[0].Value
    return $gid.Substring($gid.LastIndexOf("-") + 1)
}

function Get-UserByName
{
    Param
    (
        [Parameter(Mandatory=$true)][String]$Name,
        [Parameter(Mandatory=$false)][Switch]$OnlySID
    )
    $_Name = $Name
    if ($Name.LastIndexOf("\") -ne -1)
    {
        $Domain = $Name.Substring(0, $Name.LastIndexOf("\"))
        $Name = $Name.Substring($Name.LastIndexOf("\") + 1)
    }
    else
    {
        $Domain = $__MDOMAIN
    }
    $user = ([ADSI]"WinNT://$Domain/$Name,user")
    $sid = $user.objectSid
    if ($sid -eq $null)
    {
        __exit ("Can not find user: $_Name")
    }
    $out = @($Name, "`tname = $Name", "`tgecos = $Domain\$Name")
    $sid = (New-Object System.Security.Principal.SecurityIdentifier($sid.Value,0)).Value
    if ($OnlySID)
    {
        return $sid
    }
    $out += "`tsid = $sid"
    $dir = (Get-WmiObject -Class Win32_UserProfile -Filter "SID='$sid'").LocalPath
    if ($dir -eq $null)
    {
        $ret = [Win32Api]::LoadProfile($Domain, $Name)
        if ($ret -ne 0)
        {
            if ($ret -eq 1)
            {
                __exit ("Can not find cred for user: $_Name")
            }
            elseif ($ret -eq 2)
            {
                __exit ("Invalid password for user: $_Name")
            }
            else
            {
                __exit ("Failed to load userprofile for: $_Name")
            }
        }
        $dir = (Get-WmiObject -Class Win32_UserProfile -Filter "SID='$sid'").LocalPath
        if ($dir -eq $null)
        {
            __exit ("Can not find home dir for user: $_Name")
        }
    }
    $gid = $user.PrimaryGroupId.Value
    $out += "`tgid = $($user.PrimaryGroupId.Value)"
    $out += "`tdir = $dir"
    echo ($out -join "`n")
}

function Get-UserById
{
    Param
    (
        [Parameter(Mandatory=$true)][String]$Id
    )
    $user = (Get-WmiObject -Class Win32_UserAccount | ? {$_.SID.EndsWith($Id)}).Caption
    if ($user -eq $null)
    {
        __exit ("Can not find uid: $Id")
    }
    Get-UserByName -Name $user
}

function Get-AllUser
{
    Get-WmiObject -Class Win32_UserAccount | % {
        try
        {
            Get-UserByName -Name $_.Caption
            echo ""
        }
        catch
        {
        }
    }
}

function Get-GroupByName
{
    Param
    (
        [Parameter(Mandatory=$true)][String]$Name,
        [Parameter(Mandatory=$false)][Switch]$OnlySID
    )
    $_Name = $Name
    if ($Name.LastIndexOf("\") -ne -1)
    {
        $Domain = $Name.Substring(0, $Name.LastIndexOf("\"))
        $Name = $Name.Substring($Name.LastIndexOf("\") + 1)
    }
    else
    {

        $Domain = $__MDOMAIN
    }
    $group = ([ADSI]"WinNT://$Domain/$Name,group")
    try
    {
        $members = @($group.Invoke("Members"))
    }
    catch
    {
        __exit ("Can not find group: $_Name")
    }
    $out = @($Name, "`tname = $Name")
    $sid = (New-Object System.Security.Principal.SecurityIdentifier($group.ObjectSid.Value,0)).Value
    if ($OnlySID)
    {
        return $sid
    }
    $out += "`tsid = $sid"
    if ($members.Count -gt 0)
    {
        $members = $members | % { New-Object System.Security.Principal.SecurityIdentifier($_.GetType().InvokeMember("objectSid", "GetProperty", $null, $_, $null), 0) }
        $members = $members | % { $_.Translate([System.Security.Principal.NTAccount]).Value } | Sort-Object
        $out += "`tmem = $($members -join ',')"
    }
    else
    {
        $out += "`tmem = __NONE__"
    }
    echo ($out -join "`n")
}

function Get-GroupById
{
    Param
    (
        [Parameter(Mandatory=$true)][String]$Id
    )
    $group = (Get-WmiObject -Class Win32_Group | ? {$_.SID.EndsWith($Id)}).Caption
    if ($group -eq $null)
    {
        __exit ("Can not find gid: $Id")
    }
    Get-GroupByName -Name $group
}

function Get-AllGroup
{
    Get-WmiObject -Class Win32_Group | % {
        try
        {
            Get-GroupByName -Name $_.Caption
            echo ""
        }
        catch
        {
        }
    }
}

function Set-FileMode
{
    Param
    (
        [Parameter(Mandatory=$true)]
        [ValidateScript({
            $m = $_
            $_m = $m[0..$m.Length]
            if ($_m[0] -ne "0")
            {
                __exit ("Invalid mode: $m, mode must be start with 0")
            }
            $_m = $_m[1..$_m.Length]
            if ($_m.Length -gt "4" -or $_m.Length -lt "3")
            {
                __exit ("Invalid mode: $m, mode bits len must be 4 or 5 (including first 0)")
            }
            $_m | % {
                if ($_ -gt "7")
                {
                    __exit ("Invalid mode: $m, mode must be in octal value")
                }
                if (!($_ -match "[0-9]"))
                {
                    __exit ("Invalid mode: $m, mode must be digits")
                }
            }
            return $true
        })]
        [String]$Mode,
        [Parameter(Mandatory=$false)][Switch]$Recurse,
        [Parameter(Mandatory=$true)][String[]]$Path
    )
    function __get_perms
    {
        Param
        (
            [Parameter(Mandatory=$true)][String]$s,
            [Parameter(Mandatory=$true)][String]$m
        )
        $out = @()
        $out += @("/remove", "`*$s")
        switch ($m)
        {
            0   {}
            1   { $out += ("/grant", "`*$s`:RX") }
            2   { $out += ("/grant", "`*$s`:``(W``,D``)") }
            3   { $out += ("/grant", "`*$s`:RX") }
            4   { $out += ("/grant", "`*$s`:R") }
            5   { $out += ("/grant", "`*$s`:RX") }
            6   { $out += ("/grant", "`*$s`:``(R``,W``,D``)") }
            7   { $out += ("/grant", "`*$s`:F") }
        }
        return $out
    }
    $Path | % {
        $_Path = $_
        $user = [Security.Principal.WindowsIdentity]::GetCurrent()
        $admin = [System.Security.Principal.NTAccount]"BUILTIN\Administrators"
        $admin = ($admin.Translate([System.Security.Principal.SecurityIdentifier])).Value
        $_Mode = $Mode[1..$Mode.Length]
        if ($_Mode.Length -eq 4)
        {
            # ignore setuid, setgid or sticky bit
            $_Mode = $_Mode[1..$_Mode.Length]
        }
        if ($_Mode.Length -eq 3)
        {
            $_cmd = @("icacls", $_Path)
            $_cmd += ("/L", "/Q", "/C")
            if ($Recurse)
            {
                $_cmd += ("/T")
            }
            Invoke-Expression (($_cmd + @("/reset")) -join " ") | Out-Null
            $_cmd += @("/inheritance`:r")
            $_cmd += __get_perms $user.User.Value $_Mode[0]
            $_cmd += __get_perms $user.Groups[0].Value $_Mode[1]
            $_cmd += __get_perms "S-1-1-0" $_Mode[2]
            $_cmd += __get_perms $admin "7"
            Invoke-Expression ($_cmd -join " ")
        }
    }
}

function Set-FileOwner
{
    Param
    (
        [Parameter(Mandatory=$true)][String]$Owner,
        [Parameter(Mandatory=$false)][Switch]$Recurse,
        [Parameter(Mandatory=$true)][String[]]$Path
    )
    if ([Win32Api]::AddPrivilege("SeRestorePrivilege") -ne "0")
    {
        __exit ("Failed to set owner on file")
    }
    $Path | % {
        $_Path = $_
        if ($Owner.LastIndexOf("\") -eq -1)
        {
            $Owner = $__MDOMAIN + "\" + $Owner
        }
        $o = [System.Security.Principal.NTAccount]$Owner
        $acl = Get-Acl -Path $_Path
        $acl.SetOwner($o)
        Set-Acl -AclObject $acl -Path $_Path
        if ($Recurse)
        {
            Get-ChildItem -Path $_Path -Recurse | % {
                $__Path = $_.FullName
                $acl = Get-Acl -Path $__Path
                $acl.SetOwner($o)
                Set-Acl -AclObject $acl -Path $__Path
            }
        }
    }
}

function Set-FileGroup
{
    Param
    (
        [Parameter(Mandatory=$true)][String]$Group,
        [Parameter(Mandatory=$false)][Switch]$Recurse,
        [Parameter(Mandatory=$true)][String[]]$Path
    )
    if ([Win32Api]::AddPrivilege("SeRestorePrivilege") -ne "0")
    {
        __exit ("Failed to set owner group on file")
    }
    $Path | % {
        $_Path = $_
        if ($Group.LastIndexOf("\") -eq -1)
        {
            $Group = $__MDOMAIN + "\" + $Group
        }
        $g = [System.Security.Principal.NTAccount]$Group
        $acl = Get-Acl -Path $_Path
        $acl.SetGroup($g)
        Set-Acl -AclObject $acl -Path $_Path
        if ($Recurse)
        {
            Get-ChildItem -Path $_Path -Recurse | % {
                $__Path = $_.FullName
                $acl = Get-Acl -Path $__Path
                $acl.SetGroup($g)
                Set-Acl -AclObject $acl -Path $__Path
            }
        }
    }
}

function Find-Command
{
    Param
    (
        [Parameter(Mandatory=$true)][String[]]$Path,
        [Parameter(Mandatory=$false)][Switch]$All
    )

    $Path | % {
        $cmd = (Get-Command -ErrorAction SilentlyContinue (Split-Path -Leaf $_))
        if ($cmd -eq $null)
        {
            continue
        }
        $_cmd = @()
        $_cmd += $cmd
        if (-NOT $All)
        {
            $_cmd = @($_cmd[0])
        }
        $_cmd | % {
            $cmd = $_
            switch ($cmd.CommandType)
            {
                "Function" { echo $cmd.Name }
                "Application" { echo $cmd.Path }
                "Cmdlet" { echo $cmd.Name }
                "Alias" { echo $cmd.Definition }
            }
        }
    }
}

function Get-Dir
{
    Param
    (
        [Parameter(Mandatory=$false)][String]$Path
    )
    if (-NOT $Path)
    {
        $Path = "."
    }
    $out = (Get-ChildItem -Path $Path -ErrorAction SilentlyContinue)
    if ($out -eq $null)
    {
        __exit ("Failed to list: $Path")
    }
    $_out = @()
    $_out += $out
    $_out | % { $_.FullName }
}

function Get-UserInfo
{
    [CmdletBinding(DefaultParameterSetName="ALL")]
    Param
    (
        [Parameter(Mandatory=$true)][String]$Name,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="UserSID")][Switch]$UserSID,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="GroupSID")][Switch]$GroupSID,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="GroupsSID")][Switch]$GroupsSID,
        [Parameter(Mandatory=$false,Position=1,ParameterSetName="UserSID")]
        [Parameter(Mandatory=$false,Position=1,ParameterSetName="GroupSID")]
        [Parameter(Mandatory=$false,Position=1,ParameterSetName="GroupsSID")]
        [Switch]$NamesOnly,
        [Parameter(Mandatory=$false,Position=0,ParameterSetName="ALL")][Switch]$All = $true
    )
    $_Name = $Name
    if ($Name.LastIndexOf("\") -ne -1)
    {
        $Domain = $Name.Substring(0, $Name.LastIndexOf("\"))
        $Name = $Name.Substring($Name.LastIndexOf("\") + 1)
    }
    else
    {
        $Domain = $__MDOMAIN
    }
    $Domain = $Domain.ToUpper()
    $user = ([ADSI]"WinNT://$Domain/$Name,user")
    $sid = $user.objectSid
    if ($sid -eq $null)
    {
        __exit ("Can not find user: $_Name")
    }
    $sid = (New-Object System.Security.Principal.SecurityIdentifier($sid.Value,0)).Value
    $sid = $sid.Substring($sid.LastIndexOf("-") + 1)
    $fqdn = $Domain + "\" + $Name
    $query = "SELECT * FROM Win32_GroupUser WHERE PartComponent = `"Win32_UserAccount.Domain='$Domain',Name='$Name'`""
    $groups = (Get-WmiObject -Query $query) | % { $_.GroupComponent }
    $groups = $groups | % { ($_ -split 'Domain="')[1].Replace('",Name="', "\").Replace('"', "") }
    $_groups = @()
    $pgroup = @()
    $groups | % {
        $g = $_
        $gid = (Get-GroupByName -Name $g -OnlySID)
        $gid = $gid.Substring($gid.LastIndexOf("-") + 1)
        if ($user.PrimaryGroupId.Value -eq $gid)
        {
            $pgroup = @($gid, $g)
        }
        else
        {
            $_groups += ,($gid, $g)
        }
    }
    if ($All)
    {
        $out = "uid=$sid($fqdn) group=$($pgroup[0])($($pgroup[1]))"
        if ($_groups.Count -gt 0)
        {
            $_out = @()
            $_groups | % { $_out += "$($_[0])($($_[1]))" }
            $out += " groups=" + ($_out -join ",")
        }
        echo $out
    }
    else
    {
        $out = @()
        if ($UserSID)
        {
            $out = @($sid, $fqdn)
        }
        elseif ($GroupSID)
        {
            $out = $pgroup
        }
        elseif ($GroupSID)
        {
            $out = @()
            if ($_groups.Count -gt 0)
            {
                $_out = $_groups | % { $_[0] }
                $out += ,($_out)
                $_out = $_groups | % { $_[1] }
                $out += ,($_out)
            }
        }
        if ($out.Count -gt 0)
        {
            if ($NamesOnly)
            {
                echo ($out[1] -join " ")
            }
            else
            {
                echo ($out[0] -join " ")
            }
        }
    }
}

function Enable-PTLRemoting
{
    Param
    (
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="File")][String]$PassFile,
        [Parameter(Mandatory=$true,Position=0,ParameterSetName="User")][String[]]$User
    )

    $current_user = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    if (-NOT ([System.Security.Principal.WindowsPrincipal]$current_user).IsInRole("Administrators"))
    {
        __exit ("You Don't have admin priv")
    }
    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine -Force -Confirm:$false
    Enable-PSRemoting -Force -Confirm:$false | Out-Null
    $PSSDDL = (Get-PSSessionConfiguration -Name "Microsoft.PowerShell").SecurityDescriptorSDDL
    $PSSDDL = New-Object System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList $false, $false, $PSSDDL
    $WMSDDL = (Get-Item -Path "WSMan:\localhost\Service\RootSDDL").Value
    $WMSDDL = New-Object System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList $false, $false, $WMSDDL
    $DefSDDL = "O:NSG:BAD:P(A;;GA;;;BA)S:P(AU;FA;GA;;;WD)(AU;SA;GWGX;;;WD)"
    $DefSDDL = New-Object System.Security.AccessControl.CommonSecurityDescriptor -ArgumentList $false, $false, $DefSDDL
    if ($User)
    {
        $User | % {
            $sid = (Get-UserByName -OnlySID $_)
            $PSSDDL.DiscretionaryAcl.AddAccess("Allow", $sid, 0x10000000L, "none", "none") | Out-Null
            $WMSDDL.DiscretionaryAcl.AddAccess("Allow", $sid, 0x10000000L, "none", "none") | Out-Null
        }
    }
    else
    {
        Get-Content $PassFile | % {
            $Line = $_.Split(":")
            $Name = $Line[0]
            $Pass = ($Line[1..$Line.Length] -join ":")
            [Win32Api]::WriteCred($Name, $Pass)
            $sid = (Get-UserByName -OnlySID $Name)
            $PSSDDL.DiscretionaryAcl.AddAccess("Allow", $sid, 0x10000000L, "none", "none") | Out-Null
            $WMSDDL.DiscretionaryAcl.AddAccess("Allow", $sid, 0x10000000L, "none", "none") | Out-Null
        }
    }
    $PSSDDL_s = $PSSDDL.GetSddlForm("All")
    $WMSDDL_s = $WMSDDL.GetSddlForm("All")
    $DefSDDL_s = $DefSDDL.GetSddlForm("All")
    Set-Item -Path "WSMan:\localhost\Service\RootSDDL" -Value $WMSDDL_s -Confirm:$false -Force | Out-Null
    Get-PSSessionConfiguration | % {
        Set-PSSessionConfiguration -name $_.Name -SecurityDescriptorSddl $PSSDDL_s -Force -Confirm:$false | Out-Null
    }
}

Export-ModuleMember -Function Get-*, Set-*, Enable-*, Find-*
