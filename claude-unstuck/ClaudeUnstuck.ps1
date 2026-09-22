[CmdletBinding()]
param(
    [switch]$ScanOnly,
    [switch]$Yes,
    [switch]$NoRelaunch
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Test-IsAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Restart-Elevated {
    if (-not $PSCommandPath) {
        throw "Claude Unstuck needs an elevated PowerShell window. Re-run PowerShell as Administrator."
    }

    $args = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"{0}"' -f $PSCommandPath))
    if ($ScanOnly) { $args += "-ScanOnly" }
    if ($Yes) { $args += "-Yes" }
    if ($NoRelaunch) { $args += "-NoRelaunch" }

    Write-Host "Requesting administrator access..."
    Start-Process powershell.exe -Verb RunAs -ArgumentList $args | Out-Null
    exit
}

if (-not (Test-IsAdministrator)) {
    Restart-Elevated
}

if (-not ("ClaudeJobProbe" -as [type])) {
Add-Type @"
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Runtime.InteropServices;

public class ClaudeJobSnapshot
{
    public string Name;
    public uint Assigned;
    public long[] Pids;
}

public static class ClaudeJobProbe
{
    const uint DIRECTORY_QUERY = 0x0001;
    const uint JOB_OBJECT_QUERY = 0x0004;
    const uint OBJ_CASE_INSENSITIVE = 0x00000040;
    const int JobObjectBasicProcessIdList = 3;

    [StructLayout(LayoutKind.Sequential)]
    struct UNICODE_STRING
    {
        public ushort Length;
        public ushort MaximumLength;
        public IntPtr Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct OBJECT_ATTRIBUTES
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct OBJECT_DIRECTORY_INFORMATION
    {
        public UNICODE_STRING Name;
        public UNICODE_STRING TypeName;
    }

    [DllImport("ntdll.dll")]
    static extern int NtOpenDirectoryObject(
        out IntPtr DirectoryHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes);

    [DllImport("ntdll.dll")]
    static extern int NtQueryDirectoryObject(
        IntPtr DirectoryHandle,
        IntPtr Buffer,
        uint Length,
        [MarshalAs(UnmanagedType.U1)] bool ReturnSingleEntry,
        [MarshalAs(UnmanagedType.U1)] bool RestartScan,
        ref uint Context,
        out uint ReturnLength);

    [DllImport("ntdll.dll")]
    static extern int NtOpenJobObject(
        out IntPtr JobHandle,
        uint DesiredAccess,
        ref OBJECT_ATTRIBUTES ObjectAttributes);

    [DllImport("ntdll.dll")]
    static extern int NtClose(IntPtr Handle);

    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool QueryInformationJobObject(
        IntPtr hJob,
        int JobObjectInformationClass,
        IntPtr lpJobObjectInformation,
        uint cbJobObjectInformationLength,
        out uint lpReturnLength);

    static OBJECT_ATTRIBUTES MakeOA(string name, out IntPtr stringBuffer, out IntPtr unicodeBuffer)
    {
        stringBuffer = Marshal.StringToHGlobalUni(name);

        UNICODE_STRING us = new UNICODE_STRING();
        us.Length = (ushort)(name.Length * 2);
        us.MaximumLength = (ushort)((name.Length + 1) * 2);
        us.Buffer = stringBuffer;

        unicodeBuffer = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(UNICODE_STRING)));
        Marshal.StructureToPtr(us, unicodeBuffer, false);

        OBJECT_ATTRIBUTES oa = new OBJECT_ATTRIBUTES();
        oa.Length = Marshal.SizeOf(typeof(OBJECT_ATTRIBUTES));
        oa.RootDirectory = IntPtr.Zero;
        oa.ObjectName = unicodeBuffer;
        oa.Attributes = OBJ_CASE_INSENSITIVE;
        oa.SecurityDescriptor = IntPtr.Zero;
        oa.SecurityQualityOfService = IntPtr.Zero;
        return oa;
    }

    static IntPtr OpenRootDirectory()
    {
        IntPtr str, us;
        OBJECT_ATTRIBUTES oa = MakeOA("\\", out str, out us);

        try
        {
            IntPtr handle;
            int status = NtOpenDirectoryObject(out handle, DIRECTORY_QUERY, ref oa);
            if (status != 0)
                throw new Exception("NtOpenDirectoryObject failed: 0x" + status.ToString("X8"));
            return handle;
        }
        finally
        {
            Marshal.FreeHGlobal(us);
            Marshal.FreeHGlobal(str);
        }
    }

    static IntPtr OpenJob(string fullName)
    {
        IntPtr str, us;
        OBJECT_ATTRIBUTES oa = MakeOA(fullName, out str, out us);

        try
        {
            IntPtr handle;
            int status = NtOpenJobObject(out handle, JOB_OBJECT_QUERY, ref oa);
            if (status != 0)
                return IntPtr.Zero;
            return handle;
        }
        finally
        {
            Marshal.FreeHGlobal(us);
            Marshal.FreeHGlobal(str);
        }
    }

    static long[] ReadJobPids(IntPtr job, out uint assigned)
    {
        int size = 1024 * 1024;
        IntPtr buffer = Marshal.AllocHGlobal(size);

        try
        {
            uint returned;
            if (!QueryInformationJobObject(
                job,
                JobObjectBasicProcessIdList,
                buffer,
                (uint)size,
                out returned))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            assigned = (uint)Marshal.ReadInt32(buffer, 0);
            uint count = (uint)Marshal.ReadInt32(buffer, 4);

            long[] pids = new long[count];
            int offset = 8;

            for (int i = 0; i < count; i++)
            {
                if (IntPtr.Size == 8)
                    pids[i] = Marshal.ReadInt64(buffer, offset + (i * IntPtr.Size));
                else
                    pids[i] = (uint)Marshal.ReadInt32(buffer, offset + (i * IntPtr.Size));
            }

            return pids;
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static ClaudeJobSnapshot[] GetClaudeJobs()
    {
        List<ClaudeJobSnapshot> results = new List<ClaudeJobSnapshot>();
        IntPtr dir = OpenRootDirectory();
        IntPtr buffer = Marshal.AllocHGlobal(65536);

        try
        {
            uint context = 0;
            bool restart = true;

            while (true)
            {
                uint returned;
                int status = NtQueryDirectoryObject(
                    dir,
                    buffer,
                    65536,
                    true,
                    restart,
                    ref context,
                    out returned);

                restart = false;
                if (status != 0)
                    break;

                OBJECT_DIRECTORY_INFORMATION info =
                    (OBJECT_DIRECTORY_INFORMATION)Marshal.PtrToStructure(
                        buffer,
                        typeof(OBJECT_DIRECTORY_INFORMATION));

                string name = info.Name.Buffer == IntPtr.Zero
                    ? ""
                    : Marshal.PtrToStringUni(info.Name.Buffer, info.Name.Length / 2);

                string type = info.TypeName.Buffer == IntPtr.Zero
                    ? ""
                    : Marshal.PtrToStringUni(info.TypeName.Buffer, info.TypeName.Length / 2);

                if (type == "Job" &&
                    name.StartsWith("Container_Claude_", StringComparison.OrdinalIgnoreCase))
                {
                    IntPtr job = OpenJob("\\" + name);

                    if (job != IntPtr.Zero)
                    {
                        try
                        {
                            uint assigned;
                            long[] pids = ReadJobPids(job, out assigned);

                            ClaudeJobSnapshot snap = new ClaudeJobSnapshot();
                            snap.Name = name;
                            snap.Assigned = assigned;
                            snap.Pids = pids;
                            results.Add(snap);
                        }
                        finally
                        {
                            NtClose(job);
                        }
                    }
                }
            }
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
            NtClose(dir);
        }

        return results.ToArray();
    }
}
"@
}

function Get-ClaudeJobs {
    return @([ClaudeJobProbe]::GetClaudeJobs())
}

function Get-ProcessDetails([long]$ProcessId) {
    try {
        return Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $ProcessId) -ErrorAction Stop
    }
    catch {
        return $null
    }
}

function Show-JobProcesses($Job) {
    Write-Host ""
    Write-Host ("Stale container: {0}" -f $Job.Name) -ForegroundColor Yellow
    Write-Host ("Processes keeping it alive: {0}" -f $Job.Pids.Count)

    foreach ($processId in $Job.Pids) {
        $process = Get-ProcessDetails $processId
        if ($null -eq $process) {
            Write-Host ("  PID {0}: already exited" -f $processId)
            continue
        }

        Write-Host ""
        Write-Host ("  PID:     {0}" -f $process.ProcessId)
        Write-Host ("  Name:    {0}" -f $process.Name)
        Write-Host ("  Parent:  {0}" -f $process.ParentProcessId)
        Write-Host ("  Started: {0}" -f $process.CreationDate)
        Write-Host ("  Path:    {0}" -f $process.ExecutablePath)
        Write-Host ("  Command: {0}" -f $process.CommandLine)
    }
}

function Remove-StaleJobMembers([string]$JobName) {
    for ($round = 1; $round -le 4; $round++) {
        $snapshot = Get-ClaudeJobs | Where-Object { $_.Name -eq $JobName } | Select-Object -First 1
        if ($null -eq $snapshot) {
            return $true
        }

        foreach ($processId in @($snapshot.Pids)) {
            try {
                Stop-Process -Id ([int]$processId) -Force -ErrorAction Stop
                Write-Host ("Stopped PID {0}" -f $processId)
            }
            catch {
                if (Get-Process -Id ([int]$processId) -ErrorAction SilentlyContinue) {
                    Write-Warning ("Could not stop PID {0}: {1}" -f $processId, $_.Exception.Message)
                }
            }
        }

        Start-Sleep -Milliseconds 400
    }

    $stillThere = Get-ClaudeJobs | Where-Object { $_.Name -eq $JobName } | Select-Object -First 1
    return ($null -eq $stillThere)
}

$package = Get-AppxPackage -Name Claude -ErrorAction SilentlyContinue |
    Sort-Object Version -Descending |
    Select-Object -First 1

if ($null -eq $package) {
    Write-Error "Claude Desktop MSIX package was not found for the current user."
    exit 2
}

$currentVersion = $package.Version.ToString()
$currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$jobPattern = '^Container_Claude_(?<Version>\d+(?:\.\d+){3})_[^-]+-(?<Scope>.+)$'

Write-Host "Claude Unstuck"
Write-Host ("Installed Claude version: {0}" -f $currentVersion)
Write-Host ("Current user SID: {0}" -f $currentSid)
Write-Host ""

$allJobs = Get-ClaudeJobs
$staleJobs = @()

foreach ($job in $allJobs) {
    $match = [regex]::Match($job.Name, $jobPattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
    if (-not $match.Success) {
        continue
    }

    $jobVersion = $match.Groups["Version"].Value
    $scope = $match.Groups["Scope"].Value

    if ($scope -eq "PackagedService") {
        continue
    }

    if ($scope -eq $currentSid -and $jobVersion -ne $currentVersion) {
        $staleJobs += $job
    }
}

if ($staleJobs.Count -eq 0) {
    Write-Host "No stale Claude user containers from an older version were found." -ForegroundColor Green
    Write-Host "Nothing was changed."
    exit 0
}

Write-Host ("Found {0} stale Claude container(s)." -f $staleJobs.Count) -ForegroundColor Yellow

foreach ($job in $staleJobs) {
    Show-JobProcesses $job
}

if ($ScanOnly) {
    Write-Host ""
    Write-Host "Scan-only mode: nothing was changed."
    exit 0
}

Write-Host ""
Write-Warning "The processes above were launched inside an older Claude AppX job. Stopping them can terminate work that was intentionally left running by that old Claude session."

$approved = $Yes.IsPresent
if (-not $approved) {
    $answer = Read-Host "Stop only these stale-job processes and release the old Claude container? [y/N]"
    $approved = $answer -match '^(y|yes)$'
}

if (-not $approved) {
    Write-Host "Cancelled. Nothing was changed."
    exit 0
}

$failed = @()

foreach ($job in $staleJobs) {
    Write-Host ""
    Write-Host ("Cleaning {0}" -f $job.Name)
    if (-not (Remove-StaleJobMembers $job.Name)) {
        $failed += $job.Name
    }
}

if ($failed.Count -gt 0) {
    Write-Warning "Some stale containers are still present:"
    $failed | ForEach-Object { Write-Warning ("  {0}" -f $_) }
    Write-Warning "No package data was deleted. You can run the script again to inspect the remaining members."
    exit 1
}

Write-Host ""
Write-Host "Stale Claude container released." -ForegroundColor Green

if (-not $NoRelaunch) {
    $startApp = Get-StartApps | Where-Object { $_.Name -eq "Claude" } | Select-Object -First 1

    if ($null -ne $startApp) {
        Write-Host "Relaunching Claude..."
        Start-Process explorer.exe -ArgumentList ("shell:AppsFolder\{0}" -f $startApp.AppID)
        Start-Sleep -Seconds 2

        if (Get-Process Claude -ErrorAction SilentlyContinue) {
            Write-Host "Claude is running. No reboot required." -ForegroundColor Green
        }
        else {
            Write-Warning "The stale job is gone, but Claude was not detected after relaunch. Try opening Claude normally."
        }
    }
    else {
        Write-Warning "Claude Start Menu AppID was not found. Open Claude normally."
    }
}
