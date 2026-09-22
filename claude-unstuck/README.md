# Claude Unstuck

Fix a specific Claude Desktop for Windows failure without rebooting:

- Claude updates.
- The old version leaves child processes inside a stale Desktop AppX Job Object.
- The new Claude package is registered correctly, but launch fails with `0x80070020`.
- Event Viewer may show AppModel-Runtime events 208/215 and a failure while converting the job/container.
- Task Manager, `handle.exe`, and ordinary process-tree inspection can miss the relationship because the old `Claude.exe` parent is already gone.

`ClaudeUnstuck.ps1` reads the Windows Job Object membership directly, finds old-version Claude user containers for the current Windows SID, shows every process keeping them alive, and can terminate only those members after confirmation.

## Quick start

Open PowerShell and run:

    $p = "$env:TEMP\ClaudeUnstuck.ps1"
    irm "https://raw.githubusercontent.com/audioses/cr-test/main/claude-unstuck/ClaudeUnstuck.ps1" -OutFile $p
    powershell -NoProfile -ExecutionPolicy Bypass -File $p

The script will request Administrator access if needed.

## Scan only

    powershell -NoProfile -ExecutionPolicy Bypass -File .\ClaudeUnstuck.ps1 -ScanOnly

## Non-interactive fix

    powershell -NoProfile -ExecutionPolicy Bypass -File .\ClaudeUnstuck.ps1 -Yes

Add `-NoRelaunch` if you do not want the script to reopen Claude after cleanup.

## Safety

The default behavior is deliberately conservative:

- It only targets `Container_Claude_*` Job Objects.
- It only treats jobs belonging to the current Windows user SID as candidates.
- It only targets jobs whose Claude version is older than the currently installed Claude version.
- It ignores `PackagedService` jobs such as `CoworkVMService`.
- It shows PID, parent PID, executable path, start time, and full command line before asking for confirmation.
- It does not uninstall Claude, delete package data, reset settings, or modify AppX registration.

Old Claude sessions can contain processes you intentionally left running, such as WSL, Node, Python, SSH, Git, or local servers. Read the process list before approving cleanup.

## Why this works

Desktop AppX applications run processes inside Windows Job Objects. A child process launched by an older Claude session can outlive the visible Claude window and keep the old container alive. When the next Claude version tries to create its Desktop AppX container, Windows can fail with `0x80070020` even though no ordinary file handle appears to be holding `Claude.exe`.

This script uses Windows native APIs (`NtQueryDirectoryObject`, `NtOpenJobObject`, and `QueryInformationJobObject` with `JobObjectBasicProcessIdList`) to enumerate the actual process membership of those stale Claude Job Objects.

## Requirements

- Windows 10 or Windows 11
- Claude Desktop installed as the current MSIX/AppX package
- Windows PowerShell 5.1 or newer
- Administrator rights for cleanup

## What this is not

This is not an Anthropic product and is not affiliated with Anthropic. It is a narrow workaround for a Windows/Claude Desktop stale-container failure mode. If Claude changes its package/container naming, the script may need an update.

## License

MIT