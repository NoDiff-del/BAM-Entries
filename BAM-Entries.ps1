Clear-Host

$signature = @'
[DllImport("kernel32.dll", SetLastError=true)]
[return: MarshalAs(UnmanagedType.Bool)]
public static extern bool GetVolumePathNamesForVolumeNameW([MarshalAs(UnmanagedType.LPWStr)] string lpszVolumeName,
        [MarshalAs(UnmanagedType.LPWStr)] [Out] StringBuilder lpszVolumeNamePaths, uint cchBuferLength, 
        ref UInt32 lpcchReturnLength);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern IntPtr FindFirstVolume([Out] StringBuilder lpszVolumeName,
   uint cchBufferLength);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern bool FindNextVolume(IntPtr hFindVolume, [Out] StringBuilder lpszVolumeName, uint cchBufferLength);

[DllImport("kernel32.dll", SetLastError = true)]
public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);
'@;

Add-Type -MemberDefinition $signature -Name Win32Utils -Namespace PInvoke -Using PInvoke,System.Text;

[UInt32] $lpcchReturnLength = 0;
[UInt32] $Max = 65535
$sbVolumeName = New-Object System.Text.StringBuilder($Max, $Max)
$sbPathName = New-Object System.Text.StringBuilder($Max, $Max)
$sbMountPoint = New-Object System.Text.StringBuilder($Max, $Max)

[IntPtr] $volumeHandle = [PInvoke.Win32Utils]::FindFirstVolume($sbVolumeName, $Max)

$deviceMapping = @{ }

do {
    $volume = $sbVolumeName.toString()
    $unused = [PInvoke.Win32Utils]::GetVolumePathNamesForVolumeNameW($volume, $sbMountPoint, $Max, [Ref] $lpcchReturnLength)
    $ReturnLength = [PInvoke.Win32Utils]::QueryDosDevice($volume.Substring(4, $volume.Length - 1 - 4), $sbPathName, [UInt32] $Max)
    
    if ($ReturnLength) {
        $DriveMapping = @{
            DriveLetter = $sbMountPoint.toString()
            VolumeName = $volume
            DevicePath = $sbPathName.ToString()
        }
        $deviceMapping[$DriveMapping.DevicePath] = $DriveMapping.DriveLetter
    }
} while ([PInvoke.Win32Utils]::FindNextVolume([IntPtr] $volumeHandle, $sbVolumeName, $Max))

$Bias = (Get-TimeZone).BaseUtcOffset.TotalMinutes

$bamRegistryPaths = @("bam", "bam\State")
$userSIDs = @()

Try {
    foreach ($registryPath in $bamRegistryPaths) {
        $userSIDs += Get-ChildItem -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$($registryPath)\UserSettings\" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty PSChildName
    }
}
Catch {
    Write-Host "Error: An issue occurred while searching for BAM." -ForegroundColor Red
    exit
}

$serviceRegistryPaths = @("HKLM:\SYSTEM\CurrentControlSet\Services\bam\", "HKLM:\SYSTEM\CurrentControlSet\Services\bam\state\")
$bamEntries = @()

Write-Host "Scanning SIDs... Please hold on, this may take a moment." -ForegroundColor Cyan

foreach ($sid in $userSIDs) {
    foreach ($servicePath in $serviceRegistryPaths) {
        $bamItems = Get-Item -Path "$($servicePath)UserSettings\$sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Property

        foreach ($item in $bamItems) {
            $keyValue = Get-ItemProperty -Path "$($servicePath)UserSettings\$sid" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty $item

            if ($keyValue.length -eq 24) {
                $hexValue = [System.BitConverter]::ToString($keyValue[7..0]) -replace "-", ""
                $executionTime = (Get-Date ([DateTime]::FromFileTimeUtc([Convert]::ToInt64($hexValue, 16))).AddMinutes($Bias)).ToString("yyyy-MM-dd HH:mm:ss")

                $fileName = if ((((Split-Path -Path $item) | ConvertFrom-String -Delimiter "\\").P3) -match '\d{1}') {
                    Split-Path -Leaf ($item).TrimStart()
                } else {
                    $item
                }

                $fullPath = $item

                $bamEntries += [PSCustomObject]@{
                    'Execution Time' = $executionTime   
                    'Executables' = if ($fileName -like "*.exe") { $fileName } else { $fileName }
                    'Modified Extension' = if ($fileName -like "*.exe") { "No" } else { "Yes" }
                    Path = $fullPath
                    'Signatures' = "Not Found"
                }
            }
        }
    }
}

foreach ($entry in $bamEntries) {
    $originalPath = $entry.Path

    foreach ($device in $deviceMapping.Keys) {
        if ($originalPath -like "*$device*") {
            $escapedDevice = [regex]::Escape($device)
            $newPath = $originalPath -replace $escapedDevice, "$($deviceMapping[$device])"
            $entry.Path = $newPath -replace '\\+', '\'
            break
        }
    }
}

$strings = @(
    "mouse_event", "AutoClicker", "[...]", "[NONE]", "[Bind: ", "Reach", "AimAssist", "Nametags",
    "SelfDestruct", "mouse_button", "uiAccess='false'", "Reeach", "AutoClicker", "[Bind:", "key_key.",
    "autoclicker", "killaura.killaura", "dreamagent", "VeraCrypt", "makecert", "start /MIN cmd.exe ",
    "vape.gg", "Aimbot", "aimbot", "Tracers", "tracers", "LeftMinCPS", "[Bind", "LCLICK", "RCLICK",
    "fastplace", "self destruct", "sc stop", "reg delete", "misc", "hide bind", "iUW#Xd",
    "Waiting for minecraft process...", "Autoclicker->", "MoonDLL.pdb", "slinky_init"
)

Write-Output " "
Write-Output "Initiating malicious string analysis..."

foreach ($entry in $bamEntries) {
    $fullPath = $entry.Path
    
    if (-not [string]::IsNullOrEmpty($fullPath) -and (Test-Path $fullPath)) {
        $maliciousStringsFound = @()
        
        foreach ($string in $strings) {
            $escapedString = [Regex]::Escape($string)
            $findstrResult = cmd.exe /c "findstr /i /c:`"$escapedString`" `"$fullPath`""

            if ($findstrResult) {
                $maliciousStringsFound += $string
            }
        }

        if ($maliciousStringsFound.Count -gt 0) {
            $maliciousStringList = $maliciousStringsFound -join ", "
            $entry | Add-Member -MemberType NoteProperty -Name "Contains Malicious Strings" -Value $maliciousStringList
        } else {
            $entry | Add-Member -MemberType NoteProperty -Name "Contains Malicious Strings" -Value "N/A"
        }
    }
}

Write-Output "Analysis of malicious strings completed (Gridview will start soon)."

$usnjournalONE = "C:\newnamefiles.txt"
$usnjournalTWO = "C:\deletedfiles.txt"

if (Test-Path $usnjournalONE) { Remove-Item $usnjournalOne -Force }
if (Test-Path $usnjournalTWO) { Remove-Item $usnjournalTWO -Force }

cmd.exe /c "fsutil usn readjournal C: csv | findstr /i /c:0x00002000 >> C:\newnamefiles.txt"
cmd.exe /c "fsutil usn readjournal C: csv | findstr /i /c:0x80000200 >> C:\deletedfiles.txt"

$newFiles = Get-Content "C:\newnamefiles.txt" | ForEach-Object {
    if ($_ -match ',"([^"]+)"') {
        $matches[1]
    }
}

$deletedFiles = Get-Content "C:\deletedfiles.txt" | ForEach-Object {
    if ($_ -match ',"([^"]+)"') {
        $matches[1]
    }
}

$deletedSet = @{ }
foreach ($file in $deletedFiles) {
    $deletedSet[$file] = $true
}

$newFileCounts = @{ }
foreach ($file in $newFiles) {
    if ($newFileCounts.ContainsKey($file)) {
        $newFileCounts[$file]++
    } else {
        $newFileCounts[$file] = 1
    }
}

foreach ($entry in $bamEntries) {
    $fileName = $entry.Executables
    $replaces = $false

    if ($newFileCounts.ContainsKey($fileName) -and $newFileCounts[$fileName] -ge 2 -and $deletedSet.ContainsKey($fileName)) {
        $replaces = $true
    }

    $entry | Add-Member -MemberType NoteProperty -Name "Replaces" -Value $replaces
}

Write-Host "Completed processing for all SIDs (BAM Entries)." -ForegroundColor Green
$bamEntries | Out-GridView -Title "BAM Entries script created by diff"
