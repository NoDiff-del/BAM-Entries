Clear-Host

$DynAssembly = New-Object System.Reflection.AssemblyName('SysUtils')
$AssemblyBuilder = [AppDomain]::CurrentDomain.DefineDynamicAssembly($DynAssembly, [Reflection.Emit.AssemblyBuilderAccess]::Run)
$ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('SysUtils', $False)

$TypeBuilder = $ModuleBuilder.DefineType('Kernel32', 'Public, Class')
$PInvokeMethod = $TypeBuilder.DefinePInvokeMethod('QueryDosDevice', 'kernel32.dll', ([Reflection.MethodAttributes]::Public -bor [Reflection.MethodAttributes]::Static), [Reflection.CallingConventions]::Standard, [UInt32], [Type[]]@([String], [Text.StringBuilder], [UInt32]), [Runtime.InteropServices.CallingConvention]::Winapi, [Runtime.InteropServices.CharSet]::Auto)
$DllImportConstructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor(@([String]))
$SetLastError = [Runtime.InteropServices.DllImportAttribute].GetField('SetLastError')
$SetLastErrorCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($DllImportConstructor, @('kernel32.dll'), [Reflection.FieldInfo[]]@($SetLastError), @($true))
$PInvokeMethod.SetCustomAttribute($SetLastErrorCustomAttribute)
$Kernel32 = $TypeBuilder.CreateType()

$Max = 65536
$StringBuilder = New-Object System.Text.StringBuilder($Max)

$deviceMapping = @{}

Get-WmiObject Win32_Volume | Where-Object { $_.DriveLetter } | ForEach-Object {
    $ReturnLength = $Kernel32::QueryDosDevice($_.DriveLetter, $StringBuilder, $Max)

    if ($ReturnLength) {
        $deviceMapping[$StringBuilder.ToString()] = $_.DriveLetter
    }
}

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
            $entry.Path = $newPath.TrimEnd('\')
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

foreach ($entry in $bamEntries) {
    $fullPath = $entry.Path

    if (-not [string]::IsNullOrEmpty($fullPath) -and (Test-Path $fullPath)) {
        $signature = Get-AuthenticodeSignature $fullPath
        $entry.Signatures = if ($signature.Status -eq 'Valid') { "Signed" } else { "Not Signed" }

        $containsMaliciousString = $strings | Where-Object { $fullPath -contains $_ }

        if ($containsMaliciousString) {
            $maliciousString = $containsMaliciousString | Select-Object -First 1
            $entry | Add-Member -MemberType NoteProperty -Name "Contains Malicious Strings" -Value $maliciousString
        } else {
            $entry | Add-Member -MemberType NoteProperty -Name "Contains Malicious Strings" -Value "N/A"
        }
    }
}

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
