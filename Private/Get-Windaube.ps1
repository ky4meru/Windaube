function Get-WindaubeSystemInfo
{
    Write-Verbose "Getting system information"
    $(Get-ComputerInfo).PSObject.Properties | Select-Object Name, Value
}

function Get-WindaubeLocalUsers
{
    Write-Verbose "Getting local users"
    Get-LocalUser | Select-Object -Property Name, Description, Enabled
}

function Get-WindaubeLocalGroupMembers
{
    param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $LocalGroupName
    )
    process
    {
        $Members = @()
        $Output = net localgroup $LocalGroupName
        $Output = $Output[6..($Output.Length-3)]

        if ($Output[0] -ne "The command completed successfully.")
        {
            $Output | ForEach-Object -Process { $Members += $_ }
        }

        $Members
    }
}

function Get-WindaubeLocalGroups
{
    Write-Verbose "Getting local groups"
    $LocalGroups = Get-LocalGroup | Select-Object -Property Name, Description
    $LocalGroups | ForEach-Object -Process { $_ | Add-Member -Type NoteProperty -Name "Members" -Value $(Get-WindaubeLocalGroupMembers $_.Name) }
    $LocalGroups
}

function Get-WindaubeAntiVirusProducts
{
    Write-Verbose "Getting installed antivirus products"
    Get-WMIObject -Class "AntiVirusProduct" -Namespace "root\SecurityCenter2" -ErrorAction SilentlyContinue | Select-Object -Property displayName, pathToSignedReportingExe
}

function Get-WindaubeServices
{
    Write-Verbose "Getting services"
    Get-WmiObject Win32_Service | Select-Object -Property DisplayName, StartName, ServiceType, PathName, State
}

function Get-WindaubeProcesses
{
    Write-Verbose "Getting processes"
    Get-WmiObject Win32_Process | Select-Object -Property ProcessId, Name, ExecutablePath
}

function Get-WindaubeStartupItems
{
    Write-Verbose "Getting startup items"
    Get-CimInstance Win32_StartupCommand -Verbose:$false | Select-Object -Property Name, Command, User
}

function Get-WindaubeScheduledTasks
{
    Write-Verbose "Getting scheduled tasks"
    Get-ScheduledTask | Select-Object -Property TaskName, TaskPath, Description
}

function Get-WindaubeDisks
{
    Write-Verbose "Getting disks"
    Get-WMIObject Win32_LogicalDisk -Namespace "root\CIMV2" -ErrorAction SilentlyContinue | Select-Object -Property DeviceID, FreeSpace, Size
}

function Get-WindaubeAppLockerPolicies
{
    Write-Verbose "Getting AppLocker policies"
    Get-AppLockerPolicy -Effective | Select-Object Version, RuleCollections, RuleCollectionTypes
}

function Get-WindaubeNetworkShares
{
    <# TODO: Get AccessRight as String instead of Int #>
    Write-Verbose "Getting network shares"
    $NetworkShares = Get-SmbShare | Select-Object -Property Name, Description, Path
    $NetworkShares | ForEach-Object -Process { $_ | Add-Member -Type NoteProperty -Name "ACL" -Value $(Get-SmbShareAccess -Name $_.Name | Select-Object -Property AccountName, AccessRight) }
    $NetworkShares
}

function Get-WindaubeSecurityPolicies
{
    Write-Verbose "Getting security policies"

    $TempSecurityPoliciesFile = "$($Env:Temp)\$(Get-Date -Format yyyyMMdd-HHmmss)-WindaubeSecurityPolicies.txt"
    SecEdit.exe /export /cfg $TempSecurityPoliciesFile | Out-Null
    
    $Results = @{}

    foreach ($SecurityPolicy in $SecurityPolicies)
    {
        $Value = $(Get-Content $TempSecurityPoliciesFile | Select-String -Pattern "^$($SecurityPolicy.Name)" | Out-String).Trim().Split("=")[1].Replace('"','').Trim()
        $Results.Add($SecurityPolicy.Name, $Value)
    }

    Remove-Item $TempSecurityPoliciesFile
    
    $Results
}

function Get-WindaubeEnvironmentVariables
{
    Write-Verbose "Getting environment variables"
    Get-ChildItem Env: | Select-Object -Property Name, Value
}

function Get-WindaubeAuditPolicies
{
    Write-Verbose "Getting audit policies"

    $Results = @{}

    foreach ($AuditPolicy in $AuditPolicies)
    {
        $Output = AuditPol.exe /Get /SubCategory:"$($AuditPolicy.Name)" 2>&1

        if ($Output -Match "0x00000057")
        {
            Write-Verbose "- Audit policy '$($AuditPolicy.Name)' was not found on the system"
            continue
        }

        Write-Verbose "- Getting '$($AuditPolicy.Name)' audit policy"

        $Result = $($Output | Select-String -Pattern " $($AuditPolicy.Name) " | Out-String).Trim()
        $Value = $Result.Replace($($AuditPolicy.Name), "").Trim()
        $Results.Add($($AuditPolicy.Name), $Value)
    }

    $Results
}

function Get-WindaubeRegistryEntries
{
    Write-Verbose "Getting registry entries"
    
    $Results = @{}

    foreach ($RegistryEntry in $RegistryEntries)
    {
        if ($Results.ContainsKey("$($RegistryEntry.Path):$($RegistryEntry.Name)"))
        {
            continue
        }

        Write-Verbose "- Getting '$($RegistryEntry.Path):$($RegistryEntry.Name)' registry entry"

        if (-not $(Test-Path $RegistryEntry.Path))
        {
            Write-Verbose "- Registry path '$($RegistryEntry.Path)' was not found on the system"
            continue
        }
        
        $ResultName = "$($RegistryEntry.Path):$($RegistryEntry.Name)"
        $RegistryPath = Get-ItemProperty -Path $RegistryEntry.Path

        if ($RegistryPath.PSObject.Properties.Name -contains "$($RegistryEntry.Name)")
        {
            $Results.Add($ResultName, $(Get-ItemPropertyValue -Path $RegistryEntry.Path -Name $RegistryEntry.Name))
        }
        else
        {
            Write-Verbose "- Registry entry '$ResultName' was not found on the system"
            $Results.Add($ResultName, "Not found")
        }
    }

    $Results
}

function Get-WindaubeFirewallRules
{
    Write-Verbose "Getting firewall rules"
    Get-NetFirewallRule | Select-Object -Property Name, DisplayName, DisplayGroup, Enabled, Profile, Direction, Action
}

function Get-WindaubeInstalledSoftwares
{
    Write-Verbose "Getting installed softwares"

    $InstalledSoftwares = @()
    
    foreach ($InstalledSoftware in Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate)
    {
        if ([String]::IsNullOrEmpty($InstalledSoftware.DisplayName))
        {
            continue
        }
    }

    foreach ($InstalledSoftware in Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate)
    {
        if ([String]::IsNullOrEmpty($InstalledSoftware.DisplayName))
        {
            continue
        }

        if (-not ($($InstalledSoftwares | Select-Object -ExpandProperty DisplayName) -contains $InstalledSoftware.DisplayName))
        {
            $InstalledSoftwares += $InstalledSoftware
        }
    }

    $InstalledSoftwares
}

function Get-WindaubeNetworkInterfaces
{
    Write-Verbose "Getting network interfaces"
    Get-WMIObject Win32_NetworkAdapter -NameSpace "root\CIMV2" -ErrorAction SilentlyContinue | Select-Object -Property NetEnabled, Name, ServiceName, MacAddress, AdapterType
}