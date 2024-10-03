<#
.SYNOPSIS
    Gets the Windows security configuration
.DESCRIPTION
    The 'Get-Windaube' cmdlet gets various Windows configurations as a 'PSCustomObject'. Since it can take a long time to get the configuration, it is recommended to store the result in a variable instead of invoking the cmdlet everytime. Once stored, pipe the output of the variable to the `Select-Object` cmdlet with the `ExpandProperty` parameter specified as the desired properties. To export the output of `Get-Windaube` in a JSON file, pipe it to the 'ConvertTo-Json' cmdlet, then pipe it again to the `Out-File` cmdlet with the `Path` parameter specified as the desired location.
.EXAMPLE
    PS :> $Configuration = Get-Windaube
    Stores the result of 'Get-Windaube' cmdlet in the 'Configuration' variable.
.EXAMPLE
    PS :> Get-Windaube.LocalUsers
    Displays local Windows users by requesting the 'LocalUsers' property of 'Get-Windaube' cmdlet result. Available properties are 'AntiVirusProducts', 'AuditPolicies', 'Disks', 'EnvironmentVariables', 'FirewallRules', 'InstalledSoftwares', 'LocalGroups', 'LocalUsers', 'NetworkInterfaces', 'NetworkShares', 'Processes', 'RegistryEntries', 'ScheduledTasks', 'SecurityPolicies', 'Services', 'StartupItems' and 'SystemInfo'.
.EXAMPLE
    PS :> Get-Windaube.Processes | ConvertTo-Csv | Out-File 'Processes.csv'
    Exports the processes gathered by 'Get-Windaube' cmdlet in a CSV format.
.EXAMPLE
    PS :> Get-Windaube | ConvertTo-Json | Out-File 'Configuration.json'
    Exports the result of 'Get-Windaube' cmdlet in a JSON format. It can be imported and analyzed with 'Test-Windaube' later.
.NOTES
    Name: Get-Windaube
    Author: Ky4meru
#>
function Get-Windaube
{
    [CmdletBinding()]
    [OutputType('PSCustomObject')]
    param
    (

    )
    process
    {
        <# TODO: Get rights on services (icacls) #>
        <# TODO: Get rights on critical directories (Get-Acl) #>
        <# TODO: Get IPSec parameters #>
        <# TODO: Get SMB server configuration (Get-SMBServerConfiguration) #>

        [PSCustomObject]@{
            SystemInfo = Get-WindaubeSystemInfo
            LocalUsers = Get-WindaubeLocalUsers
            LocalGroups = Get-WindaubeLocalGroups
            Services = Get-WindaubeServices
            Processes = Get-WindaubeProcesses
            StartupItems = Get-WindaubeStartupItems
            ScheduledTasks = Get-WindaubeScheduledTasks
            AntiVirusProducts = Get-WindaubeAntiVirusProducts
            Disks = Get-WindaubeDisks
            NetworkShares = Get-WindaubeNetworkShares
            SecurityPolicies = Get-WindaubeSecurityPolicies
            EnvironmentVariables = Get-WindaubeEnvironmentVariables
            AppLockerPolicies = Get-WindaubeAppLockerPolicies
            AuditPolicies = Get-WindaubeAuditPolicies
            RegistryEntries = Get-WindaubeRegistryEntries
            FirewallRules = Get-WindaubeFirewallRules
            InstalledSoftwares = Get-WindaubeInstalledSoftwares
            NetworkInterfaces = Get-WindaubeNetworkInterfaces
        }
    }
}