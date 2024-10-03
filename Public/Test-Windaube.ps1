<#
.SYNOPSIS
    Tests the Windows security configuration
.DESCRIPTION
    The 'Test-Windaube' cmdlet analyzes the result of 'Get-Windaube' cmdlet based on various tests from CIS Benchmarks and Microsoft official documentation. It returns a 'Collection' of 'PSCustomObject' representing the results of the tests on the Windows configuration provided as input.
.EXAMPLE
    PS :> $Results = Get-Content "Path\To\File.json" | ConvertFrom-Json | Test-Windaube
    Imports a previously saved Windows configuration as JSON and analyzes it with the 'Test-Windaube' cmdlet. Finally, stores the results of the analysis in the 'Results' variable.
.EXAMPLE
    PS :> $Results | Sort-Object -Property Status | Format-Table
    Gets all results sorted by their 'Status', in a table format.
.EXAMPLE
    PS :> $Results | Where-Object { $_.Category -eq "Accounts" } | Format-Table
    Gets all results from the 'Accounts' category only, in a table format.
.EXAMPLE
    PS :> $Results | Select-Object -Property Name, Rational, Status | Format-Table
    Gets control names, associated rationale and status only, in a table format.
.EXAMPLE
    PS :> $Results | ConvertTo-Csv | Out-File "Results.csv"
    Exports results of 'Test-Windaube' cmdlet in a CSV file.
.NOTES
    Name: Test-Windaube
    Author: Ky4meru
#>
function Test-Windaube
{
    [CmdletBinding()]
    [OutputType('Collection')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true, ValueFromPipeline = $true)]
        [PSObject]
        $Configuration
    )
    process
    {
        $Tests = @()

        foreach ($RegistryEntry in $RegistryEntries)
        {
            if ($(-not [String]::IsNullOrEmpty($RegistryEntry.Condition)) -and -not $(Test-WindaubeCondition $Configuration $RegistryEntry.Condition))
            {
                Write-Verbose "$($RegistryEntry.Description) was skipped because the configuration does not meet the test condition"
                continue
            }

            $Value = Get-WindaubeValueOrNotFound('$Configuration.RegistryEntries."$($RegistryEntry.Path):$($RegistryEntry.Name)"')

            if ($Value -eq "Not found")
            {
                $StatusExpression = '$RegistryEntry.Expected.ToString().Contains("not found")'
            }
            else
            {
                $StatusExpression = [String]::Format("$($RegistryEntry.Control)", $Configuration.RegistryEntries."$($RegistryEntry.Path):$($RegistryEntry.Name)")
            }

            $Tests += [PSCustomObject]@{
                Category = $RegistryEntry.Category
                Name = $RegistryEntry.Description
                Rationale = $RegistryEntry.Rationale
                Control = "$($RegistryEntry.Path):$($RegistryEntry.Name)";
                Expected = $RegistryEntry.Expected;
                Value = $Value
                Status = Invoke-Expression $StatusExpression
            }
        }

        foreach ($AuditPolicy in $AuditPolicies)
        {
            $Tests += [PSCustomObject]@{
                Category = "Audit Policies"
                Name = "Ensure '$($AuditPolicy.Name)' is set to at least '$($AuditPolicy.Expected)'"
                Rationale = "May be useful when investigating a security incident"
                Control = "Audit policy '$($AuditPolicy.Name)'"
                Expected = $AuditPolicy.Expected
                Value = Get-WindaubeValueOrNotFound('$Configuration.AuditPolicies."$($AuditPolicy.Name)"')
                Status = $Configuration.AuditPolicies."$($AuditPolicy.Name)" -match "$($AuditPolicy.Expected)*"
            }
        }

        foreach ($Disk in $Configuration.Disks)
        {
            $MinimumFreeSpace = [Math]::Round($(ConvertTo-GigaBits($Disk.Size)) / 10, 2)

            $Tests += [PSCustomObject]@{
                Category = "Mass Storage"
                Name = "Ensure '$($Disk.DeviceID)' has at least 10% of available free space"
                Rationale = "Prevent unexpected behavior because of a lack of disk space"
                Control = "Disk '$($Disk.DeviceID)'"
                Expected = "$MinimumFreeSpace Gbits or more"
                Value = "$(ConvertTo-GigaBits($Disk.FreeSpace)) Gbits"
                Status = $Disk.FreeSpace -ge $MinimumFreeSpace
            }
        }

        foreach ($SecurityPolicy in $SecurityPolicies)
        {
            $Value = Get-WindaubeValueOrNotFound('$Configuration.SecurityPolicies."$($SecurityPolicy.Name)"')

            if ($Value -eq "Not found")
            {
                $StatusExpression = '$SecurityPolicy.Expected.ToString().Contains("not found")'
            }
            else
            {
                $StatusExpression = [String]::Format("$($SecurityPolicy.Control)", $Configuration.SecurityPolicies."$($SecurityPolicy.Name)")
            }  

            $Tests += [PSCustomObject]@{
                Category = $SecurityPolicy.Category
                Name = $SecurityPolicy.Description
                Rationale = $SecurityPolicy.Rationale
                Control = "Security policy '$($SecurityPolicy.Name)'";
                Expected = $SecurityPolicy.Expected;
                Value = $Configuration.SecurityPolicies."$($SecurityPolicy.Name)"
                Status = Invoke-Expression $StatusExpression
            }
        }

        $Tests | Sort-Object -Property 'Category'
    }
}