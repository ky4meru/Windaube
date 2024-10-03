# Windaube :stethoscope:

> **Daube */dob/***
> 
> In french slang, the word *daube* is used to describe something of poor quality.

*Windaube* is a PowerShell module that automatically extracts and audits Windows configuration based on security best practices. Mostly, it takes sources from:
* [CIS Benchmarks](https://downloads.cisecurity.org/#/)
* [Microsoft Documentation](https://learn.microsoft.com/en-us/windows/security/)

## Usage

### TL;DR

From an elevated PowerShell prompt, get Windows configuration and test it. Simply as that.

```powershell
Import-Module ./Windaube.psm1
Get-Windaube | Test-Windaube
```

### Get-Windaube

The cmdlet `Get-Windaube` returns a `PSCustomObject` representing Windows configuration.

```powershell
# Store Windows configuration.
$Configuration = Get-Windaube

# Display local users.
$Configuration.LocalUsers

# Export processes in a CSV file.
$Configuration.Processes | ConvertTo-Csv | Out-File "Path\To\File.csv"

# Export Windows configuration in a JSON file.
$Configuration | ConvertTo-Json | Out-File "Path\To\File.json"
```

### Test-Windaube

The cmdlet `Test-Windaube` returns a `Collection` of `PSCustomObject` representing the results of the tests on the Windows configuration provided as input.

```powershell
# Import Windows configuration from a previously exported JSON file and test it.
$Results = Get-Content "Path\To\File.json" | ConvertFrom-Json | Test-Windaube

# Get all results sorted by status, in a table format.
$Results | Sort-Object -Property Status | Format-Table

# Get results from the 'Accounts' category only, in a table format.
$Results | Where-Object { $_.Category -eq "Accounts" } | Format-Table

# Get control names, associated rational and status only, in a table format.
$Results | Select-Object -Property Name, Rational, Status | Format-Table

# Export results in a CSV file.
$Results | ConvertTo-Csv | Out-File "Path\To\File.csv"
```

## License

See [LICENSE](./LICENSE) file.
