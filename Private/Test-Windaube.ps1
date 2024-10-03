function Get-WindaubeValueOrNotFound
{
    param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $Expression
    )
    process
    {
        $Value = Invoke-Expression $Expression

        if ([String]::IsNullOrEmpty($Value))
        {
            $Value = "Not found"
        }

        $Value
    }
}

function ConvertTo-GigaBits
{
    param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $Bits
    )
    process
    {
        $Value = [System.Convert]::ToInt64($Bits)
        [Math]::Round($Value / 1000000000, 2)
    }
}

function Test-WindaubeIsPartOfDomain
{
    [OutputType('Bool')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [PSObject]
        $Configuration
    )
    process
    {
        -not (Test-WindaubeIsWorkgroup $Configuration)
    }
}

function Test-WindaubeIsWorkgroup
{
    [OutputType('Bool')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [PSObject]
        $Configuration
    )
    process
    {
        $($Configuration.SystemInfo | Where-Object { $_.Name -eq 'CSDomain' } | Select-Object -ExpandProperty 'Value') -eq "WORKGROUP"
    }
}

function Test-WindaubeIsWorkstation
{
    [OutputType('Bool')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [PSObject]
        $Configuration
    )
    process
    {
        -not $(Test-WindaubeIsServer $Configuration)
    }
}

function Test-WindaubeIsServer
{
    [OutputType('Bool')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [PSObject]
        $Configuration
    )
    process
    {
        $($Configuration.SystemInfo | Where-Object { $_.Name -eq 'OsProductType' } | Select-Object -ExpandProperty 'Value') -gt 1
    }
}

function Test-WindaubeCondition
{
    [OutputType('Bool')]
    param
    (
        [Parameter(Position = 0, Mandatory = $true)]
        [PSObject]
        $Configuration,

        [Parameter(Position = 1, Mandatory = $true)]
        [String]
        $Condition
    )
    process
    {
        $Result = $(Test-WindaubeIsWorkgroup $Configuration) -and $($Condition -eq 'Workgroup')
        $Result = $Result -or ($(Test-WindaubeIsPartOfDomain $Configuration) -and $($Condition -eq 'Domain'))
        $Result = $Result -or ($(Test-WindaubeIsServer $Configuration) -and $($Condition -eq 'Server'))
        $Result = $Result -or ($(Test-WindaubeIsWorkstation $Configuration) -and $($Condition -eq 'Workstation'))
        $Result
    }
}