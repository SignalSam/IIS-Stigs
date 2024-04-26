# STIG Check Information
<#
Group Title:
    SRG-APP-000141-WSR-000077

Rule Title:
    All IIS 10.0 web server sample code, example applications, and tutorials must be removed
    from a production IIS 10.0 server.

Discussion:
    Web server documentation, sample code, example applications, and tutorials may be an
    exploitable threat to a web server. A production web server may only contain components that
    are operationally necessary (i.e., compiled code, scripts, web content, etc.). Delete all
    directories containing samples and any scripts used to execute the samples.

Check Text: Navigate to the following folders:

inetpub\
Program Files\Common Files\System\msadc
Program Files (x86)\Common Files\System\msadc

If the folder or sub-folders contain any executable sample code, example applications, or tutorials which are not explicitly used by a production website, this is a finding.

Fix Text: Remove any executable sample code, example applications, or tutorials which are not explicitly used by a production website.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Checks if there are any items in the default MSADC directories.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>

Set-PSDebug -Strict
$ErrorActionPreference = 'Stop'

# Script variable to track overall compliance.
[Boolean] $CheckCompliant = $True

Try
{
    [System.Collections.Generic.List[System.Object]] $ItemsFound = Get-ChildItem -Path "$($env:CommonProgramFiles)\System\msadc" -Attributes !Directory -Recurse
    If ($ItemsFound.Count -GT 0)
        { $CheckCompliant = $False }

    $ItemsFound = Get-ChildItem -Path "$(${env:CommonProgramFiles(x86)})\System\msadc"  -Attributes !Directory -Recurse
    If ($ItemsFound.Count -GT 0)
        { $CheckCompliant = $False }
}
Catch
    { $Host.SetShouldExit(1) }

Write-Output $CheckCompliant