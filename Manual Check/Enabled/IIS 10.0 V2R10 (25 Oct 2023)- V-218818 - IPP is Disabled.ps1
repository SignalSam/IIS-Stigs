# STIG Check Information
<#
Group Title:
    SRG-APP-000383-WSR-000175

Rule Title:
    The Internet Printing Protocol (IPP) must be disabled on the IIS 10.0 web server.

Discussion:
    The use of IPP on an IIS web server allows client access to shared printers. This
    privileged access could allow remote code execution by increasing the web servers
    attack surface. Additionally, since IPP does not support SSL, it is considered a
    risk and will not be deployed.

Check Text:
    If the Print Services role and the Internet Printing role are not installed, this check is Not Applicable.
    Navigate to the following directory:
        %windir%\web\printers
    If this folder exists, this is a finding.

    Determine whether Internet Printing is enabled:
    Click “Start”, click “Administrative Tools”, and then click “Server Manager”.
    Expand the roles node, right-click “Print Services”, and then select “Remove Roles Services”.
    If the Internet Printing option is enabled, this is a finding.

Fix Text:
    Click “Start”, click “Administrative Tools”, and then click “Server Manager”.
    Expand the roles node, right-click “Print Services”, and then select “Remove Roles Services”.
    If the Internet Printing option is checked, clear the check box, click “Next”, and then click “Remove” to complete the wizard.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Check if Print Services is enabled.
* Check if Internet Printing is enabled.
This check is done per server.

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
    If ((Test-Path -Path "$env:SystemRoot\Web\Printers"))
        { $CheckCompliant = $False }

    # This is to test the script on a Windows 10/11 system.
    #If ((Get-WindowsOptionalFeature -Online -FeatureName Printing-Foundation-InternetPrinting-Client).State -NE 'Disabled')
    #    { $CheckCompliant = $False }

    # This is to test the script on a Windows Server system.
    If (((Get-WindowsFeature -Name Print-Internet).InstallState -EQ 'Installed') -OR `
        ((Get-WindowsFeature -Name Internet-Print-Client).InstallState -EQ 'Installed'))
        { $CheckCompliant = $False }
}
Catch
    { $Host.SetShouldExit(1) }

Write-Output $CheckCompliant