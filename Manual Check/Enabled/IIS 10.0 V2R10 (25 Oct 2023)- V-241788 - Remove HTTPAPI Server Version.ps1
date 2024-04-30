# STIG Check Information
<#
Group Title:
    SRG-APP-000266-WSR-000159

Rule Title:
    HTTPAPI Server version must be removed from the HTTP Response Header information.

Discussion:
    HTTP Response Headers contain information that could enable an attacker to gain access
    to an information system. Failure to prevent the sending of certain HTTP Response Header
    information to remote requesters exposes internal configuration information to potential
    attackers.

Check Text:
    Open Registry Editor.
    Navigate to “HKLM\System\CurrentControlSet\Services\HTTP\Parameters”
    Verify “DisableServerHeader” is set to “1”.
    If REG_DWORD DisableServerHeader is not set to 1, this is a finding.
    If the System Administrator can show that Server Version information has been removed via other means, such as using a rewrite outbound rule, this is not a finding.

Fix Text:
    Navigate to “HKLM\System\CurrentControlSet\Services\HTTP\Parameters”.
    Create REG_DWORD “DisableServerHeader” and set it to “1”.
    Note: This can be performed multiple ways, this is an example.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Check if “DisableServerHeader” is set to “1”.
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
    If (-NOT ((Get-ItemPropertyValue -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\HTTP\Parameters\' -Name DisableServerHeader) -EQ 1))
        { $CheckCompliant = $False }
}
Catch
    { $CheckCompliant = $False }

Write-Output $CheckCompliant