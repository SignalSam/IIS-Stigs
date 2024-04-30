# STIG Check Information
<#
Group Title:
    SRG-APP-000001-WSR-000001

Rule Title:
    The IIS 10.0 websites MaxConnections setting must be configured to limit the number of allowed simultaneous session requests.

Discussion:
    Resource exhaustion can occur when an unlimited number of concurrent requests are
    allowed on a website, facilitating a Denial of Service (DoS) attack. Mitigating this
    kind of attack will include limiting the number of concurrent HTTP/HTTPS requests
    per IP address and may include, where feasible, limiting parameter values associated
    with keepalive (i.e., a parameter used to limit the amount of time a connection may be inactive).

Check Text:
    Access the IIS 10.0 IIS Manager.
    Click the IIS 10.0 server.
    Select "Configuration Editor" under the "Management" section.
    From the "Section:" drop-down list at the top of the configuration editor, locate "system.applicationHost/sites".
    Expand "siteDefaults".
    Expand "limits".
    Review the results and verify the value is greater than zero for the "maxconnections" parameter.
    If the maxconnections parameter is set to zero, this is a finding.

Fix Text:
    Access the IIS 10.0 IIS Manager.
    Click the IIS 10.0 server.
    Select "Configuration Editor" under the "Management" section.
    From the "Section:" drop-down list at the top of the configuration editor, locate "system.applicationHost/sites".
    Expand "siteDefaults".
    Expand "limits".
    Set the "maxconnections" parameter to a value greater than zero.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Check if maxConnections is greater than 0.
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
    If ((Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter 'system.applicationHost/sites' -Name siteDefaults).limits.maxConnections -EQ 0)
        { $CheckCompliant = $False }
}
Catch
    { $Host.SetShouldExit(1) }

Write-Output $CheckCompliant