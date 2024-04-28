# STIG Check Information
<#
Group Title:
    SRG-APP-000266-WSR-000159

Rule Title:
    Warning and error messages displayed to clients must be modified to minimize the identity
    of the IIS 10.0 web server, patches, loaded modules, and directory paths.

Discussion:
    HTTP error pages contain information that could enable an attacker to gain access to an
    information system. Failure to prevent the sending of HTTP error pages with full information
    to remote requesters exposes internal configuration information to potential attackers.

Check Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Double-click the "Error Pages" icon.
    Click any error message, and then click "Edit Feature Setting" from the "Actions" Pane. This will apply to all error messages.
    If the feature setting is not set to "Detailed errors for local requests and custom error pages for remote requests", or "Custom error pages"  this is a finding.

Fix Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Double-click the "Error Pages" icon.
    Click any error message, and then click "Edit Feature Setting" from the "Actions" Pane. This will apply to all error messages.
    Set Feature Setting to "Detailed errors for local requests and custom error pages for remote requests" or "Custom error pages".
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Checks if "IIS > Error Pages> Feature Settings..." is set to "Detailed errors for local requests and custom error pages for remote requests" or "Custom error pages".
This check is done per server.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>


Set-PSDebug -Strict
$ErrorActionPreference = 'Stop'

# Script variable to track overall compliance.
[Boolean] $CheckCompliant = $True

If ((Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/httpErrors" -Name errorMode) -EQ 'Detailed')
    { $CheckCompliant = $False }

Write-Output $CheckCompliant
