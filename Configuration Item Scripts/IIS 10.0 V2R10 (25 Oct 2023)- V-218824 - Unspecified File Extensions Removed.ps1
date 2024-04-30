# STIG Check Information
<#
Group Title:
    SRG-APP-000516-WSR-000174

Rule Title:
    Unspecified file extensions on a production IIS 10.0 web server must be removed.

Discussion:
    By allowing unspecified file extensions to execute, the web servers attack surface
    is significantly increased. This increased risk can be reduced by only allowing
    specific ISAPI extensions or CGI extensions to run on the web server.

Check Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Double-click the "ISAPI and CGI restrictions" icon.
    Click “Edit Feature Settings".
    Verify the "Allow unspecified CGI modules" and the "Allow unspecified ISAPI modules" check boxes are NOT checked.
    If either or both of the "Allow unspecified CGI modules" and the "Allow unspecified ISAPI modules" check boxes are checked, this is a finding.

Fix Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Double-click the "ISAPI and CGI restrictions" icon.
    Click "Edit Feature Settings".
    Remove the check from the "Allow unspecified CGI modules" and the "Allow unspecified ISAPI modules" check boxes.
    Click "OK".
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Check if "Allow unspecified CGI modules" is enabled.
* Check if "Allow unspecified ISAPI modules" is enabled.
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
    If ((Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/isapiCgiRestriction" -Name notListedCgisAllowed).Value)
        { $CheckCompliant = $False }
    If ((Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/security/isapiCgiRestriction" -Name notListedIsapisAllowed).Value)
        { $CheckCompliant = $False }
}
Catch
    { $Host.SetShouldExit(1) }

Write-Output $CheckCompliant