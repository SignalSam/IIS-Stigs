# STIG Check Information
<#
Group Title:
    SRG-APP-000439-WSR-000152

Rule Title:
    IIS 10.0 web server session IDs must be sent to the client using TLS.

Discussion:
    The HTTP protocol is a stateless protocol. To maintain a session, a session
    identifier is used. The session identifier is a piece of data used to identify
    a session and a user. If the session identifier is compromised by an attacker,
    the session can be hijacked. By encrypting the session identifier, the identifier
    becomes more difficult for an attacker to hijack, decrypt, and use before the
    session has expired.

Check Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Under the "Management" section, double-click the "Configuration Editor" icon.
    From the "Section:" drop-down list, select "system.webServer/asp".
    Expand the "session" section.
    Verify the "keepSessionIdSecure" is set to "True".
    If the "keepSessionIdSecure" is not set to "True", this is a finding.

Fix Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Under "Management" section, double-click the "Configuration Editor" icon.
    From the "Section:" drop-down list, select "system.webServer/asp".
    Expand the "session" section.
    Select "True" for the "keepSessionIdSecure" setting.
    Select "Apply" from the "Actions" pane.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Check if "keepSessionIdSecure" is set to "True".
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
    If ((Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/asp" -Name session).keepSessionIdSecure -NE $True)
        { $CheckCompliant = $False }
}
Catch
    { $Host.SetShouldExit(1) }

Write-Output $CheckCompliant