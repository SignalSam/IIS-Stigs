# STIG Check Information
<#
Group Title:
    SRG-APP-000223-WSR-000011

Rule Title:
    The IIS 10.0 web server must use cookies to track session state.

Discussion:
    Cookies are used to exchange data between the web server and the client. Cookies,
    such as a session cookie, may contain session information and user credentials used
    to maintain a persistent connection between the user and the hosted application
    since HTTP/HTTPS is a stateless protocol.

    Using URI will embed the session ID as a query string in the Uniform Resource Identifier
    (URI) request and then the URI is redirected to the originally requested URL. The changed
    URI request is used for the duration of the session, so no cookie is necessary.

    By requiring expired session IDs to be regenerated while using URI, potential attackers
    have less time to capture a cookie and gain access to the Web server content.

Satisfies:
    SRG-APP-000223-WSR-000011, SRG-APP-000220-WSR-000201

Check Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Under "ASP.Net", double-click the "Session State" icon.
    Under "Cookie Settings", verify the "Mode" has "Use Cookies" selected from the drop-down list.
    If the "Cookie Settings" "Mode" is not set to "Use Cookies", this is a finding.

Alternative method:
    Click the site name.
    Select "Configuration Editor" under the "Management" section.
    From the "Section:" drop-down list at the top of the configuration editor, locate "system.web/sessionState".
    Verify the "cookieless" is set to "UseCookies".
    If the "cookieless" is not set to "UseCookies", this is a finding.

    Note: If IIS 10.0 server/site is used only for system-to-system maintenance, does not allow users to connect to interface, and is restricted to specific system IPs, this is Not Applicable.

Fix Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Under "ASP.Net", double-click the "Session State" icon.
    Under "Cookie Settings", select "Use Cookies” from the "Mode" drop-down list.

    Click "Apply" in the "Actions" pane.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Checks if "ASP.NET > Session State > Cookie Settings > Mode" is set to "Use Cookies".
This check is done per server.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>


Set-PSDebug -Strict
$ErrorActionPreference = 'Stop'

# Script variable to track overall compliance.
[Boolean] $CheckCompliant = $True

If ((Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.web/sessionState" -Name cookieless) -NE 'UseCookies')
    { $CheckCompliant = $False }

Write-Output $CheckCompliant