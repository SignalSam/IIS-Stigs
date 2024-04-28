# STIG Check Information
<#
Group Title:
    SRG-APP-000223-WSR-000145

Rule Title:
    The IIS 10.0 web server must accept only system-generated session identifiers.

Discussion:
    ASP.NET provides a session state, which is available as the HttpSessionState class,
    as a method of storing session-specific information that is visible only within the
    session. ASP.NET session state identifies requests from the same browser during a
    limited time window as a session and provides the ability to persist variable values
    for the duration of that session.

    When using the URI mode for cookie settings under session state, IIS will reject and
    reissue session IDs that do not have active sessions. Configuring IIS to expire session
    IDs and regenerate tokens gives a potential attacker less time to capture a cookie and
    gain access to server content.

Check Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Under the "ASP.NET" section, select "Session State".
    Under "Cookie Settings", verify the "Use Cookies" mode is selected from the "Mode:" drop-down list.
    Under "Time-out (in minutes)", verify a maximum of 20 minutes is entered.
    If the "Use Cookies" mode is selected and Time-out (in minutes) is configured for "20 minutes" (or less), this is not a finding.

Alternative method:
    Click the site name.
    Select "Configuration Editor" under the "Management" section.
    From the "Section:" drop-down list at the top of the configuration editor, locate "system.web/sessionState".
    Verify the "cookieless" is set to "UseCookies".
    If the "cookieless" is not set to "UseCookies", this is a finding.

    Note: If IIS 10.0 server/site is used only for system-to-system maintenance, does not
    allow users to connect to interface, and is restricted to specific system IPs, this is Not Applicable.

Fix Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Under the "ASP.NET" section, select "Session State".
    Under "Cookie Settings", select the "Use Cookies" mode from the "Mode:" drop-down list.
    Under "Time-out (in minutes)", enter a value of "20 or less".
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Checks if "ASP.NET > Session State > Cookie Settings > Mode" is set to "Use Cookies".
* Checks if "ASP.NET > Session State > Cookie Settings > Time-out (in-minutes)" is set to 20 or less.
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

If ((Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.web/sessionState" -Name timeout).Value.TotalMinutes -GT 20)
    { $CheckCompliant = $False }

Write-Output $CheckCompliant
