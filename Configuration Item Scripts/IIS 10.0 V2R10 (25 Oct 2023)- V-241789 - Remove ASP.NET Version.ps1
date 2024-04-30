# STIG Check Information
<#
Group Title:
    SRG-APP-000266-WSR-000159

Rule Title:
    ASP.NET version must be removed from the HTTP Response Header information.

Discussion:
    HTTP Response Headers contain information that could enable an attacker to
    gain access to an information system. Failure to prevent the sending of certain
    HTTP Response Header information to remote requesters exposes internal
    configuration information to potential attackers.

Check Text:
    Open the IIS 10.0 Manager.
    Under the "Connections" pane on the left side of the management console, select the IIS 10.0 web server.
    Click the HTTP Response Headers button.
    Click to select the “X-Powered-By” HTTP Header.
    If “X-Powered-By” has not been removed, this is a finding.

Fix Text:
    Open the IIS 10.0 Manager.
    Under the "Connections" pane on the left side of the management console, select the IIS 10.0 web server.
    Click the HTTP Response Headers button.
    Click to select the “X-Powered-By” HTTP Header.
    Click “Remove” in the Actions Panel.
    Note: This can be performed multiple ways, this is an example.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Check if the “X-Powered-By” HTTP Header has been removed.
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
    [System.Collections.Generic.List[PSObject]] $CustomHeaders = `
        (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/httpProtocol" -Name customHeaders).collection

    ForEach ($CustomHeader In $CustomHeaders)
    {
        If ($CustomHeader.name -EQ 'X-Powered-By')
            { $CheckCompliant = $False }
    }
}
Catch
    { write-host 'ouch' } #$Host.SetShouldExit(1) }

Write-Output $CheckCompliant