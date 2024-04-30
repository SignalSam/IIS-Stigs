# STIG Check Information
<#
Group Title:
    SRG-APP-000141-WSR-000076

Rule Title:
    The IIS 10.0 web server must not be both a website server and a proxy server.

Discussion:
    A web server should be primarily a web server or a proxy server but not both,
    for the same reasons that other multi-use servers are not recommended. Scanning
    for web servers that also proxy requests into an otherwise protected network is
    a common attack, making the attack anonymous.

Check Text:
    Open the IIS 10.0 Manager.
    Under the "Connections" pane on the left side of the management console, select the IIS 10.0 web server.
    If, under the IIS installed features "Application Request Routing Cache" is not present, this is not a finding.
    If, under the IIS installed features "Application Request Routing Cache" is present, double-click the icon to open the feature.
    From the right "Actions" pane under "Proxy", select "Server Proxy Settings...".
    In the "Application Request Routing" settings window, verify whether "Enable proxy" is selected.
    If "Enable proxy" is selected under the "Application Request Routing" settings, this is a finding.

    If the server has been approved to be a Proxy server, this requirement is Not Applicable.

Fix Text:
    Open the IIS 10.0 Manager.
    Under the "Connections" pane on the left side of the management console, select the IIS 10.0 web server.
    Under the IIS installed features, if "Application Request Routing Cache" is present, double-click the icon to open the feature.
    From the right "Actions" pane, under "Proxy", select "Server Proxy Settings...".
    In the "Application Request Routing" settings window, remove the check from the "Enable proxy" check box.

    Click "Apply" in the "Actions" pane.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Checks if the ARR proxy is installed, if so if it is enabled.
This check is done per server.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>

Function Get-IISAppRequestRoutingConfig
{
    # Function variable for desired state.
    [String] $ProxyEnabled = 'false'

    $ErrorActionPreference = 'Stop'
    Try
        { [Microsoft.IIs.PowerShell.Framework.ConfigurationSection] $ProxySection = Get-IISConfigSection -SectionPath 'system.webServer/proxy' }
    Catch
        { Return $True }
    $ErrorActionPreference = 'Continue'

    If ($ProxySection.GetAttributeValue('enabled') -NE $ProxyEnabled)
        { Return $True }
    Else
        { Return $False }
}

Set-PSDebug -Strict
$ErrorActionPreference = 'Stop'

# Script variable to track overall compliance.
[Boolean] $CheckCompliant = $True

If (-NOT (Get-IISAppRequestRoutingConfig))
    { $CheckCompliant = $False }

Write-Output $CheckCompliant