# STIG Check Information
<#
Group Title:
    SRG-APP-000251-WSR-000157

Rule Title:
    Directory Browsing on the IIS 10.0 web server must be disabled.

Discussion:
    Directory browsing allows the contents of a directory to be displayed upon
    request from a web client. If directory browsing is enabled for a directory in
    IIS, users could receive a web page listing the contents of the directory. If
    directory browsing is enabled, the risk of inadvertently disclosing sensitive
    content is increased.

Check Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Double-click the "Directory Browsing" icon.
    Under the “Actions” pane verify "Directory Browsing" is disabled.
    If “Directory Browsing” is not disabled, this is a finding.

Fix Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Double-click the "Directory Browsing" icon.
    Under the "Actions" pane click "Disabled".

    Under the "Actions" pane, click "Apply".
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Checks if "IIS > Directory Browsing" is disabled.
This check is done per server.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>


Set-PSDebug -Strict
$ErrorActionPreference = 'Stop'

# Script variable to track overall compliance.
[Boolean] $CheckCompliant = $True

If ((Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/DirectoryBrowse" -Name enabled) -NE $False)
    { $CheckCompliant = $False }

Write-Output $CheckCompliant
