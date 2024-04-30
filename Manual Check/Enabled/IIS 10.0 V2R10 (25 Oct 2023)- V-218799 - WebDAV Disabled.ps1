# STIG Check Information
<#
Group Title:
    SRG-APP-000141-WSR-000085

Rule Title:
    The IIS 10.0 web server must have Web Distributed Authoring and Versioning (WebDAV) disabled.

Discussion:
    A web server can be installed with functionality that by its nature is not secure. Web Distributed
    Authoring (WebDAV) is an extension to the HTTP protocol which, when developed, was meant to allow
    users to create, change, and move documents on a server, typically a web server or web share. Allowing
    this functionality, development, and deployment is much easier for web authors.

    WebDAV is not widely used and has serious security concerns because it may allow clients to modify
    unauthorized files on the web server.

Check Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Review the features listed under the “IIS" section.
    If the "WebDAV Authoring Rules" icon exists, this is a finding.

Fix Text:
    Access Server Manager on the IIS 10.0 web server.
    Click the IIS 10.0 web server name.
    Click on "Manage".
    Select "Add Roles and Features".
    Click "Next" in the "Before you begin" dialog box.
    Select "Role-based or feature-based installation" on the "Installation Type" dialog box and click "Next".
    Select the IIS 10.0 web server in the "Server Selection" dialog box.
    From the "Windows Features" dialog box, navigate to "World Wide Web Services" >> "Common HTTP Features".

    De-select "WebDAV Publishing", and click "Next" to complete removing the WebDAV Publishing feature from the IIS 10.0 web server.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Checks if WebDAV Publishing is enabled.
This check is done per server.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>


Set-PSDebug -Strict
$ErrorActionPreference = 'Stop'

# Script variable to track overall compliance.
[Boolean] $CheckCompliant = $True

# This is to test the script on a Windows 10/11 system.
#If ((Get-WindowsOptionalFeature -Online -FeatureName IIS-WebDAV).State -NE 'Disabled')
#    { $CheckCompliant = $False }

# This is to test the script on a Windows Server system.
If ((Get-WindowsFeature -Name IIS-WebDAV).InstallState -EQ 'Installed')
    { $CheckCompliant = $False }

Write-Output $CheckCompliant