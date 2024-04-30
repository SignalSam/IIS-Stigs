# STIG Check Information
<#
Group Title:
    SRG-APP-000231-WSR-000144

Rule Title:
    The production IIS 10.0 web server must utilize SHA2 encryption for the Machine Key.

Discussion:
    The Machine Key element of the ASP.NET web.config specifies the algorithm and keys
    that ASP.NET will use for encryption. The Machine Key feature can be managed to specify
    hashing and encryption settings for application services such as view state, forms
    authentication, membership and roles, and anonymous identification. Ensuring a strong
    encryption method can mitigate the risk of data tampering in crucial functional areas
    such as forms authentication cookies, or view state.

Check Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Double-click the "Machine Key" icon in the website Home Pane.
    Verify "HMACSHA256" or stronger encryption is selected for the Validation method and "Auto" is selected for the Encryption method.
    If "HMACSHA256" or stronger encryption is not selected for the Validation method and/or "Auto" is not selected for the Encryption method, this is a finding.
    If .NET is not installed, this is Not Applicable.

Fix Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Double-click the "Machine Key" icon in the web server Home Pane.
    Set the Validation method to "HMACSHA256" or stronger.
    Set the Encryption method to "Auto".

    Click "Apply" in the "Actions" pane.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Checks if "ASP.NET > Machine Key > Validation method" is set to "HMACSHA256", "HMACSHA384", or "HMACSHA512".
* Checks if "ASP.NET > Machine Key > Encryption method" is set to "Auto".
This check is done per server.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>


Set-PSDebug -Strict
$ErrorActionPreference = 'Stop'

# Script variable to track overall compliance.
[Boolean] $CheckCompliant = $True

If ((Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.web/machineKey" -Name validation) -NOTLIKE 'HMACSHA*')
    { $CheckCompliant = $False }

If ((Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.web/machineKey" -Name decryption).Value -NE 'Auto')
    { $CheckCompliant = $False }

Write-Output $CheckCompliant