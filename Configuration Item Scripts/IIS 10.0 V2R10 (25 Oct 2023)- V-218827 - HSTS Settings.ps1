# STIG Check Information
<#
Group Title:
    SRG-APP-000516-WSR-000174

Rule Title:
    The IIS 10.0 web server must enable HTTP Strict Transport Security (HSTS).

Discussion:
    HTTP Strict Transport Security (HSTS) ensures browsers always connect to a website over
    TLS. HSTS exists to remove the need for redirection configurations. HSTS relies on the
    browser, web server, and a public "Allowlist". If the browser does not support HSTS,
    it will be ignored.

Check Text:
    Access the IIS 10.0 Web Server.
    Open IIS Manager.
    Click the IIS 10.0 web server name.
    Open on Configuration Editor under Management.
    For the Section, navigate to system.applicationHost/sites.
    Expand siteDefaults and HSTS.
    If enabled is not set to True, this is a finding.
    If includeSubDomains is not set to True, this is a finding.
    If max-age is not set to a value greater than 0, this is a finding.
    If redirectHttpToHttps is not True, this is a finding.
    If the website is behind a load balancer or proxy server, and HSTS enablement is handled there, this is Not Applicable.
    If the version of Windows Server does not natively support HSTS, this is not a finding.

Fix Text:
    Using the Configuration Editor in the IIS Manager or Powershell:
    Enable HSTS.
    Set includeSubDomains to True.
    Set max-age to a value greater than 0.
    Set redirectHttpToHttps to True.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Check if HSTS settings are what the check expects.
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
    [Microsoft.IIs.PowerShell.Framework.ConfigurationElement] $HSTSConfiguration = `
        (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.applicationHost/sites" -Name siteDefaults).hsts
    If (($HSTSConfiguration.enabled -NE $True) -OR `
        ($HSTSConfiguration.includeSubDomains -NE $True) -OR `
        ($HSTSConfiguration.'max-age' -EQ 0) -OR `
        ($HSTSConfiguration.redirectHttpToHttps -NE $True))
        { $CheckCompliant = $False }
}
Catch
    { $Host.SetShouldExit(1) }

Write-Output $CheckCompliant