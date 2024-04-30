# STIG Check Information
<#
Group Title:
    SRG-APP-000516-WSR-000174

Rule Title:
    The IIS 10.0 web server must have a global authorization rule configured to restrict access.

Discussion:
    Authorization rules can be configured at the server, website, folder (including Virtual Directories),
    or file level. It is recommended that URL Authorization be configured to only grant access to the
    necessary security principals. Configuring a global Authorization rule that restricts access ensures
    inheritance of the settings down through the hierarchy of web directories. This will ensure access
    to current and future content is only granted to the appropriate principals, mitigating risk of
    unauthorized access.

Check Text:
    Note: If ASP.NET is not installed, this is Not Applicable.
    Note: If the Server is hosting Microsoft SharePoint, this is Not Applicable.
    Note: If the server is hosting WSUS, this is Not Applicable.
    Note: If the server is hosting Exchange, this is Not Applicable.
    Note: If the server is public facing, this is Not Applicable.

    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Double-click the ".NET Authorization Rules" icon.
    Ensure "All Users" is set to "Allow", and "Anonymous Users" is set to "Deny", otherwise this is a finding.
    If any other rules are present, this is a finding.

Fix Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Double-click the ".NET Authorization Rules" icon.
    Alter the list as necessary to ensure "All Users" is set to "Allow" and "Anonymous Users" is set to "Deny".
    Remove any other line items.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Check if rules exists for: "All Users" is set to "Allow".
* Check if rules exists for: "Anonymous Users" is set to "Deny".
This check is done per server.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>


Set-PSDebug -Strict
$ErrorActionPreference = 'Stop'

# Script variable to track overall compliance.
[Boolean] $CheckCompliant = $True

# Script variables to track rule discovery.
[Boolean] $AllUsersAllowFound = $False
[Boolean] $AllAnonymousUsersDenyFound = $False

Try
{
    [System.Collections.Generic.List[Microsoft.IIs.PowerShell.Framework.ConfigurationElement]] $AuthorizationRules = `
        Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.web/authorization" -Name collection
    If ($AuthorizationRules.Count -NE 2)
        { $CheckCompliant = $False }
    ForEach ($AuthorizationRule In $AuthorizationRules)
    {
        If (($AuthorizationRule.users -EQ '*') -AND ($AuthorizationRule.ElementTagName -EQ 'allow'))
            { $AllUsersAllowFound = $True }

        If (($AuthorizationRule.users -EQ '?') -AND ($AuthorizationRule.ElementTagName -EQ 'deny'))
            { $AllAnonymousUsersDenyFound = $True } 
    }

    If (-NOT (($AllUsersAllowFound) -AND ($AllAnonymousUsersDenyFound)))
        { $CheckCompliant = $False }
}
Catch
    { $Host.SetShouldExit(1) }

Write-Output $CheckCompliant