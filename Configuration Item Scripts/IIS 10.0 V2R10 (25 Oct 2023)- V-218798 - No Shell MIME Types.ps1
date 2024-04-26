# STIG Check Information
<#
Group Title:
    SRG-APP-000141-WSR-000081

Rule Title:
    The IIS 10.0 web server must have Multipurpose Internet Mail Extensions (MIME) that
    invoke OS shell programs disabled.

Discussion:
    Controlling what a user of a hosted application can access is part of the security
    posture of the web server. Any time a user can access more functionality than is needed
    for the operation of the hosted application poses a security issue. A user with too
    much access can view information that is not needed for the user's job role, or the user
    could use the function in an unintentional manner.

    A MIME tells the web server the type of program, various file types, and extensions and what
    external utilities or programs are needed to execute the file type.

    A shell is a program that serves as the basic interface between the user and the operating
    system to ensure hosted application users do not have access to these programs. Shell
    programs may execute shell escapes and can perform unauthorized activities that could damage
    the security posture of the web server.

Check Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Under IIS, double-click the "MIME Types" icon.
    From the "Group by:" drop-down list, select "Content Type".
    From the list of extensions under "Application", verify MIME types for OS shell program
    extensions have been removed, to include at a minimum, the following extensions:
        .exe
        .dll
        .com
        .bat
        .csh

    If any OS shell MIME types are configured, this is a finding.

Fix Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Under IIS, double-click the "MIME Types" icon.
    From the "Group by:" drop-down list, select "Content Type".
    From the list of extensions under "Application", remove MIME types for OS shell program extensions,
    to include at a minimum, the following extensions:
        .exe
        .dll
        .com
        .bat    
        .csh

    Under the "Actions" pane, click "Apply".
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Checks if any prohibited MIME type is configured in IIS.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>

Function Get-IISMIMEType
{
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$True)][Alias('E')][String] $Extension)

    # Function variable for storing MIMEType.
    [Microsoft.IIs.PowerShell.Framework.ConfigurationElement] $MIMEType = `
        (Get-WebConfigurationProperty -PSPath 'MACHINE/WEBROOT/APPHOST' -Filter "system.webServer/staticContent" -Name ".").Collection | Where-Object { $_.fileExtension -EQ $Extension }

    If ($Null -NE $MIMEType)
        { Return $True }
    Else
        { Return $False }
}

Set-PSDebug -Strict
$ErrorActionPreference = 'Stop'

# Script variable to track overall compliance.
[Boolean] $CheckCompliant = $True

Try
{
    [System.Collections.Generic.List[String]] $ProhibitedTypes = @()
        $ProhibitedTypes.Add('.exe')
        $ProhibitedTypes.Add('.dll')
        $ProhibitedTypes.Add('.com')
        $ProhibitedTypes.Add('.bat')
        $ProhibitedTypes.Add('.csh')

    ForEach ($MIMEType In $ProhibitedTypes)
    {
        If (Get-IISMIMEType -Extension $MIMEType)
            { $CheckCompliant = $False }
    }
}
Catch
    { $Host.SetShouldExit(1) }

Write-Output $CheckCompliant