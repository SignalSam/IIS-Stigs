# STIG Check Information
<#
Group Title:
    SRG-APP-000120-WSR-000070

Rule Title:
    The log information from the IIS 10.0 web server must be protected from unauthorized modification or deletion.

Discussion:
    A major tool in exploring the website use, attempted use, unusual conditions, and problems are the access and
    error logs. In the event of a security incident, these logs can provide the System Administrator (SA) and the
    web manager with valuable information. Failure to protect log files could enable an attacker to modify the log
    file data or falsify events to mask an attacker's activity.

Satisfies:
    SRG-APP-000120-WSR-000070, SRG-APP-000118-WSR-000068, SRG-APP-000118-WSR-000069

Check Text:
    This check does not apply to service account IDs utilized by automated services necessary to process, manage, and store log files.
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Click the "Logging" icon.
    Click "Browse" and navigate to the directory where the log files are stored.
    Right-click the log file directory to review.
    Click "Properties".
    Click the "Security" tab.

    Verify log file access is restricted as follows. Otherwise, this is a finding.
        SYSTEM - Full Control
        Administrators - Full Control

Fix Text:
    Open the IIS 10.0 Manager.
    Click the IIS 10.0 web server name.
    Click the "Logging" icon.
    Click "Browse" and navigate to the directory where the log files are stored.
    Right-click the log file directory to review and click "Properties".
    Click the "Security" tab.

    Set the log file permissions for the appropriate group(s).
    Click "OK".

    Select "Apply" in the "Actions" pane.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Permissions on the log directory match what the check defines.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>

Function Get-IISLogDirectoryAccess
{
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$True)][Alias('N')][String] $Name)

    # Function variable to track discovery of unexpected rule.
    [Boolean] $UnexpectedRuleFound = $False

    # Function variables to setup access entries.
    [System.Security.Principal.NTAccount] $System = 'NT AUTHORITY\SYSTEM'
    [System.Security.Principal.NTAccount] $Administrators = 'BUILTIN\Administrators'
    [System.Security.AccessControl.FileSystemRights] $FullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
    [System.Security.AccessControl.AccessControlType] $Allow = [System.Security.AccessControl.AccessControlType]::Allow
    [System.Security.AccessControl.InheritanceFlags] $InheritAll = `
        [System.Security.AccessControl.InheritanceFlags]::ContainerInherit + [System.Security.AccessControl.InheritanceFlags]::ObjectInherit
    [System.Security.AccessControl.PropagationFlags] $PropNone = [System.Security.AccessControl.PropagationFlags]::None

    [System.Collections.Generic.List[System.Security.AccessControl.FileSystemAccessRule]] $ExpectedRules = @()
        $ExpectedRules.Add((New-Object System.Security.AccessControl.FileSystemAccessRule($System, $FullControl, $InheritAll, $PropNone, $Allow)))
        $ExpectedRules.Add((New-Object System.Security.AccessControl.FileSystemAccessRule($Administrators, $FullControl, $InheritAll, $PropNone, $Allow)))
   
    [System.Security.AccessControl.AuthorizationRuleCollection] $LogAccess = `
        (Get-Acl -Path ([System.Environment]::ExpandEnvironmentVariables((Get-ItemProperty "IIS:\sites\$Name" -Name 'logFile').directory))).Access

    ForEach ($AccessRule In $LogAccess)
    {
        [Boolean] $MatchesExpectedRule = $False
        ForEach ($Rule In $ExpectedRules)
        {
            If ($Null -EQ (Compare-Object -ReferenceObject $Rule -DifferenceObject $AccessRule -Property FileSystemRights, AccessControlType, IdentityReference, InheritanceFlags, PropagationFlags))
                { $MatchesExpectedRule = $True }
        }

        If (-NOT $MatchesExpectedRule)
            { $UnexpectedRuleFound = $True }
    }

    If (-NOT $UnexpectedRuleFound)
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
    [System.Collections.Generic.List[Microsoft.IIs.PowerShell.Framework.ConfigurationElement]] $IISSites = Get-Website

    ForEach ($IISSite In $IISSites)
    {
        If (-NOT (Get-IISLogDirectoryAccess -Name $IISSite.Name))
            { $CheckCompliant = $False }
    }
}
Catch
    {write-host 'ouch'
        # $Host.SetShouldExit(1) 
    }

Write-Output $CheckCompliant