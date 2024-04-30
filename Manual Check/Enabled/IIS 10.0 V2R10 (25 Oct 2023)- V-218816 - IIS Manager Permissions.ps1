# STIG Check Information
<#
Group Title:
    SRG-APP-000380-WSR-000072

Rule Title:
    Access to web administration tools must be restricted to the web manager and the
    web managers designees.

Discussion:
    A web server can be modified through parameter modification, patch installation,
    upgrades to the web server or modules, and security parameter changes. With each
    of these changes, there is the potential for an adverse effect such as a DoS, web
    server instability, or hosted application instability.

    To limit changes to the web server and limit exposure to any adverse effects from
    the changes, files such as the web server application files, libraries, and configuration
    files must have permissions and ownership set properly to only allow privileged users access.

    The key web service administrative and configuration tools must only be accessible by
    the web server staff. All users granted this authority will be documented and approved by
    the ISSO. Access to the IIS Manager will be limited to authorized users and administrators.

Satisfies:
    SRG-APP-000380-WSR-000072, SRG-APP-000435-WSR-000147, SRG-APP-000033-WSR-000169

Check Text:
    Right-click "InetMgr.exe", then click "Properties" from the "Context" menu.
    Select the "Security" tab.
    Review the groups and user names.
    The following accounts may have Full control privileges:
        TrustedInstaller
        Web Managers
        Web Manager designees
        CREATOR OWNER: Full Control, Subfolders and files only
    The following accounts may have read and execute, or read permissions:
        Non Web Manager Administrators
        ALL APPLICATION PACKAGES (built-in security group)
        ALL RESTRICTED APPLICATION PACKAGES (built-in security group)
        SYSTEM
        Users

    Specific users may be granted read and execute and read permissions.
    Compare the local documentation authorizing specific users, against the users observed when reviewing the groups and users.

    If any other access is observed, this is a finding.

Fix Text:
    Restrict access to the web administration tool to only the web manager and the web manager’s designees.
#>


# Script Information
<#
This script checks and reports compliance of the following items listed in the relevant check:
* Permissions on C:\Windows\System32\inetsrv\InetMgr.exe.
Note: This check references non-explicit groups such as "Web Managers" and "Non Web Manager Administrators",
as such this script cannot test for those unless you define them. The script will consider "BUILTIN\Administrators"
as a "Non Web Manager".
This check is done per server.

This script returns a true or false value representing compliance on the whole, any item failure
will result in the entire check being considered non-compliant.

This script makes no changes to any configuration or settings.
#>


Function Get-InetMgrAccess
{
    [CmdletBinding()]
    Param ([Parameter(Mandatory=$True)][Alias('P')][String] $Path)

    # Function variable to track discovery of unexpected rule.
    [Boolean] $UnexpectedRuleFound = $False

    # Functionvariabes to hold information.
    [System.Security.AccessControl.AuthorizationRuleCollection] $InetSrvRules = (Get-Acl -Path $Path).Access

    # Function variables to setup access entries.
    [System.Security.Principal.NTAccount] $System = 'NT AUTHORITY\SYSTEM'
    [System.Security.Principal.NTAccount] $Administrators = 'BUILTIN\Administrators'
    [System.Security.Principal.NTAccount] $TrustedInstaller = 'NT SERVICE\TrustedInstaller'
    [System.Security.Principal.NTAccount] $AllApplicationPackages = 'APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES'
    [System.Security.Principal.NTAccount] $AllRestrictedApplicationPackages = 'APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES'
    # Typedef isn't needed for checking, only setting.
    #[System.Security.Principal.SecurityIdentifier] $AllRestrictedApplicationPackages = `
    #    [Security.Principal.NTAccount]::new('ALL RESTRICTED APPLICATION PACKAGES').Translate([System.Security.Principal.SecurityIdentifier])
    [System.Security.Principal.NTAccount] $Users = 'BUILTIN\Users'
    [System.Security.Principal.NTAccount] $CreatorOwner = 'CREATOR OWNER'
    [System.Security.AccessControl.FileSystemRights] $FullControl = [System.Security.AccessControl.FileSystemRights]::FullControl
    [System.Security.AccessControl.FileSystemRights] $ReadAndExecute = [System.Security.AccessControl.FileSystemRights]::ReadAndExecute
    # Synchronize is being automatically added to ReadAndExecute.
    #[System.Security.AccessControl.FileSystemRights] $ReadExecuteSynchronize = `
    #    [System.Security.AccessControl.FileSystemRights]::ReadAndExecute + [System.Security.AccessControl.FileSystemRights]::Synchronize
    [System.Security.AccessControl.AccessControlType] $Allow = [System.Security.AccessControl.AccessControlType]::Allow
    [System.Security.AccessControl.InheritanceFlags] $InheritNone = [System.Security.AccessControl.InheritanceFlags]::None
    [System.Security.AccessControl.PropagationFlags] $PropNone = [System.Security.AccessControl.PropagationFlags]::None
    [System.Security.AccessControl.PropagationFlags] $PropInheretOnly = [System.Security.AccessControl.PropagationFlags]::InheritOnly

    [System.Collections.Generic.List[System.Security.AccessControl.FileSystemAccessRule]] $ExpectedRules = @()
        $ExpectedRules.Add((New-Object System.Security.AccessControl.FileSystemAccessRule($System, $ReadAndExecute, $InheritNone, $PropNone, $Allow)))
        $ExpectedRules.Add((New-Object System.Security.AccessControl.FileSystemAccessRule($Administrators, $ReadAndExecute, $InheritNone, $PropNone, $Allow)))
        $ExpectedRules.Add((New-Object System.Security.AccessControl.FileSystemAccessRule($TrustedInstaller, $FullControl, $InheritNone, $PropNone, $Allow)))
        $ExpectedRules.Add((New-Object System.Security.AccessControl.FileSystemAccessRule($AllApplicationPackages, $ReadAndExecute, $InheritNone, $PropNone, $Allow)))
        $ExpectedRules.Add((New-Object System.Security.AccessControl.FileSystemAccessRule($AllRestrictedApplicationPackages, $ReadAndExecute, $InheritNone, $PropNone, $Allow)))
        $ExpectedRules.Add((New-Object System.Security.AccessControl.FileSystemAccessRule($Users, $ReadAndExecute, $InheritNone, $PropNone, $Allow)))
        $ExpectedRules.Add((New-Object System.Security.AccessControl.FileSystemAccessRule($CreatorOwner, $FullControl, $InheritNone, $PropInheretOnly, $Allow)))
   
    ForEach ($InetSrvRule In $InetSrvRules)
    {
        [Boolean] $MatchesExpectedRule = $False
        ForEach ($Rule In $ExpectedRules)
        {
            If ($Null -EQ (Compare-Object -ReferenceObject $Rule -DifferenceObject $InetSrvRule -Property FileSystemRights, AccessControlType, IdentityReference, InheritanceFlags, PropagationFlags))
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
    If ((Test-Path -Path "$env:SystemRoot\System32\inetsrv\InetMgr.exe"))
    {
        [String] $EXEPath = (Get-Item -Path "$env:SystemRoot\System32\inetsrv\InetMgr.exe").FullName

        If (-NOT (Get-InetMgrAccess -Path $EXEPath))
            { $CheckCompliant = $False }
    }
    Else
        { $CheckCompliant = $False }
}
Catch
    { $Host.SetShouldExit(1) }

Write-Output $CheckCompliant